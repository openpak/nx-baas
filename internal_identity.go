package main

// The identity API: what the services split out of this one (nx-shop, nx-penne, nx-pctl;
// docs/service-split.md) may ask the core about accounts. It is the whole of their access to
// baas.json and the account backend -- they hold no copy of either -- so it stays small:
// who a BAAS user or a Nintendo Account is and whether the account is locked, an account's
// Switch id, a user's picture, one friend preference, and the presence a console publishes
// over Penne (the core owns presence; the frontline only decodes it).
//
// It lives on the game-API listener beside the other /internal routes, with one difference
// from most of them: like the store admin API, no key configured means no caller, because
// these answers map accounts to each other.
//
// The JSON shapes are github.com/openpak/nx-common/nxapi's (User, NA, Account, Presence,
// PresenceRenewal, FriendPreference). This file does not import that module; the tests in
// internal_identity_test.go pin the field names instead.

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"nx-baas/redact"
	"strings"
)

// identityAuth answers for every identity route: 503 when no key is configured, 401 for a
// wrong one. True means the caller may proceed.
func identityAuth(w http.ResponseWriter, r *http.Request) bool {
	if err := storeAdminAuth(r); err != nil {
		writeAdminErr(w, err)
		return false
	}
	return true
}

// identityUsers serves /internal/identity/users/{id}[/avatar | /friends/{friend}/preference].
func (s *server) identityUsers(w http.ResponseWriter, r *http.Request) {
	if !identityAuth(w, r) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/internal/identity/users/"), "/")
	u := s.store.User(parts[0])
	if u == nil || r.Method != http.MethodGet {
		apiErr(w, http.StatusNotFound, "no such user")
		return
	}
	switch {
	case len(parts) == 1:
		writeJSON(w, 200, map[string]any{
			"id": u.ID, "na_id": u.NaID, "pid": u.PID, "nickname": u.Nickname, "lock": s.userLock(u),
		})
	case len(parts) == 2 && parts[1] == "avatar":
		// Exactly what the cdn-image host serves for /1/<id>: the shop's corner picture is
		// the one the console's profile shows.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/1/" + u.ID
		s.baas(w, r2, nil)
	case len(parts) == 4 && parts[1] == "friends" && parts[3] == "preference":
		writeJSON(w, 200, map[string]any{"online_notification": onlineNotificationOf(s.prefOf(u, parts[2]))})
	default:
		apiErr(w, http.StatusNotFound, "no such route")
	}
}

// identityNA serves /internal/identity/na/{na_id}. An NA id this server signed a token for
// names an account even before a console linked to it, so an unknown id is a 200 with no
// BAAS user, the same answer shopPrincipal used to compute in-process.
func (s *server) identityNA(w http.ResponseWriter, r *http.Request) {
	if !identityAuth(w, r) {
		return
	}
	naID := strings.TrimPrefix(r.URL.Path, "/internal/identity/na/")
	if naID == "" || strings.Contains(naID, "/") || r.Method != http.MethodGet {
		apiErr(w, http.StatusNotFound, "no such route")
		return
	}
	out := map[string]any{"na_id": naID, "baas_user_id": "", "pid": uint64(0), "lock": s.naLock(naID)}
	if pid := s.store.PIDForNA(naID); pid != 0 {
		out["pid"] = pid
		if u := s.store.UserByPID(pid); u != nil {
			out["baas_user_id"] = u.ID
		}
	}
	writeJSON(w, 200, out)
}

// identityAccounts serves /internal/identity/accounts/{account_id}: the Switch Nintendo
// Account id the projection minted for a core account (the store admin's account views).
func (s *server) identityAccounts(w http.ResponseWriter, r *http.Request) {
	if !identityAuth(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/internal/identity/accounts/")
	b, ok := s.acct.(*openpakBackend)
	if !ok || id == "" || r.Method != http.MethodGet {
		apiErr(w, http.StatusNotFound, "account lookup needs the openpak backend")
		return
	}
	naID := ""
	b.proj.mu.Lock()
	if pr := b.proj.ByAccount[id]; pr != nil {
		naID = pr.NaID
	}
	b.proj.mu.Unlock()
	if naID == "" {
		apiErr(w, http.StatusNotFound, "no Switch identity for this account")
		return
	}
	writeJSON(w, 200, map[string]any{"account_id": id, "na_id": naID})
}

// identityPresence serves POST /internal/identity/presence (a DAPresence frame the Penne
// frontline decoded) and POST /internal/identity/presence/renew (its lease).
func (s *server) identityPresence(w http.ResponseWriter, r *http.Request) {
	if !identityAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		apiErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var in struct {
		UserID   string `json:"user_id"`
		Device   string `json:"device"`
		State    string `json:"state"`
		AppID    string `json:"app_id"`
		AppField string `json:"app_field"`
		GroupID  string `json:"group_id"`
		ACDIndex *int   `json:"acd_index"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil || in.UserID == "" {
		apiErr(w, http.StatusBadRequest, "user_id required")
		return
	}
	u := s.store.User(in.UserID)
	if u == nil {
		apiErr(w, http.StatusNotFound, "no such user")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/renew") {
		s.renewDevicePresence(u.ID, in.Device)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if in.State == "" {
		apiErr(w, http.StatusBadRequest, "state required")
		return
	}
	acd := -1
	if in.ACDIndex != nil {
		acd = *in.ACDIndex
	}
	// Only a real console speaks Penne: emulators publish over REST (penne_presence.go).
	s.noteClientPresence(u, in.Device, "switch", "", in.State, in.AppID, in.AppField, in.GroupID, acd)
	w.WriteHeader(http.StatusNoContent)
}

// adminError is the strict internal routes' error: {"error": code, "message": msg}. The
// store admin API introduced it; the identity API answers in the same shape.
type adminError struct {
	status    int
	code, msg string
}

func (e *adminError) Error() string { return e.code + ": " + e.msg }

func adminErr(status int, code, format string, a ...any) *adminError {
	return &adminError{status: status, code: code, msg: fmt.Sprintf(format, a...)}
}

func writeAdminErr(w http.ResponseWriter, err error) {
	var ae *adminError
	if !errors.As(err, &ae) {
		log.Printf("[store-admin] internal: %v", redact.Err(err))
		ae = adminErr(500, "internal", "%v", err)
	}
	writeJSON(w, ae.status, map[string]any{"error": ae.code, "message": ae.msg})
}

// storeAdminAuth is internalOK made strict: same header, same key, but no key configured
// means nobody gets in.
func storeAdminAuth(r *http.Request) error {
	k := getenv("NX_INTERNAL_KEY", getenv("OPENPAK_INTERNAL_KEY", ""))
	if k == "" {
		return adminErr(503, "internal_key_not_configured", "set NX_INTERNAL_KEY to use the store admin API")
	}
	if !hmac.Equal([]byte(k), []byte(r.Header.Get("X-Internal-Key"))) {
		return adminErr(401, "unauthorized", "X-Internal-Key missing or wrong")
	}
	return nil
}
