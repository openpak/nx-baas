package main

// POST /internal/switch/identity {"openpak":"nx2…"}, {"id_token":"eyJ…"} or {"pid":18…} -> the
// player's Switch projection plus the friends that have one. The title-server surface (PRD §8):
// an NPLN or NEX server hands over the openpak claim it found in a client's id_token, the whole
// id_token when there is no claim to find, or a pid it already proved from its own bearer, and
// never needs the signing key or the core.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"time"
)

type switchPlayer struct {
	PID        uint64 `json:"pid"`
	BaasUserID string `json:"baas_user_id"` // the NSA id titles see
	Nickname   string `json:"nickname"`
}

func (s *server) switchIdentity(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		OpenPak    string `json:"openpak"`
		IDToken string `json:"id_token"`
		PID     uint64 `json:"pid"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	pid := in.PID
	switch {
	case in.OpenPak != "":
		var ok bool
		if pid, _, ok = verifyNexToken(s.acct.nexSigningKey(), in.OpenPak); !ok {
			apiErr(w, http.StatusUnauthorized, "openpak not proven")
			return
		}
	case in.IDToken != "":
		var genuine bool
		if pid, genuine = s.pidForIDToken(in.IDToken); !genuine {
			apiErr(w, http.StatusUnauthorized, "id_token not proven")
			return
		}
		// pid can be 0 here, and that is deliberately not a 401: the token is genuine and we
		// simply do not know the account. servers/nex maps 401 to TokenExpired and the console
		// fetches a fresh token and retries, so answering 401 for an unknown account is a
		// refresh loop. Falling through gives the 404 that maps to ValidationFailed instead.
	}
	id, err := s.acct.Identity(pid)
	if err != nil {
		logErr("identity", err)
		apiErr(w, http.StatusNotFound, "unknown pid")
		return
	}
	friends := make([]switchPlayer, 0, len(id.Friends))
	for _, f := range id.Friends {
		friends = append(friends, switchPlayer{PID: f.PID, BaasUserID: f.BaasUserID, Nickname: f.Nickname})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pid": id.PID, "baas_user_id": id.BaasUserID, "nickname": id.Nickname, "friends": friends,
		// Where the player lives, so a game server can place their room on the region node for it.
		"country": id.Country})
}

// pidForIDToken proves a BAAS id_token this server issued and answers with the account behind
// it. A retail console sends a plain id_token with no binding claim -- only an emulator build
// adds one -- so treating a missing claim as an error refuses every real console. The signature
// is the proof, and it is one we can check because we minted the token.
//
// Every token this server signs uses the same key, so the signature alone does not say what kind
// of token this is: "typ" and "iss" are what keep an access token, a Nintendo-Account token or a
// refresh token from being spent here as a login.
//
// The bool is "this token is genuine", not "this call succeeded". A genuine token for an account
// we do not know returns (0, true), because the two cases are answered with different status
// codes and a caller that conflates them makes a console retry forever.
func (s *server) pidForIDToken(tok string) (uint64, bool) {
	c, err := parseJWT(tok, &s.key.PublicKey)
	if err != nil {
		return 0, false
	}
	if str(c, "typ") != "id_token" || str(c, "iss") != baasIssuer {
		return 0, false
	}
	exp, _ := c["exp"].(float64)
	if int64(exp) <= time.Now().Unix() {
		return 0, false
	}
	// Genuine from here on. ponytail: the subject is the BAAS user id, which is the store's own
	// key, so the lookup is the mapping. A session table is the upgrade if a token ever has to be
	// revocable before it expires.
	u := s.store.User(str(c, "sub"))
	if u == nil || u.PID == 0 {
		return 0, true
	}
	return u.PID, true
}

// switchFriendCode answers "what is this account's friend code" for the
// website, which cannot know: the code is minted here and the core holds only
// the link subject, which is the BAAS user id. The site was formatting that
// hex id as SW-xxxx-xxxx-xxxx, so people were being shown, and reading out, an
// identifier that is not their friend code.
func (s *server) switchFriendCode(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	accountID := r.URL.Query().Get("account_id")
	if accountID == "" {
		apiErr(w, http.StatusBadRequest, "account_id required")
		return
	}
	code, ok := s.acct.friendCodeForAccount(accountID)
	if !ok {
		apiErr(w, http.StatusNotFound, "no console linked to that account")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"friend_code": code})
}

// ---- the emulator surface ----
//
// An emulator has no console certificate and no BAAS device account; it signs in on the
// website and asks, through the website, for the Switch identity of its OpenPak account: the
// PID and friend code, the openpak token its locally signed id_token carries so title servers know
// who is playing, and the friend graph with the presence the game servers report. The website
// is the only caller; it proves the bearer and sends the account id.

// switchEmulator answers GET /internal/switch/emulator?account_id=…
func (s *server) switchEmulator(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	accountID := r.URL.Query().Get("account_id")
	if accountID == "" {
		apiErr(w, http.StatusBadRequest, "account_id required")
		return
	}
	b, ok := s.acct.(*openpakBackend)
	if !ok {
		apiErr(w, http.StatusNotImplemented, "openpak backend only")
		return
	}
	// First sight of an account mints its Switch identity, exactly as linking a console does.
	pr, err := b.ensure(r.Context(), accountID)
	if err != nil {
		logErr("emulator ensure", err)
		apiErr(w, http.StatusBadGateway, "identity unavailable")
		return
	}
	id, err := s.acct.Identity(pr.PID)
	if err != nil {
		logErr("emulator identity", err)
		apiErr(w, http.StatusNotFound, "unknown account")
		return
	}
	friend := func(f Friend) map[string]any {
		return map[string]any{
			"pid": f.PID, "account_id": b.accountFor(f.PID), "name": f.Nickname, "friend_code": f.FriendCode,
			"presence": map[string]any{"status": f.PresenceStatus, "app_field": f.PresenceAppField, "app_id": f.PresenceAppID},
		}
	}
	friends := make([]map[string]any, 0, len(id.Friends))
	for _, f := range id.Friends {
		friends = append(friends, friend(f))
	}
	requests := make([]map[string]any, 0, len(id.FriendRequests))
	for _, f := range id.FriendRequests {
		requests = append(requests, friend(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pid": pr.PID, "username": id.Nickname, "friend_code": pr.FriendCode, "baas_user_id": pr.BaasUserID,
		"token": s.acct.nexToken(pr.PID, id.Nickname), "friends": friends, "requests": requests,
	})
}

// switchEmulatorFriend answers POST /internal/switch/emulator/friend
// {"account_id":…, "action":"request"|"accept"|"decline", "pid":…, "friend_code":…}
func (s *server) switchEmulatorFriend(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		AccountID  string `json:"account_id"`
		Action     string `json:"action"`
		PID        uint64 `json:"pid"`
		FriendCode string `json:"friend_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || in.AccountID == "" {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	b, ok := s.acct.(*openpakBackend)
	if !ok {
		apiErr(w, http.StatusNotImplemented, "openpak backend only")
		return
	}
	pr, err := b.ensure(r.Context(), in.AccountID)
	if err != nil {
		apiErr(w, http.StatusBadGateway, "identity unavailable")
		return
	}
	target := in.PID
	if in.Action == "request" && in.FriendCode != "" {
		f, err := s.acct.Resolve(url.Values{"friend_code": {in.FriendCode}})
		if err != nil || f == nil {
			apiErr(w, http.StatusNotFound, "no account for that friend code")
			return
		}
		target = f.PID
	}
	if target == 0 || target == pr.PID {
		apiErr(w, http.StatusBadRequest, "pid or friend_code required")
		return
	}
	switch in.Action {
	case "request":
		err = s.acct.FriendRequest(pr.PID, target)
	case "accept":
		err = s.acct.FriendAccept(pr.PID, target, true)
	case "decline":
		err = s.acct.FriendAccept(pr.PID, target, false)
	default:
		apiErr(w, http.StatusBadRequest, "unknown action")
		return
	}
	if err != nil {
		apiErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// switchCA hands the website the CA every console-facing certificate chains to, so an
// emulator can fetch it over public TLS from openpak.org and pin it, instead of turning
// verification off.
func (s *server) switchCA(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	pem, err := os.ReadFile(getenv("NX_CA_DIR", "/data/ca") + "/ca.pem")
	if err != nil {
		apiErr(w, http.StatusNotFound, "no CA on this adapter")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(pem)
}
