// Package services is the other console services, per kinnay's server list: online save storage
// (OLSC/SCSI), friend recommendations and the per-title service status. Each was
// reaching this server and being answered with a 404 and an empty object, which
// is what a console shows as an error rather than as "there is nothing here".
//
// An empty, correctly shaped answer is a true statement -- this network has no
// cloud saves -- and it lets the console finish the screen instead of failing
// it. The saves PRD replaces the first one. BCAT and the News channel are
// nx-bcat's.
package services

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"nx-baas/internal/bans"
	"nx-baas/internal/core"
	"nx-baas/internal/friends"
	"nx-baas/internal/httpx"
	"nx-baas/redact"
	"strings"
	"sync"
)

// olsc is the answer when no saves service is configured (SAVES_URL empty):
// nothing is stored, so every list is empty and every upload is refused
// politely rather than 404'd. A console that gets a 404 here reports a
// save-data error; one that gets an empty list simply has no cloud saves.
// With SAVES_URL set the scsi hosts never reach this: see savesProxy.
func (s *Service) OLSC(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "notification_tokens"):
		// Echo the token back, which is what the documented reply carries.
		tok := friends.BodyField(body, r.URL.Query(), "notification_token")
		s.bindTokenProfile(r, tok)
		httpx.WriteJSON(w, 200, map[string]any{"notification_token": tok})
	case strings.HasSuffix(p, "/save_data_archives"):
		httpx.WriteJSON(w, 200, map[string]any{"save_data_archives": []any{}})
	case strings.Contains(p, "/save_data_archives/"):
		// start_upload, finish_upload, generate_key_seed_package and the rest
		// of the upload dance. Cloud saves are the saves PRD's job; until then
		// the honest answer is that this archive does not exist.
		httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
	case strings.Contains(p, "/application_policy/"):
		// Whether a title may sync at all. "No" is the true answer today.
		httpx.WriteJSON(w, 200, map[string]any{"application_policy": map[string]any{"save_data_backup": false}})
	default:
		httpx.Dump(r, body, "!! UNHANDLED olsc")
		httpx.WriteJSON(w, 200, map[string]any{})
	}
}

// frs is the friend recommendation service the friends applet calls when it
// opens. The module parses the reply as JSON (auth kind 1: none): $.items[*]
// with required requestedClientFriendId, clientFriend.nickname and createdAt,
// and errors in $.errors[0].{code,message}. An empty body is not the failure it
// was once written up as: rapidjson error 1 (document empty) is mapped to
// success with 0 items by the result table at 0x222448. What does fail is a
// *malformed* body (2121-0101/-0102/-0103), so the reply must be valid JSON.
// {"items":[]} is that, and it states the emptiness rather than implying it
// [friends-contract-22.5.0 §A.9, C18].
//
// Two constraints the parser imposes on any real list we serve later: an item
// missing one required field is skipped silently, and mii_image_url_param is
// truncated to 15 chars with the item still counted — so an over-long param
// becomes a broken image URL on the console rather than an error here.
//
// Only the recommendations operation is evidenced. Everything else FRS could
// serve is answered with an explicit gRPC UNIMPLEMENTED and a NOTICE log
// (SOC-04): an undocumented operation that pretends to succeed with an empty
// body is indistinguishable from a working one, which is exactly how
// unsupported operations stay broken and invisible. A console trace naming
// another operation is the evidence that promotes it to a documented answer.
func (s *Service) FRS(w http.ResponseWriter, r *http.Request, _ []byte) {
	const knownGood = "/v1/friend_recommendations"
	if strings.HasPrefix(r.URL.Path, knownGood) {
		log.Printf("[nx-baas] frs %s", redact.Path(r.URL.Path))
		// No recommendations of any kind: nintendo_account, nintendo_3ds
		// and nintendo_network_id all read the same $.items[].
		httpx.WriteJSON(w, 200, map[string]any{"items": []any{}})
		return
	}
	log.Printf("[nx-baas] frs UNSUPPORTED %s %s (answered grpc-status 12)", r.Method, redact.Path(r.URL.Path))
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", "12") // UNIMPLEMENTED
	w.Header().Set("Grpc-Message", "operation not implemented by this server")
	w.WriteHeader(http.StatusOK)
}

// serviceStatus is the "is this game's online service up" check. Saying yes for
// everything we serve is right; saying nothing at all reads as an outage.
func (s *Service) ServiceStatus(w http.ResponseWriter, r *http.Request, _ []byte) {
	log.Printf("[nx-baas] service status %s", redact.Path(r.URL.Path))
	httpx.WriteJSON(w, 200, map[string]any{"status": "available", "type": "NORMAL"})
}

// newSavesProxy forwards a scsi-host request to the saves service: same path under /scsi,
// same query, body streamed. The console's bearer is replaced by the account it proves.
func NewSavesProxy(base string) *httputil.ReverseProxy {
	target, err := url.Parse(base)
	if err != nil {
		log.Fatalf("[nx-baas] SAVES_URL %q: %v", base, redact.Err(err))
	}
	return &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
			r.URL.Path = "/scsi" + r.URL.Path
			r.URL.RawPath = ""
			r.Host = target.Host
		},
		FlushInterval: -1,
	}
}

// savesProxy attaches who the console is. The storage API carries the BAAS access token;
// the blob hosts carry nothing, and the saves service treats their signed URLs as the
// credential. The token never travels on: only the account it proved does.
// bindTokenProfile learns which user a console profile belongs to. Within a
// second of minting a profile's notification token, olsc uploads that token to
// scsi .../network_service_accounts/<user>/notification_tokens with the user's
// own token: token -> profile (recorded at mint) -> user (proven here)
// [firmware, olsc; internal research notes §1].
func (s *Service) bindTokenProfile(r *http.Request, tok string) {
	claims := s.Bearer(r)
	if tok == "" || claims == nil {
		return
	}
	uid := httpx.Str(claims, "sub")
	if s.Store.User(uid) == nil {
		return
	}
	s.Penne.BindToken(tok, uid)
}

func (s *Service) SavesProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/notification_tokens") {
		// Small JSON; read it for the profile binding and hand it on intact.
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		s.bindTokenProfile(r, friends.BodyField(body, r.URL.Query(), "notification_token"))
	}
	r.Header.Del("X-OpenPak-Account")
	r.Header.Del("X-OpenPak-NSA")
	r.Header.Del("X-OpenPak-Device")
	r.Header.Set("X-Internal-Key", s.SavesKey)
	if claims := s.Bearer(r); claims != nil {
		if uid := httpx.Str(claims, "sub"); uid != "" {
			if u := s.Store.User(uid); u != nil {
				if b, ok := s.Acct.(interface{ AccountFor(uint64) string }); ok {
					if acct := b.AccountFor(u.PID); acct != "" {
						r.Header.Set("X-OpenPak-Account", acct)
						r.Header.Set("X-OpenPak-NSA", uid)
						r.Header.Set("X-OpenPak-Device", httpx.Str(claims, "bs:did"))
					}
				}
			}
		}
	}
	r.Header.Del("Authorization")
	s.Saves.ServeHTTP(w, r)
}

// Service is the other Nintendo services a console reaches through nx-baas: the NSO pages,
// the voice lobby, error reports, play reports and the connection test, play history, the
// vermillion gateway, the save-data cloud and the NIM routes that need no catalog.
type Service struct {
	*core.Core
	Locks *bans.Checker
	// Saves forwards the scsi hosts (save-data cloud) to the saves service, with the console's
	// proven account attached; nil answers the empty-cloud fallback instead.
	Saves    *httputil.ReverseProxy
	SavesKey string
	// Reports is the console error-report spool (errorreport.go).
	Reports *ReportSpool
	mu      sync.Mutex
}
