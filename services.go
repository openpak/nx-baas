package main

// The other console services, per kinnay's server list: news (BCAT) and online
// save storage (OLSC/SCSI). Both were reaching this server and being answered
// with a 404 and an empty object, which is what a console shows as an error
// rather than as "there is nothing here".
//
// Neither stores anything yet. An empty, correctly shaped answer is a true
// statement -- this network has no news and no cloud saves -- and it lets the
// console finish the screen instead of failing it. The saves PRD replaces the
// second one; the news PRD the first.

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// bcat serves the news service. The console asks per title and expects a
// content container; an empty topic list is "no news for this game".
func (s *server) bcat(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/topics"):
		writeJSON(w, 200, map[string]any{"topics": []any{}})
	case strings.HasSuffix(p, "/catalog"):
		writeJSON(w, 200, map[string]any{"topics": []any{}, "updatedAt": time.Now().Unix()})
	case strings.Contains(p, "/latest_news/"), strings.Contains(p, "/online_archives"):
		writeJSON(w, 200, map[string]any{"news": []any{}})
	default:
		dump(r, body, "!! UNHANDLED bcat")
		writeJSON(w, 200, map[string]any{})
	}
}

// olsc is the answer when no saves service is configured (SAVES_URL empty):
// nothing is stored, so every list is empty and every upload is refused
// politely rather than 404'd. A console that gets a 404 here reports a
// save-data error; one that gets an empty list simply has no cloud saves.
// With SAVES_URL set the scsi hosts never reach this: see savesProxy.
func (s *server) olsc(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "notification_tokens"):
		// Echo the token back, which is what the documented reply carries.
		tok := bodyField(body, r.URL.Query(), "notification_token")
		writeJSON(w, 200, map[string]any{"notification_token": tok})
	case strings.HasSuffix(p, "/save_data_archives"):
		writeJSON(w, 200, map[string]any{"save_data_archives": []any{}})
	case strings.Contains(p, "/save_data_archives/"):
		// start_upload, finish_upload, generate_key_seed_package and the rest
		// of the upload dance. Cloud saves are the saves PRD's job; until then
		// the honest answer is that this archive does not exist.
		baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
	case strings.Contains(p, "/application_policy/"):
		// Whether a title may sync at all. "No" is the true answer today.
		writeJSON(w, 200, map[string]any{"application_policy": map[string]any{"save_data_backup": false}})
	default:
		dump(r, body, "!! UNHANDLED olsc")
		writeJSON(w, 200, map[string]any{})
	}
}

// frs is the friend recommendation service the friends applet calls when it
// opens. Captured from a working server on 2026-09-08: 200, content-type
// application/grpc, empty body. We answered 404 {} and the applet had a
// failure in the middle of the screen that shows friends.
//
// Only that one operation is evidenced. Everything else FRS could serve is
// answered with an explicit gRPC UNIMPLEMENTED and a NOTICE log (SOC-04):
// an undocumented operation that pretends to succeed with an empty body is
// indistinguishable from a working one, which is exactly how unsupported
// operations stay broken and invisible. A console trace naming another
// operation is the evidence that promotes it to a documented answer.
func (s *server) frs(w http.ResponseWriter, r *http.Request, _ []byte) {
	const knownGood = "/v1/friend_recommendations"
	if strings.HasPrefix(r.URL.Path, knownGood) {
		log.Printf("[nx-baas] frs %s", r.URL.Path)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		return
	}
	log.Printf("[nx-baas] frs UNSUPPORTED %s %s (answered grpc-status 12)", r.Method, r.URL.Path)
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", "12") // UNIMPLEMENTED
	w.Header().Set("Grpc-Message", "operation not implemented by this server")
	w.WriteHeader(http.StatusOK)
}

// serviceStatus is the "is this game's online service up" check. Saying yes for
// everything we serve is right; saying nothing at all reads as an outage.
func (s *server) serviceStatus(w http.ResponseWriter, r *http.Request, _ []byte) {
	log.Printf("[nx-baas] service status %s", r.URL.Path)
	writeJSON(w, 200, map[string]any{"status": "available", "type": "NORMAL"})
}

// newSavesProxy forwards a scsi-host request to the saves service: same path under /scsi,
// same query, body streamed. The console's bearer is replaced by the account it proves.
func newSavesProxy(base string) *httputil.ReverseProxy {
	target, err := url.Parse(base)
	if err != nil {
		log.Fatalf("[nx-baas] SAVES_URL %q: %v", base, err)
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
func (s *server) savesProxy(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("X-OpenPak-Account")
	r.Header.Del("X-OpenPak-NSA")
	r.Header.Del("X-OpenPak-Device")
	r.Header.Set("X-Internal-Key", s.savesKey)
	if claims := s.bearer(r); claims != nil {
		if uid := str(claims, "sub"); uid != "" {
			if u := s.store.User(uid); u != nil {
				if b, ok := s.acct.(interface{ accountFor(uint64) string }); ok {
					if acct := b.accountFor(u.PID); acct != "" {
						r.Header.Set("X-OpenPak-Account", acct)
						r.Header.Set("X-OpenPak-NSA", uid)
						r.Header.Set("X-OpenPak-Device", str(claims, "bs:did"))
					}
				}
			}
		}
	}
	r.Header.Del("Authorization")
	s.saves.ServeHTTP(w, r)
}
