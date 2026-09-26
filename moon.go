package main

// moon is the parental-controls API: `api-<env>.pctl.srv.nintendo.net/moon/v1/…`,
// the only thing the pctl sysmodule (22.5.0 title 010000000000002E) needs from a
// server. Everything the console does on its own -- the PIN, the restriction
// level, the play timer, the bedtime alarm -- lives in pctl's system savedata and
// works offline. What dies without a server is pairing with the parent app and
// the settings sync. Contract: docs/switch/parental-controls-firmware-2026-09-26.md.
//
// Phase 0 of nx-baas/prds/native-switch-parental-controls-prd.md: log what the
// console sends and refuse in the shape it recognises. The ten paths, their
// verbs and their bodies are not invented here -- one on-console pairing attempt
// against this handler prints them, and the phases after this are written against
// that log.

import (
	"net/http"
	"strings"
)

// The error identities pctl carries as literals (study §5). A refusal that does
// not name one of these is a refusal the client cannot classify, which is why
// this handler never answers a bare status.
const (
	moonErrorBase        = "https://moon.nintendo.com/errors/v1/"
	moonNotFound         = "404/resource_is_not_found"
	moonMethodNotAllowed = "405/method_not_allowed"
	moonInvalidToken     = "401/invalid_token"
	moonOverTheTimeLimit = "409/over_the_time_limit"
	moonDevicesMaxed     = "400/devices_maxed"
	moonInternalError    = "500/internal_server_error"
)

// moonError writes a refusal. `type` is the identity above; `status`, `code` and
// `detail` are the other three error keys in pctl's string table (997708 and
// neighbours), so the envelope is those four and nothing guessed beyond them.
// ponytail: four keys because four are evidenced. If hardware shows the client
// reading a fifth, the log will name it.
func moonError(w http.ResponseWriter, slug string) {
	status, code, _ := strings.Cut(slug, "/")
	writeJSON(w, statusOf(status), map[string]any{
		"type":   moonErrorBase + slug,
		"status": statusOf(status),
		"code":   code,
		"detail": code,
	})
}

// statusOf reads the HTTP status out of the identity's own first segment, so the
// status line and the type URI can never disagree.
func statusOf(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 500
		}
		n = n*10 + int(c-'0')
	}
	if n < 100 || n > 599 {
		return 500
	}
	return n
}

// moon answers the pctl host. Anything under /moon/v1 is the parental-controls
// API; anything else on this host keeps the service-status answer it got before
// this handler existed, so nothing regresses while the surface is being learned.
func (s *server) moon(w http.ResponseWriter, r *http.Request, body []byte) {
	if !strings.HasPrefix(r.URL.Path, "/moon/v1") {
		s.serviceStatus(w, r, body)
		return
	}
	// The whole point of phase 0: the request, in full, in the log. dump keeps
	// the bearer truncated -- it is a device token, not a secret we need whole.
	dump(r, body, "[moon] pctl")
	moonError(w, moonNotFound)
}
