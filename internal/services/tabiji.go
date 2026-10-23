package services

import (
	"log"
	"net/http"
	"nx-baas/internal/httpx"
	"nx-baas/redact"
	"strings"
)

// tabiji: firmware 23.0.0's play-history service (api.hac.%.tabiji.srv.nintendo.net), spoken by
// eupld's pdm.syn thread with the user's NSA id token. Decompiled from 23.0.1 eupld
// (docs: scratch/home/openpak-firmware-audit-23.0.x/social/FINDINGS.md §1):
//   - POST /console/v1/play_histories uploads up to 8 play sessions. The reply must carry all four
//     backpressure values, or the upload fails (2178-1681), stays queued and files an error report
//     every cycle.
//   - GET /console/v1/play_statistics/<016x> asks for one title's server-side totals; 404 means
//     "no record" and is skipped silently.
//
// ponytail: histories are discarded like prepo's play reports (netdiag.go: OpenPak collects no
// play reports) and every statistic is a 404. Storing them would give cross-device play time for
// the title grid; add a table here when that is wanted.
func (s *Service) Tabiji(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	if _, genuine := s.PIDForIDToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); !genuine {
		log.Printf("[tabiji] %s %s: no valid NSA id token", r.Method, redact.Path(p))
		httpx.WriteJSON(w, 401, map[string]any{"status": 401, "code": "unauthorized", "detail": "invalid id token"})
		return
	}
	switch {
	case r.Method == http.MethodPost && p == "/console/v1/play_histories":
		log.Printf("[tabiji] play histories: %d bytes discarded (OpenPak collects no play reports)", len(body))
		// max_play_histories_count 0 = no per-cycle cap; min_interval_sec is the wait before the next
		// cycle (the console never goes below 60).
		httpx.WriteJSON(w, 200, map[string]any{"backpressure": map[string]any{
			"standard": map[string]any{"max_play_histories_count": 0, "min_interval_sec": 3600},
			"catchup":  map[string]any{"max_play_histories_count": 0, "min_interval_sec": 60},
		}})
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/console/v1/play_statistics/"):
		httpx.WriteJSON(w, 404, map[string]any{"status": 404, "code": "not_found", "detail": "no play statistic"})
	default:
		httpx.Dump(r, body, "!! UNHANDLED tabiji")
		httpx.WriteJSON(w, 404, map[string]any{"status": 404, "code": "not_found", "detail": "no such route"})
	}
}
