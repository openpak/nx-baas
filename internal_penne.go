package main

// The penne API: the push state other services read and drive, served by whichever process
// holds it -- this one until the Penne cut-over, nx-penne after (docs/service-split.md). Both
// answer the same paths with the same JSON (github.com/openpak/nx-common/nxapi), so a caller
// only changes its base URL when Penne moves.
//
// Keyed like the identity API: no key configured, no caller.

import (
	"net/http"
	"strings"
)

// penneRegistrations serves GET /internal/penne/registrations/{penne_id}: whether the
// registration is live, the user it was made for and every user signed in on that console.
// It is what nx-shop's pushmo /p/<penne id> resolves accounts through.
func (s *server) penneRegistrations(w http.ResponseWriter, r *http.Request) {
	if !identityAuth(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/internal/penne/registrations/")
	if id == "" || strings.Contains(id, "/") || r.Method != http.MethodGet {
		apiErr(w, http.StatusNotFound, "no such route")
		return
	}
	ps := s.notifStore()
	out := map[string]any{"penne_id": id, "live": false, "user_id": "", "users": []string{}}
	if a := ps.AssocIfLive(id); a != nil {
		out["live"], out["user_id"] = true, a.UserID
		if users := ps.UsersOn(id); users != nil {
			out["users"] = users
		}
	}
	writeJSON(w, 200, out)
}
