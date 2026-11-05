package gameapi

// DELETE /internal/accounts/{account_id}/data -- account erasure (card openpak/prds#120).
// Authorization: Bearer $ACCOUNT_ERASE_KEY, the one key the website's finaliser sends to
// every service, so this route does not use the X-Internal-Key scheme of the other
// /internal routes (a per-service key the finaliser does not hold). It lives on the game
// API listener (NX_API_ADDR), which is container-network-only and never routed by Traefik.

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"nx-baas/internal/erase"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/invitations"
	"nx-baas/redact"
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (s *Service) eraseAccount(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/internal/accounts/")
	id, tail, _ := strings.Cut(rest, "/")
	if tail != "data" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodDelete {
		httpx.APIErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	key := os.Getenv("ACCOUNT_ERASE_KEY")
	if key == "" {
		httpx.APIErr(w, http.StatusServiceUnavailable, "erasure not configured")
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare([]byte(got), []byte(key)) != 1 {
		httpx.APIErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !uuidRE.MatchString(id) {
		httpx.APIErr(w, http.StatusBadRequest, "invalid account id")
		return
	}
	id = strings.ToLower(id)
	b, ok := s.Acct.(*identity.OpenpakBackend)
	if !ok {
		httpx.APIErr(w, http.StatusServiceUnavailable, "account core backend not in use")
		return
	}
	n, err := erase.Account(r.Context(), b, erase.Targets{Store: s.Store, Invitations: invitations.StoreFor(), Acbaa: s.Acbaa}, id, true)
	if err != nil {
		log.Printf("[nx-baas] account erase failed: %v", redact.Err(err))
		httpx.APIErr(w, http.StatusInternalServerError, "erase failed")
		return
	}
	log.Printf("account erased account=%s rows=%d service=nx-baas", id, n)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"service": "nx-baas", "rows": n})
}
