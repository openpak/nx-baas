package acbaa

import (
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"nx-baas/internal/core"
	"nx-baas/internal/store"
)

// serve reads the body the way nx-baas's router does (at most 1 MiB) and hands it to Handle.
func serve(s *Service, w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.Handle(w, r, body)
}

func testServer(t *testing.T) *Service {
	t.Helper()
	return &Service{Core: &core.Core{Store: store.Load(filepath.Join(t.TempDir(), "baas.json"))}}
}
