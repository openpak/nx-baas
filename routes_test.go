package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"nx-baas/internal/core"
)

// The ACNH web API is reached through the router, past the catch-all: before it was routed the
// game errored (2219-xxxx) before it ever reached NEX. A body the API cannot parse gets its own
// refusal, never the catch-all's 404 {}.
func TestAcbaaHostIsRoutedToTheACNHAPI(t *testing.T) {
	s := &server{Core: &core.Core{}}
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/lands", strings.NewReader("\xc1"))
	r.Header.Set("Content-Type", "application/x-msgpack")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "msgpack") {
		t.Fatalf("acbaa host answered %d %q: it did not reach the ACNH API", w.Code, w.Body)
	}
}
