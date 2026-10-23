package main

// The /internal game API fails closed: without a configured key every route
// refuses, and only an explicit key (or the isolated-dev opt-out) opens it.
// The rest of the suite runs under the opt-out (TestMain); these tests pin
// both modes by managing the environment themselves.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func withEnv(t *testing.T, k, v string) {
	t.Helper()
	prev, had := os.LookupEnv(k)
	if v == "" {
		os.Unsetenv(k)
	} else {
		os.Setenv(k, v)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv(k, prev)
		} else {
			os.Unsetenv(k)
		}
	})
}

func postInternal(t *testing.T, s *server, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "https://api.openpak.org"+path, strings.NewReader(body))
	if key != "" {
		r.Header.Set("X-Internal-Key", key)
	}
	w := httptest.NewRecorder()
	s.gameAPI().ServeHTTP(w, r)
	return w
}

func TestInternalRoutesRefuseWithoutKey(t *testing.T) {
	withEnv(t, "NX_INTERNAL_KEY", "")
	withEnv(t, "OPENPAK_INTERNAL_KEY", "")
	withEnv(t, "NX_INTERNAL_INSECURE", "")
	s := testServer(t)
	w := postInternal(t, s, "/internal/photon-room", "", `{"identity":"x","room":"R"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("keyless internal route = %d, want 401", w.Code)
	}
}

func TestInternalRoutesAcceptWithKey(t *testing.T) {
	withEnv(t, "NX_INTERNAL_KEY", "test-key")
	withEnv(t, "NX_INTERNAL_INSECURE", "")
	s := testServer(t)
	// Bad body: 400 proves the request passed the key check (401 would not).
	w := postInternal(t, s, "/internal/photon-room", "test-key", `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("keyed internal route = %d, want 400 (past auth)", w.Code)
	}
	w = postInternal(t, s, "/internal/photon-room", "wrong-key", `{}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-key internal route = %d, want 401", w.Code)
	}
}

func TestInternalInsecureOptOut(t *testing.T) {
	withEnv(t, "NX_INTERNAL_KEY", "")
	withEnv(t, "OPENPAK_INTERNAL_KEY", "")
	withEnv(t, "NX_INTERNAL_INSECURE", "1")
	s := testServer(t)
	w := postInternal(t, s, "/internal/photon-room", "", `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("opt-out internal route = %d, want 400 (past auth)", w.Code)
	}
}
