package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"nx-baas/internal/core"
	"nx-baas/internal/services"
	"strings"
	"testing"
)

func TestIsSpelunkyStaysOnItsName(t *testing.T) {
	for host, want := range map[string]bool{
		"x.spelunky2.net":         true,
		"X.SPELUNKY2.NET":         true,
		"cdn.spelunky2.net":       false,
		"edge-00.spelunky2.net":   false,
		"spelunky2.net":           false,
		"x.spelunky2.net.evil.io": false,
		"accounts.nintendo.com":   false,
	} {
		if got := services.IsSpelunky(host); got != want {
			t.Errorf("isSpelunky(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestSpelunkyForwardsWhenConfigured(t *testing.T) {
	body := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2ln"
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		got, _ := io.ReadAll(r.Body)
		if string(got) != body || r.Host != "x.spelunky2.net" || r.URL.Path != "/nso" {
			t.Errorf("proxy changed the host, path or body")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(make([]byte, 18))
	}))
	defer upstream.Close()
	t.Setenv("NX_SPELUNKY2_URL", upstream.URL)
	s := &server{Core: &core.Core{}}
	r := httptest.NewRequest("POST", "https://x.spelunky2.net/nso", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || calls != 1 || w.Body.Len() != 18 {
		t.Fatalf("token check did not reach its separate service: %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content type %q, want the binary protocol's", ct)
	}
}

func TestSpelunkyFallsThroughWhenUnset(t *testing.T) {
	t.Setenv("NX_SPELUNKY2_URL", "")
	s := &server{Core: &core.Core{}}
	r := httptest.NewRequest("POST", "https://x.spelunky2.net/nso", strings.NewReader("token"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("unset service changed the catch-all: %d", w.Code)
	}
}
