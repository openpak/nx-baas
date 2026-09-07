package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The whole point of the code is that a stale one on a TV cannot be used, and that approval
// happens on the console rather than on whoever scanned the square.
func TestLinkCodeLifecycle(t *testing.T) {
	s := &server{links: newLinkStore()}
	code := s.links.new(url.Values{"client_id": {"abc"}})

	if got := s.links.get(code); got == nil || got.State != linkWaiting {
		t.Fatalf("fresh code state = %v", got)
	}
	if s.links.get("NOPE99") != nil {
		t.Error("an unknown code resolved")
	}
	// Codes are read off a screen and typed on a phone: case must not matter.
	if s.links.get(strings.ToLower(code)) == nil {
		t.Error("lower-case entry of the same code did not resolve")
	}
	if s.links.get(code).Query.Get("client_id") != "abc" {
		t.Error("the console's authorize parameters were not carried")
	}
}

func TestApproveRefusedUntilAPhoneClaims(t *testing.T) {
	s := &server{links: newLinkStore(), codes: map[string]naCode{}}
	code := s.links.new(url.Values{})

	r := httptest.NewRequest(http.MethodPost, "/connect/1.0.0/qr/approve?c="+code, nil)
	w := httptest.NewRecorder()
	if !s.qrRoutes(w, r, nil) {
		t.Fatal("approve was not routed")
	}
	if w.Code != http.StatusConflict {
		t.Errorf("approving an unclaimed code = %d, want 409", w.Code)
	}
}

func TestStateReportsWhoClaimedIt(t *testing.T) {
	s := &server{links: newLinkStore()}
	code := s.links.new(url.Values{})
	s.links.update(code, func(p *pendingLink) {
		p.State, p.Username, p.PID = linkClaimed, "hansolo", 1800000003
	})

	r := httptest.NewRequest(http.MethodGet, "/connect/1.0.0/qr/state?c="+code, nil)
	w := httptest.NewRecorder()
	s.qrRoutes(w, r, nil)

	body := w.Body.String()
	if !strings.Contains(body, `"state":"claimed"`) || !strings.Contains(body, `"account":"hansolo"`) {
		t.Errorf("state = %s", body)
	}
}

// A code goes on a television. It must not be guessable, and must not read as a word.
func TestCodeAlphabet(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c := randCode()
		if len(c) != codeLength {
			t.Fatalf("code %q has length %d", c, len(c))
		}
		if strings.ContainsAny(c, "AEIOU01L") {
			t.Errorf("code %q contains an ambiguous or vowel character", c)
		}
		seen[c] = true
	}
	if len(seen) < 190 {
		t.Errorf("only %d distinct codes in 200 draws", len(seen))
	}
}
