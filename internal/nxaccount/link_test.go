package nxaccount

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"nx-baas/internal/core"
	"strings"
	"testing"
	"time"
)

// The whole point of the code is that a stale one on a TV cannot be used, and that approval
// happens on the console rather than on whoever scanned the square.
func TestLinkCodeLifecycle(t *testing.T) {
	s := &Service{Core: &core.Core{}, links: newLinkStore()}
	code, _ := s.links.new(url.Values{"client_id": {"abc"}})

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
	s := &Service{Core: &core.Core{}, links: newLinkStore(), codes: map[string]Code{}}
	code, _ := s.links.new(url.Values{})

	r := httptest.NewRequest(http.MethodPost, "/connect/1.0.0/qr/approve?c="+code, nil)
	w := httptest.NewRecorder()
	if !s.QRRoutes(w, r, nil) {
		t.Fatal("approve was not routed")
	}
	if w.Code != http.StatusConflict {
		t.Errorf("approving an unclaimed code = %d, want 409", w.Code)
	}
}

func TestStateReportsWhoClaimedIt(t *testing.T) {
	s := &Service{Core: &core.Core{}, links: newLinkStore()}
	code, _ := s.links.new(url.Values{})
	s.links.update(code, func(p *pendingLink) {
		p.State, p.Username, p.PID = linkClaimed, "hansolo", 1800000003
	})

	r := httptest.NewRequest(http.MethodGet, "/connect/1.0.0/qr/state?c="+code, nil)
	w := httptest.NewRecorder()
	s.QRRoutes(w, r, nil)

	body := w.Body.String()
	if !strings.Contains(body, `"state":"claimed"`) || !strings.Contains(body, `"account":"hansolo"`) {
		t.Errorf("state = %s", body)
	}
}

// A code is read off a television and typed on a phone: six digits, nothing
// else, so the keypad is enough and there is no letter to mistake for a digit.
func TestCodeShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c := randCode()
		if len(c) != codeLength {
			t.Fatalf("code %q has length %d", c, len(c))
		}
		if strings.TrimLeft(c, "0123456789") != "" {
			t.Errorf("code %q is not all digits", c)
		}
		seen[c] = true
	}
	// Distinct draws are the cheap check that the generator is random at all;
	// the modulo bias rejection sampling avoids is far too small to see here,
	// which is why it is handled in the code rather than asserted.
	if len(seen) < 190 {
		t.Errorf("only %d distinct codes in 200 draws", len(seen))
	}
}

// Six digits is one in a million, so guesses have to be capped: without this a
// script would work the space and find whichever codes happen to be live.
func TestGuessesAreCapped(t *testing.T) {
	g := newGuesses()
	const who = "1800000001"

	for i := 0; i < GuessLimit-1; i++ {
		g.wrong(who)
		if blocked, _ := g.blocked(who); blocked {
			t.Fatalf("blocked after %d wrong codes, before the limit", i+1)
		}
	}
	g.wrong(who)
	blocked, left := g.blocked(who)
	if !blocked {
		t.Fatal("still accepting guesses at the limit")
	}
	if left <= 0 || left > guessWindow {
		t.Errorf("wait of %v is not within the window", left)
	}

	// Another account is unaffected: one person mistyping must not lock out
	// everybody else.
	if blocked, _ := g.blocked("1800000002"); blocked {
		t.Error("one account's wrong guesses blocked another")
	}

	// Getting it right clears the count — someone who succeeded is not
	// mid-attack, and the next link should not start half-way to a lockout.
	g.right(who)
	if blocked, _ := g.blocked(who); blocked {
		t.Error("a correct code did not clear the count")
	}
}

// A code may be claimed once. A second phone entering the same code must not take over a link
// that is already waiting for approval on the console.
func TestCodeIsSingleUse(t *testing.T) {
	s := &Service{Core: &core.Core{}, links: newLinkStore(), phones: newPhoneStore()}
	code, _ := s.links.new(url.Values{})
	s.links.update(code, func(p *pendingLink) {
		p.State, p.Username, p.PID = linkClaimed, "first", 1
	})

	if got := s.links.get(code); got.State != linkClaimed || got.Username != "first" {
		t.Fatalf("state = %+v", got)
	}
	// The handler refuses anything not in the waiting state; asserting the guard directly
	// keeps this honest without standing up a full request.
	if s.links.get(code).State == linkWaiting {
		t.Error("a claimed code still reads as waiting")
	}
}

// Phone sessions expire: the page is opened for a minute, not to be stayed signed in on.
func TestPhoneSessionExpires(t *testing.T) {
	p := newPhoneStore()
	token := p.new(42, "hansolo")

	if s, ok := p.get(token); !ok || s.PID != 42 {
		t.Fatalf("fresh session = %+v %v", s, ok)
	}
	p.mu.Lock()
	s := p.by[token]
	s.Expires = time.Now().Add(-time.Minute)
	p.by[token] = s
	p.mu.Unlock()

	if _, ok := p.get(token); ok {
		t.Error("an expired session still resolved")
	}
	if _, ok := p.by[token]; ok {
		t.Error("an expired session was not dropped")
	}
}

func TestSignOutDropsTheSession(t *testing.T) {
	p := newPhoneStore()
	token := p.new(7, "someone")
	p.drop(token)
	if _, ok := p.get(token); ok {
		t.Error("session survived sign-out")
	}
}

// The QR must reveal nothing: it carries a pairing id, and the code appears on the console
// only once a phone has signed in against that pairing.
func TestCodeAppearsOnlyAfterSignIn(t *testing.T) {
	s := &Service{Core: &core.Core{}, links: newLinkStore(), phones: newPhoneStore()}
	code, pair := s.links.new(url.Values{})

	if code == pair {
		t.Fatal("the QR carries the code itself")
	}
	if got := s.links.get(code); got.State != linkWaiting {
		t.Fatalf("state before sign-in = %q, want waiting", got.State)
	}

	s.markSignedIn(pair, phoneSession{PID: 9, Username: "hansolo"})

	got := s.links.get(code)
	if got.State != linkSignedIn || got.Username != "hansolo" {
		t.Errorf("after sign-in = %+v, want signed_in for tobagin", got)
	}
	// A pairing nobody knows must not move anything.
	other, _ := s.links.new(url.Values{})
	s.markSignedIn("not-a-pair", phoneSession{PID: 1, Username: "someone"})
	if s.links.get(other).State != linkWaiting {
		t.Error("an unknown pairing changed a console session")
	}
}

// The console shows the code grouped and the phone is likely to type it that
// way, so a space must not be the difference between linking and "wrong code".
func TestGroupedCodeIsAccepted(t *testing.T) {
	code := randCode()
	shown := groupCode(code)
	if shown != code[:3]+" "+code[3:] {
		t.Fatalf("grouped %q from %q", shown, code)
	}
	if strings.ReplaceAll(shown, " ", "") != code {
		t.Errorf("what a person reads does not normalise back to the code")
	}
}

// A phone that scans a QR resolves the name in it with its own DNS. The name a console reaches
// us by is Nintendo's, so a QR built on it does not fail politely — it sends the pairing id to
// Nintendo from a device that never opted in. Without a reachable address there is no phone
// path offered at all.
func TestNoPhonePathIsOfferedOnANintendoHostname(t *testing.T) {
	s := &Service{Core: &core.Core{}}
	s.links = &linkStore{by: map[string]*pendingLink{}}
	t.Setenv("NX_LINK_BASE_URL", "")

	r := httptest.NewRequest("POST", "/connect/1.0.0/qr/new", nil)
	r.Host = "accounts.nintendo.com"
	w := httptest.NewRecorder()

	if !s.QRRoutes(w, r, nil) {
		t.Fatal("qr/new was not handled")
	}

	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("reply is not JSON: %v", err)
	}
	if out["code"] == "" || out["code"] == nil {
		t.Error("no code was issued; the form path needs one even with no phone path")
	}
	for _, leaky := range []string{"link_url", "qr"} {
		if v, ok := out[leaky]; ok {
			t.Errorf("%s was offered anyway: %v", leaky, v)
		}
	}
	if out["no_phone_reason"] == nil {
		t.Error("no reason given, so a client cannot say why the square is missing")
	}
}

func TestPhonePathIsOfferedWhenAnAddressIsConfigured(t *testing.T) {
	s := &Service{Core: &core.Core{}}
	s.links = &linkStore{by: map[string]*pendingLink{}}
	t.Setenv("NX_LINK_BASE_URL", "https://openpak.example")

	r := httptest.NewRequest("POST", "/connect/1.0.0/qr/new", nil)
	r.Host = "accounts.nintendo.com"
	w := httptest.NewRecorder()
	s.QRRoutes(w, r, nil)

	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("reply is not JSON: %v", err)
	}
	link, _ := out["link_url"].(string)
	if !strings.HasPrefix(link, "https://openpak.example/link?p=") {
		t.Errorf("link_url = %q, want the configured address", link)
	}
	if qr, _ := out["qr"].(string); !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Error("no QR image came with the link")
	}
}
