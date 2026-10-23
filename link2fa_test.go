package main

// Console two-factor step-up: the password proves, the code completes.
// Nothing is signed in, linked or approved between the two.

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"net/url"
	"nx-baas/internal/identity"
	"regexp"
	"strings"
	"testing"
)

func twoFAServer(t *testing.T) (*server, *fakeCore) {
	t.Helper()
	s := testServer(t)
	f := newFakeCore()
	f.addAccount("plain@example.com", "Plain", "correct horse battery")
	f.add2FAAccount("2fa@example.com", "TwoFA", "correct horse battery", "123456")
	b := identity.NewOpenpakBackendWithClients(t.TempDir(), fakeIdentity{f: f}, fakeLinks{f: f}, fakeSocial{f: f}, []byte(strings.Repeat("k", 32)))
	s.Acct = b
	s.links = newLinkStore()
	s.guesses = newGuesses()
	s.phones = newPhoneStore()
	s.pending2FA = newPending2FAStore()
	s.codes = map[string]naCode{}
	s.device = map[string]string{}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.Key, s.IDKid, s.AccKid, s.NAKid = key, "id", "acc", "na"
	return s, f
}

func postLink(t *testing.T, s *server, path, form string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "https://link.openpak.org"+path, strings.NewReader(form))
	r.Host = "link.openpak.org"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	if !s.qrRoutes(w, r, []byte(form)) {
		t.Fatalf("%s not routed", path)
	}
	return w
}

var pendingTokenRe = regexp.MustCompile(`name="token" value="([0-9a-f]{64})"`)

// TestPhoneLinkSecondFactor: password, then code, then the console can be claimed.
func TestPhoneLinkSecondFactor(t *testing.T) {
	s, _ := twoFAServer(t)

	w := postLink(t, s, "/link", url.Values{"email": {"2fa@example.com"}, "password": {"correct horse battery"}, "pair": {""}}.Encode())
	body := w.Body.String()
	if !strings.Contains(body, "authenticator") {
		t.Fatalf("password step did not ask for the second factor: %.200s", body)
	}
	m := pendingTokenRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no pending token in the second-factor page")
	}
	if c := w.Result().Cookies(); len(c) != 0 {
		t.Fatal("a session cookie was set before the code verified")
	}

	// Wrong code: the page comes back, still no session.
	w = postLink(t, s, "/link/2fa", url.Values{"token": {m[1]}, "code": {"000000"}}.Encode())
	if !strings.Contains(w.Body.String(), "did not work") {
		t.Fatalf("wrong code did not re-render the page: %.200s", w.Body.String())
	}
	if c := w.Result().Cookies(); len(c) != 0 {
		t.Fatal("a session cookie was set on a wrong code")
	}

	// Right code: signed in, pending consumed.
	w = postLink(t, s, "/link/2fa", url.Values{"token": {m[1]}, "code": {"123456"}}.Encode())
	if !strings.Contains(w.Body.String(), "TwoFA") {
		t.Fatalf("correct code did not finish sign-in: %.200s", w.Body.String())
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == phoneCookie && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("no phone session cookie after the code verified")
	}

	// The token is single-use: replaying it restarts sign-in, not the session.
	w = postLink(t, s, "/link/2fa", url.Values{"token": {m[1]}, "code": {"123456"}}.Encode())
	if !strings.Contains(w.Body.String(), "Sign in") {
		t.Fatalf("replayed token did not restart sign-in: %.200s", w.Body.String())
	}
}

// TestPhoneLinkSecondFactorRecoveryCode: a recovery code works where the
// authenticator is gone.
func TestPhoneLinkSecondFactorRecoveryCode(t *testing.T) {
	s, f := twoFAServer(t)
	f.totp["2fa@example.com"] = "never-this"
	w := postLink(t, s, "/link", url.Values{"email": {"2fa@example.com"}, "password": {"correct horse battery"}}.Encode())
	m := pendingTokenRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatal("no pending token")
	}
	w = postLink(t, s, "/link/2fa", url.Values{"token": {m[1]}, "recovery_code": {"recovery-2fa@example.com"}}.Encode())
	if !strings.Contains(w.Body.String(), "TwoFA") {
		t.Fatalf("recovery code did not finish sign-in: %.200s", w.Body.String())
	}
}

// TestPhoneLinkWithout2FAIsUnchanged: accounts without a second factor keep
// the old one-step flow.
func TestPhoneLinkWithout2FAIsUnchanged(t *testing.T) {
	s, _ := twoFAServer(t)
	w := postLink(t, s, "/link", url.Values{"email": {"plain@example.com"}, "password": {"correct horse battery"}}.Encode())
	if !strings.Contains(w.Body.String(), "Plain") || strings.Contains(w.Body.String(), "authenticator") {
		t.Fatalf("plain account did not take the one-step flow: %.200s", w.Body.String())
	}
}

// TestPhoneLinkPasswordsAreCapped: password guessing on the link form buys a
// wait, like link codes do.
func TestPhoneLinkPasswordsAreCapped(t *testing.T) {
	s, _ := twoFAServer(t)
	form := url.Values{"email": {"plain@example.com"}, "password": {"wrong"}}.Encode()
	for i := 0; i < guessLimit; i++ {
		w := postLink(t, s, "/link", form)
		if strings.Contains(w.Body.String(), "Too many attempts") {
			t.Fatalf("throttled after %d wrong passwords, want %d", i+1, guessLimit)
		}
	}
	w := postLink(t, s, "/link", form)
	if !strings.Contains(w.Body.String(), "Too many attempts") {
		t.Fatalf("password guesses not capped: %.200s", w.Body.String())
	}
}

// TestAuthorizeSecondFactor: the console authorize form runs the same two
// steps and ends in the same redirect as the password form.
func TestAuthorizeSecondFactor(t *testing.T) {
	s, _ := twoFAServer(t)
	post := func(path, form string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://accounts.nintendo.com"+path, strings.NewReader(form))
		r.Host = "accounts.nintendo.com"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	q := url.Values{"response_type": {"code"}, "redirect_uri": {"nintendo://app"}, "state": {"st"}, "client_id": {"c"}}.Encode()
	w := post("/connect/1.0.0/authorize", q+"&email=2fa%40example.com&password=correct+horse+battery")
	if !strings.Contains(w.Body.String(), "authenticator") {
		t.Fatalf("authorize did not ask for the second factor: %.200s", w.Body.String())
	}
	m := pendingTokenRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatal("no pending token in the authorize second-factor page")
	}
	w = post("/connect/1.0.0/authorize/2fa", url.Values{"token": {m[1]}, "code": {"123456"}}.Encode())
	loc := w.Header().Get("Location")
	if w.Code != 302 || !strings.Contains(loc, "nintendo://app") || !strings.Contains(loc, "code=") {
		t.Fatalf("authorize/2fa = %d %q, want the console redirect", w.Code, loc)
	}
}
