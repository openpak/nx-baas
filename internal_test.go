package main

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

// A retail console's BAAS id token carries no binding claim -- only an emulator build adds one --
// so a NEX or NPLN title has nothing to hand over but the whole token. Proving it is what lets a
// real console finish a login; refusing an access token for the same account is what stops the
// endpoint becoming a way to spend the wrong token as one.
func TestSwitchIdentityProvesAPlainConsoleIDToken(t *testing.T) {
	s := testServer(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.key, s.idKid, s.accKid = key, "test-id-kid", "test-acc-kid"
	u := s.store.User("aaaa")

	// id == nil is the retail shape: signed, but with no "openpak" claim in it.
	tok := s.idToken(u, nil, "OutboundHost", nil)
	if strings.Contains(tok, "openpak") {
		t.Fatal("test token is not the claimless shape a console sends")
	}
	w := do(t, s, "POST", "/internal/switch/identity", "", `{"id_token":"`+tok+`"}`)
	if w.Code != 200 {
		t.Fatalf("a console's own id token was refused: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"nickname":"OutboundHost"`) {
		t.Fatalf("wrong account behind the token: %s", w.Body)
	}

	// Same key, same subject, different kind of token: it must not buy a login.
	access := s.accessToken(u.ID, 2, u.BsDid, "", "")
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"id_token":"`+access+`"}`); w.Code != 401 {
		t.Fatalf("an access token was accepted as a login: %d %s", w.Code, w.Body)
	}
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"id_token":"not.a.jwt"}`); w.Code != 401 {
		t.Fatalf("a junk token was accepted: %d %s", w.Code, w.Body)
	}
}
