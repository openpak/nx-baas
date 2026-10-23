package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http/httptest"
	"nx-baas/internal/token"
	"strings"
	"testing"
	"time"
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

	// A genuine token for an account we do not know is NOT 401. platforms/switch/games/switch-nex maps 401 to
	// TokenExpired, so the console would throw a perfectly good token away and fetch another,
	// forever. It has to be the 404 that maps to ValidationFailed.
	stranger, _ := s.store.NewUser()
	unknown := s.idToken(stranger, nil, "", nil)
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"id_token":"`+unknown+`"}`); w.Code != 404 {
		t.Fatalf("unlinked account answered %d, want 404 -- 401 puts the console in a refresh loop: %s", w.Code, w.Body)
	}
}

func TestSwitchIdentityExposesOnlyVerifiedApplication(t *testing.T) {
	s, _ := banServer(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.key = key
	u := s.store.User("aaaa")
	application := map[string]any{"nintendo": map[string]any{"ai": "010070201D1BA000"}}
	tok := s.idToken(u, nil, "Keeper", application)
	w := do(t, s, "POST", "/internal/switch/identity", "", `{"id_token":"`+tok+`"}`)
	// banServer's host account is locked. Even a genuine title token cannot
	// escape that existing check.
	if w.Code != 403 {
		t.Fatalf("banned ID-token accepted: %d", w.Code)
	}
	// The fixture's second account is allowed.
	u = s.store.User("bbbb")
	if u == nil {
		t.Fatal("missing allowed user")
	}
	tok = s.idToken(u, nil, "Keeper", application)
	w = do(t, s, "POST", "/internal/switch/identity", "", `{"id_token":"`+tok+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"application_id":"010070201D1BA000"`) || !strings.Contains(w.Body.String(), `"account_id":"acc-4"`) {
		t.Fatalf("missing verified application/account: %d %s", w.Code, w.Body)
	}
	claims, err := token.ParseJWT(tok, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]any){
		"expired":      func(c map[string]any) { c["exp"] = time.Now().Unix() - 1 },
		"wrong issuer": func(c map[string]any) { c["iss"] = "other" },
		"wrong type":   func(c map[string]any) { c["typ"] = "token" },
	} {
		t.Run(name, func(t *testing.T) {
			c := make(map[string]any)
			for k, v := range claims {
				c[k] = v
			}
			change(c)
			bad := token.SignJWT(map[string]any{"alg": "RS256"}, c, key)
			if w := do(t, s, "POST", "/internal/switch/identity", "", `{"id_token":"`+bad+`"}`); w.Code != 401 {
				t.Fatalf("invalid token exposed identity: %d", w.Code)
			}
		})
	}
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"id_token":"`+tok+`x"}`); w.Code != 401 {
		t.Fatal("tampered token accepted")
	}
	w = do(t, s, "POST", "/internal/switch/identity", "", `{"pid":1800000004}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"application_id":""`) {
		t.Fatal("PID-only lookup asserted an application")
	}
}

// Adding a friend by Switch friend code from the website or the app never
// worked: the site looked the code up as a core "switch" link subject, and that
// subject is the BAAS user id, so every code answered "no account found". This
// is the lookup that actually holds the mapping.
func TestAccountByFriendCodeFindsTheAccountHoweverItIsTyped(t *testing.T) {
	b := &openpakBackend{proj: &projectionStore{
		ByAccount: map[string]*projection{},
		ByPID:     map[uint64]string{},
		ByBaas:    map[string]string{},
		ByCode:    map[string]string{"SW-1000-0000-0001": "e4a030bf-b4a9-4592-8891-d3a9fc58f4be"},
	}}

	for _, typed := range []string{
		"SW-1000-0000-0001", "sw-1000-0000-0001", "SW100000000001",
		"1000-0000-0001", "100000000001", "SW 1000 0000 0001",
	} {
		got, ok := b.accountForFriendCode(typed)
		if !ok || got != "e4a030bf-b4a9-4592-8891-d3a9fc58f4be" {
			t.Errorf("%q -> %q/%v, want the account", typed, got, ok)
		}
	}

	for _, bad := range []string{"", "SW-0000-0000-0000", "12345", "not a code"} {
		if _, ok := b.accountForFriendCode(bad); ok {
			t.Errorf("%q matched an account", bad)
		}
	}
}

// The internal route the website calls, end to end.
func TestSwitchAccountByFriendCodeRoute(t *testing.T) {
	s := &server{acct: &openpakBackend{proj: &projectionStore{
		ByAccount: map[string]*projection{},
		ByPID:     map[uint64]string{},
		ByBaas:    map[string]string{},
		ByCode:    map[string]string{"SW-1000-0000-0002": "5011153a-6621-451e-a299-082bc56fea50"},
	}}}

	r := httptest.NewRequest("GET", "/internal/switch/account-by-friend-code?friend_code=SW-1000-0000-0002", nil)
	w := httptest.NewRecorder()
	s.switchAccountByFriendCode(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if got["account_id"] != "5011153a-6621-451e-a299-082bc56fea50" {
		t.Fatalf("account_id = %v", got["account_id"])
	}

	w = httptest.NewRecorder()
	s.switchAccountByFriendCode(w, httptest.NewRequest("GET", "/internal/switch/account-by-friend-code?friend_code=SW-0000-0000-0001", nil))
	if w.Code != 404 {
		t.Fatalf("unknown code answered %d, want 404", w.Code)
	}
}
