package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A third-party network (EA's Nucleus) receives the Nintendo Account authorization code, or the
// NA id_token, from the title and asks which OpenPak player it belongs to.
func TestSwitchIdentityResolvesNintendoAccountProofs(t *testing.T) {
	s := testServer(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.key = key
	s.store.RememberNA("00aa00aa00aa00aa", hostPID)
	c := naCode{PID: hostPID, NaID: "00aa00aa00aa00aa", ClientID: "0100c56010fd8000"}
	code := issue(s, c)

	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"na_code":"`+code+`","client_id":"0100C56010FD8001"}`); w.Code != 401 {
		t.Fatalf("a code for another client was accepted: %d %s", w.Code, w.Body)
	}
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"na_code":"`+code+`"}`); w.Code != 401 {
		t.Fatalf("a code without a client id was accepted: %d", w.Code)
	}
	w := do(t, s, "POST", "/internal/switch/identity", "", `{"na_code":"`+code+`","client_id":"0100C56010FD8000"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"nickname":"OutboundHost"`) {
		t.Fatalf("code not resolved: %d %s", w.Code, w.Body)
	}
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"na_code":"`+code+`","client_id":"0100C56010FD8000"}`); w.Code != 401 {
		t.Fatalf("a spent code was accepted again: %d", w.Code)
	}

	idt := s.naIDToken(c, "", "")
	w = do(t, s, "POST", "/internal/switch/identity", "", `{"na_id_token":"`+idt+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"nickname":"OutboundHost"`) {
		t.Fatalf("NA id_token not resolved: %d %s", w.Code, w.Body)
	}
	// A BAAS id_token is not an NA id_token.
	baas := s.idToken(s.store.User("aaaa"), nil, "OutboundHost", nil)
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"na_id_token":"`+baas+`"}`); w.Code != 401 {
		t.Fatalf("a BAAS id_token passed as an NA id_token: %d", w.Code)
	}
	// An NA access token carries typ=token and is no login proof.
	at := s.naAccessToken(c)
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"na_id_token":"`+at+`"}`); w.Code != 401 {
		t.Fatalf("an NA access token passed as an id_token: %d", w.Code)
	}
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"na_id_token":"junk"}`); w.Code != 401 {
		t.Fatalf("junk accepted: %d", w.Code)
	}
}

// An emulator signs in with a BAAS id_token and has no NA access token: the silent authorize
// takes it as the Bearer, and the code it issues resolves back to the same player.
func TestSilentAuthorizeAcceptsTheBaasIDToken(t *testing.T) {
	s := testServer(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.key = key
	s.codes = map[string]naCode{}
	idtok := s.idToken(s.store.User("aaaa"), nil, "OutboundHost", nil)
	form := url.Values{"prompt": {"none"}, "response_type": {"code id_token"}, "client_id": {"0100c56010fd8000"},
		"redirect_uri": {"npf0100c56010fd8000://auth"}, "state": {"st"}, "nonce": {"nn"}}.Encode()
	r := httptest.NewRequest("POST", "https://accounts.nintendo.com/connect/1.0.0/authorize", strings.NewReader(form))
	r.Host = "accounts.nintendo.com"
	r.Header.Set("Authorization", "Bearer "+idtok)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	loc := w.Header().Get("Location")
	if w.Code != 302 || !strings.Contains(loc, "code=") || !strings.Contains(loc, "id_token=") || !strings.Contains(loc, "state=st") {
		t.Fatalf("silent authorize = %d %q", w.Code, loc)
	}
	u, _ := url.Parse(loc)
	frag, _ := url.ParseQuery(u.Fragment)
	w2 := do(t, s, "POST", "/internal/switch/identity", "", `{"na_code":"`+frag.Get("code")+`","client_id":"0100c56010fd8000"}`)
	if w2.Code != 200 {
		t.Fatalf("issued code not resolved: %d %s", w2.Code, w2.Body)
	}
}

func issue(s *server, c naCode) string {
	if s.codes == nil {
		s.codes = map[string]naCode{}
	}
	code := randHex(16)
	s.mu.Lock()
	s.codes[code] = c
	s.mu.Unlock()
	return code
}
