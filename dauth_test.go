package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func dauthServer(t *testing.T) *server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &server{key: key, idKid: "test-kid", jwks: jwksFor(&key.PublicKey, "test-kid")}
}

// The device token is the contract between dauth and /1.0.0/application/token, which reads
// "sub" as the device id. If that field moves, the login breaks with no error anywhere.
func TestDeviceTokenCarriesDeviceID(t *testing.T) {
	s := dauthServer(t)
	claims, err := parseJWT(s.deviceToken("dev-123", "client-abc"), nil)
	if err != nil {
		t.Fatalf("device token does not decode: %v", err)
	}
	if got := str(claims, "sub"); got != "dev-123" {
		t.Errorf("sub = %q, want %q", got, "dev-123")
	}
	if got := str(claims, "aud"); got != "client-abc" {
		t.Errorf("aud = %q, want %q", got, "client-abc")
	}
}

// dcert serves the keys the console verifies those tokens with; an empty JWKS would fail
// the console with no useful error.
func TestDcertServesTheSigningKey(t *testing.T) {
	s := dauthServer(t)
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)
	r.Host = "dcert-lp1.ndas.srv.nintendo.net"
	w := httptest.NewRecorder()
	s.dauth(w, r, nil)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "test-kid") {
		t.Fatalf("dcert /keys = %d %s", w.Code, w.Body.String())
	}
}

// The console posts JSON with a list of client ids and no device identifier anywhere; an
// earlier form-encoded reading of this body issued zero tokens and left the console retrying
// in a loop.
func TestDeviceTokensFromRealConsoleBody(t *testing.T) {
	s := dauthServer(t)
	body := []byte(`{"system_version":"00160500","fw_revision":"ae93061a","ist":false,` +
		`"token_requests":[{"client_id":"8f849b5d34778d8e"},{"client_id":"dc656ea03b63cf68"}],` +
		`"key_generation":22,"challenge":"pdvfdf910","mac":"xn-ynLKpF0BC"}`)
	r := httptest.NewRequest(http.MethodPost, "/v8/device_auth_tokens", strings.NewReader(string(body)))
	r.Host = "dauth-lp1.ndas.srv.nintendo.net"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.dauth(w, r, body)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	// The console reads the list from "results"; a different envelope key failed the link
	// with 2124-4798 even though every token in it was valid.
	var out struct {
		Tokens []struct {
			ClientID string `json:"client_id"`
			Token    string `json:"device_auth_token"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tokens) != 2 {
		t.Fatalf("got %d tokens, want one per token_request", len(out.Tokens))
	}
	if out.Tokens[0].ClientID != "8f849b5d34778d8e" {
		t.Errorf("first client_id = %q", out.Tokens[0].ClientID)
	}
	claims, err := parseJWT(out.Tokens[1].Token, nil)
	if err != nil || str(claims, "aud") != "dc656ea03b63cf68" {
		t.Errorf("second token does not carry its client_id (%v)", err)
	}
}

// Every path the console touches during account setup must answer. Each 404 here was an
// account that could not be added: the licence service is asked for all of these while a
// user is imported, and a missing one reads as "no entitlement".
func TestAccountSetupPathsAllAnswer(t *testing.T) {
	s := dauthServer(t)
	for _, c := range []struct{ host, path string }{
		{"dragons.hac.lp1.dragons.nintendo.net", "/v2/contents_authorization_token_for_aauth/issue"},
		{"dragons.hac.lp1.dragons.nintendo.net", "/v2/elicense_archives/publish"},
		{"dragons.hac.lp1.dragons.nintendo.net", "/v2/rights/publish_device_linked_elicenses"},
		{"dragons.hac.lp1.dragons.nintendo.net", "/v2/elicenses/exercise"},
		{"dragons.hac.lp1.dragons.nintendo.net", "/v2/elicenses/migration_state"},
		{"dragons.hac.lp1.dragons.nintendo.net", "/v2/penne_id"},
		{"acert-lp1.ndas.srv.nintendo.net", "/keys"},
		{"dcert-lp1.ndas.srv.nintendo.net", "/keys"},
	} {
		r := httptest.NewRequest("POST", "https://"+c.host+c.path, nil)
		r.Host = c.host
		w := httptest.NewRecorder()
		// Through ServeHTTP, not s.dauth: routing the host to this handler at all is half
		// the contract, and acert was once missing from that list while dauth answered fine.
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%s%s = %d, want 200", c.host, c.path, w.Code)
		}
	}
}

// The serial travels from the device token into the BAAS access token, and the console reads
// it there. It has to be non-empty and the same on every request from one console.
func TestDeviceTokenCarriesAStableSerial(t *testing.T) {
	s := dauthServer(t)
	claims, _ := parseJWT(s.deviceToken("dev-123", "client-abc"), nil)
	n, _ := claims["nintendo"].(map[string]any)
	sn := str(n, "sn")
	if sn == "" || sn != consoleSerial("dev-123") {
		t.Fatalf("serial = %q, want the stable one for dev-123", sn)
	}
	if consoleSerial("dev-123") == consoleSerial("dev-456") {
		t.Error("two consoles share a serial")
	}
}

// Parity with the stack that actually links consoles: serve what the account holds and invent
// nothing. A shared profile blob makes the console drop the profile to local-only, and the one
// captured working response carries "0000-00-00" as a birthday, so substituting a "valid" one
// was inventing a fix for a problem never observed.
func TestUserObjectInventsNothing(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{}
	t.Setenv("NX_DEFAULT_NXACCOUNT", "a-foreign-console-profile")
	t.Setenv("NX_DEFAULT_COUNTRY", "GB")
	t.Setenv("NX_DEFAULT_BIRTHDAY", "1990-01-01")
	u := &User{ID: "user-1", Birthday: "0000-00-00"}
	obj := s.userObj(u, &Identity{PID: 1, Nickname: "someone", FriendCode: "SW-0000-0000-0000"}, "")

	self := obj["extras"].(map[string]any)["self"].(map[string]any)
	if _, ok := self["nxAccount"]; ok {
		t.Error("a linked user with no uploaded blob was served one anyway")
	}
	if got := obj["birthday"]; got != "0000-00-00" {
		t.Errorf("birthday = %v, want the account's own 0000-00-00", got)
	}
	if got := obj["country"]; got != "" {
		t.Errorf("country = %q, want the account's own empty value", got)
	}
}

// The console reads the Nintendo Account object and the BAAS user object in one link. When the
// account holds a country, both must say so — telling it the person lives in GB while the other
// half says the account holds nothing is a contradiction we used to ship unconditionally.
func TestNintendoAccountFollowsTheAccountsOwnProfile(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{}
	id := &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "someone", Country: "IE", Birthday: "1984-03-02"}

	country, birthday := naProfile(id)
	if country != "IE" || birthday != "1984-03-02" {
		t.Fatalf("users/me served %q/%q, want the account's own IE/1984-03-02", country, birthday)
	}
	obj := s.userObj(&User{ID: "u1", Country: "IE", Birthday: "1984-03-02"}, id, "")
	if obj["country"] != country || obj["birthday"] != birthday {
		t.Errorf("the two objects disagree: BAAS %v/%v vs NA %v/%v", obj["country"], obj["birthday"], country, birthday)
	}

	// With nothing on the account the fallback stands, because a Nintendo Account cannot have
	// an empty country — but it is the only place in the stack still allowed to substitute.
	t.Setenv("NA_FALLBACK_COUNTRY", "GB")
	if c, _ := naProfile(&Identity{NaID: "x"}); c != "GB" {
		t.Errorf("fallback country = %q, want GB", c)
	}
}

// The console uploads its profile picture while adding an account, and stops
// with 2124-5104 if that 404s. This endpoint was deleted once on the reasoning
// that an older stack never answered it; the console had already been observed
// accepting a reply here, so the test says so rather than the commit message.
func TestProfileImageUploadIsAccepted(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()

	// A one-pixel JPEG is enough: what matters is that base64 in, 200 out, and
	// the bytes are kept rather than dropped.
	jpeg := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xD8, 0xFF, 0xD9})
	body := []byte(`{"rawContent":"` + jpeg + `"}`)
	r := httptest.NewRequest("POST", "https://"+baasHost+"/1.0.0/image_upload", nil)
	r.Host = baasHost
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "", ""))
	w := httptest.NewRecorder()
	s.baas(w, r, body)

	if w.Code != http.StatusOK {
		t.Fatalf("image_upload = %d, want 200", w.Code)
	}
	if got := s.store.User(u.ID); got == nil || got.Avatar != jpeg {
		t.Error("the uploaded picture was not kept")
	}
}
