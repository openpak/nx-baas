package main

import (
	"crypto/rand"
	"crypto/rsa"
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
	var out struct {
		Tokens []struct {
			ClientID string `json:"client_id"`
			Token    string `json:"device_auth_token"`
		} `json:"device_auth_tokens"`
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
