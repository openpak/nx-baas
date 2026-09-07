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

func TestDauthIssuesOneTokenPerClient(t *testing.T) {
	s := dauthServer(t)
	body := "device_id=dev-9&client_id=aaa&client_id=bbb"
	r := httptest.NewRequest(http.MethodPost, "/v8/device_auth_tokens", strings.NewReader(body))
	r.Host = "dauth-lp1.ndas.srv.nintendo.net"
	w := httptest.NewRecorder()
	s.dauth(w, r, []byte(body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
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
		t.Fatalf("got %d tokens, want 2", len(out.Tokens))
	}
	for _, tok := range out.Tokens {
		claims, err := parseJWT(tok.Token, nil)
		if err != nil || str(claims, "aud") != tok.ClientID {
			t.Errorf("token for %s does not carry its client_id (%v)", tok.ClientID, err)
		}
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
