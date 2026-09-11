package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The Penne frontline POST must be held open, not 404-ed, and only for a real
// login ticket: the console re-registers on a denial, so a denial must be fast
// and honest. These tests drive s.penne (the routed entry point) the way the
// console drives it after registration.
func frontlineServer(t *testing.T, deviceID string) (*server, string) {
	t.Helper()
	s := &server{}
	id, pw := s.notifStore().Register(deviceID, "u_"+deviceID, "", time.Now())
	_, ticket, err := s.notifStore().IssueTicket(id, pw, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	return s, ticket
}

func frontlineRequest(ticket, deviceID string) *http.Request {
	return frontlineRequestCtx(context.Background(), ticket, deviceID)
}

func frontlineRequestCtx(ctx context.Context, ticket, deviceID string) *http.Request {
	r := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
	r.Host = "fro-3.hac.lp1.penne.srv.nintendo.net"
	if ticket != "" {
		r.Header.Set("Authorization", "Bearer "+ticket)
	}
	if deviceID != "" {
		r.Header.Set("User-Agent", "NintendoSDK Firmware/22.5.0 (platform:NX; did:"+deviceID+"; eid:lp1)")
	}
	return r
}

func TestFrontlineHoldsOpenWithATicket(t *testing.T) {
	const device = "0123456789abcdef"
	s, ticket := frontlineServer(t, device)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.penne(w, frontlineRequestCtx(ctx, ticket, device), nil); close(done) }()

	select { // held open: it must not return on its own
	case <-done:
		t.Fatal("frontline returned without the client disconnecting")
	case <-time.After(50 * time.Millisecond):
	}
	cancel() // console hung up
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("frontline did not return after the client disconnected")
	}
	// Only after the handler returned may the recorder be read.
	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("content type = %q, want octet-stream", ct)
	}
}

func TestFrontlineDeniesBadTickets(t *testing.T) {
	const device = "0123456789abcdef"
	s, ticket := frontlineServer(t, device)
	id, pw := s.notifStore().Register(device, "u2", "", time.Now())

	_, revoked, err := s.notifStore().IssueTicket(id, pw, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("issue revoked ticket: %v", err)
	}
	_, expired, err := s.notifStore().IssueTicket(id, pw, time.Now().Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("issue expired ticket: %v", err)
	}
	s.notifStore().Revoke(id, time.Now())

	cases := map[string]struct {
		ticket, device string
	}{
		"no ticket":      {"", ""},
		"unknown ticket": {strings.Repeat("ab", 32), device},
		"revoked":        {revoked, device},
		"expired":        {expired, device},
		"wrong device":   {ticket, "ffffffffffffffff"},
	}
	for name, tc := range cases {
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { s.penne(w, frontlineRequest(tc.ticket, tc.device), nil); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s: frontline stayed open on a denial", name)
		}
		if w.Code != 401 {
			t.Errorf("%s: status = %d, want 401", name, w.Code)
		}
	}
}

// A gw. account read must answer 200 with a {"payload": base64(json)} envelope. vphyms used to
// answer 404, which the title reads as account setup failed -- it then restarts its whole
// bootstrap with a fresh penne id, forever. An empty inner object is fine; the envelope is not.
func TestAccountsVphymsAnswersAPayloadEnvelopeNot404(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/accounts/vphyms", nil)
	r.Host = "gw.hac.lp1.vermillion.srv.nintendo.net"
	w := httptest.NewRecorder()
	(&server{}).penne(w, r, nil)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if _, err := decodePayload(t, w.Body.Bytes()); err != nil {
		t.Fatalf("body is not a payload envelope: %v (%s)", err, w.Body.String())
	}
}

// config is the online gate: its payload must carry online_license.is_available true, or the game
// reaches the lobby and stops with 2321-4992. Before this it fell to the gw. catchall and answered
// a bare "{}", which carries no licence at all.
func TestAccountsConfigCarriesOnlineLicense(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/accounts/config", nil)
	r.Host = "gw.hac.lp1.vermillion.srv.nintendo.net"
	w := httptest.NewRecorder()
	(&server{}).penne(w, r, nil)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	inner, err := decodePayload(t, w.Body.Bytes())
	if err != nil {
		t.Fatalf("body is not a payload envelope: %v (%s)", err, w.Body.String())
	}
	lic, _ := inner["online_license"].(map[string]any)
	if lic == nil || lic["is_available"] != true {
		t.Errorf("online_license.is_available is not true; payload = %v", inner)
	}
}

// decodePayload unwraps a {"payload": base64(json)} envelope into its inner object, asserting the
// reply is not a bare "{}" (the known failure class on these endpoints).
func decodePayload(t *testing.T, body []byte) (map[string]any, error) {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	p, ok := env["payload"].(string)
	if !ok {
		return nil, errNoPayload
	}
	raw, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, err
	}
	var inner map[string]any
	err = json.Unmarshal(raw, &inner)
	return inner, err
}

var errNoPayload = errors.New(`reply has no string "payload" field`)

// The vermillion gateway's device id is read by the client as a URL path segment and stored as
// its device identity. Three things have to hold at once or the client never leaves its
// bootstrap: the key is camelCase, the value decodes to 16 bytes, and the encoding contains no
// "/". Answering "{}" -- what this endpoint did before -- is the failure this guards.
func TestVermillionDeviceIDIsUsableAsAPathSegment(t *testing.T) {
	const ua = "NintendoSDK Firmware/20.1.5-4.0 (platform:NX; did:0123456789abcdef; eid:lp1)"

	r := httptest.NewRequest("GET", "/v1/devices/vermillion-device-id", nil)
	r.Host = "gw.hac.lp1.vermillion.srv.nintendo.net"
	r.Header.Set("User-Agent", ua)
	w := httptest.NewRecorder()
	(&server{}).penne(w, r, nil)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body does not decode: %v", err)
	}
	id, ok := got["vermillionDeviceId"].(string)
	if !ok {
		t.Fatalf("no string vermillionDeviceId in %v", got)
	}
	if strings.Contains(id, "/") {
		t.Errorf("device id %q contains a /, which crashes the client using it as a path segment", id)
	}
	raw, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("device id %q is not base64: %v", id, err)
	}
	if len(raw) != 16 {
		t.Errorf("device id decodes to %d bytes, want 16", len(raw))
	}

	// Stable for the same console: the client keeps the value, so a fresh one per request
	// would make it re-register forever.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/v1/devices/vermillion-device-id", nil)
	r2.Host = r.Host
	r2.Header.Set("User-Agent", ua)
	(&server{}).penne(w2, r2, nil)
	if w2.Body.String() != w.Body.String() {
		t.Errorf("device id is not stable: %s then %s", w.Body.String(), w2.Body.String())
	}
}
