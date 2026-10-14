package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Penne frontline POST must be held open, not 404-ed, and only for a real
// login ticket: the console re-registers on a denial, so a denial must be fast
// and honest. These tests drive s.penne (the routed entry point) the way the
// console drives it after registration.
// NPNS 22.5.0 requires the nested parameter descriptors to all report success
// before its login routine returns success (RVA 0xbf100 and 0xb8b50). Values
// below come from its constructor at RVA 0xb82e0, not from our renderer.
func TestPenneBootstrapIncludesRequiredNativeConnectionParameters(t *testing.T) {
	for _, path := range []string{"/v1/frontlines", "/v1/login_tickets"} {
		t.Run(path, func(t *testing.T) {
			s := &server{}
			id, pw := s.notifStore().Register("console", "user", "", time.Now())
			body, _ := json.Marshal(map[string]string{"id": id, "password": pw})
			req := httptest.NewRequest(http.MethodPost, "https://val.hac.lp1.penne.srv.nintendo.net"+path, strings.NewReader(string(body)))
			rr := httptest.NewRecorder()
			s.penne(rr, req, body)
			if rr.Code != http.StatusOK {
				t.Fatalf("status: %d", rr.Code)
			}
			var reply map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			params, ok := reply["persistent_connection_params_simple"].(map[string]any)
			if !ok {
				t.Fatal("missing connection parameters")
			}
			for key, want := range map[string]any{
				"ignore_rst": true, "retry_count": float64(2), "wait_sec": float64(3600),
				"wowl_timeout": float64(410), "rtt_max": float64(300),
			} {
				if got := params[key]; got != want {
					t.Errorf("%s = %v, want native default %v", key, got, want)
				}
			}
			for name, disabled := range map[string]bool{"awake": false, "sleep": true} {
				mode, ok := params[name].(map[string]any)
				if !ok {
					t.Fatalf("missing %s parameters", name)
				}
				count := float64(2)
				if name == "sleep" {
					count = 1440
				}
				for key, want := range map[string]any{"idle": float64(60), "interval": float64(10), "count": count, "disable": disabled} {
					if got := mode[key]; got != want {
						t.Errorf("%s.%s = %v, want native default %v", name, key, got, want)
					}
				}
			}
		})
	}
}

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

// The console reports its previous frontline attempt on every Penne request.
// An all-zero result is "nothing to report" and stays quiet; anything else is
// the console telling us why it dropped the last connection, and it must reach
// the log rather than be discarded.
func TestConsoleReportedFrontlineResultIsLogged(t *testing.T) {
	s := &server{}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	call := func(fro string) {
		r := httptest.NewRequest("GET", "https://val.hac.lp1.penne.srv.nintendo.net/v1/frontlines", nil)
		r.Host = "val.hac.lp1.penne.srv.nintendo.net"
		if fro != "" {
			r.Header.Set("X-Fro-Result", fro)
			r.Header.Set("X-Login-Try", "2")
		}
		s.penne(httptest.NewRecorder(), r, nil)
	}

	call("000-0000")
	if strings.Contains(logged.String(), "console reports") {
		t.Errorf("an all-zero result was logged as a failure: %s", logged.String())
	}
	call("2-ABCDE")
	if !strings.Contains(logged.String(), "console reports last frontline result 2-ABCDE") {
		t.Errorf("a reported failure did not reach the log: %s", logged.String())
	}
}

// A console keeps its Penne registration in its own save data and presents it
// forever. One that registered against a different server arrives with an id
// this store never minted; answering 403 leaves it holding credentials we
// reject with no way to get ones we accept, so it never opens a frontline again
// and every notification for it is undeliverable for the life of the console.
// That is what a real console looked like on 2026-09-12: active on BAAS all
// evening, no Penne registration at all, no frontline connection ever.
func TestUnknownPenneIdIsRegisteredNotRefused(t *testing.T) {
	s, _ := liveServer(t)
	store := s.notifStore()

	body := `{"id":"pneverminted0000000000000000000","password":"whatever"}`
	r := httptest.NewRequest("POST", "https://god.hac.lp1.penne.srv.nintendo.net/v1/penne_ids",
		strings.NewReader(body))
	r.Host = "god.hac.lp1.penne.srv.nintendo.net"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.penne(w, r, []byte(body))

	if w.Code != 200 {
		t.Fatalf("status %d: a console with a foreign id must be able to register, not be locked out", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	id, _ := got["id"].(string)
	if id == "" || id == "pneverminted0000000000000000000" {
		t.Fatalf("id = %q, want a freshly minted one", id)
	}
	if pw, _ := got["password"].(string); pw == "" {
		t.Fatal("no password: the console cannot use the registration it was just given")
	}
	if !store.KnowsAssoc(id) {
		t.Fatal("the minted id is not in the store")
	}
}

// The other half: a known id with a wrong password is still a denial. Minting
// on an unverifiable id must not become a way to take over one that exists.
func TestKnownPenneIdWithABadPasswordIsStillRefused(t *testing.T) {
	s, _ := liveServer(t)
	store := s.notifStore()
	id, _ := store.Register("dev-1", "user-1", "", time.Now())

	body := `{"id":"` + id + `","password":"wrong"}`
	r := httptest.NewRequest("POST", "https://god.hac.lp1.penne.srv.nintendo.net/v1/penne_ids",
		strings.NewReader(body))
	r.Host = "god.hac.lp1.penne.srv.nintendo.net"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.penne(w, r, []byte(body))

	if w.Code != 403 {
		t.Fatalf("status %d, want 403", w.Code)
	}
}

// The console names its registration without a password when it asks for a
// notification token, and the request is authenticated by its bearer instead.
// Refusing it 401'd a console presenting its own live penne_id on every
// attempt, so the console account id in the path -- the address the friends
// module requires every event to carry -- was never recorded.
// Captured from hardware 2026-09-12:
//
//	POST /v1/accounts/1000000000a100010000000000000001/notification_tokens
//	{"penne_id":"pzxi…","application_id":"0x010000000000003e"}
func TestNotificationTokenAcceptsAPasswordlessPenneId(t *testing.T) {
	s, _ := liveServer(t)
	store := s.notifStore()
	id, _ := store.Register("", "user-1", "", time.Now())

	const account = "1000000000a100010000000000000001"
	body := `{"penne_id":"` + id + `","application_id":"0x010000000000003e"}`
	r := httptest.NewRequest("POST",
		"https://god.hac.lp1.penne.srv.nintendo.net/v1/accounts/"+account+"/notification_tokens",
		strings.NewReader(body))
	r.Host = "god.hac.lp1.penne.srv.nintendo.net"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.penne(w, r, []byte(body))

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if tok, _ := got["notification_token"].(string); tok == "" {
		t.Fatal("no notification_token in the reply")
	}
	// The point of the route: the console account id must now be on record
	// against this registration. It is the address the friends module requires
	// every event to carry, and the only place the console ever shows it to us.
	a := store.AssocByID(id)
	if a == nil || len(a.AccountIDs) == 0 || a.AccountIDs[0] != account {
		t.Fatalf("registration records %v, want the console account from the path", a)
	}
}

// A revoked registration is still refused, password or not.
func TestPasswordlessPenneIdIsRefusedOnceRevoked(t *testing.T) {
	s, _ := liveServer(t)
	store := s.notifStore()
	id, _ := store.Register("", "user-1", "", time.Now())
	store.Revoke(id, time.Now())

	body := `{"penne_id":"` + id + `"}`
	r := httptest.NewRequest("POST",
		"https://god.hac.lp1.penne.srv.nintendo.net/v1/accounts/1000000000a100010000000000000001/notification_tokens",
		strings.NewReader(body))
	r.Host = "god.hac.lp1.penne.srv.nintendo.net"
	w := httptest.NewRecorder()
	s.penne(w, r, []byte(body))

	if w.Code != 401 {
		t.Fatalf("status %d, want 401 for a revoked registration", w.Code)
	}
}

// The console's steady state is the NA token refresh, not /1.0.0/login: sleep/wake and
// days-long play sessions reuse the Nintendo-Account session, so the login may not recur
// for a very long time. The refresh request carries both halves — the device token names
// the console, the refresh token's account resolves to the BAAS user — so the bind, and
// the heal of addresses recorded under the certificate, must happen there too.
func TestNARefreshBindsTheConsoleAndHealsItsAddresses(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const pid = uint64(1900000002)
	s := &server{
		store: loadStore(filepath.Join(t.TempDir(), "baas.json")),
		acct:  fakeBackend{id: &Identity{PID: pid, BaasUserID: "aaaaaaaaaaaa0002", NaID: "bbbbbbbbbbbb0002", Nickname: "Leia"}},
		key:   key,
	}
	store := s.notifStore()

	const cert, account = "cert-dddddddddddd0001", "1000000000a100010000000000000001"
	penneID, _ := store.Register("device-a", cert, "", time.Now())
	store.NoteAccount(penneID, account, cert) // recorded while only the certificate was known
	s.store.RememberNA("bbbbbbbbbbbb0002", pid)

	form := url.Values{
		"refresh_token":               {s.naRefreshToken(naCode{PID: pid, Username: "Leia", ClientID: "6ffd70c434d303c8", NaID: "bbbbbbbbbbbb0002"})},
		"device_authentication_token": {s.deviceToken(cert, "81333c548b2e876d")},
		"client_id":                   {"6ffd70c434d303c8"},
		"scope":                       {"user"},
	}
	r := httptest.NewRequest("POST", "https://accounts.nintendo.com/connect/1.0.0/api/token", strings.NewReader(form.Encode()))
	r.Host = "accounts.nintendo.com"
	w := httptest.NewRecorder()
	s.na(w, r, []byte(form.Encode()))

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if got := store.AccountsFor("aaaaaaaaaaaa0002"); len(got) != 1 || got[0] != account {
		t.Fatalf("after the refresh, AccountsFor(leia) = %v, want [%s]", got, account)
	}
	if got := store.ResolveUser(cert); got != "aaaaaaaaaaaa0002" {
		t.Fatalf("after the refresh, ResolveUser(cert) = %q", got)
	}
}
