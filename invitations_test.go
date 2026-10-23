package main

// Tests for the native online-play invitation surface (INV-01..04).
//
// Shape fixtures carry provenance in their headers: field names and nesting
// come from the 22.5.0 friends module's own parser strings (build 8bd39f5b…)
// and the documented contract (kinnay/NintendoClients wiki,
// Online-Play-Invitation-Server, accessed 2026-09-12). Nothing here was
// captured from Nintendo's servers; hardware parity is a separate gate.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"nx-baas/internal/store"
	"nx-baas/internal/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- harness ----------

type fakeInvCore struct {
	denied map[string]string // target account id -> denial reason
	fail   bool              // core outage
	live   map[string]bool   // account id -> live session
}

func (f *fakeInvCore) CheckInteraction(_ context.Context, _, target string) (bool, string, error) {
	if f.fail {
		return false, "", fmt.Errorf("core down")
	}
	if reason, ok := f.denied[target]; ok {
		return false, reason, nil
	}
	return true, "", nil
}

func (f *fakeInvCore) ResolveSession(_ context.Context, accountID, _ string) (bool, error) {
	return f.live[accountID], nil
}

func (f *fakeInvCore) AccountForBaas(uid string) (string, bool) { return "acct-" + uid, true }

const (
	invSenderUID   = "a1b2c3d4e5f60718"
	invReceiverUID = "b2c3d4e5f6071829"
	invStrangerUID = "c3d4e5f60718293a"
)

func fiveServer(t *testing.T) *server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// The durable store is the behavior under test: every server instance in a
	// test may reopen the same file to prove restart/cross-device semantics.
	st := loadInvitationStore(filepath.Join(dir, "invitations.json"))
	invStoreOverride = st
	t.Cleanup(func() { invStoreOverride = nil })
	s := &server{key: key, store: store.Load(filepath.Join(dir, "baas.json"))}
	for uid, pid := range map[string]uint64{invSenderUID: 1800000010, invReceiverUID: 1800000011, invStrangerUID: 1800000012} {
		s.store.Users[uid] = &store.User{ID: uid, PID: pid, Nickname: "user-" + uid}
	}
	s.acct = &stubBackend{
		key: []byte("0123456789abcdef0123456789abcdef"),
		// Mutual friendships among all three, so the non-core fallback (no
		// core attached) allows invites unless a test removes the edge.
		friends: map[uint64][]uint64{
			1800000010: {1800000011, 1800000012},
			1800000011: {1800000010, 1800000012},
			1800000012: {1800000010, 1800000011},
		},
		names: map[uint64]string{1800000010: "host", 1800000011: "joiner", 1800000012: "stranger"},
	}
	return s
}

func fiveToken(s *server, uid string) string {
	return s.accessToken(uid, 2, "did", "device", "serial")
}

func fiveDo(t *testing.T, s *server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "https://app.lp1.five.nintendo.net"+path, strings.NewReader(body))
	r.Host = "app.lp1.five.nintendo.net"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.five(w, r, []byte(body))
	return w
}

const validAppData = "AQAAAAdRMlpXOUQC" // u32_le(1)||u8(7)||"Q2ZW9Q"-shaped opaque bytes

func createBody(receivers ...string) string {
	quoted := make([]string, len(receivers))
	for i, r := range receivers {
		quoted[i] = fmt.Sprintf("%q", r)
	}
	return fmt.Sprintf(`{"receiver_ids":[%s],"invitation_type":"friend","application_id":"0100ed9024eb8000",`+
		`"application_group_id":"0100ed9024eb8000","application_data":%q,`+
		`"messages":{"en-US":"Join my room!"},"application_id_match":false,"acd_index":3}`, strings.Join(quoted, ","), validAppData)
}

// ---------- INV-01: authentication binds the principal ----------

func TestFiveAuthRejectsForeignTokens(t *testing.T) {
	s := fiveServer(t)
	cases := []struct {
		name, token string
	}{
		{"no token", ""},
		{"garbage", "not.a.jwt"},
		{"wrong issuer", token.SignJWT(map[string]any{"alg": "RS256", "kid": "x"}, map[string]any{
			"aud": baasAudience, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"iss": "https://elsewhere.example", "sub": invSenderUID, "typ": "token", "bs:grt": 2}, s.key)},
		{"expired", token.SignJWT(map[string]any{"alg": "RS256", "kid": "x"}, map[string]any{
			"aud": baasAudience, "exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix(),
			"iss": baasIssuer, "sub": invSenderUID, "typ": "token", "bs:grt": 2}, s.key)},
		{"wrong type", token.SignJWT(map[string]any{"alg": "RS256", "kid": "x"}, map[string]any{
			"aud": baasAudience, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"iss": baasIssuer, "sub": invSenderUID, "typ": "id_token", "bs:grt": 2}, s.key)},
		{"anonymous device grant", token.SignJWT(map[string]any{"alg": "RS256", "kid": "x"}, map[string]any{
			"aud": baasAudience, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"iss": baasIssuer, "sub": "pz00000000000000", "typ": "token", "bs:grt": 1}, s.key)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := fiveDo(t, s, "GET", "/v2/users/"+invSenderUID+"/invitations/inbox", c.token, "")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s: inbox = %d, want 401 (%s)", c.name, w.Code, w.Body)
			}
			if !strings.Contains(w.Body.String(), `"code":"0006"`) {
				t.Fatalf("%s: body lacks the documented error code: %s", c.name, w.Body)
			}
		})
	}
}

func TestFiveInboxPathIDIsBoundToThePrincipal(t *testing.T) {
	s := fiveServer(t)
	// A valid token for the sender must not read the receiver's inbox.
	w := fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox", fiveToken(s, invSenderUID), "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-account inbox = %d, want 403 (%s)", w.Code, w.Body)
	}
	w = fiveDo(t, s, "PATCH", "/v1/users/"+invReceiverUID+"/invitations/mark_as_read", fiveToken(s, invSenderUID), "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-account mark_as_read = %d, want 403 (%s)", w.Code, w.Body)
	}
}

// ---------- INV-01/02: create, shape, persistence ----------

func TestFiveCreateGroupV2(t *testing.T) {
	s := fiveServer(t)
	w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID))
	if w.Code != 200 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	var group map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	// Group ids render with the firmware's %llu: they must be JSON numbers.
	id, ok := group["id"].(float64)
	if !ok || id <= 0 {
		t.Fatalf("group id is not a number: %v", group["id"])
	}
	if group["sender_id"] != invSenderUID {
		t.Fatalf("sender_id = %v", group["sender_id"])
	}
	invitations, ok := group["invitations"].([]any)
	if !ok || len(invitations) != 1 {
		t.Fatalf("invitations = %v", group["invitations"])
	}
	inv := invitations[0].(map[string]any)
	if _, ok := inv["id"].(float64); !ok {
		t.Fatalf("invitation id is not a number: %v", inv["id"])
	}
	if inv["receiver_id"] != invReceiverUID {
		t.Fatalf("receiver_id = %v", inv["receiver_id"])
	}

	// INV-02: the row is durable before the response — a fresh store instance
	// on the same file (a restart, another device) sees the same invitation.
	reopened := loadInvitationStore(invStoreOverride.path)
	if len(reopened.Invitations) != 1 {
		t.Fatalf("reopened store holds %d invitations, want 1", len(reopened.Invitations))
	}
}

func TestFiveCreateVersionSkew(t *testing.T) {
	s := fiveServer(t)
	body := `{"receiver_ids":["` + invReceiverUID + `"],"application_id":"0100ed9024eb8000","application_group_id":"0100ed9024eb8000"}`
	if w := fiveDo(t, s, "POST", "/v1/invitation_groups", fiveToken(s, invSenderUID), body); w.Code != 200 {
		t.Fatalf("v1 create without invitation_type = %d %s", w.Code, w.Body)
	}
	// v2 predates nothing: an absent type is tolerated as the hardcoded value,
	// a wrong one is a client bug.
	if w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), body); w.Code != 200 {
		t.Fatalf("v2 create without invitation_type = %d %s", w.Code, w.Body)
	}
	bad := strings.Replace(body, `}`, `,"invitation_type":"party"}`, 1)
	if w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), bad); w.Code != 400 {
		t.Fatalf("v2 create with invitation_type=party = %d, want 400", w.Code)
	}
}

func TestFiveCreateValidation(t *testing.T) {
	s := fiveServer(t)
	token := fiveToken(s, invSenderUID)
	cases := []struct {
		name, body, wantCode, wantMsg string
	}{
		{"self invite", `{"receiver_ids":["` + invSenderUID + `"],"application_id":"0100ed9024eb8000"}`, "0002", "receiver_must_be_different_from_sender"},
		{"bad application id", `{"receiver_ids":["` + invReceiverUID + `"],"application_id":"nope"}`, "0002", "invalid_params"},
		{"bad base64", `{"receiver_ids":["` + invReceiverUID + `"],"application_id":"0100ed9024eb8000","application_data":"!!!"}`, "0002", "invalid_params"},
		{"oversized application data", `{"receiver_ids":["` + invReceiverUID + `"],"application_id":"0100ed9024eb8000","application_data":"` + base64.StdEncoding.EncodeToString(make([]byte, 1025)) + `"}`, "0011", "application_data_is_too_large"},
		{"unknown language", `{"receiver_ids":["` + invReceiverUID + `"],"application_id":"0100ed9024eb8000","messages":{"xx-XX":"hi"}}`, "0002", "not_acceptable_language"},
		{"no receivers", `{"receiver_ids":[],"application_id":"0100ed9024eb8000"}`, "0002", "could_not_retrieve_receiver"},
		{"unknown receiver", `{"receiver_ids":["0000000000000000"],"application_id":"0100ed9024eb8000"}`, "0002", "could_not_retrieve_receiver"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := fiveDo(t, s, "POST", "/v2/invitation_groups", token, c.body)
			if w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"`+c.wantCode+`"`) ||
				!strings.Contains(w.Body.String(), c.wantMsg) {
				t.Fatalf("%s = %d %s", c.name, w.Code, w.Body)
			}
		})
	}
	// Bound: one more receiver than the documented adapter cap is refused.
	var ids []string
	for i := 0; i < invitationMaxReceivers+1; i++ {
		ids = append(ids, fmt.Sprintf("%016x", i+1000))
	}
	w := fiveDo(t, s, "POST", "/v2/invitation_groups", token,
		`{"receiver_ids":["`+strings.Join(ids, `","`)+`"],"application_id":"0100ed9024eb8000"}`)
	if w.Code != 400 {
		t.Fatalf("receiver cap: = %d, want 400", w.Code)
	}
}

func TestFiveCreatePolicyDenial(t *testing.T) {
	s := fiveServer(t)
	core := &fakeInvCore{denied: map[string]string{"acct-" + invReceiverUID: "blocked"}}
	invCoreOverride = core
	t.Cleanup(func() { invCoreOverride = nil })

	// Only receiver is denied -> the native error names it, nothing commits.
	w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "sender_blocks_receiver") {
		t.Fatalf("all denied = %d %s", w.Code, w.Body)
	}
	if len(invStoreOverride.Invitations) != 0 {
		t.Fatalf("denied invitation committed anyway: %d rows", len(invStoreOverride.Invitations))
	}

	// A core outage must not read as policy: the call fails, the console retries.
	core.fail = true
	w = fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("core outage = %d, want 502", w.Code)
	}
	core.fail = false
}

// ---------- INV-01/02: inbox ----------

func TestFiveInboxShapeAndFilters(t *testing.T) {
	s := fiveServer(t)
	invCoreOverride = &fakeInvCore{}
	t.Cleanup(func() { invCoreOverride = nil })
	if w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID)); w.Code != 200 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	if w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invStrangerUID), createBody(invReceiverUID)); w.Code != 200 {
		t.Fatalf("create2 = %d %s", w.Code, w.Body)
	}

	w := fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox?invitation_types=friend", fiveToken(s, invReceiverUID), "")
	if w.Code != 200 {
		t.Fatalf("inbox = %d %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/invitation-inbox-shape.json")
	if err != nil {
		t.Fatal(err)
	}
	var wantShape map[string]any
	if err := json.Unmarshal(want, &wantShape); err != nil {
		t.Fatal(err)
	}
	if missing, extra := compareShape(wantShape, got, ""); len(missing)+len(extra) > 0 {
		t.Fatalf("inbox shape: missing=%v extra=%v", missing, extra)
	}
	if got["count"].(float64) != 2 {
		t.Fatalf("count = %v, want 2", got["count"])
	}
	item := got["items"].([]any)[0].(map[string]any)
	wantItem, _ := os.ReadFile("testdata/invitation-inbox-item-shape.json")
	var wantItemShape map[string]any
	if err := json.Unmarshal(wantItem, &wantItemShape); err != nil {
		t.Fatal(err)
	}
	if missing, extra := compareShape(wantItemShape, item, ""); len(missing)+len(extra) > 0 {
		t.Fatalf("item shape: missing=%v extra=%v", missing, extra)
	}
	if item["read"] != false {
		t.Fatalf("fresh invitation read = %v", item["read"])
	}
	// Newest first.
	first := item["sender_id"].(string)
	if first != invStrangerUID {
		t.Fatalf("newest item sender = %v, want the later create (%s)", first, invStrangerUID)
	}

	// read=false → only unread (both are), fields=count → the count alone.
	w = fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox?fields=count&read=false&invitation_types=friend",
		fiveToken(s, invReceiverUID), "")
	var countOnly map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &countOnly); err != nil {
		t.Fatal(err)
	}
	if countOnly["count"].(float64) != 2 {
		t.Fatalf("unread count = %v", countOnly["count"])
	}
	if _, has := countOnly["items"]; has {
		t.Fatalf("fields=count must not carry items: %s", w.Body)
	}
	// Unknown invitation types select nothing.
	w = fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox?invitation_types=party", fiveToken(s, invReceiverUID), "")
	if !strings.Contains(w.Body.String(), `"count":0`) {
		t.Fatalf("unknown type: %s", w.Body)
	}
}

// ---------- INV-02: read state — durable, idempotent, cross-device ----------

func TestFiveReadStateSurvivesRestartAndSyncs(t *testing.T) {
	s := fiveServer(t)
	invCoreOverride = &fakeInvCore{}
	t.Cleanup(func() { invCoreOverride = nil })
	if w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID)); w.Code != 200 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	var group map[string]any
	json.Unmarshal(fiveDo(t, s, "GET", "/v1/invitation_groups/"+invGroupID(t, 0), fiveToken(s, invSenderUID), "").Body.Bytes(), &group)

	// Mark all read, twice: idempotent.
	for i := 0; i < 2; i++ {
		w := fiveDo(t, s, "PATCH", "/v1/users/"+invReceiverUID+"/invitations/mark_as_read", fiveToken(s, invReceiverUID), "")
		if w.Code != 200 {
			t.Fatalf("mark_as_read = %d %s", w.Code, w.Body)
		}
	}
	// A restart (fresh store instance on the same file) sees the read state.
	reopened := loadInvitationStore(invStoreOverride.path)
	for _, inv := range reopened.Invitations {
		if !inv.Read || inv.ReadAt == 0 {
			t.Fatalf("read state did not survive the restart: %+v", inv)
		}
	}
	// And the unread count the console polls is zero on a third instance.
	invStoreOverride = loadInvitationStore(invStoreOverride.path)
	w := fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox?fields=count&read=false",
		fiveToken(s, invReceiverUID), "")
	if !strings.Contains(w.Body.String(), `"count":0`) {
		t.Fatalf("unread after read+restart = %s", w.Body)
	}
}

func TestFiveJSONPatchReadForms(t *testing.T) {
	s := fiveServer(t)
	invCoreOverride = &fakeInvCore{}
	t.Cleanup(func() { invCoreOverride = nil })
	if w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID)); w.Code != 200 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	var id string
	for k := range invStoreOverride.Invitations {
		id = k
	}

	// The firmware's own patch path: /extras/receiver/read with the id in the path.
	w := fiveDo(t, s, "PATCH", "/v1/invitations", fiveToken(s, invReceiverUID),
		fmt.Sprintf(`[{"op":"replace","path":"/invitations/%s/extras/receiver/read","value":true}]`, id))
	if w.Code != 200 {
		t.Fatalf("patch = %d %s", w.Code, w.Body)
	}
	if invStoreOverride.Invitations[id].Read != true {
		t.Fatal("patch did not commit read state")
	}

	// A path we cannot bind to an invitation is a 400, never a silent success.
	w = fiveDo(t, s, "PATCH", "/v1/invitations", fiveToken(s, invReceiverUID),
		`[{"op":"replace","path":"/extras/receiver/read","value":true}]`)
	if w.Code != 400 {
		t.Fatalf("unbindable patch = %d, want 400", w.Code)
	}
	// A stranger's id is ignored without leaking anything.
	w = fiveDo(t, s, "PATCH", "/v1/invitations", fiveToken(s, invStrangerUID),
		fmt.Sprintf(`[{"op":"replace","path":"/invitations/%s/extras/receiver/read","value":true}]`, id))
	if w.Code != 200 {
		t.Fatalf("foreign patch = %d %s", w.Code, w.Body)
	}
}

// ---------- group detail ----------

func TestFiveGroupDetailAuthorization(t *testing.T) {
	s := fiveServer(t)
	invCoreOverride = &fakeInvCore{}
	t.Cleanup(func() { invCoreOverride = nil })
	if w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID)); w.Code != 200 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	var id string
	for k := range invStoreOverride.Groups {
		id = k
	}
	for _, c := range []struct {
		uid, want string
		code      int
	}{
		{invSenderUID, "", 200},
		{invReceiverUID, "", 200}, // a receiver renders the detail too
		{invStrangerUID, "resource_is_not_found", 404},
	} {
		w := fiveDo(t, s, "GET", "/v1/invitation_groups/"+id, fiveToken(s, c.uid), "")
		if w.Code != c.code || (c.want != "" && !strings.Contains(w.Body.String(), c.want)) {
			t.Fatalf("detail as %s = %d %s, want %d %q", c.uid, w.Code, w.Body, c.code, c.want)
		}
	}
	w := fiveDo(t, s, "GET", "/v1/invitation_groups/999999999999999", fiveToken(s, invSenderUID), "")
	if w.Code != 404 || !strings.Contains(w.Body.String(), "resource_is_not_found") {
		t.Fatalf("unknown group = %d %s", w.Code, w.Body)
	}
}

// ---------- expiry ----------

func TestFiveInboxExcludesExpired(t *testing.T) {
	s := fiveServer(t)
	invCoreOverride = &fakeInvCore{}
	t.Cleanup(func() { invCoreOverride = nil })
	if w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID)); w.Code != 200 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	for _, inv := range invStoreOverride.Invitations {
		inv.ExpiresAt = time.Now().Unix() - 1
	}
	w := fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox", fiveToken(s, invReceiverUID), "")
	if !strings.Contains(w.Body.String(), `"count":0`) {
		t.Fatalf("expired invitation still in the inbox: %s", w.Body)
	}
}

// ---------- INV-04/mailbox: durable mailbox, stale rooms, native visibility ----------

func TestMailboxIsDurableAndNativelyVisible(t *testing.T) {
	s := fiveServer(t)
	host := s.store.Users[invSenderUID]
	joiner := s.store.Users[invReceiverUID]
	s.store.Update(host, func(u *store.User) { u.Presence = store.Presence{State: "PLAYING", AppID: "0100ed9024eb8000"} })

	// The emulator sends exactly what it always sent.
	r := httptest.NewRequest("POST", "/api/invitations", strings.NewReader(
		fmt.Sprintf(`{"target_pids":[%d],"app_param_base64":%q}`, joiner.PID, validAppData)))
	r.Header.Set("Authorization", "Bearer "+s.acct.nexToken(host.PID, "host"))
	w := httptest.NewRecorder()
	s.gameAPI().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"sent":1`) {
		t.Fatalf("mailbox send = %d %s", w.Code, w.Body)
	}

	// It shows up in the receiver's native inbox: one lifecycle, two surfaces.
	w = fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox", fiveToken(s, invReceiverUID), "")
	if !strings.Contains(w.Body.String(), `"count":1`) {
		t.Fatalf("native inbox missed the mailbox invitation: %s", w.Body)
	}

	// The pop consumes it, and the consumption is durable: a restart (fresh
	// instance on the same file) must not resurrect a joined room.
	w = httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/invitations", nil)
	r2.Header.Set("Authorization", "Bearer "+s.acct.nexToken(joiner.PID, "joiner"))
	s.gameAPI().ServeHTTP(w, r2)
	if !strings.Contains(w.Body.String(), `"from_pid":`) {
		t.Fatalf("pop = %d %s", w.Code, w.Body)
	}
	reopened := loadInvitationStore(invStoreOverride.path)
	if len(reopened.Invitations) != 0 {
		t.Fatalf("popped invitation came back: %d rows", len(reopened.Invitations))
	}
}

func TestMailboxStaleRoomIsDroppedCleanly(t *testing.T) {
	s := fiveServer(t)
	host := s.store.Users[invSenderUID]
	joiner := s.store.Users[invReceiverUID]

	// Hosted a room (presence carries the title), sent, then went away.
	s.store.Update(host, func(u *store.User) { u.Presence = store.Presence{State: "PLAYING", AppID: "0100ed9024eb8000"} })
	if _, ok := createMailboxInvitation(host, "host", joiner, validAppData, "0100ed9024eb8000"); !ok {
		t.Fatal("create failed")
	}
	s.store.Update(host, func(u *store.User) { u.Presence = store.Presence{State: "OFFLINE"} })
	if got := popMailboxInvitations(s, joiner); len(got) != 0 {
		t.Fatalf("a dead room was delivered: %d rows", len(got))
	}

	// No title recorded at send time: nothing to judge, the TTL decides.
	if _, ok := createMailboxInvitation(host, "host", joiner, validAppData, ""); !ok {
		t.Fatal("create failed")
	}
	if got := popMailboxInvitations(s, joiner); len(got) != 1 {
		t.Fatalf("unjudgeable invitation was dropped: %d rows", len(got))
	}

	// A live core session keeps the invitation deliverable.
	s.store.Update(host, func(u *store.User) { u.Presence = store.Presence{State: "OFFLINE"} })
	if _, ok := createMailboxInvitation(host, "host", joiner, validAppData, "0100ed9024eb8000"); !ok {
		t.Fatal("create failed")
	}
	invCoreOverride = &fakeInvCore{live: map[string]bool{"acct-" + invSenderUID: true}}
	t.Cleanup(func() { invCoreOverride = nil })
	if got := popMailboxInvitations(s, joiner); len(got) != 1 {
		t.Fatalf("core-live room was dropped: %d rows", len(got))
	}
}

func TestMailboxQueueIsBounded(t *testing.T) {
	s := fiveServer(t)
	host := s.store.Users[invSenderUID]
	joiner := s.store.Users[invReceiverUID]
	for i := 0; i < maxQueuedMailboxPerTarget+3; i++ {
		if _, ok := createMailboxInvitation(host, "host", joiner, validAppData, ""); !ok {
			t.Fatal("create failed")
		}
	}
	if got := popMailboxInvitations(s, joiner); len(got) != maxQueuedMailboxPerTarget {
		t.Fatalf("queue grew past the bound: %d", len(got))
	}
}

// ---------- semantic event seam ----------

func TestNotificationHookFiresAfterCommit(t *testing.T) {
	s := fiveServer(t)
	invCoreOverride = &fakeInvCore{}
	t.Cleanup(func() { invCoreOverride = nil })
	var got []InvitationEvent
	invitationNotify = func(ev InvitationEvent) {
		// The event promises an invitation the inbox really has: by the time
		// the hook runs, the store must already hold the committed row.
		if invStoreOverride.Invitations[ev.InvitationID] == nil {
			t.Error("event fired before the invitation was committed")
		}
		got = append(got, ev)
	}
	t.Cleanup(func() { invitationNotify = nil })

	if w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID)); w.Code != 200 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	if len(got) != 1 {
		t.Fatalf("hook fired %d times, want 1", len(got))
	}
	ev := got[0]
	if ev.EventID != "invitation:"+ev.InvitationID || ev.Type != "friend_invitation_received" ||
		ev.ReceiverID != invReceiverUID || ev.SenderID != invSenderUID || ev.ApplicationID != "0100ed9024eb8000" {
		t.Fatalf("wrong event: %+v", ev)
	}
	if ev.UnreadCount != 1 {
		t.Fatalf("unread count = %d, want 1", ev.UnreadCount)
	}
}

// ---------- non-core fallback (no core) ----------

func TestOpenPakFallbackEnforcesBlocks(t *testing.T) {
	s := fiveServer(t) // stubBackend: no core
	sender := s.store.Users[invSenderUID]
	receiver := s.store.Users[invReceiverUID]
	// Not friends -> refused (the fallback consults the friend projection).
	s.acct.(*stubBackend).friends[sender.PID] = nil
	w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID))
	if w.Code != 400 {
		t.Fatalf("stranger invite = %d", w.Code)
	}
	// Friends, but the receiver blocked the sender -> refused.
	s.acct.(*stubBackend).friends[sender.PID] = []uint64{receiver.PID}
	s.store.Update(receiver, func(u *store.User) { u.Blocks = []string{sender.ID} })
	w = fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "sender_blocks_receiver") {
		t.Fatalf("blocked invite = %d %s", w.Code, w.Body)
	}
	// Unblock -> the invitation commits.
	s.store.Update(receiver, func(u *store.User) { u.Blocks = nil })
	w = fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID))
	if w.Code != 200 {
		t.Fatalf("clean invite = %d %s", w.Code, w.Body)
	}
}

// invGroupID returns the nth group id in the store (tests create exactly one).
func invGroupID(t *testing.T, n int) string {
	t.Helper()
	ids := make([]string, 0, len(invStoreOverride.Groups))
	for k := range invStoreOverride.Groups {
		ids = append(ids, k)
	}
	if n >= len(ids) {
		t.Fatalf("no group %d in the store", n)
	}
	return ids[n]
}

// The console marks invitations read with a form, not a JSON patch:
// PATCH /v1/invitations, "read=true&ids=<id>%2C<id>" [firmware, 0x1e24b0].
func TestInvitationsAreMarkedReadWithTheConsolesForm(t *testing.T) {
	s := fiveServer(t)
	ids := []string{}
	for i := 0; i < 2; i++ {
		w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID))
		if w.Code != 200 {
			t.Fatalf("create = %d %s", w.Code, w.Body)
		}
		var group struct {
			Invitations []struct {
				ID json.Number `json:"id"` // a 64-bit id: never through float64
			} `json:"invitations"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &group); err != nil || len(group.Invitations) != 1 {
			t.Fatalf("group: %v %s", err, w.Body)
		}
		ids = append(ids, group.Invitations[0].ID.String())
	}

	w := fiveDo(t, s, "PATCH", "/v1/invitations", fiveToken(s, invReceiverUID),
		"read=true&ids="+ids[0]+"%2C"+ids[1])
	if w.Code != 200 {
		t.Fatalf("form mark-as-read = %d %s", w.Code, w.Body)
	}

	// Both are read, so the unread count the console polls is zero.
	w = fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox?fields=count&read=false&invitation_types=friend",
		fiveToken(s, invReceiverUID), "")
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["count"] != float64(0) {
		t.Errorf("unread after the form patch = %v, want 0", got["count"])
	}
}

// An invitation is only worth showing while its sender is still in the game
// they invited into: a host who quit leaves a room nobody can join. Presence
// we do not have is never taken as evidence, and a fresh invitation is never
// judged by presence at all (2026-09-20).
func TestInvitationDropsOutWhenTheSenderLeftTheGame(t *testing.T) {
	s := fiveServer(t)
	w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID))
	if w.Code != 200 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	inbox := func() float64 {
		t.Helper()
		w := fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox?invitation_types=friend",
			fiveToken(s, invReceiverUID), "")
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		n, _ := got["count"].(float64)
		return n
	}
	if inbox() != 1 {
		t.Fatalf("a fresh invitation is not offered: %v", inbox())
	}

	// Age it past the grace, with the sender still hosting that title.
	st := invitationStoreFor()
	st.mu.Lock()
	for _, inv := range st.Invitations {
		inv.CreatedAt -= int64(invitationSenderGrace.Seconds()) + 60
	}
	st.mu.Unlock()
	sender := s.store.User(invSenderUID)
	if sender == nil {
		t.Skip("the five test server has no user store entry for the sender")
	}
	s.noteDevicePresence(sender, "dev-1", "PLAYING", "0100ed9024eb8000", "", "", -1)
	if inbox() != 1 {
		t.Errorf("an invitation from a sender still in that game was hidden")
	}

	// They quit to the Home menu: the room is gone with them.
	s.noteDevicePresence(s.store.User(invSenderUID), "dev-1", "INACTIVE", "", "", "", -1)
	if got := inbox(); got != 0 {
		t.Errorf("inbox = %v after the sender left the game, want 0", got)
	}
}

// A second invitation from the same friend for the same game replaces the
// first: the room code in the older one names a room its sender has left.
func TestANewInvitationSupersedesTheSendersOlderOne(t *testing.T) {
	s := fiveServer(t)
	send := func() string {
		t.Helper()
		w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, invSenderUID), createBody(invReceiverUID))
		if w.Code != 200 {
			t.Fatalf("create = %d %s", w.Code, w.Body)
		}
		var group struct {
			Invitations []struct {
				ID json.Number `json:"id"`
			} `json:"invitations"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &group); err != nil || len(group.Invitations) != 1 {
			t.Fatalf("group: %v %s", err, w.Body)
		}
		return group.Invitations[0].ID.String()
	}
	first := send()
	second := send()

	w := fiveDo(t, s, "GET", "/v2/users/"+invReceiverUID+"/invitations/inbox?invitation_types=friend",
		fiveToken(s, invReceiverUID), "")
	var box struct {
		Count int `json:"count"`
		Items []struct {
			ID json.Number `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &box); err != nil {
		t.Fatal(err)
	}
	if box.Count != 1 || len(box.Items) != 1 {
		t.Fatalf("inbox holds %d invitations, want only the newest", box.Count)
	}
	if got := box.Items[0].ID.String(); got != second || got == first {
		t.Errorf("inbox holds %s, want the newest %s (older was %s)", got, second, first)
	}
}
