package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubBackend: the friend graph the invitation check consults, nothing else.
type stubBackend struct {
	key     []byte
	friends map[uint64][]uint64
	names   map[uint64]string
}

func (b *stubBackend) Identity(pid uint64) (*Identity, error) {
	name, ok := b.names[pid]
	if !ok {
		return nil, fmt.Errorf("unknown pid %d", pid)
	}
	id := &Identity{PID: pid, Nickname: name, FriendCode: "SW-0000-0000-0000", Country: "AU"}
	for _, f := range b.friends[pid] {
		id.Friends = append(id.Friends, Friend{PID: f})
	}
	return id, nil
}
func (b *stubBackend) Resolve(url.Values) (*Friend, error)             { return nil, nil }
func (b *stubBackend) LoginPID(string, string) (uint64, string, error) { return 0, "", nil }
func (b *stubBackend) FriendRequest(uint64, uint64) error              { return nil }
func (b *stubBackend) FriendAccept(uint64, uint64, bool) error         { return nil }
func (b *stubBackend) nexSigningKey() []byte                           { return b.key }
func (b *stubBackend) friendCodeForAccount(string) (string, bool)      { return "SW-0000-0000-0000", true }
func (b *stubBackend) nexToken(pid uint64, username string) string {
	payload := fmt.Sprintf("%d.%s.%d", pid, username, time.Now().Add(time.Hour).Unix())
	mac := hmac.New(sha256.New, b.key)
	mac.Write([]byte("nex:" + payload))
	return "nx2." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (b *stubBackend) RegenerateFriendCode(uint64) error { return nil }

const (
	hostPID   = 1800000003
	joinerPID = 1800000004
)

func testServer(t *testing.T) *server {
	t.Helper()
	// The durable invitation store lives in the test's temp dir (INV-03: the
	// mailbox survives restarts, so tests must exercise the file, not memory).
	invStoreOverride = loadInvitationStore(filepath.Join(t.TempDir(), "invitations.json"))
	t.Cleanup(func() { invStoreOverride = nil })
	acct := &stubBackend{
		key:     []byte("0123456789abcdef0123456789abcdef"),
		friends: map[uint64][]uint64{hostPID: {joinerPID}, joinerPID: {hostPID}},
		names:   map[uint64]string{hostPID: "OutboundHost", joinerPID: "OutboundJoiner"},
	}
	s := &server{store: loadStore(t.TempDir() + "/baas.json"), acct: acct}
	s.store.Users["aaaa"] = &User{ID: "aaaa", PID: hostPID, BsDid: "hostbsdid"}
	s.store.Users["bbbb"] = &User{ID: "bbbb", PID: joinerPID, BsDid: "joinerbsdid"}
	return s
}

func do(t *testing.T, s *server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.gameAPI().ServeHTTP(w, r)
	return w
}

func TestNexTokenRoundTripAndTamper(t *testing.T) {
	s := testServer(t)
	tok := s.acct.nexToken(hostPID, "OutboundHost")
	pid, name, ok := verifyNexToken(s.acct.nexSigningKey(), tok)
	if !ok || pid != hostPID || name != "OutboundHost" {
		t.Fatalf("round trip: pid=%d name=%q ok=%v", pid, name, ok)
	}
	if _, _, ok := verifyNexToken(s.acct.nexSigningKey(), tok[:len(tok)-2]+"xx"); ok {
		t.Fatal("a tampered signature verified")
	}
	if _, _, ok := verifyNexToken([]byte("another key another key another!"), tok); ok {
		t.Fatal("a foreign key verified")
	}
}

func TestInvitationMailbox(t *testing.T) {
	s := testServer(t)
	tok := s.acct.nexToken(hostPID, "OutboundHost")
	appParam := base64.StdEncoding.EncodeToString([]byte{1, 0, 0, 0, 6, 'Q', '3', '5', 'V', '9', 'E'})

	if w := do(t, s, "POST", "/api/invitations", "", `{"target_pids":[1800000004]}`); w.Code != 401 {
		t.Fatalf("unauthenticated send: %d", w.Code)
	}
	body := fmt.Sprintf(`{"target_pids":[%d,1800000099],"app_param_base64":%q}`, joinerPID, appParam)
	w := do(t, s, "POST", "/api/invitations", tok, body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"sent":1`) {
		t.Fatalf("send: %d %s (only the friend should be queued)", w.Code, w.Body)
	}

	var out struct {
		Invitations []struct {
			FromPID  uint64 `json:"from_pid"`
			FromName string `json:"from_name"`
			AppParam string `json:"app_param_base64"`
		} `json:"invitations"`
	}
	w = do(t, s, "GET", "/api/invitations", s.acct.nexToken(joinerPID, "OutboundJoiner"), "")
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Invitations) != 1 {
		t.Fatalf("poll: %d %s err=%v", w.Code, w.Body, err)
	}
	if out.Invitations[0].FromPID != hostPID || out.Invitations[0].AppParam != appParam {
		t.Fatalf("wrong invitation delivered: %+v", out.Invitations[0])
	}
	w = do(t, s, "GET", "/api/invitations", s.acct.nexToken(joinerPID, "OutboundJoiner"), "")
	if !strings.Contains(w.Body.String(), `"invitations":[]`) {
		t.Fatalf("poll must consume: %s", w.Body)
	}
}

// The Photon master places a new room on the node for its creator's country; this is where it
// learns the country. Same identity shapes as photon-room, same refusal of a stranger.
func TestPhotonIdentityAnswersCountry(t *testing.T) {
	s := testServer(t)
	for _, identity := range []string{"nex:" + s.acct.nexToken(hostPID, "OutboundHost"), "bsdid:hostbsdid"} {
		w := do(t, s, "POST", "/internal/photon-identity", "", fmt.Sprintf(`{"identity":%q}`, identity))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"country":"AU"`) {
			t.Fatalf("%s: %d %s", identity, w.Code, w.Body)
		}
	}
	if w := do(t, s, "POST", "/internal/photon-identity", "", `{"identity":"bsdid:nobody"}`); w.Code != 400 {
		t.Fatalf("unknown identity accepted: %d", w.Code)
	}
	// The identity reply a game server reads carries it too.
	w := do(t, s, "POST", "/internal/switch/identity", "", fmt.Sprintf(`{"pid":%d}`, hostPID))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"country":"AU"`) {
		t.Fatalf("switch/identity: %d %s", w.Code, w.Body)
	}
}

func TestPhotonRoomSetsJoinablePresence(t *testing.T) {
	s := testServer(t)
	want := base64.StdEncoding.EncodeToString([]byte{1, 0, 0, 0, 6, 'Q', '3', '5', 'V', '9', 'E'})

	for _, identity := range []string{"nex:" + s.acct.nexToken(hostPID, "OutboundHost"), "bsdid:hostbsdid"} {
		s.store.Update(s.store.User("aaaa"), func(u *User) { u.Presence = Presence{State: "ONLINE"} })
		body := fmt.Sprintf(`{"identity":%q,"room":"Q35V9E","app_id":"0100ED9024EB8000"}`, identity)
		if w := do(t, s, "POST", "/internal/photon-room", "", body); w.Code != 200 {
			t.Fatalf("%s: %d %s", identity, w.Code, w.Body)
		}
		u := s.store.User("aaaa")
		if u.Presence.State != "PLAYING" || u.Presence.AppField != want {
			t.Fatalf("%s: presence not joinable: %+v", identity, u.Presence)
		}
	}
	bad := `{"identity":"bsdid:nobody","room":"Q35V9E","app_id":"0100ED9024EB8000"}`
	if w := do(t, s, "POST", "/internal/photon-room", "", bad); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown identity accepted: %d", w.Code)
	}
	bad = `{"identity":"bsdid:hostbsdid","room":"bad code","app_id":"0100ED9024EB8000"}`
	if w := do(t, s, "POST", "/internal/photon-room", "", bad); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed room code accepted: %d", w.Code)
	}
}

func TestMintTokenIsUsableAsBearer(t *testing.T) {
	s := testServer(t)
	w := do(t, s, "POST", "/internal/mint-token", "", `{"pid":1800000003}`)
	var out struct {
		Username string `json:"username"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Username != "OutboundHost" {
		t.Fatalf("mint: %d %s err=%v", w.Code, w.Body, err)
	}
	if pid, _, ok := verifyNexToken(s.acct.nexSigningKey(), out.Token); !ok || pid != hostPID {
		t.Fatalf("minted token does not authenticate its pid: %v %d", ok, pid)
	}
}
