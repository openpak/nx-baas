package main

import (
	"encoding/json"
	"net/http/httptest"
	"nx-baas/internal/store"
	"strings"
	"sync"
	"testing"
)

const testNAID = "aabbccdd11223344"
const testDevice = "6265ca40780b1c0d"

// consoleUA is the SDK User-Agent shape the adapter already parses (did: extraction).
func consoleUA() string {
	return "NintendoSDK Firmware/22.5.0-1.0 (platform:NX; did:" + testDevice + "; eid:lp1)"
}

// linkedServer is a dauth-ready server with one console user (PID 7) linked to testNAID.
func linkedServer(t *testing.T) *server {
	t.Helper()
	s := dauthServer(t)
	s.store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *store.User) { u.PID = 7; u.Nickname = "tester" })
	s.store.RememberNA(testNAID, 7)
	s.acct = fakeBackend{id: &Identity{PID: 7, NaID: testNAID, Nickname: "tester"}}
	return s
}

// naIDTokenFor mints the NA id token a console page's identify() step would deliver.
func naIDTokenFor(s *server) string {
	return s.naIDToken(naCode{NaID: testNAID, ClientID: "test-client"}, "access", "")
}

func hostReq(s *server, host, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	req.Host = host
	req.Header.Set("User-Agent", consoleUA())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("reply is not JSON: %v: %s", err, rec.Body.String())
	}
	return m
}

// recordingNotifier stands in for nx-penne: it keeps what the core handed on, in order.
type recordingNotifier struct {
	mu  sync.Mutex
	got []PenneDelivery
}

func (n *recordingNotifier) submit(d PenneDelivery, _ bool) PenneSubmission {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, d)
	return PenneSubmission{Accepted: true, Outcome: "recorded", ID: d.ID}
}

// recordNotifications points s's notifications at a recorder.
func recordNotifications(s *server) *recordingNotifier {
	n := &recordingNotifier{}
	s.notifier = n
	return n
}

// outboxOf lists what the core handed on for one recipient, oldest first.
func outboxOf(s *server, userID string) []PenneDelivery {
	n, _ := s.notifier.(*recordingNotifier)
	if n == nil {
		panic("outboxOf: the server has no recording notifier (recordNotifications)")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []PenneDelivery
	for _, d := range n.got {
		if d.UserID == userID {
			out = append(out, d)
		}
	}
	return out
}
