package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"

	accountv1 "nx-baas/accountpb"
)

// markSessions records what reached the core's MarkOnline.
type markSessions struct {
	accountv1.SessionsClient
	calls [][]*accountv1.OnlinePlayer
}

func (m *markSessions) MarkOnline(_ context.Context, r *accountv1.MarkOnlineRequest, _ ...grpc.CallOption,
) (*accountv1.MarkOnlineResponse, error) {
	m.calls = append(m.calls, r.GetPlayers())
	return &accountv1.MarkOnlineResponse{Marked: int32(len(r.GetPlayers()))}, nil
}

func onlineServer(t *testing.T) (*server, *markSessions) {
	t.Helper()
	const a1, a2, a3 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222",
		"33333333-3333-3333-3333-333333333333"
	sess := &markSessions{}
	b := &openpakBackend{namespace: "switch", sessions: sess, proj: &projectionStore{
		ByAccount: map[string]*projection{a1: {AccountID: a1}, a2: {AccountID: a2}, a3: {AccountID: a3}},
		ByPID:     map[uint64]string{1800000001: a1, 1800000003: a3},
		ByBaas:    map[string]string{"baas2": a2},
		ByCode:    map[string]string{},
	}}
	s := &server{store: loadStore(t.TempDir() + "/baas.json"), acct: b}
	// A BAAS user the projection has no by_baas entry for still resolves through its pid.
	s.store.Users["baas3"] = &User{ID: "baas3", PID: 1800000003}
	return s, sess
}

func TestSwitchOnlineMarksKnownPlayers(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k")
	s, sess := onlineServer(t)

	body := `{"title_id":"0100F8F0000A2000","players":[
		{"pid":1800000001},
		{"account_id":"22222222-2222-2222-2222-222222222222"},
		{"baas_user_id":"baas3"},
		{"pid":1800000001},
		{"pid":42},
		{"account_id":"99999999-9999-9999-9999-999999999999"},
		{"baas_user_id":"nobody"},
		{}]}`

	if w := do(t, s, "POST", "/internal/switch/online", "", body); w.Code != 401 {
		t.Fatalf("no key answered %d", w.Code)
	}

	w := doKey(t, s, body)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got struct{ Marked, Unknown int }
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Marked != 3 || got.Unknown != 4 {
		t.Fatalf("got %+v, want marked 3 unknown 4", got)
	}
	if len(sess.calls) != 1 || len(sess.calls[0]) != 3 {
		t.Fatalf("core calls = %v", sess.calls)
	}
	for _, p := range sess.calls[0] {
		if p.GetNamespace() != "switch" || p.GetTitleId() != "0100f8f0000a2000" {
			t.Errorf("player sent as %v", p)
		}
	}
}

func TestSwitchOnlineRejectsBadBodies(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k")
	s, sess := onlineServer(t)

	many := make([]string, maxOnlineMarks+1)
	for i := range many {
		many[i] = fmt.Sprintf(`{"pid":%d}`, i+1)
	}
	for name, body := range map[string]string{
		"over cap":  `{"players":[` + strings.Join(many, ",") + `]}`,
		"bad title": `{"title_id":"xyz","players":[{"pid":1800000001}]}`,
		"not json":  `{`,
	} {
		if w := doKey(t, s, body); w.Code != 400 {
			t.Errorf("%s answered %d", name, w.Code)
		}
	}
	// Nobody known: nothing to tell the core.
	if w := doKey(t, s, `{"players":[{"pid":7}]}`); w.Code != 200 || len(sess.calls) != 0 {
		t.Fatalf("unknown-only answered %d, core calls %d", w.Code, len(sess.calls))
	}
}

func doKey(t *testing.T, s *server, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/internal/switch/online", strings.NewReader(body))
	r.Header.Set("X-Internal-Key", "k")
	w := httptest.NewRecorder()
	s.gameAPI().ServeHTTP(w, r)
	return w
}
