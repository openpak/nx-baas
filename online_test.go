package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	accountv1 "nx-baas/accountpb"
	"nx-baas/internal/identity"
)

// markingBackend is the stub backend that also records which logins marked a player online.
type markingBackend struct {
	*stubBackend
	mu     sync.Mutex
	marked []uint64
}

func (m *markingBackend) MarkOnline(pid uint64) {
	m.mu.Lock()
	m.marked = append(m.marked, pid)
	m.mu.Unlock()
}

func TestIdentityLookupsMarkPlayersOnline(t *testing.T) {
	s := testServer(t)
	m := &markingBackend{stubBackend: s.acct.(*stubBackend)}
	s.acct = m

	if w := do(t, s, "POST", "/internal/switch/identity", "", fmt.Sprintf(`{"pid":%d}`, hostPID)); w.Code != 200 {
		t.Fatalf("switch identity %d: %s", w.Code, w.Body)
	}
	if w := do(t, s, "POST", "/internal/photon-identity", "", `{"identity":"bsdid:joinerbsdid"}`); w.Code != 200 {
		t.Fatalf("photon identity %d: %s", w.Code, w.Body)
	}
	// Failed lookups mark nobody.
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"pid":42}`); w.Code != 404 {
		t.Fatalf("unknown pid answered %d", w.Code)
	}
	if w := do(t, s, "POST", "/internal/photon-identity", "", `{"identity":"bsdid:nobody"}`); w.Code != 400 {
		t.Fatalf("unknown identity answered %d", w.Code)
	}
	if w := do(t, s, "POST", "/internal/switch/identity", "", `{"openpak":"nx2.bad.token"}`); w.Code != 401 {
		t.Fatalf("bad openpak answered %d", w.Code)
	}
	if len(m.marked) != 2 || m.marked[0] != hostPID || m.marked[1] != joinerPID {
		t.Fatalf("marked %v, want [%d %d]", m.marked, hostPID, joinerPID)
	}
}

// markSessions records what reached the core's MarkOnline.
type markSessions struct {
	accountv1.SessionsClient
	calls []*accountv1.OnlinePlayer
	err   error
}

func (x *markSessions) MarkOnline(_ context.Context, r *accountv1.MarkOnlineRequest, _ ...grpc.CallOption,
) (*accountv1.MarkOnlineResponse, error) {
	x.calls = append(x.calls, r.GetPlayers()...)
	return &accountv1.MarkOnlineResponse{Marked: 1}, x.err
}

func TestBackendMarkOnlineSendsTheAccount(t *testing.T) {
	orig := identity.GoAsync
	identity.GoAsync = func(f func()) { f() }
	t.Cleanup(func() { identity.GoAsync = orig })

	const acct = "11111111-1111-1111-1111-111111111111"
	sess := &markSessions{}
	b := &identity.OpenpakBackend{Namespace: "switch", Sessions: sess, Proj: &identity.ProjectionStore{
		ByAccount: map[string]*identity.Projection{acct: {AccountID: acct}},
		ByPID:     map[uint64]string{1800000001: acct},
	}}
	b.MarkOnline(1800000001)
	b.MarkOnline(42) // no account: nothing sent
	if len(sess.calls) != 1 {
		t.Fatalf("core calls = %v", sess.calls)
	}
	if p := sess.calls[0]; p.GetAccountId() != acct || p.GetNamespace() != "switch" || p.GetTitleId() != "" {
		t.Fatalf("sent %v", p)
	}
	// A failing core is swallowed; no core configured is a no-op.
	sess.err = errors.New("down")
	b.MarkOnline(1800000001)
	(&identity.OpenpakBackend{Proj: b.Proj}).MarkOnline(1800000001)
}

// blockingSessions is a core that hangs until released.
type blockingSessions struct {
	accountv1.SessionsClient
	release chan struct{}
	called  chan struct{}
}

func (x *blockingSessions) MarkOnline(ctx context.Context, _ *accountv1.MarkOnlineRequest, _ ...grpc.CallOption,
) (*accountv1.MarkOnlineResponse, error) {
	close(x.called)
	<-x.release
	return nil, errors.New("too late")
}

// A hung core never holds up the login that triggered the mark.
func TestBackendMarkOnlineDoesNotWaitForTheCore(t *testing.T) {
	const acct = "11111111-1111-1111-1111-111111111111"
	sess := &blockingSessions{release: make(chan struct{}), called: make(chan struct{})}
	b := &identity.OpenpakBackend{Namespace: "switch", Sessions: sess, Proj: &identity.ProjectionStore{
		ByAccount: map[string]*identity.Projection{acct: {AccountID: acct}},
		ByPID:     map[uint64]string{1800000001: acct},
	}}
	start := time.Now()
	b.MarkOnline(1800000001)
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("markOnline blocked for %v", d)
	}
	select {
	case <-sess.called:
	case <-time.After(2 * time.Second):
		t.Fatal("core never called")
	}
	close(sess.release)
}
