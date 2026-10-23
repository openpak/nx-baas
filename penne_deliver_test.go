package main

// penne_deliver_test.go: the core side of the submission contract. The core refuses what
// is not a native event or has no recipient here, and hands everything else on.

import (
	"nx-baas/internal/core"
	"nx-baas/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func mustStore(t *testing.T) *store.Store {
	t.Helper()
	return store.Load(filepath.Join(t.TempDir(), "baas.json"))
}

func deliverServer(t *testing.T) (*server, string) {
	t.Helper()
	s := &server{Core: &core.Core{Store: mustStore(t)}}
	recordNotifications(s)
	u, _ := s.Store.NewUser()
	return s, u.ID
}

func TestSubmitNotificationValidatesKindAndRecipient(t *testing.T) {
	s, uid := deliverServer(t)

	if r := s.SubmitNotification(PenneDelivery{UserID: uid, Kind: "presence_updated"}); !r.Accepted || r.ID == "" {
		t.Fatalf("native kind not handed on: %+v", r)
	}
	if r := s.SubmitNotification(PenneDelivery{UserID: uid, Kind: "arbitrary_json"}); r.Accepted {
		t.Fatal("non-native kind accepted")
	}
	if r := s.SubmitNotification(PenneDelivery{UserID: "nobody", Kind: EventFriendDeleted}); r.Outcome != penneRejectUser {
		t.Fatalf("unknown recipient: %+v", r)
	}
	if got := len(outboxOf(s, uid)); got != 1 {
		t.Fatalf("%d deliveries handed on, want only the valid one", got)
	}
	for _, kind := range []string{
		EventPresenceUpdated, EventFriendInvitationReceived, EventFriendRequestReceived,
		EventFriendRequestAuthorized, EventFriendDeleted,
	} {
		if r := s.SubmitNotification(PenneDelivery{ID: "id-" + kind, UserID: uid, Kind: kind}); !r.Accepted || r.ID != "id-"+kind {
			t.Fatalf("%s: %+v", kind, r)
		}
	}
}

// A server without nx-penne (only a test can build one: main requires NX_PENNE_URL) says
// so rather than pretending the event went anywhere.
func TestSubmitWithoutNxPenneIsNotAccepted(t *testing.T) {
	s := &server{Core: &core.Core{Store: mustStore(t)}}
	u, _ := s.Store.NewUser()
	if r := s.SubmitNotification(PenneDelivery{UserID: u.ID, Kind: EventFriendDeleted}); r.Accepted || r.Outcome != penneNoService {
		t.Fatalf("no nx-penne: %+v", r)
	}
}

func TestMain(m *testing.M) {
	// The suite drives /internal routes the way isolated development does:
	// without a configured key, under the explicit insecure opt-out. The
	// fail-closed default (key required) is pinned by TestInternalRoutes*
	// in internal_test.go, which manage the environment themselves.
	os.Setenv("NX_INTERNAL_INSECURE", "1")
	os.Exit(m.Run())
}
