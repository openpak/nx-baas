package main

// Tests for the integration seams in notify_wiring.go: core friend events and
// presence changes (A's side) and committed invitations (C's side) becoming
// durable deliveries in B's outbox. These prove the pipeline end to end on the
// server; they do not and cannot prove a console parsed anything.

import (
	"testing"
	"time"
)

// outboxOf reads a recipient's pending deliveries without claiming them (a
// claim would reschedule them and hide a duplicate).
func outboxOf(s *server, userID string) []*penneOutRec {
	st := s.notifStore()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]*penneOutRec, len(st.d.Outbox[userID]))
	copy(out, st.d.Outbox[userID])
	return out
}

// The core addresses each friend event at the account that must hear it, so
// the recipient is AccountId and the counterparty is SubjectId. Getting this
// backwards would alert the wrong console, which no later test would catch.
func TestCoreFriendEventsNotifyTheAccountTheCoreAddressed(t *testing.T) {
	s, _, users := socialServer(t)
	b := s.acct.(*openpakBackend)
	a, other := users[0], users[1]

	for _, tc := range []struct {
		core, native string
		version      uint64
	}{
		{"friend_requested", EventFriendRequestReceived, 11},
		{"friend_accepted", EventFriendRequestAuthorized, 12},
		{"friend_removed", EventFriendDeleted, 13},
	} {
		s.notifyCoreFriendEvent(b, tc.core, "acc-a@example.com", "acc-b@example.com", tc.version)
		queue := outboxOf(s, a.ID)
		if len(queue) == 0 {
			t.Fatalf("%s produced no delivery", tc.core)
		}
		last := queue[len(queue)-1]
		if last.Kind != tc.native {
			t.Fatalf("%s became %q, want %q", tc.core, last.Kind, tc.native)
		}
		if got, _ := last.Payload["friendId"].(string); got != other.ID {
			t.Fatalf("%s names friendId %q, want the subject %q", tc.core, got, other.ID)
		}
		if len(outboxOf(s, other.ID)) != 0 {
			t.Fatalf("%s also alerted the subject; the core addresses one side per event", tc.core)
		}
	}
}

// A poll page reprocessed after a crash resubmits the same core versions. The
// event id is the version, so the recipient must not be alerted twice.
func TestReplayedCoreEventsDoNotAlertTwice(t *testing.T) {
	s, _, users := socialServer(t)
	b := s.acct.(*openpakBackend)

	s.notifyCoreFriendEvent(b, "friend_requested", "acc-a@example.com", "acc-b@example.com", 77)
	s.notifyCoreFriendEvent(b, "friend_requested", "acc-a@example.com", "acc-b@example.com", 77)

	if got := len(outboxOf(s, users[0].ID)); got != 1 {
		t.Fatalf("a replayed core event queued %d deliveries, want 1", got)
	}
}

// An account with no Switch identity on the receiving side has nothing native
// to be told; the wiring must not invent a recipient.
func TestCoreEventForAnUnprojectedAccountIsDropped(t *testing.T) {
	s, _, users := socialServer(t)
	b := s.acct.(*openpakBackend)

	s.notifyCoreFriendEvent(b, "friend_requested", "acc-nobody@example.com", "acc-b@example.com", 5)

	for _, u := range users {
		if len(outboxOf(s, u.ID)) != 0 {
			t.Fatal("an unprojected account's event reached a console")
		}
	}
}

// Presence fans out to authorized friends on a real state change, and only on
// a real change: a heartbeat that renews the same state is not an event.
func TestPresenceChangeNotifiesFriendsOnceAndOnlyOnChange(t *testing.T) {
	s, _, users := socialServer(t)
	viewer, subject := users[0], users[1]

	s.noteDevicePresence(subject, "dev-1", "ONLINE", "", "", "", -1)
	queue := outboxOf(s, viewer.ID)
	if len(queue) != 1 {
		t.Fatalf("going online produced %d deliveries, want 1", len(queue))
	}
	if queue[0].Kind != EventPresenceUpdated {
		t.Fatalf("kind %q, want %q", queue[0].Kind, EventPresenceUpdated)
	}
	if got, _ := queue[0].Payload["friendId"].(string); got != subject.ID {
		t.Fatalf("presence names %q, want the subject %q", got, subject.ID)
	}
	// The state lives under $.value, which is where the console's parser
	// reads it; friendId stays at the top for our own surfaces.
	value, _ := queue[0].Payload["value"].(map[string]any)
	if got, _ := value["state"].(string); got != "ONLINE" {
		t.Fatalf("state %q, want ONLINE (payload %v)", got, queue[0].Payload)
	}
	if got, _ := value["userId"].(string); got != subject.ID {
		t.Fatalf("value.userId = %q, want %q", got, subject.ID)
	}

	// A renewal at the same state changes nothing the friend needs told.
	s.noteDevicePresence(s.store.User(subject.ID), "dev-1", "ONLINE", "", "", "", -1)
	if got := len(outboxOf(s, viewer.ID)); got != 1 {
		t.Fatalf("a heartbeat queued another delivery (%d total)", got)
	}

	// Starting a title is a change, and coalescing keeps one entry per subject.
	s.noteDevicePresence(s.store.User(subject.ID), "dev-1", "PLAYING", "0100000000010000", "", "", -1)
	queue = outboxOf(s, viewer.ID)
	if len(queue) != 1 {
		t.Fatalf("presence updates did not coalesce: %d pending", len(queue))
	}
	value, _ = queue[0].Payload["value"].(map[string]any)
	if got, _ := value["state"].(string); got != "PLAYING" {
		t.Fatalf("coalesced state %q, want the latest (PLAYING)", got)
	}
	extras, _ := value["extras"].(map[string]any)
	friends, _ := extras["friends"].(map[string]any)
	if got, _ := friends["appInfo:appId"].(string); got != "0100000000010000" {
		t.Errorf("the title the friend started is not in the event: %v", friends)
	}
}

// PRE-03: a block hides presence from the blocked side. The visibility check
// runs per recipient at submit time, so a blocked viewer is never queued.
func TestBlockedViewerIsNotToldAboutPresence(t *testing.T) {
	s, _, users := socialServer(t)
	viewer, subject := users[0], users[1]
	s.store.Update(viewer, func(u *User) { u.Blocks = append(u.Blocks, subject.ID) })

	s.noteDevicePresence(s.store.User(subject.ID), "dev-1", "ONLINE", "", "", "", -1)

	if got := len(outboxOf(s, viewer.ID)); got != 0 {
		t.Fatalf("a blocked viewer was queued %d presence deliveries", got)
	}
}

// C commits the invitation, then calls its hook. The wiring turns that into a
// friend_invitation_received carrying the parser paths C recorded as
// firmware-confirmed.
func TestCommittedInvitationReachesTheOutbox(t *testing.T) {
	s, _, users := socialServer(t)
	s.wireInvitationNotifications()
	t.Cleanup(func() { invitationNotify = nil })

	notifyCommitted(InvitationEvent{
		EventID:       "invitation:1234",
		Type:          EventFriendInvitationReceived,
		ReceiverID:    users[0].ID,
		SenderID:      users[1].ID,
		InvitationID:  "1234",
		GroupID:       "99",
		ApplicationID: "0100000000010000",
		UnreadCount:   1,
	})

	queue := outboxOf(s, users[0].ID)
	if len(queue) != 1 {
		t.Fatalf("a committed invitation queued %d deliveries, want 1", len(queue))
	}
	if queue[0].Kind != EventFriendInvitationReceived {
		t.Fatalf("kind %q", queue[0].Kind)
	}
	if queue[0].ID != "invitation:1234" {
		t.Fatalf("event id %q: C's stable identity must survive", queue[0].ID)
	}
	inv, ok := queue[0].Payload["invitation"].(map[string]any)
	if !ok {
		t.Fatal("payload carries no $.invitation object")
	}
	for k, want := range map[string]string{
		"id": "1234", "sender_id": users[1].ID,
		"application_id": "0100000000010000", "invitation_group_id": "99",
	} {
		if got, _ := inv[k].(string); got != want {
			t.Fatalf("$.invitation.%s = %q, want %q", k, got, want)
		}
	}

	// The hook is idempotent by C's event id: a retried notify is one alert.
	notifyCommitted(InvitationEvent{
		EventID: "invitation:1234", Type: EventFriendInvitationReceived,
		ReceiverID: users[0].ID, SenderID: users[1].ID, InvitationID: "1234",
	})
	if got := len(outboxOf(s, users[0].ID)); got != 1 {
		t.Fatalf("a retried invitation notify queued %d deliveries", got)
	}
}

// The REST surfaces must not depend on the notification side existing: an
// unwired hook is a no-op, not a failure.
func TestInvitationNotifyWithoutWiringIsHarmless(t *testing.T) {
	invitationNotify = nil
	notifyCommitted(InvitationEvent{EventID: "invitation:1", ReceiverID: "nobody"})
	_ = time.Now()
}

// The presence event's shape is the parser's, not ours: the presence nests
// under $.value with the friend's id inside it, the event's own stamp is
// $.createdAt, and the app fields keep the types the console publishes them in
// [firmware, friends module 0xa7510].
func TestPresenceEventCarriesTheParsersShape(t *testing.T) {
	p := Presence{State: "PLAYING", AppID: "0100000000010000", AppField: "AA==",
		PresenceGroupID: "0100000000010000", ACDIndex: 3, UpdatedAt: 100, LogoutAt: 0}
	extras := presenceEventExtras(p)
	if extras["appInfo:appId"] != "0100000000010000" || extras["appInfo:acdIndex"] != 3 {
		t.Errorf("extras = %v", extras)
	}
	// Nothing published means nothing sent, rather than zero values that read
	// as "index 0" and "title 0000000000000000".
	empty := presenceEventExtras(Presence{State: "ONLINE", ACDIndex: -1})
	if len(empty) != 0 {
		t.Errorf("extras for a bare ONLINE = %v, want empty", empty)
	}
}
