package main

// Tests for the integration seams in notify_wiring.go: core friend events and
// presence changes (A's side) and committed invitations (C's side) becoming
// deliveries handed to nx-penne (recorded here by recordNotifications). These prove the
// core's decisions -- who hears what, in which shape, under which event id -- not that a
// console parsed anything; nx-penne's own tests cover the outbox and the wire.

import (
	"nx-baas/internal/identity"
	"nx-baas/internal/penne"
	"nx-baas/internal/store"
	"testing"
	"time"
)

// The core addresses each friend event at the account that must hear it, so
// the recipient is AccountId and the counterparty is SubjectId. Getting this
// backwards would alert the wrong console, which no later test would catch.
func TestCoreFriendEventsNotifyTheAccountTheCoreAddressed(t *testing.T) {
	s, _, users := socialServer(t)
	b := s.Acct.(*identity.OpenpakBackend)
	a, other := users[0], users[1]

	for _, tc := range []struct {
		core, native string
		version      uint64
	}{
		{"friend_requested", penne.EventFriendRequestReceived, 11},
		{"friend_accepted", penne.EventFriendRequestAuthorized, 12},
		{"friend_removed", penne.EventFriendDeleted, 13},
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

// friend_request_received fails the console's parse without
// $.value.channels[0]; the push carries the channel the request was sent
// with when this server saw the send, FRIEND_CODE otherwise
// [friends-notifications-firmware-2026-09-19.md §2.2].
func TestRequestReceivedPushCarriesTheChannel(t *testing.T) {
	s, _, users := socialServer(t)
	b := s.Acct.(*identity.OpenpakBackend)
	a, other := users[0], users[1]

	id, _ := s.Store.EnsureRequest(other.PID, a.PID)
	s.noteRequestRoute(id, []byte(`{"channels":["IN_APP"]}`))
	s.notifyCoreFriendEvent(b, "friend_requested", "acc-a@example.com", "acc-b@example.com", 21)
	queue := outboxOf(s, a.ID)
	if len(queue) != 1 {
		t.Fatalf("friend_requested produced %d deliveries, want 1", len(queue))
	}
	value, _ := queue[len(queue)-1].Payload["value"].(map[string]any)
	ch, _ := value["channels"].([]string)
	if len(ch) != 1 || ch[0] != "IN_APP" {
		t.Fatalf("channels = %v, want [IN_APP]", value["channels"])
	}

	// A request this server never saw still parses: FRIEND_CODE.
	s2, _, users2 := socialServer(t)
	b2 := s2.Acct.(*identity.OpenpakBackend)
	s2.notifyCoreFriendEvent(b2, "friend_requested", "acc-a@example.com", "acc-b@example.com", 22)
	queue2 := outboxOf(s2, users2[0].ID)
	if len(queue2) != 1 {
		t.Fatalf("friend_requested produced %d deliveries, want 1", len(queue2))
	}
	value2, _ := queue2[len(queue2)-1].Payload["value"].(map[string]any)
	ch2, _ := value2["channels"].([]string)
	if len(ch2) != 1 || ch2[0] != "FRIEND_CODE" {
		t.Fatalf("channels = %v, want [FRIEND_CODE]", value2["channels"])
	}
}

// A poll page reprocessed after a crash resubmits the same core versions. The event id is
// the version, so nx-penne (which dedups on it) alerts the recipient once.
func TestReplayedCoreEventsKeepTheirEventID(t *testing.T) {
	s, _, users := socialServer(t)
	b := s.Acct.(*identity.OpenpakBackend)

	s.notifyCoreFriendEvent(b, "friend_requested", "acc-a@example.com", "acc-b@example.com", 77)
	s.notifyCoreFriendEvent(b, "friend_requested", "acc-a@example.com", "acc-b@example.com", 77)

	q := outboxOf(s, users[0].ID)
	if len(q) != 2 || q[0].ID == "" || q[0].ID != q[1].ID {
		t.Fatalf("a replayed core event went out as %+v; both must carry one event id", q)
	}
}

// An account with no Switch identity on the receiving side has nothing native
// to be told; the wiring must not invent a recipient.
func TestCoreEventForAnUnprojectedAccountIsDropped(t *testing.T) {
	s, _, users := socialServer(t)
	b := s.Acct.(*identity.OpenpakBackend)

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
	if queue[0].Kind != penne.EventPresenceUpdated {
		t.Fatalf("kind %q, want %q", queue[0].Kind, penne.EventPresenceUpdated)
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
	s.noteDevicePresence(s.Store.User(subject.ID), "dev-1", "ONLINE", "", "", "", -1)
	if got := len(outboxOf(s, viewer.ID)); got != 1 {
		t.Fatalf("a heartbeat queued another delivery (%d total)", got)
	}

	// Starting a title is a change: one more event, carrying the new state (nx-penne
	// coalesces per subject, so a sleeping console still converges to the latest).
	s.noteDevicePresence(s.Store.User(subject.ID), "dev-1", "PLAYING", "0100000000010000", "", "", -1)
	queue = outboxOf(s, viewer.ID)
	if len(queue) != 2 {
		t.Fatalf("starting a title produced %d deliveries in all, want 2", len(queue))
	}
	value, _ = queue[1].Payload["value"].(map[string]any)
	if got, _ := value["state"].(string); got != "PLAYING" {
		t.Fatalf("state %q, want the latest (PLAYING)", got)
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
	s.Store.Update(viewer, func(u *store.User) { u.Blocks = append(u.Blocks, subject.ID) })

	s.noteDevicePresence(s.Store.User(subject.ID), "dev-1", "ONLINE", "", "", "", -1)

	if got := len(outboxOf(s, viewer.ID)); got != 0 {
		t.Fatalf("a blocked viewer was queued %d presence deliveries", got)
	}
}

// C commits the invitation, then calls its hook. The wiring turns that into a
// friend_invitation_received carrying the parser paths C recorded as
// firmware-confirmed.
func TestCommittedInvitationIsHandedToPenne(t *testing.T) {
	s, _, users := socialServer(t)
	s.wireInvitationNotifications()
	t.Cleanup(func() { invitationNotify = nil })

	notifyCommitted(InvitationEvent{
		EventID:       "invitation:1234",
		Type:          penne.EventFriendInvitationReceived,
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
	if queue[0].Kind != penne.EventFriendInvitationReceived {
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
		"sender_id": users[1].ID, "application_id": "0100000000010000",
	} {
		if got, _ := inv[k].(string); got != want {
			t.Fatalf("$.invitation.%s = %q, want %q", k, got, want)
		}
	}
	// The ids are JSON integers: the console drops the whole event otherwise.
	for k, want := range map[string]uint64{"id": 1234, "invitation_group_id": 99} {
		if got, ok := inv[k].(uint64); !ok || got != want {
			t.Fatalf("$.invitation.%s = %#v, want the integer %d", k, inv[k], want)
		}
	}

	// A retried notify carries C's event id again, which nx-penne dedups on.
	notifyCommitted(InvitationEvent{
		EventID: "invitation:1234", Type: penne.EventFriendInvitationReceived,
		ReceiverID: users[0].ID, SenderID: users[1].ID, InvitationID: "1234",
	})
	if q := outboxOf(s, users[0].ID); len(q) != 2 || q[1].ID != "invitation:1234" {
		t.Fatalf("a retried invitation notify went out as %+v", q)
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
	p := store.Presence{State: "PLAYING", AppID: "0100000000010000", AppField: "AA==",
		PresenceGroupID: "0100000000010000", ACDIndex: 3, UpdatedAt: 100, LogoutAt: 0}
	extras := presenceEventExtras(p)
	if extras["appInfo:appId"] != "0100000000010000" || extras["appInfo:acdIndex"] != 3 {
		t.Errorf("extras = %v", extras)
	}
	// No game is the all-zero id the console itself publishes from HOME: the
	// parser fails the whole event without appInfo:appId, appInfo:presenceGroupId
	// and appField (mask 0x3eb, friends 0x1a74a0). acdIndex is optional and stays
	// out when nobody published one, rather than reading as "index 0".
	empty := presenceEventExtras(store.Presence{State: "ONLINE", ACDIndex: -1})
	if len(empty) != 3 || empty["appField"] != "{}" || empty["appInfo:appId"] != "0000000000000000" ||
		empty["appInfo:presenceGroupId"] != "0000000000000000" {
		t.Errorf("extras for a bare ONLINE = %v, want appField \"{}\" and all-zero ids", empty)
	}
}
