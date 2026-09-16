package main

// penne_deliver_test.go: the semantic submission contract (kinds, outcomes,
// policy revalidation) and the envelope conversion.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nx-baas/internal/penne"
)

func mustStore(t *testing.T) *Store {
	t.Helper()
	return loadStore(filepath.Join(t.TempDir(), "baas.json"))
}

func deliverServer(t *testing.T) (*server, string) {
	t.Helper()
	s := &server{store: mustStore(t)}
	u, _ := s.store.NewUser()
	return s, u.ID
}

func TestSubmitNotificationValidatesKindAndRecipient(t *testing.T) {
	s, uid := deliverServer(t)

	if r := s.SubmitNotification(PenneDelivery{UserID: uid, Kind: "presence_updated"}); !r.Accepted {
		t.Fatalf("native kind rejected: %+v", r)
	}
	if r := s.SubmitNotification(PenneDelivery{UserID: uid, Kind: "arbitrary_json"}); r.Accepted {
		t.Fatal("non-native kind accepted")
	}
	if r := s.SubmitNotification(PenneDelivery{UserID: "nobody", Kind: EventFriendDeleted}); r.Outcome != penneRejectUser {
		t.Fatalf("unknown recipient: %+v", r)
	}
	if r := s.SubmitNotification(PenneDelivery{UserID: uid, Kind: EventFriendDeleted, ExpiresAt: time.Now().Add(-time.Minute)}); r.Outcome != penneRejectExpiry {
		t.Fatalf("expired submission: %+v", r)
	}
}

// Timestamp invalidation alone is not delivery (NTF-04): every firmware kind
// must survive the whole pipeline as a native event with its type intact.
func TestAllFiveEventKindsRideThePipeline(t *testing.T) {
	s, uid := deliverServer(t)
	for _, kind := range []string{
		EventPresenceUpdated, EventFriendInvitationReceived, EventFriendRequestReceived,
		EventFriendRequestAuthorized, EventFriendDeleted,
	} {
		r := s.SubmitNotification(PenneDelivery{
			ID: "id-" + kind, UserID: uid, Kind: kind,
			Payload: map[string]any{"friendId": "aaaa"},
		})
		if !r.Accepted {
			t.Fatalf("%s: %+v", kind, r)
		}
		body := penneEventJSON(PenneDelivery{ID: r.ID, Kind: kind, Payload: map[string]any{"friendId": "aaaa"}})
		var parsed map[string]any
		if err := json.Unmarshal([]byte(body), &parsed); err != nil {
			t.Fatalf("%s: body is not JSON: %v", kind, err)
		}
		if parsed["type"] != kind {
			t.Fatalf("%s: wire type = %v", kind, parsed["type"])
		}
		frame := penneEventFrame(&penneOutRec{ID: r.ID, Kind: kind, Payload: map[string]any{"friendId": "aaaa"}})
		env, err := penne.DecodeEnvelope(frame)
		if err != nil {
			t.Fatalf("%s: frame malformed: %v", kind, err)
		}
		if env.Type() != penne.TypeMessageRequest {
			t.Fatalf("%s: carrier = %s", kind, env.TypeName())
		}
	}
}

// Policy revalidation happens at dispatch: a held event stays queued until
// expiry instead of being dropped, so sleep mode can converge later.
func TestPolicyHoldsDeliveryAtDispatch(t *testing.T) {
	s, uid := deliverServer(t)
	blocked := true
	s.notifHub().RegisterPolicy("test-quiet", func(d PenneDelivery, now time.Time) bool {
		return !blocked
	})

	r := s.SubmitNotification(PenneDelivery{ID: "ev1", UserID: uid, Kind: EventFriendRequestReceived})
	if !r.Accepted {
		t.Fatalf("submit: %+v", r)
	}
	sess := &penneSession{
		user: uid, device: "devA",
		ctx:  context.Background(),
		send: make(chan penneOutbound, 1),
	}
	s.notifHub().attach(sess)

	// Dispatch with the policy closed: nothing leaves, nothing is dropped.
	s.penneWake(uid)
	select {
	case o := <-sess.send:
		t.Fatalf("policy-blocked event delivered: %v", o.id)
	default:
	}
	if due := s.notifStore().ClaimDue(uid, "", time.Now(), 10); len(due) != 1 {
		t.Fatalf("policy-blocked event not retained: %d due", len(due))
	}

	blocked = false
	s.penneWake(uid)
	select {
	case o := <-sess.send:
		if o.id != "ev1" {
			t.Fatalf("wrong event delivered: %v", o.id)
		}
	default:
		t.Fatal("policy-open event not offered")
	}
}

// Device targeting: an event for one device must not be offered to another.
func TestDeviceTargetedDelivery(t *testing.T) {
	s, uid := deliverServer(t)
	s.SubmitNotification(PenneDelivery{
		ID: "ev1", UserID: uid, DeviceID: "deviceA", Kind: EventFriendRequestReceived,
	})
	sess := &penneSession{
		user: uid, device: "deviceB",
		ctx:  context.Background(),
		send: make(chan penneOutbound, 1),
	}
	s.notifHub().attach(sess)
	s.penneWake(uid)
	select {
	case o := <-sess.send:
		t.Fatalf("device-targeted event reached another device: %v", o.id)
	default:
	}
}

func TestEventJSONCarriesTypeIDDedup(t *testing.T) {
	body := penneEventJSON(PenneDelivery{
		ID: "ev42", Kind: EventFriendInvitationReceived,
		Payload: map[string]any{"friendId": "aaaa", "type": "evil"},
	})
	if strings.Contains(body, "evil") {
		t.Fatal("payload may not override the type field")
	}
	if !strings.Contains(body, `"id":"ev42"`) || !strings.Contains(body, `"type":"friend_invitation_received"`) {
		t.Fatalf("body = %s", body)
	}
}

// The per-friend online-notification preference (A's SOC-02 state) gates the
// presence alert at dispatch but never the social events (PRE-04).
func TestOnlineNotificationPreferenceGatesOnlyPresence(t *testing.T) {
	s, uid := deliverServer(t)
	u := s.store.User(uid)
	s.store.Update(u, func(u *User) {
		p := u.pref("aaaa")
		off := false
		p.OnlineNotification = &off
	})
	sess := &penneSession{
		user: uid, device: "devA",
		ctx:  context.Background(),
		send: make(chan penneOutbound, 2),
	}
	s.notifHub().attach(sess)

	s.SubmitNotification(PenneDelivery{
		ID: "ev-pres", UserID: uid, Kind: EventPresenceUpdated,
		Payload: map[string]any{"friendId": "aaaa"},
	})
	s.SubmitNotification(PenneDelivery{
		ID: "ev-req", UserID: uid, Kind: EventFriendRequestReceived,
		Payload: map[string]any{"friendId": "aaaa"},
	})
	s.penneWake(uid)

	// Delivery is at-least-once (client dedups by event id), so collapse the
	// offered set before asserting: the presence alert must be absent and the
	// social event present.
	seen := map[string]bool{}
	for {
		select {
		case o := <-sess.send:
			seen[o.id] = true
			continue
		default:
		}
		break
	}
	if seen["ev-pres"] {
		t.Fatal("presence alert delivered despite the per-friend preference")
	}
	if !seen["ev-req"] {
		t.Fatalf("social event not delivered: %v", seen)
	}
}

// The delivery pipeline's tests still drive the old MessageRequest carrier:
// they check queueing, policy, retry, dedup and replay, which are carrier
// independent. Production holds events instead, because a console in the
// steady state drops the connection on a type it does not accept.
func TestMain(m *testing.M) {
	penneSendEvents = true
	os.Exit(m.Run())
}

// Delivery addressing: the frame has to name the console account the friends
// module checks, and it has to name the account mapped to THIS user rather than
// whatever account happened to register the console first.
func TestMessageFramesAddressTheRecipientsAccount(t *testing.T) {
	s := &server{}
	store := s.notifStore()
	store.Register("dev1", "u1", "", time.Now())
	assoc := store.AssocIDForUser("u1")
	store.NoteAccount(assoc, "e1c0f4a2b3d4e5f60718293a4b5c6d7e", "u1")
	store.NoteAccount(assoc, "00000000000000000000000000000002", "u2")

	frames := s.penneMessageFrames(&penneOutRec{
		ID: "ev1", UserID: "u1", Kind: EventFriendRequestAuthorized,
		Payload: map[string]any{"friendId": "f1"}})
	if len(frames) != 1 {
		t.Fatalf("%d frames, want one per account of u1", len(frames))
	}
	env, err := penne.DecodeEnvelope(frames[0])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	payload, _ := env.Payload()
	m, ok := penne.ParseMessage(payload)
	if !ok {
		t.Fatal("not a kind-1 message")
	}
	if m.AccountID != "e1c0f4a2b3d4e5f60718293a4b5c6d7e" {
		t.Errorf("addressed to %q; u2's account shares the console and must not be picked", m.AccountID)
	}
	if m.Receivers == "" {
		t.Error("empty receiver list; npns has nothing to route by")
	}
	if !strings.Contains(m.Body, `"friendId":"f1"`) {
		t.Errorf("body lost the payload: %s", m.Body)
	}
}

// An unaddressed frame will not land -- the friends handlers drop a zero uid --
// but it still goes on the wire, because a frame in a capture is evidence and a
// silent drop is not.
func TestMessageFramesStillSendWithoutAKnownAccount(t *testing.T) {
	s := &server{}
	if got := len(s.penneMessageFrames(&penneOutRec{ID: "ev1", UserID: "u1", Kind: EventPresenceUpdated})); got != 1 {
		t.Fatalf("%d frames for an unknown account, want one unaddressed", got)
	}
}
