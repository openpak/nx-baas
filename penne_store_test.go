package main

// penne_store_test.go: durable registration and delivery behavior (NTF-01,
// NTF-05). These are the persistence/idempotency outcomes the semantic
// delivery contract promises: durable across restart, idempotent by event id,
// bounded under overload, converging on presence.

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistrationPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "penne.json")
	s := newPenneStore(path)
	id, pw := s.Register("dev1", "user1", "nsa1", time.Now())
	if _, err := newPenneStore(path).CheckAssoc(id, pw, time.Now()); err != nil {
		t.Fatalf("registration did not survive a restart: %v", err)
	}
}

// A supplied id must not authorize its own registration (NTF-01): made-up
// credentials fail, and a registration cannot be minted or claimed by naming
// an id.
func TestSuppliedIDAuthorizesNothing(t *testing.T) {
	s := newPenneStore("")
	if _, err := s.CheckAssoc("p0123456789abcdef0123456789abcdef", "whatever", time.Now()); err == nil {
		t.Fatal("unknown id+password accepted")
	}
	if _, err := s.CheckAssoc("", "", time.Now()); err == nil {
		t.Fatal("empty credentials accepted")
	}
	// The mint path takes no client id at all: the store mints its own.
	id, _ := s.Register("dev1", "", "", time.Now())
	if id == "p0123456789abcdef0123456789abcdef" {
		t.Fatal("minted id equals a client-chosen value")
	}
}

func TestTicketExpiryRevocationAndWrongDevice(t *testing.T) {
	s := newPenneStore("")
	id, pw := s.Register("dev1", "user1", "", time.Now())

	_, expired, err := s.IssueTicket(id, pw, time.Now().Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	if _, err := s.ValidateTicket(expired, "dev1", time.Now()); err != errTicketExpired {
		t.Fatalf("expired ticket: %v", err)
	}

	_, live, err := s.IssueTicket(id, pw, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("issue live: %v", err)
	}
	if _, err := s.ValidateTicket(live, "other-device", time.Now()); err != errTicketDevice {
		t.Fatalf("wrong device: %v", err)
	}

	s.Revoke(id, time.Now())
	if _, err := s.ValidateTicket(live, "dev1", time.Now()); err != errTicketRevoked {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := s.CheckAssoc(id, pw, time.Now()); err == nil {
		t.Fatal("revoked registration still authenticates")
	}
}

func TestSubmitIsIdempotentByEventID(t *testing.T) {
	s := newPenneStore("")
	now := time.Now()
	d := PenneDelivery{ID: "ev1", UserID: "u1", Kind: EventFriendRequestReceived, Payload: map[string]any{}}
	if r := s.Submit(d, now); !r.Accepted {
		t.Fatalf("first submit: %+v", r)
	}
	if r := s.Submit(d, now); !r.Duplicate {
		t.Fatalf("second submit: %+v, want duplicate", r)
	}
	if len(s.d.Outbox["u1"]) != 1 {
		t.Fatalf("outbox holds %d copies", len(s.d.Outbox["u1"]))
	}
}

func TestPresenceUpdatesCoalescePerFriend(t *testing.T) {
	s := newPenneStore("")
	now := time.Now()
	for i, state := range []string{"ONLINE", "PLAYING", "OFFLINE"} {
		if r := s.Submit(PenneDelivery{
			UserID: "u1", Kind: EventPresenceUpdated,
			Payload: map[string]any{"friendId": "aaaa", "state": state},
		}, now.Add(time.Duration(i)*time.Second)); !r.Accepted {
			t.Fatalf("submit %d: %+v", i, r)
		}
	}
	// A different friend does not coalesce.
	if r := s.Submit(PenneDelivery{
		UserID: "u1", Kind: EventPresenceUpdated,
		Payload: map[string]any{"friendId": "bbbb", "state": "ONLINE"},
	}, now); !r.Accepted {
		t.Fatal("other friend rejected")
	}
	due := s.ClaimDue("u1", "", now.Add(time.Minute), 100)
	if len(due) != 2 {
		t.Fatalf("%d pending, want 2 (one per friend)", len(due))
	}
	for _, e := range due {
		if e.Payload["friendId"] == "aaaa" && e.Payload["state"] != "OFFLINE" {
			t.Fatalf("coalesced state = %v, want the latest", e.Payload["state"])
		}
	}
}

func TestQueueOverflowPolicy(t *testing.T) {
	s := newPenneStore("")
	now := time.Now()
	// Fill the queue with social events, which never coalesce.
	for i := 0; i < maxPendingPerUser; i++ {
		r := s.Submit(PenneDelivery{
			ID: fmt.Sprintf("ev%d", i), UserID: "u1", Kind: EventFriendDeleted,
			Payload: map[string]any{"n": i},
		}, now)
		if !r.Accepted {
			t.Fatalf("event %d rejected before the bound: %+v", i, r)
		}
	}
	// One more social event: refused (nothing sheddable).
	if r := s.Submit(PenneDelivery{ID: "ev-extra", UserID: "u1", Kind: EventFriendDeleted}, now); r.Outcome != penneRejectFull {
		t.Fatalf("overflow: %+v, want %s", r, penneRejectFull)
	}
	// A presence event is sheddable: it makes room by dropping the oldest
	// coalescable presence... none here, so it is still refused — presence for
	// a *queued* friend is shed only when one exists. Verify the explicit rule:
	// expired entries make room first.
	s.d.Outbox["u1"][0].ExpiresAt = now.Add(-time.Minute).Unix()
	if r := s.Submit(PenneDelivery{ID: "ev-extra", UserID: "u1", Kind: EventFriendDeleted}, now); !r.Accepted {
		t.Fatalf("expired room not reclaimed: %+v", r)
	}
}

func TestRetryBackoffAndExpiry(t *testing.T) {
	s := newPenneStore("")
	now := time.Now()
	s.Submit(PenneDelivery{ID: "ev1", UserID: "u1", Kind: EventFriendRequestReceived}, now)

	s.MarkFailed("u1", "ev1", "conn lost", now)
	due := s.ClaimDue("u1", "", now, 10)
	if len(due) != 0 {
		t.Fatal("failed event immediately due again")
	}
	if got := s.d.Outbox["u1"][0].NextAt; got != now.Add(retryBase).Unix() {
		t.Fatalf("first retry at %d, want +5s", got)
	}
	s.MarkFailed("u1", "ev1", "conn lost", now)
	s.MarkFailed("u1", "ev1", "conn lost", now)
	if got := s.d.Outbox["u1"][0].NextAt; got != now.Add(retryBase<<2).Unix() {
		t.Fatalf("third retry at %d, want +20s", got)
	}

	// Past expiry a failed event is dropped, not retried forever.
	s.d.Outbox["u1"][0].ExpiresAt = now.Add(-time.Second).Unix()
	s.MarkFailed("u1", "ev1", "conn lost", now)
	if len(s.d.Outbox["u1"]) != 0 {
		t.Fatal("expired event not dropped")
	}
}

func TestDeliveredRetentionDeduplicatesReplays(t *testing.T) {
	s := newPenneStore("")
	now := time.Now()
	s.Submit(PenneDelivery{ID: "ev1", UserID: "u1", Kind: EventFriendDeleted}, now)
	s.MarkDelivered("u1", "ev1", now)

	if !s.SeenRecently("u1", "ev1", now.Add(time.Hour)) {
		t.Fatal("delivered id forgotten inside the retention window")
	}
	if s.SeenRecently("u1", "ev1", now.Add(deliveredRetention+time.Hour)) {
		t.Fatal("delivered id remembered beyond the retention window")
	}
	// And a resubmission after retention is accepted again (not stuck).
	if r := s.Submit(PenneDelivery{ID: "ev1", UserID: "u1", Kind: EventFriendDeleted}, now.Add(deliveredRetention+2*time.Hour)); !r.Accepted {
		t.Fatalf("resubmission after retention: %+v", r)
	}
}

func TestSweepExpiresAndPrunes(t *testing.T) {
	s := newPenneStore("")
	now := time.Now()
	s.Submit(PenneDelivery{ID: "ev-old", UserID: "u1", Kind: EventFriendRequestReceived}, now.Add(-time.Hour))
	s.d.Outbox["u1"][0].ExpiresAt = now.Add(-time.Second).Unix()
	s.Submit(PenneDelivery{ID: "ev-new", UserID: "u1", Kind: EventFriendDeleted}, now)
	s.MarkDelivered("u1", "ev-x", now.Add(-deliveredRetention-time.Hour))

	kicked := s.Sweep(now)
	found := false
	for _, u := range kicked {
		if u == "u1" {
			found = true
		}
	}
	if !found {
		t.Fatal("sweep did not report the changed queue")
	}
	for _, e := range s.d.Outbox["u1"] {
		if e.ID == "ev-old" {
			t.Fatal("expired event survived the sweep")
		}
	}
	if _, ok := s.d.Delivered["u1"]["ev-x"]; ok {
		t.Fatal("retention window not pruned")
	}
}

func TestTicketDenialRecordsSurviveSweep(t *testing.T) {
	// Expired tickets stay a week for denial audits; older ones are purged.
	s := newPenneStore("")
	id, pw := s.Register("dev1", "user1", "", time.Now())
	_, recent, err := s.IssueTicket(id, pw, time.Now().Add(-3*24*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("issue recent: %v", err)
	}
	_, ancient, err := s.IssueTicket(id, pw, time.Now().Add(-9*24*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("issue ancient: %v", err)
	}
	s.Sweep(time.Now())
	if _, err := s.ValidateTicket(recent, "dev1", time.Now()); err != errTicketExpired {
		t.Fatalf("recently-expired ticket wrong error: %v", err)
	}
	if _, err := s.ValidateTicket(ancient, "dev1", time.Now()); err != errTicketUnknown {
		t.Fatalf("ancient ticket survived: %v", err)
	}
}

func TestPushChannelsAndLinksPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "penne.json")
	s := newPenneStore(path)
	s.RecordPushChannel("user1", "devacct1", "npns", "tok123", time.Now())
	s.LinkNSA(func() string { id, _ := s.Register("dev1", "user1", "", time.Now()); return id }(), "nsa1", time.Now())
	reloaded := newPenneStore(path)
	if reloaded.d.PushChannels["user1/npns"] == nil || reloaded.d.PushChannels["user1/npns"].DeviceTok != "tok123" {
		t.Fatal("push channel not persisted")
	}
}
