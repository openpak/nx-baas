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

func TestSweepWakesFailedDeliveryWhenRetryBecomesDue(t *testing.T) {
	s := newPenneStore("")
	now := time.Now()
	res := s.Submit(PenneDelivery{ID: "retry-event", UserID: "u1", Kind: EventFriendDeleted}, now)
	if !res.Accepted {
		t.Fatalf("submit: %+v", res)
	}
	s.MarkFailed("u1", "retry-event", "connection lost", now)
	if got := s.Sweep(now); len(got) != 0 {
		t.Fatalf("retry woke before backoff elapsed: %v", got)
	}
	if got := s.Sweep(now.Add(retryBase)); len(got) != 1 || got[0] != "u1" {
		t.Fatalf("due retry did not wake recipient: %v", got)
	}
	if got := s.ClaimDue("u1", "", now.Add(retryBase), 1); len(got) != 1 || got[0].ID != "retry-event" {
		t.Fatalf("retry was not retained: %+v", got)
	}
}

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

// Consoles that registered against the permissive build hold ids this store
// never minted; they retry a 401 forever rather than re-register, so the
// account token they already present adopts the pair. It must not become a way
// to take over an id that exists, or to register without an account.
func TestAdoptsAPreExistingIDOnlyForAProvenAccount(t *testing.T) {
	s := &server{}
	store := s.notifStore()
	now := time.Now()
	old := map[string]any{"id": "pzxi59slaemjyhqvc6ecv6yyerka74wdc", "password": "4f37li22zp0e79vnzthn9ed195pug1bh"}

	if _, ok := s.penneAuthedAssoc(store, old, "", "device-a", now); ok {
		t.Error("adopted an id with no account behind the request")
	}
	a, ok := s.penneAuthedAssoc(store, old, "user-a", "device-a", now)
	if !ok {
		t.Fatal("a console with a valid account token could not adopt its own id")
	}
	if a.UserID != "user-a" || a.DeviceID != "device-a" {
		t.Errorf("adopted association bound to %s/%s", a.UserID, a.DeviceID)
	}
	// Adopted once, it authenticates like any other registration...
	if _, err := store.CheckAssoc(old["id"].(string), old["password"].(string), now); err != nil {
		t.Errorf("adopted credentials do not authenticate: %v", err)
	}
	// ...and nobody else can claim it with a password of their own.
	thief := map[string]any{"id": old["id"], "password": "not-the-password"}
	if _, ok := s.penneAuthedAssoc(store, thief, "user-b", "device-b", now); ok {
		t.Error("a wrong password took over an existing id")
	}
	if _, err := store.CheckAssoc(old["id"].(string), old["password"].(string), now); err != nil {
		t.Errorf("the original credentials stopped working: %v", err)
	}
}

// Penne only ever sees the console's device token, whose subject is the device
// certificate — so a registration adopted from it is bound to something the
// outbox is not keyed by, and the console is told there is nothing for it
// while its events expire. The BAAS login knows both halves and binds them.
func TestConsoleCertificateBindsToTheAccountItSignsInAs(t *testing.T) {
	s := &server{}
	store := s.notifStore()
	now := time.Now()
	const cert, user = "cert-dddddddddddd0001", "aaaaaaaaaaaa0001"

	creds := map[string]any{"id": "pzxi59slaemjyhqvc6ecv6yyerka74wdc", "password": "4f37li22zp0e79vnzthn9ed195pug1bh"}
	a, ok := s.penneAuthedAssoc(store, creds, cert, "device-a", now)
	if !ok || a.UserID != cert {
		t.Fatalf("adopted association = %+v, ok=%v", a, ok)
	}
	rec, _, err := store.IssueTicketFor(a, now, time.Hour)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	if rec.UserID != cert {
		t.Fatalf("ticket bound to %s before the login", rec.UserID)
	}

	store.BindConsole(cert, user)

	if got := store.ResolveUser(cert); got != user {
		t.Errorf("ResolveUser(cert) = %s, want %s", got, user)
	}
	if got := store.AssocByID(a.ID); got == nil || got.UserID != user {
		t.Errorf("association not healed: %+v", got)
	}
	// The ticket the console is already holding has to move with it, or the
	// connection it opens next is still bound to the certificate.
	for _, tk := range store.d.Tickets {
		if tk.PenneID == a.ID && tk.UserID != user {
			t.Errorf("ticket still bound to %s", tk.UserID)
		}
	}
	// A real account id is left alone, and nothing binds a cert to itself.
	if got := store.ResolveUser(user); got != user {
		t.Errorf("ResolveUser(account) = %s", got)
	}
}
