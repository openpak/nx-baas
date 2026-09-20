package main

import (
	"testing"
	"time"

	"nx-baas/internal/penne"
)

// An answer the console is blocking on goes out before anything queued, and
// is dropped rather than sent late: a late Ack is compared against the next
// request's string and aborts npns.
func TestAckTakesThePriorityPathAndIsNeverQueued(t *testing.T) {
	sess := &penneSession{prio: make(chan []byte, 1), send: make(chan penneOutbound, 4)}
	sess.ack("topic.subscription")
	sess.ack("aaaaaaaaaaaa0001/cccccccccccc0001") // would be late: dropped
	if len(sess.prio) != 1 {
		t.Fatalf("priority queue holds %d answers, want exactly the first", len(sess.prio))
	}
	if len(sess.send) != 0 {
		t.Fatalf("an answer was queued behind the notifications: %d", len(sess.send))
	}
	env, err := penne.DecodeEnvelope(<-sess.prio)
	if err != nil || env.Type() != penne.TypeAck {
		t.Fatalf("not an Ack: %v %v", env.TypeName(), err)
	}
	payload, _ := env.Payload()
	if got, _ := payload.String(0); got != "topic.subscription" {
		t.Fatalf("ack names %q", got)
	}
	sess.ack("") // nothing to answer
	if len(sess.prio) != 0 {
		t.Fatal("an empty name was answered")
	}
}

// Presence is published on change and on nothing else, so a claim that is
// still true has to be renewed while the console holding it is connected --
// otherwise its people read as offline two minutes after they last switched
// game (2026-09-20: an invitation naming its sender "offline for 0 minutes").
func TestPresenceIsRenewedWhileTheConsoleIsConnected(t *testing.T) {
	s := &server{store: mustStore(t)}
	u, _ := s.store.NewUser()
	s.noteDevicePresence(u, "dev-1", "PLAYING", "0100a5a020d5e000", "{}", "0100a5a020d5e000", -1)

	// Age the claim to a second before it lapses.
	lease := int64(presenceLease().Seconds())
	s.store.Update(u, func(u *User) {
		u.DevicePresence["dev-1"].ExpiresAt = time.Now().Unix() + 1
	})

	sess := &penneSession{user: u.ID, penneID: "reg-1"}
	sess.published.Store(u.ID, "dev-1")
	s.penneRenewPresence(sess)

	got := s.store.User(u.ID).DevicePresence["dev-1"]
	if got.ExpiresAt < time.Now().Unix()+lease-2 {
		t.Fatalf("lease was not renewed: expires in %ds", got.ExpiresAt-time.Now().Unix())
	}
	if got.State != "PLAYING" || got.AppID != "0100a5a020d5e000" {
		t.Fatalf("renewal changed the claim: %+v", got)
	}

	// A claim that has already lapsed is not resurrected.
	s.store.Update(u, func(u *User) { u.DevicePresence["dev-1"].ExpiresAt = time.Now().Unix() - 1 })
	s.penneRenewPresence(sess)
	if s.store.User(u.ID).DevicePresence["dev-1"].ExpiresAt > time.Now().Unix() {
		t.Fatal("a lapsed claim was renewed")
	}
}
