package main

import "testing"

// A friend's CreatedAt, which a console shows as "When You Became Friends", is when the core says the
// friendship was accepted; only when the core does not say does it fall back to the time the friend
// was first seen here (the projection's), which is not the friendship.
func TestFriendCreatedAtIsTheFriendshipTime(t *testing.T) {
	b, f := newTestBackend(t)
	f.addAccount("acc-1", "One", "correct horse battery")
	f.addAccount("acc-2", "Two", "correct horse battery")
	pid1, _, err := b.LoginPID("acc-1", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.LoginPID("acc-2", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	f.befriend("acc-1", "acc-2")

	const accepted = int64(1788000000)
	f.friendsSince = map[string]int64{"acc-2": accepted}
	id, err := b.Identity(pid1)
	if err != nil || len(id.Friends) != 1 {
		t.Fatalf("identity: %v %v", id, err)
	}
	if id.Friends[0].CreatedAt != accepted {
		t.Fatalf("friend created = %d, want the friendship time %d", id.Friends[0].CreatedAt, accepted)
	}

	f.friendsSince = nil
	id, err = b.Identity(pid1)
	if err != nil || len(id.Friends) != 1 || id.Friends[0].CreatedAt == 0 || id.Friends[0].CreatedAt == accepted {
		t.Fatalf("with no time from the core the entry keeps the projection's: %+v %v", id.Friends, err)
	}
}
