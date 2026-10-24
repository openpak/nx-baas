package events

import (
	"context"
	"testing"

	accountv1 "nx-baas/accountpb"
	"nx-baas/internal/bans"
	"nx-baas/internal/identity"
)

type statusSource struct{ st accountv1.AccountStatus }

func (s *statusSource) AccountFor(uint64) string { return "" }
func (s *statusSource) AccountStatus(context.Context, string) (accountv1.AccountStatus, error) {
	return s.st, nil
}

// TestRestoredAccountIsAllowedBackAtOnce: a closed account's lock is cached as
// deleted; account_restored drops it, so the next check re-reads the core
// instead of refusing until the cache entry ages out.
func TestRestoredAccountIsAllowedBackAtOnce(t *testing.T) {
	src := &statusSource{st: accountv1.AccountStatus_ACCOUNT_STATUS_DELETION_PENDING}
	f := &Follower{Locks: &bans.Checker{Source: src}}
	b := &identity.OpenpakBackend{Proj: &identity.ProjectionStore{}}
	if got := f.Locks.AccountLock("acct1"); got != bans.Deleted {
		t.Fatalf("pending deletion lock = %q", got)
	}
	src.st = accountv1.AccountStatus_ACCOUNT_STATUS_ACTIVE
	if got := f.Locks.AccountLock("acct1"); got != bans.Deleted {
		t.Fatalf("cache not in effect: %q", got)
	}
	f.apply(b, &accountv1.InvalidationEvent{Type: "account_restored", AccountId: "acct1"})
	if got := f.Locks.AccountLock("acct1"); got != "" {
		t.Fatalf("restored account still locked: %q", got)
	}
}
