// Package events follows the account core's event stream (bans, deletions, friendships,
// presence on other networks) and carries each event to the surfaces it changes.
package events

import (
	"context"
	"log"
	"nx-baas/internal/bans"
	"nx-baas/internal/core"
	"nx-baas/internal/friends"
	"nx-baas/internal/identity"
	"nx-baas/internal/penne"
	"nx-baas/internal/presence"
	"nx-baas/internal/store"
	"nx-baas/redact"
	"os"
	"path/filepath"
	"strconv"
	"time"

	accountv1 "nx-baas/accountpb"
)

// followCoreEvents keeps Switch friend lists current when the change happened
// somewhere else: a request from a phone, an acceptance on a Wii U, a removal on
// the website. The core announces friend_requested / friend_accepted /
// friend_removed; the two projections named by the event get their
// FriendsUpdatedAt bumped, which is what makes the console re-fetch its list
// (the same path a change made on this adapter takes).
func (s *Follower) Follow(b *identity.OpenpakBackend) {
	events := accountv1.NewEventsClient(b.Conn)
	cursorPath := filepath.Join(filepath.Dir(b.Proj.FilePath), "core-events.cursor")
	version, known := ReadCursor(cursorPath)
	if !known {
		// Start from the beginning, deliberately.
		//
		// This used to "start at the head" by polling with SinceVersion =
		// 1<<62-1 and trusting the MaxVersion that came back. The core answers
		// an empty page by echoing the request (`if resp.MaxVersion <
		// sinceVersion { resp.MaxVersion = sinceVersion }`), so the probe was
		// handed 4611686018427387903 straight back and wrote it as the cursor.
		// Every poll after that asked for events above 2^62, matched nothing,
		// logged nothing, and slept -- so no friend event was ever processed on
		// this network. No list was ever invalidated and no notification was
		// ever queued, for months, silently.
		//
		// Replaying from 0 is cheap and self-correcting: the handlers are
		// idempotent (deliveries dedup on the event version, and
		// projectionFriendsChanged only bumps timestamps), so the worst case is
		// one burst of re-fetches on a fresh data directory. A cursor that can
		// wedge itself forever is not worth avoiding that.
		log.Printf("[nx-baas] core events: no cursor yet; replaying from the start")
	}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		page, err := events.PollEvents(ctx, &accountv1.PollEventsRequest{SinceVersion: version, Limit: 500})
		cancel()
		if err != nil {
			log.Printf("[nx-baas] core events: %v", redact.Err(err))
			time.Sleep(10 * time.Second)
			continue
		}
		// Only ever advance from an event that exists. MaxVersion is not a
		// head marker -- it echoes the request when the page is empty -- so it
		// must never reach the cursor.
		for _, e := range page.GetEvents() {
			s.apply(b, e)
			version = e.GetVersion()
		}
		if len(page.GetEvents()) > 0 {
			WriteCursor(cursorPath, version)
			continue
		}
		time.Sleep(2 * time.Second)
	}
}

// apply carries one core event to the surfaces it changes. Account deletion
// has two stages: account_delete_started suspends (locks re-read, sessions and
// presence end, the projection stays), account_restored lifts that, and only
// account_deleted, the final erasure, drops the projection.
func (s *Follower) apply(b *identity.OpenpakBackend, e *accountv1.InvalidationEvent) {
	switch e.GetType() {
	case "friend_requested", "friend_accepted", "friend_removed":
		s.projectionFriendsChanged(b, e.GetAccountId(), e.GetSubjectId())
		// Integration wiring: the state above is committed, so the
		// native notification may now be submitted (notify_wiring.go).
		s.NotifyCoreFriendEvent(b, e.GetType(), e.GetAccountId(), e.GetSubjectId(), e.GetVersion())
	case "presence_changed":
		// account = a friend online on this network, subject = whose presence moved.
		if e.GetNamespace() == b.Namespace { // addressed to a friend on another network: not ours
			s.Presence.NotifyCorePresence(b, e.GetAccountId(), e.GetSubjectId())
		}
	case "account_unbanned", "account_restored":
		// Allowed back now, not when the cached lock ages out. A restored
		// account kept its projection through the grace period, so its friends
		// re-fetch and see it again.
		s.Locks.Forget(e.GetAccountId())
		if e.GetType() == "account_restored" {
			s.projectionFriendsChanged(b, e.GetAccountId(), e.GetSubjectId())
		}
	case "account_banned", "account_deleted", "account_delete_started", "credential_revoked", "link_unlinked":
		if e.GetType() != "credential_revoked" && e.GetType() != "link_unlinked" {
			// Bans take effect now, not when the cache entry ages out, and the
			// console's open notification channel goes with them.
			s.Locks.Forget(e.GetAccountId())
			s.closeAccountSessions(b, e.GetAccountId())
		}
		if e.GetType() == "account_deleted" {
			// Final destruction only: bans, pending deletion, revoked
			// credentials and unlinked devices all keep the projection
			// (those accounts may come back; a deleted one cannot).
			b.DropProjection(e.GetAccountId())
		}
		// An account that can no longer sign in has no live presence:
		// end its claims here, and let its friends' consoles re-fetch
		// (PRE-03: account status reaches every read). unbanned needs
		// nothing: the account is simply allowed back.
		s.revokeAccountPresence(b, e.GetAccountId())
		s.projectionFriendsChanged(b, e.GetAccountId(), e.GetSubjectId())
	}
}

// revokeAccountPresence ends every device claim of one core account: a
// banned, deleted or unlinked account is offline everywhere, now, instead of
// whenever its leases happen to lapse.
func (s *Follower) revokeAccountPresence(b *identity.OpenpakBackend, accountID string) {
	b.Proj.Mu.Lock()
	pr := b.Proj.ByAccount[accountID]
	b.Proj.Mu.Unlock()
	if pr == nil {
		return
	}
	if u := s.Store.User(pr.BaasUserID); u != nil {
		s.Store.Update(u, func(u *store.User) {
			u.DevicePresence = nil
			u.Presence = store.Presence{State: "OFFLINE", UpdatedAt: time.Now().Unix(), LogoutAt: time.Now().Unix()}
		})
	}
}

func (s *Follower) projectionFriendsChanged(b *identity.OpenpakBackend, accountID, otherID string) {
	b.Proj.Mu.Lock()
	p, other := b.Proj.ByAccount[accountID], b.Proj.ByAccount[otherID]
	b.Proj.Mu.Unlock()
	if p == nil {
		return // no Switch identity on this side; nothing to refresh
	}
	if u := s.Store.User(p.BaasUserID); u != nil {
		otherBaas := ""
		if other != nil {
			otherBaas = other.BaasUserID
		}
		s.Friends.FriendGraphChanged(u, otherBaas)
	}
}

func ReadCursor(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(string(raw), 10, 64)
	return v, err == nil
}

func WriteCursor(path string, v uint64) {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(v, 10)), 0o600); err == nil {
		os.Rename(tmp, path)
	}
}

// Follower follows the account core's event stream and carries each event to the surfaces
// it changes: bans, friends' lists, presence, and the notifications consoles are sent.
type Follower struct {
	*core.Core
	Locks    *bans.Checker
	Friends  *friends.Service
	Presence *presence.Service
	Notify   func(penne.Delivery) penne.Submission
}
