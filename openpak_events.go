package main

import (
	"context"
	"log"
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
func (s *server) followCoreEvents(b *openpakBackend) {
	events := accountv1.NewEventsClient(b.conn)
	cursorPath := filepath.Join(filepath.Dir(b.proj.path), "core-events.cursor")
	version, known := readCursor(cursorPath)
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
			switch e.GetType() {
			case "friend_requested", "friend_accepted", "friend_removed":
				s.projectionFriendsChanged(b, e.GetAccountId(), e.GetSubjectId())
				// Integration wiring: the state above is committed, so the
				// native notification may now be submitted (notify_wiring.go).
				s.notifyCoreFriendEvent(b, e.GetType(), e.GetAccountId(), e.GetSubjectId(), e.GetVersion())
			case "presence_changed":
				// account = a friend online on this network, subject = whose presence moved.
				if e.GetNamespace() == b.namespace { // addressed to a friend on another network: not ours
					s.notifyCorePresence(b, e.GetAccountId(), e.GetSubjectId())
				}
			case "account_unbanned":
				s.forgetBan(e.GetAccountId())
			case "account_banned", "account_deleted", "account_delete_started", "credential_revoked", "link_unlinked":
				if e.GetType() != "credential_revoked" && e.GetType() != "link_unlinked" {
					// Bans take effect now, not when the cache entry ages out, and the
					// console's open notification channel goes with them.
					s.forgetBan(e.GetAccountId())
					s.closeAccountSessions(b, e.GetAccountId())
				}
				if e.GetType() == "account_deleted" {
					// Final destruction only: bans, pending deletion, revoked
					// credentials and unlinked devices all keep the projection
					// (those accounts may come back; a deleted one cannot).
					b.dropProjection(e.GetAccountId())
				}
				// An account that can no longer sign in has no live presence:
				// end its claims here, and let its friends' consoles re-fetch
				// (PRE-03: account status reaches every read). unbanned needs
				// nothing: the account is simply allowed back.
				s.revokeAccountPresence(b, e.GetAccountId())
				s.projectionFriendsChanged(b, e.GetAccountId(), e.GetSubjectId())
			}
			version = e.GetVersion()
		}
		if len(page.GetEvents()) > 0 {
			writeCursor(cursorPath, version)
			continue
		}
		time.Sleep(2 * time.Second)
	}
}

// revokeAccountPresence ends every device claim of one core account: a
// banned, deleted or unlinked account is offline everywhere, now, instead of
// whenever its leases happen to lapse.
func (s *server) revokeAccountPresence(b *openpakBackend, accountID string) {
	b.proj.mu.Lock()
	pr := b.proj.ByAccount[accountID]
	b.proj.mu.Unlock()
	if pr == nil {
		return
	}
	if u := s.store.User(pr.BaasUserID); u != nil {
		s.store.Update(u, func(u *store.User) {
			u.DevicePresence = nil
			u.Presence = store.Presence{State: "OFFLINE", UpdatedAt: time.Now().Unix(), LogoutAt: time.Now().Unix()}
		})
	}
}

func (s *server) projectionFriendsChanged(b *openpakBackend, accountID, otherID string) {
	b.proj.mu.Lock()
	p, other := b.proj.ByAccount[accountID], b.proj.ByAccount[otherID]
	b.proj.mu.Unlock()
	if p == nil {
		return // no Switch identity on this side; nothing to refresh
	}
	if u := s.store.User(p.BaasUserID); u != nil {
		otherBaas := ""
		if other != nil {
			otherBaas = other.BaasUserID
		}
		s.friendGraphChanged(u, otherBaas)
	}
}

func readCursor(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(string(raw), 10, 64)
	return v, err == nil
}

func writeCursor(path string, v uint64) {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(v, 10)), 0o600); err == nil {
		os.Rename(tmp, path)
	}
}
