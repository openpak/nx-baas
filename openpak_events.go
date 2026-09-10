package main

import (
	"context"
	"log"
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
		// Start at the head: replaying history would only re-fetch lists that are already right.
		if page, err := events.PollEvents(context.Background(), &accountv1.PollEventsRequest{SinceVersion: 1<<62 - 1, Limit: 1}); err == nil {
			version = page.GetMaxVersion()
			writeCursor(cursorPath, version)
		}
	}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		page, err := events.PollEvents(ctx, &accountv1.PollEventsRequest{SinceVersion: version, Limit: 500})
		cancel()
		if err != nil {
			log.Printf("[nx-baas] core events: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		for _, e := range page.GetEvents() {
			switch e.GetType() {
			case "friend_requested", "friend_accepted", "friend_removed":
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
