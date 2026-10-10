package main

// Playtime on openpak.org counts only time a game server confirmed the player online, and the
// confirmation is the login itself: when a game server asks who a player is and gets an answer,
// that player is on it. Each successful identity lookup therefore tells the core's MarkOnline,
// which starts the playtime clock on the player's live titled Switch session (a player with no
// such session is a no-op there).

import (
	"context"
	"log"
	"nx-baas/redact"
	"sync/atomic"
	"time"

	accountv1 "nx-baas/accountpb"
)

// onlineMarker is the backend's side: the openpak backend reaches the core; a stub records.
type onlineMarker interface {
	markOnline(pid uint64)
}

// markLoginOnline is called after a game server's identity lookup succeeded.
func (s *server) markLoginOnline(pid uint64) {
	if m, ok := s.acct.(onlineMarker); ok && pid != 0 {
		m.markOnline(pid)
	}
}

// goAsync runs the core call off the login's path; tests make it synchronous.
var goAsync = func(f func()) { go f() }

// markOnlineLastLog is the unix second of the last logged failure (at most one a minute).
var markOnlineLastLog atomic.Int64

// markOnline never slows or fails a login: it runs on its own goroutine with a short timeout,
// and a core that cannot be reached costs a log line a minute and some playtime.
func (b *openpakBackend) markOnline(pid uint64) {
	if b == nil || b.sessions == nil {
		return
	}
	accountID := b.accountFor(pid)
	if accountID == "" {
		return
	}
	sessions, ns := b.sessions, b.namespace
	goAsync(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := sessions.MarkOnline(ctx, &accountv1.MarkOnlineRequest{Players: []*accountv1.OnlinePlayer{
			{AccountId: accountID, Namespace: ns},
		}})
		if err == nil {
			return
		}
		now := time.Now().Unix()
		if last := markOnlineLastLog.Load(); now-last >= 60 && markOnlineLastLog.CompareAndSwap(last, now) {
			log.Printf("[nx-baas] mark online (logged at most once a minute): %v", redact.Err(err))
		}
	})
}
