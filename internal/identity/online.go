package identity

import (
	"context"
	"log"
	accountv1 "github.com/openpak/account-api/openpak/account/v1"
	"nx-baas/redact"
	"sync/atomic"
	"time"
)

// GoAsync runs the core call off the login's path; tests make it synchronous.
var GoAsync = func(f func()) { go f() }

// markOnlineLastLog is the unix second of the last logged failure (at most one a minute).
var markOnlineLastLog atomic.Int64

// markOnline never slows or fails a login: it runs on its own goroutine with a short timeout,
// and a core that cannot be reached costs a log line a minute and some playtime.
func (b *OpenpakBackend) MarkOnline(pid uint64) {
	if b == nil || b.Sessions == nil {
		return
	}
	accountID := b.AccountFor(pid)
	if accountID == "" {
		return
	}
	sessions, ns := b.Sessions, b.Namespace
	GoAsync(func() {
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
