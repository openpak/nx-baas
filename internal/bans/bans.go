// Package bans refuses an account the core has banned (or is deleting) on every surface this
// adapter serves, each in the error shape its client displays.
//
// The core owns ban state (identity status; set by Moderation.SetAccountBanned, which the
// website's admin pages call). Identity.GetAccount returns it, one indexed read, so that is
// the lookup; the website's /internal/bans/{account_id} would be a second hop to the same
// row. Answers are cached per account for NX_BAN_CACHE_SECONDS (default 30, capped at 60),
// and the core's account_banned/account_unbanned/account_deleted events drop the entry at
// once (openpak_events.go), so a ban or an unban takes effect within the poll interval
// rather than the TTL. A core that cannot be reached fails open with a log line: locking
// every console out because the core blinked is the worse failure.
//
// Native error shapes [firmware, 22.5.0 account module 010000000000001e, the BaaS and NA
// error tables: {u32 result, u16 status, char code[]} and {u32 result, char error[],
// char error_detail[]}]:
//
//	BaaS  403 errorCode banned_user   -> 2124-5110
//	BaaS  404 errorCode deleted_user  -> 2124-5111
//	NA token  error=invalid_grant, error_detail=user_banned|user_deleted
//	NA authorize  error=interaction_required, error_detail=user_banned (redirect)
package bans

import (
	"context"
	"log"
	"net/http"
	"net/url"
	accountv1 "nx-baas/accountpb"
	"nx-baas/internal/core"
	"nx-baas/internal/httpx"
	"nx-baas/internal/store"
	"nx-baas/internal/token"
	"nx-baas/redact"
	"strconv"
	"sync"
	"time"
)

// Lock states. "" is an account in good standing (or one this adapter cannot judge).
const (
	Banned  = "banned"
	Deleted = "deleted"
)

// Source is what the ban check needs from the identity backend: the core account behind
// a pid, and that account's status. identity.OpenpakBackend implements it; the OpenPak backend has
// no bans and does not.
type Source interface {
	AccountFor(pid uint64) string
	AccountStatus(ctx context.Context, accountID string) (accountv1.AccountStatus, error)
}

type entry struct {
	lock string
	at   time.Time
}

type cache struct {
	mu  sync.Mutex
	ttl time.Duration
	by  map[string]entry
}

// TTL is how long an answer is cached: NX_BAN_CACHE_SECONDS, default 30, at most 60.
func TTL() time.Duration {
	n, err := strconv.Atoi(httpx.Getenv("NX_BAN_CACHE_SECONDS", "30"))
	if err != nil || n < 0 {
		n = 30
	}
	return time.Duration(min(n, 60)) * time.Second
}

// cacheOf creates the cache on first use, so a Checker built as a literal works.
func (s *Checker) cacheOf() *cache {
	s.once.Do(func() { s.cache = &cache{ttl: TTL(), by: map[string]entry{}} })
	return s.cache
}

// Checker answers whether an account may use the network.
type Checker struct {
	*core.Core
	// Source is a test stand-in for the core's answer; nil asks the backend.
	Source Source
	once   sync.Once
	cache  *cache
}

// New is the ban check over the shared state.
func New(c *core.Core) *Checker { return &Checker{Core: c} }

// banSrc is the test stand-in when set, else the backend when it can answer.
func (s *Checker) Src() Source {
	if s.Source != nil {
		return s.Source
	}
	if b, ok := s.Acct.(Source); ok {
		return b
	}
	return nil
}

// forgetBan drops a cached answer (the core said something changed).
func (s *Checker) Forget(accountID string) {
	c := s.cacheOf()
	c.mu.Lock()
	delete(c.by, accountID)
	c.mu.Unlock()
}

// accountLock answers "may this core account use the network": "", lockBanned or lockDeleted.
func (s *Checker) AccountLock(accountID string) string {
	src := s.Src()
	if src == nil || accountID == "" {
		return ""
	}
	c := s.cacheOf()
	c.mu.Lock()
	e, ok := c.by[accountID]
	c.mu.Unlock()
	if ok && time.Since(e.at) < c.ttl {
		return e.lock
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := src.AccountStatus(ctx, accountID)
	if err != nil {
		log.Printf("[bans] status of %s unavailable (%v); allowing, last known %q", redact.Tag(accountID), redact.Err(err), e.lock)
		return e.lock // a stale answer beats none; none is "allowed"
	}
	lock := ""
	switch st {
	case accountv1.AccountStatus_ACCOUNT_STATUS_BANNED:
		lock = Banned
	case accountv1.AccountStatus_ACCOUNT_STATUS_DELETION_PENDING, accountv1.AccountStatus_ACCOUNT_STATUS_DELETED:
		lock = Deleted
	}
	c.mu.Lock()
	c.by[accountID] = entry{lock: lock, at: time.Now()}
	c.mu.Unlock()
	if lock != "" {
		log.Printf("[bans] account %s is %s: refusing", redact.Tag(accountID), lock)
	}
	return lock
}

func (s *Checker) PIDLock(pid uint64) string {
	src := s.Src()
	if src == nil || pid == 0 {
		return ""
	}
	return s.AccountLock(src.AccountFor(pid))
}

func (s *Checker) UserLock(u *store.User) string {
	if u == nil {
		return ""
	}
	return s.PIDLock(u.PID)
}

func (s *Checker) NALock(naID string) string {
	if naID == "" || s.Store == nil {
		return ""
	}
	return s.PIDLock(s.Store.PIDForNA(naID))
}

// baasLocked is the BaaS answer (2124-5110 / 2124-5111 on the console).
func BaasLocked(w http.ResponseWriter, r *http.Request, lock string) {
	if lock == Deleted {
		httpx.BaasErr(w, r, 404, "deleted_user", "Deleted User", "This account has been deleted")
		return
	}
	httpx.BaasErr(w, r, 403, "banned_user", "Banned User", "This account is banned from the OpenPak network")
}

// naTokenLocked is the Nintendo Account token endpoint's answer.
func NATokenLocked(w http.ResponseWriter, lock string) {
	detail := "user_banned"
	if lock == Deleted {
		detail = "user_deleted"
	}
	httpx.WriteJSON(w, 400, map[string]any{"error": "invalid_grant", "error_detail": detail,
		"error_description": "this account cannot sign in to the OpenPak network"})
}

// naAuthorizeLocked redirects a silent authorize back to the client with the error pair the
// account module maps (interaction_required / user_banned), in the fragment where the
// successful answer would have carried its code.
func NAAuthorizeLocked(w http.ResponseWriter, r *http.Request, redirectURI, state string) {
	frag := url.Values{"error": {"interaction_required"}, "error_detail": {"user_banned"}, "state": {state}}
	http.Redirect(w, r, redirectURI+"#"+frag.Encode(), http.StatusFound)
}

// internalLocked is the game-API answer: 403, never 401 (platforms/switch/games/switch-nex maps 401 to
// TokenExpired and the console would refresh and retry forever).
func InternalLocked(w http.ResponseWriter, lock string) {
	msg := "account_banned"
	if lock == Deleted {
		msg = "account_deleted"
	}
	httpx.APIErr(w, http.StatusForbidden, msg)
}

// lockedPageMessage is what a person typing their password is told.
func LockedPageMessage(lock string) string {
	if lock == Deleted {
		return "This account has been deleted."
	}
	return "This account is banned from the OpenPak network."
}

// naLockOfToken reads the lock of the account a Nintendo Account id token names.
func (s *Checker) NALockOfToken(idTok string) string {
	c, err := token.ParseJWT(idTok, &s.Key.PublicKey)
	if err != nil {
		return Banned
	}
	if lock := s.NALock(httpx.Str(c, "sub")); lock != "" {
		return lock
	}
	return Banned
}
