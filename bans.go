package main

// Bans everywhere: an account the core has banned (or is deleting) is refused on every
// surface this adapter serves, each in the error shape its client displays.
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

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"nx-baas/redact"
	"strconv"
	"sync"
	"time"

	accountv1 "nx-baas/accountpb"
)

// Lock states. "" is an account in good standing (or one this adapter cannot judge).
const (
	lockBanned  = "banned"
	lockDeleted = "deleted"
)

var errAccountLocked = errors.New("account is banned or deleted")

// banSource is what the ban check needs from the identity backend: the core account behind
// a pid, and that account's status. openpakBackend implements it; the OpenPak backend has
// no bans and does not.
type banSource interface {
	accountFor(pid uint64) string
	accountStatus(ctx context.Context, accountID string) (accountv1.AccountStatus, error)
}

func (b *openpakBackend) accountStatus(ctx context.Context, accountID string) (accountv1.AccountStatus, error) {
	res, err := b.identity.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: accountID})
	if err != nil {
		return accountv1.AccountStatus_ACCOUNT_STATUS_UNSPECIFIED, err
	}
	return res.GetStatus(), nil
}

type banEntry struct {
	lock string
	at   time.Time
}

type banCache struct {
	mu  sync.Mutex
	ttl time.Duration
	by  map[string]banEntry
}

func banTTL() time.Duration {
	n, err := strconv.Atoi(getenv("NX_BAN_CACHE_SECONDS", "30"))
	if err != nil || n < 0 {
		n = 30
	}
	return time.Duration(min(n, 60)) * time.Second
}

// banCache is created on first use so test servers built as literals work unchanged.
func (s *server) banCache() *banCache {
	s.bansOnce.Do(func() { s.bans = &banCache{ttl: banTTL(), by: map[string]banEntry{}} })
	return s.bans
}

// banSrc is the test stand-in when set, else the backend when it can answer.
func (s *server) banSrc() banSource {
	if s.banSource != nil {
		return s.banSource
	}
	if b, ok := s.acct.(banSource); ok {
		return b
	}
	return nil
}

// forgetBan drops a cached answer (the core said something changed).
func (s *server) forgetBan(accountID string) {
	c := s.banCache()
	c.mu.Lock()
	delete(c.by, accountID)
	c.mu.Unlock()
}

// accountLock answers "may this core account use the network": "", lockBanned or lockDeleted.
func (s *server) accountLock(accountID string) string {
	src := s.banSrc()
	if src == nil || accountID == "" {
		return ""
	}
	c := s.banCache()
	c.mu.Lock()
	e, ok := c.by[accountID]
	c.mu.Unlock()
	if ok && time.Since(e.at) < c.ttl {
		return e.lock
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := src.accountStatus(ctx, accountID)
	if err != nil {
		log.Printf("[bans] status of %s unavailable (%v); allowing, last known %q", redact.Tag(accountID), redact.Err(err), e.lock)
		return e.lock // a stale answer beats none; none is "allowed"
	}
	lock := ""
	switch st {
	case accountv1.AccountStatus_ACCOUNT_STATUS_BANNED:
		lock = lockBanned
	case accountv1.AccountStatus_ACCOUNT_STATUS_DELETION_PENDING, accountv1.AccountStatus_ACCOUNT_STATUS_DELETED:
		lock = lockDeleted
	}
	c.mu.Lock()
	c.by[accountID] = banEntry{lock: lock, at: time.Now()}
	c.mu.Unlock()
	if lock != "" {
		log.Printf("[bans] account %s is %s: refusing", redact.Tag(accountID), lock)
	}
	return lock
}

func (s *server) pidLock(pid uint64) string {
	src := s.banSrc()
	if src == nil || pid == 0 {
		return ""
	}
	return s.accountLock(src.accountFor(pid))
}

func (s *server) userLock(u *User) string {
	if u == nil {
		return ""
	}
	return s.pidLock(u.PID)
}

func (s *server) naLock(naID string) string {
	if naID == "" || s.store == nil {
		return ""
	}
	return s.pidLock(s.store.PIDForNA(naID))
}

// ---------- the refusals, one per surface ----------

// baasLocked is the BaaS answer (2124-5110 / 2124-5111 on the console).
func baasLocked(w http.ResponseWriter, r *http.Request, lock string) {
	if lock == lockDeleted {
		baasErr(w, r, 404, "deleted_user", "Deleted User", "This account has been deleted")
		return
	}
	baasErr(w, r, 403, "banned_user", "Banned User", "This account is banned from the OpenPak network")
}

// naTokenLocked is the Nintendo Account token endpoint's answer.
func naTokenLocked(w http.ResponseWriter, lock string) {
	detail := "user_banned"
	if lock == lockDeleted {
		detail = "user_deleted"
	}
	writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_detail": detail,
		"error_description": "this account cannot sign in to the OpenPak network"})
}

// naAuthorizeLocked redirects a silent authorize back to the client with the error pair the
// account module maps (interaction_required / user_banned), in the fragment where the
// successful answer would have carried its code.
func naAuthorizeLocked(w http.ResponseWriter, r *http.Request, redirectURI, state string) {
	frag := url.Values{"error": {"interaction_required"}, "error_detail": {"user_banned"}, "state": {state}}
	http.Redirect(w, r, redirectURI+"#"+frag.Encode(), http.StatusFound)
}

// internalLocked is the game-API answer: 403, never 401 (platforms/switch/games/switch-nex maps 401 to
// TokenExpired and the console would refresh and retry forever).
func internalLocked(w http.ResponseWriter, lock string) {
	msg := "account_banned"
	if lock == lockDeleted {
		msg = "account_deleted"
	}
	apiErr(w, http.StatusForbidden, msg)
}

// lockedPageMessage is what a person typing their password is told.
func lockedPageMessage(lock string) string {
	if lock == lockDeleted {
		return "This account has been deleted."
	}
	return "This account is banned from the OpenPak network."
}

// naLockOfToken reads the lock of the account a Nintendo Account id token names.
func (s *server) naLockOfToken(idTok string) string {
	c, err := parseJWT(idTok, &s.key.PublicKey)
	if err != nil {
		return lockBanned
	}
	if lock := s.naLock(str(c, "sub")); lock != "" {
		return lock
	}
	return lockBanned
}

// closeAccountSessions ends every live Penne connection of a core account; the console's
// reconnect then meets the frontline's ban check.
func (s *server) closeAccountSessions(b *openpakBackend, accountID string) {
	b.proj.mu.Lock()
	pr := b.proj.ByAccount[accountID]
	b.proj.mu.Unlock()
	if pr == nil {
		return
	}
	s.penneCloseUser(pr.BaasUserID)
}

// closeUser cancels a BAAS user's live frontline sessions and reports how many.
func (h *penneHub) closeUser(user string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sess := range h.sessions[user] {
		sess.cancel()
	}
	return len(h.sessions[user])
}
