// SPDX-License-Identifier: AGPL-3.0-only
package main

// Presence from the other side of the account core.
//
// A Switch publishes its presence here and nowhere else, and this adapter puts
// it into the core so the website, the app and every other console's emulator
// can read it. The same is true in reverse: a friend playing on a Wii U is
// live in the core under that platform's namespace, and without this a Switch
// would show them offline. What each platform can say about itself differs --
// one names the title, another only that somebody is signed in -- so this
// renders exactly what the core was told and invents nothing.

import (
	"context"
	"strings"
	"sync"
	"time"

	accountv1 "nx-baas/accountpb"
)

// corePresence is one account's presence as the core holds it.
type corePresence struct {
	Namespace string
	TitleID   string
	Since     int64
	Client    string
}

// corePresenceTTL is how long a lookup is reused. The core's own lease is the
// authority; this only keeps a friend list from asking once per friend per
// render.
const corePresenceTTL = 10 * time.Second

// Freshness is per account: one global timestamp made every friend but the
// first read as offline for ten seconds after any lookup.
type corePresenceCache struct {
	mu   sync.Mutex
	at   map[string]time.Time
	byID map[string]corePresence
}

// coreSeen is per server, not per process: two servers in one test binary do
// not share what the core told one of them.
func (s *server) coreSeen() *corePresenceCache {
	s.coreSeenOnce.Do(func() {
		s.corePresence = &corePresenceCache{at: map[string]time.Time{}, byID: map[string]corePresence{}}
	})
	return s.corePresence
}

// corePresenceOf reports what the core knows about an account, or false when
// it knows nothing (which is the same fact as offline there). A core that is
// unreachable answers "nothing", never a guess.
func (s *server) corePresenceOf(accountID string) (corePresence, bool) {
	b, ok := s.acct.(*openpakBackend)
	if !ok || b == nil || b.sessions == nil || accountID == "" {
		return corePresence{}, false
	}
	cache := s.coreSeen()
	cache.mu.Lock()
	if at, ok := cache.at[accountID]; ok && time.Since(at) < corePresenceTTL {
		p, known := cache.byID[accountID]
		cache.mu.Unlock()
		return p, known
	}
	cache.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := b.sessions.GetPresence(ctx, &accountv1.GetPresenceRequest{AccountIds: []string{accountID}})
	if err != nil {
		logErr("core presence", err)
		return corePresence{}, false
	}
	next := map[string]corePresence{}
	for _, p := range resp.GetPresence() {
		next[p.GetAccountId()] = corePresence{
			Namespace: p.GetNamespace(), TitleID: p.GetTitleId(), Since: p.GetSinceUnix(),
			Client: p.GetClient(),
		}
	}
	cache.mu.Lock()
	// Only the account asked about is refreshed: another friend's absence from
	// this answer means nothing about them.
	for id, p := range next {
		cache.byID[id] = p
	}
	if _, answered := next[accountID]; !answered {
		delete(cache.byID, accountID)
	}
	cache.at[accountID] = time.Now()
	cache.mu.Unlock()
	p, known := next[accountID]
	return p, known
}

// presenceFromCore renders a friend who is live somewhere that is not this
// platform. The title stays empty unless the core's namespace is this one: a
// console can only draw its own titles, and a foreign title id would render as
// a game it does not have.
//
// What a foreign title cannot say in appInfo it says in words: the appField
// carries sys_description, the key a game's SetDescription writes, e.g.
// {"sys_description":"Playing Kirby on Wii U"}. The friend-list parser reads
// any "{...}" appField into the key/value blob GetDescription searches, and
// the absent appInfo keys read as zero [firmware notes §3.1]. Whether the
// system friend list actually shows a description for a friend with no
// title is NOT verified on hardware; NX_FOREIGN_PRESENCE_DESCRIPTION=0 turns
// the text off and leaves the plain ONLINE this served before.
func (s *server) presenceFromCore(accountID, namespace string, now int64) (Presence, bool) {
	p, ok := s.corePresenceOf(accountID)
	if !ok {
		return Presence{}, false
	}
	out := Presence{State: "ONLINE", UpdatedAt: p.Since, ACDIndex: -1, Client: p.Client}
	if out.UpdatedAt == 0 {
		out.UpdatedAt = now
	}
	if strings.EqualFold(p.Namespace, namespace) {
		if p.TitleID != "" {
			out.State, out.AppID, out.PresenceGroupID = "PLAYING", p.TitleID, p.TitleID
		}
		return out, true
	}
	if getenv("NX_FOREIGN_PRESENCE_DESCRIPTION", "1") != "0" {
		out.AppField = descriptionAppField(presenceDescription(clientLabel(p.Namespace, p.Client),
			p.TitleID, siteTitleNames.name(p.Namespace, p.TitleID)))
	}
	return out, true
}
