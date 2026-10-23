package presence

import (
	"fmt"
	"nx-baas/internal/httpx"
	"nx-baas/internal/penne"
	"nx-baas/internal/store"
	"strconv"
	"strings"
	"sync"
	"time"
)

// presenceSnapshot renders an account's current aggregate as a comparable
// string. Presence is written on every heartbeat, but only a *change* is worth
// an event: comparing this before and after a mutation is what keeps a renewal
// from becoming a notification storm.
func (s *Service) Snapshot(userID string) string {
	u := s.Store.User(userID)
	if u == nil {
		return ""
	}
	p := Aggregate(u, time.Now().Unix(), Lease())
	// appField is part of it: a new room changes only appField, and a friend
	// has to hear about it.
	return p.State + "|" + p.AppID + "|" + p.AppField
}

// notifyPresenceIfChanged fans a new aggregate presence out to the friends
// allowed to see it, when it actually changed.
//
// Visibility is A's presenceVisible -- relationship, directional blocks and
// the subject's presence permission -- applied per recipient at submit time,
// and B revalidates policy again at dispatch. The per-friend online-alert
// preference is deliberately *not* consulted here: PRE-04 keeps state
// synchronization separate from toast eligibility, and B's default policy is
// where the alert half is gated.
func (s *Service) NotifyIfChanged(userID, before string) {
	// notifStore() creates the outbox lazily, so this must not gate on
	// s.penneState: an adapter that has not taken a connection yet still
	// records what a reconnecting console has to be told.
	if s.Acct == nil || s.Store == nil || userID == "" {
		return
	}
	after := s.Snapshot(userID)
	if after == "" || after == before {
		return
	}
	u := s.Store.User(userID)
	if u == nil || u.PID == 0 {
		return
	}
	id, err := s.Acct.Identity(u.PID)
	if err != nil || id == nil {
		return
	}
	now := time.Now().Unix()
	agg := HomeAsOnline(Aggregate(u, now, Lease()))
	for _, f := range id.Friends {
		viewer := s.Store.User(f.BaasUserID)
		if viewer == nil || !Visible(viewer, u, true) {
			continue
		}
		// One id per (subject, viewer, change): createdAt is strictly
		// increasing per pair (nextPresenceStamp), so a state that comes back
		// inside the same second (INACTIVE, PLAYING, INACTIVE) is a new event
		// rather than a duplicate of the first, and a newer state coalesces
		// over a pending older one inside B's outbox.
		createdAt := NextStamp(u.ID, viewer.ID, agg.UpdatedAt)
		s.Notify(penne.Delivery{
			ID:     fmt.Sprintf("presence:%s:%s:%d:%s", u.ID, viewer.ID, createdAt, after),
			UserID: viewer.ID,
			Kind:   penne.EventPresenceUpdated,
			// The parser's own paths, recovered from the module: the presence
			// nests under $.value with the friend's id inside it, and the
			// event's own timestamp is $.createdAt (camelCase here, while an
			// invitation event uses $.created_at — each follows its own REST
			// surface). Numbers stay numbers: pf and acdIndex are read as
			// bytes, the timestamps as 64-bit
			// [firmware, friends module 0xa7510].
			Payload: map[string]any{
				"friendId":  u.ID, // kept: our own surfaces read it
				"createdAt": createdAt,
				"value":     EventValue(u.ID, agg),
			},
		})
	}
}

// presenceEventValue is the presence a presence_updated event carries: the same fields the friend
// list carries, so a cached friend does not change shape between the two.
func EventValue(userID string, agg store.Presence) map[string]any {
	v := map[string]any{
		"userId":    userID,
		"state":     agg.State,
		"updatedAt": agg.UpdatedAt,
		"logoutAt":  agg.LogoutAt,
		"extras":    map[string]any{"friends": EventExtras(agg)},
	}
	if pf, ok := ProbePF(agg.Client); ok { // the probe, see testPF
		v["pf"] = pf
	}
	return v
}

// presenceEventExtras renders the app fields a presence event carries, with the
// types the console publishes them in: the ids as quoted 16-hex strings, the
// catalog index as a number (docs/switch/firmware-22.5.0-followup-2026-09-12.md §15).
//
// appField, appInfo:appId and appInfo:presenceGroupId are all required. The
// event parser keeps a field mask and, at the end of the document, fails the
// whole presence_updated unless userId, state, appId, presenceGroupId,
// appField, updatedAt, logoutAt and $.createdAt all arrived (mask 0x3eb; only
// pf and acdIndex are optional) [firmware: friends 22.5.0 0x1a74a0, 23.0.1
// 0x1aaea0; docs/switch/friends-presence-firmware-2026-09-19.md §6]. So "no
// game" is the all-zero id, exactly as the console publishes it from HOME
// ("%016llx" of 0), never an absent key: until 2026-10-10 every INACTIVE,
// OFFLINE and title-less ONLINE event was dropped by the console, which then
// never saw a friend leave and so never saw them come back.
func EventExtras(p store.Presence) map[string]any {
	// appField is a JSON-object string: "" fails the parse too [firmware, 0x1a7670].
	out := map[string]any{
		"appField":                AppFieldOrEmpty(p.AppField),
		"appInfo:appId":           HexIDOrZero(p.AppID),
		"appInfo:presenceGroupId": HexIDOrZero(p.PresenceGroupID),
	}
	if p.ACDIndex >= 0 {
		out["appInfo:acdIndex"] = p.ACDIndex
	}
	return out
}

// hexIDOrZero is a title id as the console writes one, "0000000000000000" for none.
func HexIDOrZero(id string) string {
	if id == "" {
		return "0000000000000000"
	}
	return id
}

// presenceStamps hands out each (friend, viewer) pair's $.createdAt. The friends
// module applies a presence_updated only when its createdAt is later than the
// time it already holds for that friend, and that time is the previous event's
// value.updatedAt (value.logoutAt for an offline one) [firmware: friends 22.5.0
// 0x191790, 23.0.1 0x1950d0]. Two changes inside one wall-clock second (going
// INACTIVE right after signing in, PLAYING to ONLINE as a session closes) would
// otherwise leave the second unapplied and the console showing the first for
// as long as nothing else changes. Strictly increasing per pair, starting from
// the state change's own second.
var presenceStamps = struct {
	sync.Mutex
	last map[string]int64
}{last: map[string]int64{}}

func NextStamp(subjectID, viewerID string, at int64) int64 {
	presenceStamps.Lock()
	defer presenceStamps.Unlock()
	key := subjectID + "|" + viewerID
	if prev := presenceStamps.last[key]; at <= prev {
		at = prev + 1
	}
	presenceStamps.last[key] = at
	return at
}

// appFieldOrEmpty is the value a console accepts for "nothing published".
func AppFieldOrEmpty(f string) string {
	if f == "" {
		return "{}"
	}
	return f
}

// testPF is a probe, not a feature: NX_PF_TEST="switch=1,harbor=2" gives a client's presence a `pf`
// (a one-byte enum the friends module stores per friend and the friend's page may draw as
// "Online (<platform>)"). Its value space is unknown and only a capture settles it, so this
// sends nothing unless asked and only small numbers. Remove with the experiment.
func ProbePF(client string) (int, bool) {
	if client == "" {
		client = "switch"
	}
	for _, kv := range strings.Split(httpx.Getenv("NX_PF_TEST", ""), ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && strings.EqualFold(k, client) {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 3 {
				return n, true
			}
		}
	}
	return 0, false
}
