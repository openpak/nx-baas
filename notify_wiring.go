// SPDX-License-Identifier: AGPL-3.0-only
package main

// Integration wiring for the combined native-Switch branch.
//
// The coordination plan split ownership deliberately: A owns the single core-
// event poller and the presence model, C owns invitation state, B owns wire
// delivery. Each workstream published its half of the contract and stopped at
// the boundary, because landing the call between them means touching another
// workstream's file. This file is that call and nothing else -- no new policy,
// no second poller, no competing state. Every recipient decision here is the
// core's or A's; every delivery decision below SubmitNotification is B's.
//
// What is still NOT claimed by this wiring: that a console parses these
// events. The outbound envelope remains the marked hypothesis in
// docs/penne-protocol.md §4. This makes the pipeline real end to end on the
// server side; the native gate stays open until the capture run.

import (
	"fmt"
	"nx-baas/internal/store"
	"sync"
	"time"
)

// coreEventKind maps the account core's friend events onto the five event
// kinds the 22.5.0 friends module recognizes. Only these three core events
// carry a native counterpart; presence has its own path below and invitations
// arrive through C's seam.
var coreEventKind = map[string]string{
	"friend_requested": EventFriendRequestReceived,
	"friend_accepted":  EventFriendRequestAuthorized,
	"friend_removed":   EventFriendDeleted,
}

// notifyCoreFriendEvent submits one native notification for one core friend
// event.
//
// The recipient mapping is the core's own, not a guess made here: the core
// addresses each event at the account that needs to hear about it (AccountId)
// and names the counterparty as the subject (SubjectId) -- "the addressee is
// who needs to hear about this, so they are the event's account". A removal is
// emitted once per side, so both consoles are told without this code inventing
// a second recipient.
//
// The core event version is already unique and monotonic, so it is the dedup
// identity. A poll page reprocessed after a crash resubmits the same ids and
// B's outbox recognizes them, which is what keeps A's at-least-once cursor
// safe against duplicate user-visible alerts (NTF-05).
func (s *server) notifyCoreFriendEvent(b *openpakBackend, evType, accountID, subjectID string, version uint64) {
	kind := coreEventKind[evType]
	if kind == "" || b == nil || b.proj == nil {
		return
	}
	b.proj.mu.Lock()
	me, other := b.proj.ByAccount[accountID], b.proj.ByAccount[subjectID]
	b.proj.mu.Unlock()
	if me == nil {
		return // no Switch identity on the receiving side: nothing native to tell
	}
	otherBaas := ""
	if other != nil {
		otherBaas = other.BaasUserID
	}
	payload := map[string]any{"friendId": otherBaas}
	if kind == EventFriendRequestReceived && other != nil {
		// The console's received parser fails the whole event without
		// $.value.channels[0]; nothing else in the body is read
		// [friends-notifications-firmware-2026-09-19.md §2.2]. The channel
		// is the one the request was sent with when this server saw the
		// send, FRIEND_CODE otherwise (the add-by-code common case).
		ch := s.store.RequestChannel(other.PID, me.PID)
		if ch == "" {
			ch = "FRIEND_CODE"
		}
		payload["value"] = map[string]any{"channels": []string{ch}}
	}
	s.SubmitNotification(PenneDelivery{
		ID:      fmt.Sprintf("core:%d", version),
		UserID:  me.BaasUserID,
		Kind:    kind,
		Payload: payload,
	})
}

// ---------- presence fan-out (PRE-03 visibility, NTF-04 presence_updated) ----------

// presenceSnapshot renders an account's current aggregate as a comparable
// string. Presence is written on every heartbeat, but only a *change* is worth
// an event: comparing this before and after a mutation is what keeps a renewal
// from becoming a notification storm.
func (s *server) presenceSnapshot(userID string) string {
	u := s.store.User(userID)
	if u == nil {
		return ""
	}
	p := aggregatePresence(u, time.Now().Unix(), presenceLease())
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
func (s *server) notifyPresenceIfChanged(userID, before string) {
	// notifStore() creates the outbox lazily, so this must not gate on
	// s.penneState: an adapter that has not taken a connection yet still
	// records what a reconnecting console has to be told.
	if s.acct == nil || s.store == nil || userID == "" {
		return
	}
	after := s.presenceSnapshot(userID)
	if after == "" || after == before {
		return
	}
	u := s.store.User(userID)
	if u == nil || u.PID == 0 {
		return
	}
	id, err := s.acct.Identity(u.PID)
	if err != nil || id == nil {
		return
	}
	now := time.Now().Unix()
	agg := homeAsOnline(aggregatePresence(u, now, presenceLease()))
	for _, f := range id.Friends {
		viewer := s.store.User(f.BaasUserID)
		if viewer == nil || !presenceVisible(viewer, u, true) {
			continue
		}
		// One id per (subject, viewer, change): createdAt is strictly
		// increasing per pair (nextPresenceStamp), so a state that comes back
		// inside the same second (INACTIVE, PLAYING, INACTIVE) is a new event
		// rather than a duplicate of the first, and a newer state coalesces
		// over a pending older one inside B's outbox.
		createdAt := nextPresenceStamp(u.ID, viewer.ID, agg.UpdatedAt)
		s.SubmitNotification(PenneDelivery{
			ID:     fmt.Sprintf("presence:%s:%s:%d:%s", u.ID, viewer.ID, createdAt, after),
			UserID: viewer.ID,
			Kind:   EventPresenceUpdated,
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
				"value":     presenceEventValue(u.ID, agg),
			},
		})
	}
}

// presenceEventValue is the presence a presence_updated event carries: the same fields the friend
// list carries, so a cached friend does not change shape between the two.
func presenceEventValue(userID string, agg store.Presence) map[string]any {
	v := map[string]any{
		"userId":    userID,
		"state":     agg.State,
		"updatedAt": agg.UpdatedAt,
		"logoutAt":  agg.LogoutAt,
		"extras":    map[string]any{"friends": presenceEventExtras(agg)},
	}
	if pf, ok := testPF(agg.Client); ok { // the probe, see testPF
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
func presenceEventExtras(p store.Presence) map[string]any {
	// appField is a JSON-object string: "" fails the parse too [firmware, 0x1a7670].
	out := map[string]any{
		"appField":                appFieldOrEmpty(p.AppField),
		"appInfo:appId":           hexIDOrZero(p.AppID),
		"appInfo:presenceGroupId": hexIDOrZero(p.PresenceGroupID),
	}
	if p.ACDIndex >= 0 {
		out["appInfo:acdIndex"] = p.ACDIndex
	}
	return out
}

// hexIDOrZero is a title id as the console writes one, "0000000000000000" for none.
func hexIDOrZero(id string) string {
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

func nextPresenceStamp(subjectID, viewerID string, at int64) int64 {
	presenceStamps.Lock()
	defer presenceStamps.Unlock()
	key := subjectID + "|" + viewerID
	if prev := presenceStamps.last[key]; at <= prev {
		at = prev + 1
	}
	presenceStamps.last[key] = at
	return at
}

// ---------- invitations (C's seam) ----------

// wireInvitationNotifications connects C's committed-invitation event to B's
// delivery. C calls its hook strictly after the store write returns, so an
// accepted submission here can never promise an inbox row that does not exist.
//
// The payload nests the invitation under $.invitation because those are the
// parser paths C recorded as firmware-confirmed: $.type and
// $.invitation.{id, sender_id, application_id, invitation_group_id}.
func (s *server) wireInvitationNotifications() {
	invitationNotify = func(ev InvitationEvent) {
		s.SubmitNotification(PenneDelivery{
			ID:     ev.EventID, // "invitation:<id>", already stable across retries
			UserID: ev.ReceiverID,
			Kind:   EventFriendInvitationReceived,
			Payload: map[string]any{
				// id and invitation_group_id are JSON integers: the event parser
				// type-checks them and drops the whole event on a string
				// [firmware, 0x1a9870; docs/switch/friend-invitations-firmware-2026-09-19.md §1a].
				"invitation": map[string]any{
					"id":                  jsonUint(ev.InvitationID),
					"sender_id":           ev.SenderID,
					"application_id":      ev.ApplicationID,
					"invitation_group_id": jsonUint(ev.GroupID),
				},
				"unread_count": ev.UnreadCount,
				// Read by the invitation event's numeric parser beside the
				// invitation itself [firmware, 0xa9870].
				"created_at": time.Now().Unix(),
			},
		})
	}
}

// appFieldOrEmpty is the value a console accepts for "nothing published".
func appFieldOrEmpty(f string) string {
	if f == "" {
		return "{}"
	}
	return f
}
