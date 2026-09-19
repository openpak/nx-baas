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
	s.SubmitNotification(PenneDelivery{
		ID:      fmt.Sprintf("core:%d", version),
		UserID:  me.BaasUserID,
		Kind:    kind,
		Payload: map[string]any{"friendId": otherBaas},
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
	agg := aggregatePresence(u, now, presenceLease())
	for _, f := range id.Friends {
		viewer := s.store.User(f.BaasUserID)
		if viewer == nil || !presenceVisible(viewer, u, true) {
			continue
		}
		// One id per (subject, viewer, state). The state belongs in the id,
		// not just the timestamp: going online and starting a title inside
		// the same wall-clock second are two different things to be told, and
		// a second-granular id alone would dedup the second one away. Two
		// submissions of the *same* state stay idempotent, and a newer state
		// coalesces over a pending older one inside B's outbox.
		s.SubmitNotification(PenneDelivery{
			ID:     fmt.Sprintf("presence:%s:%s:%d:%s", u.ID, viewer.ID, agg.UpdatedAt, after),
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
				"createdAt": agg.UpdatedAt,
				"value": map[string]any{
					"userId":    u.ID,
					"state":     agg.State,
					"updatedAt": agg.UpdatedAt,
					"logoutAt":  agg.LogoutAt,
					"extras":    map[string]any{"friends": presenceEventExtras(agg)},
				},
			},
		})
	}
}

// presenceEventExtras renders the app fields a presence event carries, with the
// types the console publishes them in: the ids as quoted 16-hex strings, the
// catalog index as a number, and nothing at all when the console published
// nothing (docs/switch/firmware-22.5.0-followup-2026-09-12.md §15).
func presenceEventExtras(p Presence) map[string]any {
	// appField is always a JSON-object string: the event parser drops the
	// whole presence_updated on "" or a missing one [firmware, 0x1a7670].
	out := map[string]any{"appField": appFieldOrEmpty(p.AppField)}
	if p.AppID != "" {
		out["appInfo:appId"] = p.AppID
	}
	if p.PresenceGroupID != "" {
		out["appInfo:presenceGroupId"] = p.PresenceGroupID
	}
	if p.ACDIndex >= 0 {
		out["appInfo:acdIndex"] = p.ACDIndex
	}
	return out
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
