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
	"nx-baas/internal/identity"
	"nx-baas/internal/invitations"
	"nx-baas/internal/penne"
	"time"
)

// SubmitNotification is the entry point the social, presence and invitation code calls.
// Accepted means nx-penne has it (or will, through the ordered queue); the caller never
// retries a submission that returned Accepted.
func (s *server) SubmitNotification(d penne.Delivery) penne.Submission {
	return s.submitNotification(d, false)
}

// submitNotification is SubmitNotification with the choice to wait for nx-penne's outcome.
func (s *server) submitNotification(d penne.Delivery, wait bool) penne.Submission {
	return penne.Submit(s.Store, s.notifier, d, wait)
}

// coreEventKind maps the account core's friend events onto the five event
// kinds the 22.5.0 friends module recognizes. Only these three core events
// carry a native counterpart; presence has its own path below and invitations
// arrive through C's seam.
var coreEventKind = map[string]string{
	"friend_requested": penne.EventFriendRequestReceived,
	"friend_accepted":  penne.EventFriendRequestAuthorized,
	"friend_removed":   penne.EventFriendDeleted,
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
func (s *server) notifyCoreFriendEvent(b *identity.OpenpakBackend, evType, accountID, subjectID string, version uint64) {
	kind := coreEventKind[evType]
	if kind == "" || b == nil || b.Proj == nil {
		return
	}
	b.Proj.Mu.Lock()
	me, other := b.Proj.ByAccount[accountID], b.Proj.ByAccount[subjectID]
	b.Proj.Mu.Unlock()
	if me == nil {
		return // no Switch identity on the receiving side: nothing native to tell
	}
	otherBaas := ""
	if other != nil {
		otherBaas = other.BaasUserID
	}
	payload := map[string]any{"friendId": otherBaas}
	if kind == penne.EventFriendRequestReceived && other != nil {
		// The console's received parser fails the whole event without
		// $.value.channels[0]; nothing else in the body is read
		// [friends-notifications-firmware-2026-09-19.md §2.2]. The channel
		// is the one the request was sent with when this server saw the
		// send, FRIEND_CODE otherwise (the add-by-code common case).
		ch := s.Store.RequestChannel(other.PID, me.PID)
		if ch == "" {
			ch = "FRIEND_CODE"
		}
		payload["value"] = map[string]any{"channels": []string{ch}}
	}
	s.SubmitNotification(penne.Delivery{
		ID:      fmt.Sprintf("core:%d", version),
		UserID:  me.BaasUserID,
		Kind:    kind,
		Payload: payload,
	})
}

// ---------- presence fan-out (PRE-03 visibility, NTF-04 presence_updated) ----------

// ---------- invitations (C's seam) ----------

// wireInvitationNotifications connects C's committed-invitation event to B's
// delivery. C calls its hook strictly after the store write returns, so an
// accepted submission here can never promise an inbox row that does not exist.
//
// The payload nests the invitation under $.invitation because those are the
// parser paths C recorded as firmware-confirmed: $.type and
// $.invitation.{id, sender_id, application_id, invitation_group_id}.
func (s *server) wireInvitationNotifications() {
	invitations.NotifyHook = func(ev invitations.Event) {
		s.SubmitNotification(penne.Delivery{
			ID:     ev.EventID, // "invitation:<id>", already stable across retries
			UserID: ev.ReceiverID,
			Kind:   penne.EventFriendInvitationReceived,
			Payload: map[string]any{
				// id and invitation_group_id are JSON integers: the event parser
				// type-checks them and drops the whole event on a string
				// [firmware, 0x1a9870; docs/switch/friend-invitations-firmware-2026-09-19.md §1a].
				"invitation": map[string]any{
					"id":                  invitations.JSONUint(ev.InvitationID),
					"sender_id":           ev.SenderID,
					"application_id":      ev.ApplicationID,
					"invitation_group_id": invitations.JSONUint(ev.GroupID),
				},
				"unread_count": ev.UnreadCount,
				// Read by the invitation event's numeric parser beside the
				// invitation itself [firmware, 0xa9870].
				"created_at": time.Now().Unix(),
			},
		})
	}
}
