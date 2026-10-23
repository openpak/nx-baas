package main

// penne_deliver.go: the semantic notification submission contract. Callers describe WHAT
// changed and WHO receives it; the core checks the event and its recipient here and hands
// it to nx-penne (penne_link.go), which owns the wire envelope, the delivery policy, the
// outbox and the connections.

import (
	"log"
	"nx-baas/internal/token"
	"nx-baas/redact"
	"time"
)

// The five event type strings the 22.5.0 friends module's dispatcher
// recognizes (firmware-confirmed). Anything else is not a native event.
const (
	EventPresenceUpdated          = "presence_updated"
	EventFriendInvitationReceived = "friend_invitation_received"
	EventFriendRequestReceived    = "friend_request_received"
	EventFriendRequestAuthorized  = "friend_request_authorized"
	EventFriendDeleted            = "friend_deleted"
)

var eventKinds = map[string]bool{
	EventPresenceUpdated: true, EventFriendInvitationReceived: true,
	EventFriendRequestReceived: true, EventFriendRequestAuthorized: true,
	EventFriendDeleted: true,
}

// PenneDelivery is one event for one recipient.
type PenneDelivery struct {
	ID        string // stable dedup identity; minted when empty
	UserID    string // recipient BAAS user id
	DeviceID  string // optional target device
	Kind      string // firmware event type string
	Payload   map[string]any
	ExpiresAt time.Time // zero: default TTL
}

// PenneSubmission is what became of a delivery.
type PenneSubmission struct {
	Accepted  bool
	Duplicate bool
	Outcome   penneOutcome
	ID        string
}

// penneOutcome is the submission result nx-penne reports, or the core's own refusal.
type penneOutcome string

const (
	penneRejectUser penneOutcome = "rejected_unknown_recipient"
	penneNoService  penneOutcome = "nx_penne_not_configured"
)

// notifier takes a checked delivery: nx-penne (penneRemote) in production.
type notifier interface {
	submit(d PenneDelivery, wait bool) PenneSubmission
}

// SubmitNotification is the entry point the social, presence and invitation code calls.
// Accepted means nx-penne has it (or will, through the ordered queue); the caller never
// retries a submission that returned Accepted.
func (s *server) SubmitNotification(d PenneDelivery) PenneSubmission {
	return s.submitNotification(d, false)
}

// submitNotification is SubmitNotification; the core checks the event and its recipient,
// then hands it to nx-penne, waiting for the outcome only when the caller reads it (wait).
func (s *server) submitNotification(d PenneDelivery, wait bool) PenneSubmission {
	if !eventKinds[d.Kind] {
		return PenneSubmission{Outcome: penneRejectUser} // not a native event; refuse loudly via outcome
	}
	if s.Store.User(d.UserID) == nil {
		return PenneSubmission{Outcome: penneRejectUser}
	}
	if d.ID == "" {
		d.ID = "ev" + token.RandHex(8)
	}
	n := s.notifier
	if n == nil {
		// Only a server built without main's wiring (a test) gets here: NX_PENNE_URL is
		// required at startup.
		return PenneSubmission{Outcome: penneNoService, ID: d.ID}
	}
	res := n.submit(d, wait)
	log.Printf("[nx-baas] notify: %s for %s -> %s (id=%s)", d.Kind, redact.Tag(d.UserID), res.Outcome, redact.Tag(d.ID))
	return res
}
