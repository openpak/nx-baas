package penne

// penne_deliver.go: the semantic notification submission contract. Callers describe WHAT
// changed and WHO receives it; the core checks the event and its recipient here and hands
// it to nx-penne (penne_link.go), which owns the wire envelope, the delivery policy, the
// outbox and the connections.

import (
	"log"
	"nx-baas/internal/store"
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

var EventKinds = map[string]bool{
	EventPresenceUpdated: true, EventFriendInvitationReceived: true,
	EventFriendRequestReceived: true, EventFriendRequestAuthorized: true,
	EventFriendDeleted: true,
}

// PenneDelivery is one event for one recipient.
type Delivery struct {
	ID        string // stable dedup identity; minted when empty
	UserID    string // recipient BAAS user id
	DeviceID  string // optional target device
	Kind      string // firmware event type string
	Payload   map[string]any
	ExpiresAt time.Time // zero: default TTL
}

// PenneSubmission is what became of a delivery.
type Submission struct {
	Accepted  bool
	Duplicate bool
	Outcome   Outcome
	ID        string
}

// penneOutcome is the submission result nx-penne reports, or the core's own refusal.
type Outcome string

const (
	RejectUser Outcome = "rejected_unknown_recipient"
	NoService  Outcome = "nx_penne_not_configured"
)

// notifier takes a checked delivery: nx-penne (penneRemote) in production.
type Notifier interface {
	Submit(d Delivery, wait bool) Submission
}

// Submit is the core side of a notification: it checks the event and its recipient, then hands
// it to n (nx-penne), waiting for the outcome only when the caller reads it (wait).
func Submit(st *store.Store, n Notifier, d Delivery, wait bool) Submission {
	if !EventKinds[d.Kind] {
		return Submission{Outcome: RejectUser} // not a native event; refuse loudly via outcome
	}
	if st.User(d.UserID) == nil {
		return Submission{Outcome: RejectUser}
	}
	if d.ID == "" {
		d.ID = "ev" + token.RandHex(8)
	}
	if n == nil {
		// Only a server built without main's wiring (a test) gets here: NX_PENNE_URL is
		// required at startup.
		return Submission{Outcome: NoService, ID: d.ID}
	}
	res := n.Submit(d, wait)
	log.Printf("[nx-baas] notify: %s for %s -> %s (id=%s)", d.Kind, redact.Tag(d.UserID), res.Outcome, redact.Tag(d.ID))
	return res
}
