package main

// Presence the console publishes, rather than presence we infer.
//
// A Switch never PATCHes `/1.0.0/users/<id>/device_accounts/<id>` — in this
// network's entire history not one console has, and the REST presence path is
// exercised only by emulators. What a console does instead is push a
// **DAPresence** frame up the Penne connection every 20-60 seconds, and until
// now this server logged it as "no evidence-backed answer" and dropped it. So
// presence for a real console has never existed, not because the console
// withheld it, but because we were not listening.
//
// The frame, decoded from a live console [runtime capture, 2026-09-12]:
//
//	DAPresence (type 27)
//	  0: string  device account id   "cccccccccccc0001"
//	  1: string  BAAS user id        "aaaaaaaaaaaa0001"
//	  2: table
//	       0: u8      state (1 = online)
//	       1: string  the extras document, the same shape this server serves
//	       2: u8      flags
//
// Two details worth keeping. The user it names is **not** necessarily the
// account the connection is bound to: one console publishes presence for each
// of its signed-in profiles over its single connection, which is the same
// multi-account shape the delivery side still has to grow. And the title lives
// in the extras document, not in a field of its own.

import (
	"encoding/json"
	"log"
	"strings"

	"nx-baas/internal/penne"
)

// penneNotePresence folds a DAPresence frame into the presence store. It
// returns false when the frame is not one we can read, so the caller can keep
// counting it as unparsed rather than pretending.
func (s *server) penneNotePresence(p penne.Table) bool {
	device, _ := p.String(0)
	userID, _ := p.String(1)
	inner, ok := p.Table(2)
	if !ok || userID == "" {
		return false
	}
	live, _ := inner.U8(0)
	doc, _ := inner.String(1)

	u := s.store.User(userID)
	if u == nil {
		log.Printf("[nx-baas] penne: presence for unknown user %s; ignored", userID)
		return false
	}

	state, appID, appField, groupID, acdIndex := presenceFromExtras(doc, live != 0)
	s.noteDevicePresence(u, device, state, appID, appField, groupID, acdIndex)
	log.Printf("[nx-baas] penne: presence user=%s device=%s %s app=%s", userID, device, state, appID)
	return true
}

// presenceFromExtras reads the console's own extras document. The console
// publishes the same shape this server serves back to it, so the field names
// are already known [firmware, friends module 0xa7510].
func presenceFromExtras(doc string, live bool) (state, appID, appField, groupID string, acdIndex int) {
	acdIndex = -1
	state = "OFFLINE"
	if live {
		state = "ONLINE"
	}
	var extras struct {
		Friends struct {
			AppField string          `json:"appField"`
			AppID    string          `json:"appInfo:appId"`
			ACDIndex *int            `json:"appInfo:acdIndex"`
			GroupID  string          `json:"appInfo:presenceGroupId"`
			Raw      json.RawMessage `json:"-"`
		} `json:"friends"`
	}
	if doc == "" || json.Unmarshal([]byte(doc), &extras) != nil {
		return state, "", "", "", acdIndex
	}
	f := extras.Friends
	// An all-zero title id is "not in a game", not a game whose id is zero.
	if f.AppID != "" && strings.Trim(f.AppID, "0") != "" {
		appID = f.AppID
		if live {
			state = "PLAYING"
		}
	}
	if f.AppField != "" && f.AppField != "{}" {
		appField = f.AppField
	}
	if f.GroupID != "" && strings.Trim(f.GroupID, "0") != "" {
		groupID = f.GroupID
	}
	if f.ACDIndex != nil && appID != "" {
		acdIndex = *f.ACDIndex
	}
	return state, appID, appField, groupID, acdIndex
}
