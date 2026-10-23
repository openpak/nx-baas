package main

// The friend-online pop-up on a real console, held to the firmware's rules
// (docs/switch/friends-presence-firmware-2026-09-19.md §6):
//
//   - the presence_updated parser fails the whole event unless userId, state,
//     appInfo:appId, appInfo:presenceGroupId, appField, updatedAt, logoutAt and
//     $.createdAt are all present (mask 0x3eb, friends 0x1a74a0 / 23.0.1 0x1aaea0);
//   - an event is applied only when its createdAt is later than the time the
//     console holds for the friend (0x191790 / 0x1950d0);
//   - the pop-up (ovln 7002) goes out only for a cached Offline -> Online/Playing
//     change (0x1a1790 / 0x1a5190), and overlayDisp shows it only when the
//     friend was offline more than 1799 s, measured from the cached logoutAt
//     (overlayDisp 23.0.1 0x31b2f0).

import (
	"net/url"
	"nx-baas/internal/store"
	"regexp"
	"testing"
	"time"
)

var hex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

// presenceEventGaps lists what the console's parser would miss in one
// presence_updated payload.
func presenceEventGaps(p map[string]any) []string {
	var gaps []string
	num := func(m map[string]any, k string) bool { _, ok := m[k].(int64); return ok }
	if !num(p, "createdAt") {
		gaps = append(gaps, "$.createdAt")
	}
	value, _ := p["value"].(map[string]any)
	if value == nil {
		return append(gaps, "$.value")
	}
	if s, _ := value["userId"].(string); !hex16.MatchString(s) {
		gaps = append(gaps, "$.value.userId")
	}
	if s, _ := value["state"].(string); s == "" {
		gaps = append(gaps, "$.value.state")
	}
	for _, k := range []string{"updatedAt", "logoutAt"} {
		if !num(value, k) {
			gaps = append(gaps, "$.value."+k)
		}
	}
	extras, _ := value["extras"].(map[string]any)
	friends, _ := extras["friends"].(map[string]any)
	for _, k := range []string{"appInfo:appId", "appInfo:presenceGroupId"} {
		if s, _ := friends[k].(string); !hex16.MatchString(s) {
			gaps = append(gaps, "$.value.extras.friends."+k)
		}
	}
	if s, _ := friends["appField"].(string); len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		gaps = append(gaps, "$.value.extras.friends.appField")
	}
	return gaps
}

// lastPresenceEvent is the newest presence_updated queued for viewer.
func lastPresenceEvent(t *testing.T, s *server, viewerID string) map[string]any {
	t.Helper()
	q := outboxOf(s, viewerID)
	if len(q) == 0 {
		t.Fatal("no presence_updated queued")
	}
	return q[len(q)-1].Payload
}

func valueOf(p map[string]any) map[string]any {
	v, _ := p["value"].(map[string]any)
	return v
}

// Every state a friend can be in reaches the console as an event it parses,
// "no game" included: until 2026-10-10 INACTIVE, OFFLINE and a title-less
// ONLINE went out without the app ids and the console dropped every one.
func TestEveryPresenceEventPassesTheConsolesFieldMask(t *testing.T) {
	s, _, users := socialServer(t)
	viewer, subject := users[0], users[1]
	for _, step := range []struct{ state, app string }{
		{"INACTIVE", ""}, {"ONLINE", "0100152000022000"}, {"PLAYING", "0100152000022000"},
		{"INACTIVE", "0000000000000000"}, {"OFFLINE", ""},
	} {
		s.noteDevicePresence(s.store.User(subject.ID), "dev-1", step.state, step.app, "", step.app, -1)
		p := lastPresenceEvent(t, s, viewer.ID)
		if got, _ := valueOf(p)["state"].(string); got != step.state {
			t.Fatalf("%s: queued state %q", step.state, got)
		}
		if gaps := presenceEventGaps(p); len(gaps) > 0 {
			t.Errorf("%s %s: the console's parser drops this event, missing %v (payload %v)", step.state, step.app, gaps, p)
		}
	}
}

// Two changes inside one second: the second must carry a later createdAt than
// the time the first one leaves on the console, or it is never applied.
func TestSameSecondPresenceChangesAreBothApplied(t *testing.T) {
	s, _, users := socialServer(t)
	viewer, subject := users[0], users[1]
	s.noteDevicePresence(subject, "dev-1", "PLAYING", "0100152000022000", "{}", "0100152000022000", -1)
	first := lastPresenceEvent(t, s, viewer.ID)
	s.noteDevicePresence(s.store.User(subject.ID), "dev-1", "ONLINE", "0100152000022000", "{}", "0100152000022000", -1)
	second := lastPresenceEvent(t, s, viewer.ID)
	if valueOf(second)["state"] != "ONLINE" {
		t.Fatalf("second event state %v", valueOf(second)["state"])
	}
	held := valueOf(first)["updatedAt"].(int64) // what the console caches from the first
	if c1, c2 := first["createdAt"].(int64), second["createdAt"].(int64); c2 <= c1 || c2 <= held {
		t.Fatalf("createdAt %d then %d (first updatedAt %d): the console would ignore the second", c1, c2, held)
	}
}

// Signing in at HOME after a long time off is not a departure: the friends see
// INACTIVE with the old logoutAt, so the game started next is a change from
// Offline, more than 1799 s after the cached time, and the pop-up shows.
func TestSigningInAtHomeKeepsTheLastDeparture(t *testing.T) {
	s, _, users := socialServer(t)
	viewer, subject := users[0], users[1]
	// socialServer renames its users after the device accounts were made, so
	// the subject's device account is pointed back at it here.
	s.store.Mu.Lock()
	dev := s.store.Devices[subject.DeviceAccounts[0]]
	dev.UserID = subject.ID
	s.store.Mu.Unlock()
	away := time.Now().Unix() - 2*3600
	s.store.Update(s.store.User(subject.ID), func(u *store.User) {
		u.DevicePresence = map[string]*store.DevicePresence{
			dev.ID: {DeviceID: dev.ID, State: "OFFLINE", UpdatedAt: away, LogoutAt: away},
		}
		u.Presence = store.Presence{State: "OFFLINE", UpdatedAt: away, LogoutAt: away}
	})

	form := url.Values{"id": {dev.ID}, "password": {dev.Password}}.Encode()
	if w := baasReq(s, "POST", "/1.0.0/login", "", form); w.Code != 200 {
		t.Fatalf("login = %d %s", w.Code, w.Body)
	}
	signedIn := lastPresenceEvent(t, s, viewer.ID)
	if got := valueOf(signedIn)["state"]; got != "INACTIVE" {
		t.Fatalf("a sign-in told friends %v; the console reads only INACTIVE as signed in at HOME", got)
	}
	if got := valueOf(signedIn)["logoutAt"].(int64); got != away {
		t.Fatalf("sign-in logoutAt %d, want the last departure %d", got, away)
	}

	// The device's own INACTIVE right after changes nothing the friends see: whatever goes
	// out (nx-penne coalesces per subject) still says INACTIVE since the last departure.
	s.noteClientPresence(s.store.User(subject.ID), dev.ID, "harbor", "android", "INACTIVE", "0000000000000000", "{}", "", -1)
	if v := valueOf(lastPresenceEvent(t, s, viewer.ID)); v["state"] != "INACTIVE" || v["logoutAt"].(int64) != away {
		t.Fatalf("the device's INACTIVE after the sign-in moved what friends hold: %v", v)
	}

	s.noteClientPresence(s.store.User(subject.ID), dev.ID, "harbor", "android", "ONLINE", "0100152000022000", "{}", "", -1)
	game := lastPresenceEvent(t, s, viewer.ID)
	if got := valueOf(game)["state"]; got != "ONLINE" {
		t.Fatalf("game start state %v", got)
	}
	cachedOffline := valueOf(signedIn)["logoutAt"].(int64)
	if offlineFor := game["createdAt"].(int64) - cachedOffline; offlineFor <= 1799 {
		t.Fatalf("offline for %d s at the game start as the console counts it; overlayDisp needs > 1799", offlineFor)
	}
}
