// Presence: one accurate answer to "where is this person right now", built
// from per-device claims with leases (PRE-01/02) and filtered by what the
// viewer may see (PRE-03).
//
// The state model:
//
//   - Every device (BAAS device account) carries its own entry: state,
//     title metadata, the moment the state changed, and the instant the
//     claim lapses unless renewed.
//   - The aggregate a friend list renders is deterministic: PLAYING beats
//     ONLINE beats OFFLINE; among equal states the most recent state change
//     wins (someone with two consoles playing two titles shows the title
//     they started last).
//   - A claim older than its lease is not presence, it is residue: it decays
//     to OFFLINE with logoutAt set to the moment the lease ran out. Stale
//     persisted data therefore cannot override an expired session, including
//     across a server restart (the deadlines are absolute timestamps).
//
// The core session registry is reconciled against this: while the aggregate
// says the account is live, the adapter renews its core session (heartbeat);
// when the core says the session is gone anyway, the local claim is dropped
// rather than shown. One poller, one cursor, one presence reconciler.

package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	accountv1 "nx-baas/accountpb"
)

// presenceLease is how long a presence claim lives without renewal. The
// native renewal cadence has not been measured on hardware yet (the audit is
// explicit that nothing establishes what a client sends while merely idle),
// so the bound is conservative and configurable: long enough that a quiet
// console is not blinked offline by a lost request, short enough that a
// sleeping one converges to OFFLINE within it plus one reconcile pass.
//
// NX_PRESENCE_LEASE_SECONDS overrides it. Measuring the native cadence and
// revisiting this bound with evidence is a declared hardware gate (PRE-02);
// until then this value is a documented choice, not a measured fact.
func presenceLease() time.Duration {
	if v := os.Getenv("NX_PRESENCE_LEASE_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 && n <= 3600 {
			return time.Duration(n) * time.Second
		}
		log.Printf("[nx-baas] NX_PRESENCE_LEASE_SECONDS=%q out of range (10..3600); using default", v)
	}
	return 120 * time.Second
}

// reconcileEvery is how often the presence reconciler sweeps: expiring leases,
// renewing core sessions for accounts that are still live, and expiring core
// sessions for accounts that are not.
const reconcileEvery = 15 * time.Second

// stateRank orders the states the way the aggregation needs: the bigger the
// number, the more the state says.
func stateRank(state string) int {
	switch strings.ToUpper(state) {
	case "PLAYING":
		return 2
	case "ONLINE", "INACTIVE":
		return 1
	default: // OFFLINE and anything unrecognised (the console also falls back to offline)
		return 0
	}
}

// aggregatePresence reduces a user's per-device entries to the single Presence
// a friend list renders. Offline and expired evidence is remembered as
// logoutAt, never as state: an entry past its lease means the person left at
// the latest when the lease ran out (PRE-01: timestamps derive from state
// changes, not from render time, so rendering the same state twice yields the
// same bytes and a stable list etag).
func aggregatePresence(u *User, now int64, lease time.Duration) Presence {
	out := Presence{State: "OFFLINE"}
	best := (*DevicePresence)(nil)
	consider := func(e *DevicePresence) {
		if e == nil {
			return
		}
		if stateRank(e.State) == 0 { // explicit offline: evidence of a departure
			if e.LogoutAt > out.LogoutAt {
				out.LogoutAt = e.LogoutAt
			}
			if e.UpdatedAt > out.UpdatedAt {
				out.UpdatedAt = e.UpdatedAt
			}
			return
		}
		if e.ExpiresAt != 0 && e.ExpiresAt <= now {
			// The claim lapsed: they went away when it ran out, at the latest.
			if e.ExpiresAt > out.LogoutAt {
				out.LogoutAt = e.ExpiresAt
			}
			return
		}
		if e.ExpiresAt == 0 && now-e.UpdatedAt >= int64(lease.Seconds()) {
			// Legacy entry (the pre-lease field) with an implied lease.
			if left := e.UpdatedAt + int64(lease.Seconds()); left > out.LogoutAt {
				out.LogoutAt = left
			}
			return
		}
		if best == nil || devicePresenceWins(e, best) {
			best = e
		}
	}
	for _, e := range u.DevicePresence {
		consider(e)
	}
	// The pre-lease field: one presence per user, written by paths that know
	// nothing about device entries. It counts only when there are no device
	// entries at all — a user with device entries has a newer, more specific
	// record of every state change, and letting the shadow outlive a device
	// lease would be exactly the stale-data override this model forbids.
	if len(u.DevicePresence) == 0 && u.Presence.State != "" && stateRank(u.Presence.State) > 0 {
		consider(&DevicePresence{DeviceID: "legacy", State: u.Presence.State, AppID: u.Presence.AppID,
			AppField: u.Presence.AppField, PresenceGroupID: u.Presence.PresenceGroupID,
			UpdatedAt: u.Presence.UpdatedAt, ExpiresAt: 0})
	}
	if best == nil {
		if out.UpdatedAt == 0 && u.CreatedAt > 0 {
			out.UpdatedAt = u.CreatedAt // never seen: the account's own clock, not the render's
		}
		return out
	}
	return Presence{State: best.State, AppID: best.AppID, AppField: best.AppField,
		PresenceGroupID: best.PresenceGroupID, UpdatedAt: best.UpdatedAt, LogoutAt: out.LogoutAt}
}

// devicePresenceWins picks between two live claims: higher rank first, then
// the more recent state change. Deterministic, so two renders of the same
// evidence agree.
func devicePresenceWins(a, b *DevicePresence) bool {
	ra, rb := stateRank(a.State), stateRank(b.State)
	if ra != rb {
		return ra > rb
	}
	return a.UpdatedAt > b.UpdatedAt
}

// noteDevicePresence records one device's claim. state OFFLINE ends the
// device's live claim (kept as remembered departure evidence, not as a live
// one). Whether the account as a whole is anywhere is the aggregate's call.
func (s *server) noteDevicePresence(u *User, deviceID, state, appID, appField, groupID string) {
	now := time.Now().Unix()
	lease := int64(presenceLease().Seconds())
	s.store.Update(u, func(u *User) {
		if u.DevicePresence == nil {
			u.DevicePresence = map[string]*DevicePresence{}
		}
		if stateRank(state) == 0 {
			u.DevicePresence[deviceID] = &DevicePresence{DeviceID: deviceID, State: "OFFLINE",
				UpdatedAt: now, LogoutAt: now}
		} else {
			u.DevicePresence[deviceID] = &DevicePresence{DeviceID: deviceID, State: strings.ToUpper(state),
				AppID: appID, AppField: appField, PresenceGroupID: groupID,
				UpdatedAt: now, ExpiresAt: now + lease}
		}
		// Shadow the old field for anything that still reads it (rollback
		// builds, scripts). The aggregate never trusts it over device entries.
		u.Presence.State = strings.ToUpper(state)
		u.Presence.UpdatedAt = now
		if stateRank(state) == 0 {
			u.Presence.LogoutAt = now
		} else {
			u.Presence.AppID, u.Presence.AppField, u.Presence.PresenceGroupID = appID, appField, groupID
		}
	})
}

// expireDevicePresence drops one device's live claim (device unlink, account
// switch): the console is gone even though it never said so. When no other
// live claim remains, the old presence field is ended with it, so an account
// switch ends the previous user's presence now rather than at lease time.
func (s *server) expireDevicePresence(u *User, deviceID string) {
	now := time.Now().Unix()
	s.store.Update(u, func(u *User) {
		e := u.DevicePresence[deviceID]
		if e == nil || e.ExpiresAt <= now {
			return // not live; nothing to end
		}
		delete(u.DevicePresence, deviceID)
		if !hasLiveDeviceClaim(u, now, presenceLease()) {
			u.Presence.State, u.Presence.LogoutAt, u.Presence.UpdatedAt = "OFFLINE", now, now
		}
	})
}

// hasLiveDeviceClaim answers whether any device entry still holds a live
// (non-offline, unexpired) claim. Called with the store lock held.
func hasLiveDeviceClaim(u *User, now int64, lease time.Duration) bool {
	for _, e := range u.DevicePresence {
		if stateRank(e.State) == 0 {
			continue
		}
		if e.ExpiresAt != 0 && e.ExpiresAt > now {
			return true
		}
		if e.ExpiresAt == 0 && now-e.UpdatedAt < int64(lease.Seconds()) {
			return true
		}
	}
	return false
}

// expireDeviceEverywhere ends a device account's claim in every other user's
// record: one console holds one signed-in user at a time, so when it signs in
// as someone new, the previous account's presence for that device is a lie
// the moment the new login commits (PRE-02, account switch). The user being
// signed in is skipped — their own claim was about to be written.
func (s *server) expireDeviceEverywhere(deviceID, exceptUserID string) {
	if deviceID == "" {
		return
	}
	for _, u := range s.store.LiveUsers() {
		if u.ID == exceptUserID {
			continue
		}
		if _, ok := u.DevicePresence[deviceID]; ok {
			s.expireDevicePresence(s.store.User(u.ID), deviceID)
		}
	}
}

// presenceVisible answers whether viewer may see a friend's presence (PRE-03):
// the subject's own presence permission decides — FRIENDS (the default),
// FAVORITE_FRIENDS or SELF — and a block in either direction hides presence
// outright. areFriends is the core's answer (the caller renders from the
// core's friend list); account status is enforced there too, because an
// inactive account is not delivered as a friend at all.
func presenceVisible(viewer, subject *User, areFriends bool) bool {
	if viewer == nil || subject == nil {
		return false
	}
	if blocksEither(viewer, subject) {
		return false
	}
	switch perm, _ := subject.Permissions["presence"].(string); perm {
	case "SELF":
		return viewer.ID == subject.ID
	case "FAVORITE_FRIENDS":
		return viewer.ID == subject.ID || (areFriends && subject.pref(viewer.ID).Favorite)
	default: // "" and FRIENDS: friends see presence
		return viewer.ID == subject.ID || areFriends
	}
}

// blocksEither is the directional-block rule: a block by either side stops
// presence (and everything else social) in both directions.
func blocksEither(a, b *User) bool {
	return containsID(a.Blocks, b.ID) || containsID(b.Blocks, a.ID)
}

func containsID(list []string, id string) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

// reconcilePresenceLoop is the single presence reconciler (PRE-02): expire
// lapsed claims, renew core sessions for accounts that are live, expire core
// sessions for accounts that are not, and drop local claims the core already
// considers gone. Runs beside the core-event poller; both are the adapter's
// one integration with the core's clock.
func (s *server) reconcilePresenceLoop() {
	lease := presenceLease()
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for range t.C {
		s.reconcilePresenceOnce(time.Now(), lease)
	}
}

func (s *server) reconcilePresenceOnce(now time.Time, lease time.Duration) {
	b, ok := s.acct.(*openpakBackend)
	if !ok {
		return // the legacy backend keeps presence to itself
	}
	unix := now.Unix()
	for _, u := range s.store.LiveUsers() {
		agg := aggregatePresence(u, unix, lease)
		switch {
		case agg.State != "OFFLINE":
			// The claim is fresh, so the console renewed within the lease:
			// keep the core session alive for it. A session id we lost (a
			// restart) is re-derived, never invented from residue.
			if s.liveSessions[u.ID] != "" {
				s.renewCoreSession(b, u)
				continue
			}
			s.registerCoreSession(b, u)
		default:
			// The aggregate is offline: end the core session at once instead
			// of waiting out its lease, and stop showing the claim locally.
			s.expireCoreSession(b, u)
			s.expireLocalPresence(u, unix, lease)
		}
	}
}

// expireLocalPresence drops claims the lease has ended. Entries are replaced
// (never mutated in place), so a snapshot taken under the store lock stays
// consistent while this runs.
func (s *server) expireLocalPresence(u *User, now int64, lease time.Duration) {
	s.store.Update(u, func(u *User) {
		for id, e := range u.DevicePresence {
			if e.ExpiresAt != 0 && e.ExpiresAt <= now {
				delete(u.DevicePresence, id)
			}
		}
		if stateRank(u.Presence.State) > 0 && now-u.Presence.UpdatedAt >= int64(lease.Seconds()) {
			u.Presence.State, u.Presence.LogoutAt = "OFFLINE", u.Presence.UpdatedAt+int64(lease.Seconds())
		}
	})
}

// registerCoreSession tells the core the account is signed in. Best effort:
// presence is never worth failing a console request over.
func (s *server) registerCoreSession(b *openpakBackend, u *User) {
	accountID := b.accountFor(u.PID)
	if accountID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := b.sessions.RegisterSession(ctx, &accountv1.RegisterSessionRequest{
		AccountId: accountID, Namespace: b.namespace, TitleId: "",
		EndpointRef: "baas", LeaseSeconds: int32(onlineLease.Seconds()),
	})
	if err != nil {
		logErr("presence register", err)
		return
	}
	if s.liveSessions == nil {
		s.liveSessions = map[string]string{}
	}
	s.liveSessions[u.ID] = resp.GetSessionId()
}

// renewCoreSession heartbeats the account's session so the core's shorter
// lease does not outlive a console that is merely quiet. A session the core
// no longer knows (expired, core restarted) is re-registered — the recovery
// path, not a second source of truth.
func (s *server) renewCoreSession(b *openpakBackend, u *User) {
	id := s.liveSessions[u.ID]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := b.sessions.Heartbeat(ctx, &accountv1.HeartbeatRequest{SessionId: id}); err == nil {
		return
	}
	delete(s.liveSessions, u.ID)
	s.registerCoreSession(b, u)
}

// expireCoreSession ends the core session for an account that is offline.
func (s *server) expireCoreSession(b *openpakBackend, u *User) {
	id := s.liveSessions[u.ID]
	if id == "" {
		return
	}
	delete(s.liveSessions, u.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := b.sessions.ExpireSession(ctx, &accountv1.ExpireSessionRequest{SessionId: id}); err != nil {
		logErr("presence expire", err)
	}
}
