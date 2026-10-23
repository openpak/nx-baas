// Package presence is one accurate answer to "where is this person right now", built
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

package presence

import (
	"context"
	"log"
	"nx-baas/internal/core"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/penne"
	"nx-baas/internal/store"
	"nx-baas/redact"
	"os"
	"strconv"
	"strings"
	"sync"
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
func Lease() time.Duration {
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
func Aggregate(u *store.User, now int64, lease time.Duration) store.Presence {
	out := store.Presence{State: "OFFLINE"}
	best := (*store.DevicePresence)(nil)
	consider := func(e *store.DevicePresence) {
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
			if left := departedAt(e, e.ExpiresAt); left > out.LogoutAt {
				out.LogoutAt = left
			}
			return
		}
		if e.ExpiresAt == 0 && now-e.UpdatedAt >= int64(lease.Seconds()) {
			// Old entry (the pre-lease field) with an implied lease.
			if left := e.UpdatedAt + int64(lease.Seconds()); left > out.LogoutAt {
				out.LogoutAt = left
			}
			return
		}
		// A live INACTIVE claim carries the moment it went INACTIVE: friends
		// read it as offline, and "last online" is that moment.
		if e.LogoutAt > out.LogoutAt {
			out.LogoutAt = e.LogoutAt
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
		consider(&store.DevicePresence{DeviceID: "prelease", State: u.Presence.State, AppID: u.Presence.AppID,
			AppField: u.Presence.AppField, PresenceGroupID: u.Presence.PresenceGroupID,
			ACDIndex: u.Presence.ACDIndex, UpdatedAt: u.Presence.UpdatedAt, ExpiresAt: 0})
	}
	// The old field remembers departures nothing else does: an account whose
	// device entries were all dropped (revoked, pre-lease stores).
	if u.Presence.LogoutAt > out.LogoutAt {
		out.LogoutAt = u.Presence.LogoutAt
	}
	if best == nil {
		if out.UpdatedAt == 0 && u.CreatedAt > 0 {
			out.UpdatedAt = u.CreatedAt // never seen: the account's own clock, not the render's
		}
		return out
	}
	return store.Presence{State: best.State, AppID: best.AppID, AppField: best.AppField,
		PresenceGroupID: best.PresenceGroupID, ACDIndex: best.ACDIndex,
		UpdatedAt: best.UpdatedAt, LogoutAt: out.LogoutAt, Client: best.Client, OS: best.OS}
}

// homeAsOnline is what friends are shown for somebody sitting at HOME. A console with no game
// running publishes INACTIVE, which the friends module reads as offline, so a person signed in
// and waiting was invisible. With NX_HOME_AS_ONLINE=1 they are served as ONLINE (no title) and
// the platform they are on goes in the description, "Harbor" or "Switch". Off unless set.
// ponytail: whether the HOME friend list draws sys_description is unverified (a friend on
// another platform already carries one and shows plain "Online"); the state is the part that
// is known to work.
func HomeAsOnline(p store.Presence) store.Presence {
	if p.State != "INACTIVE" || httpx.Getenv("NX_HOME_AS_ONLINE", "") != "1" {
		return p
	}
	p.State = "ONLINE"
	if p.AppID == "" && (p.AppField == "" || p.AppField == "{}") {
		p.AppField = DescriptionAppField(ClientLabel("switch", p.Client))
	}
	if id := ReservedID("switch", p.Client); id != "" && p.AppID == "" && platformTitle() {
		p.AppID, p.PresenceGroupID = id, id
	}
	return p
}

// departedAt answers when a device's claim, ending at `at`, stopped reading as
// online to friends. INACTIVE already reads as offline, so a claim that went
// INACTIVE keeps the moment it did: staying at HOME, or switching off from
// there, does not move "last online" forward.
func departedAt(e *store.DevicePresence, at int64) int64 {
	if e != nil && strings.ToUpper(e.State) == "INACTIVE" && e.LogoutAt > 0 && e.LogoutAt <= at {
		return e.LogoutAt
	}
	return at
}

// departureBefore answers when a device last stopped reading as online to its
// friends, given the entry it had before this claim. Only a live ONLINE or
// PLAYING claim leaves now. A device that was gone, lapsed, never seen or
// already at HOME (INACTIVE reads as offline) keeps the departure it had: a
// console switched on after a night off was not "online a moment ago".
//
// It matters to the console's friend-online pop-up. overlayDisp drops it unless
// the friend was offline for more than 1799 seconds (23.0.1 0x31b2f0 `cmp w22,
// #0x707; b.le`), and the friends module measures that from the offline time it
// cached, which for an offline friend is the logoutAt we sent [friends 22.5.0
// 0x1a74a0, 0x1a1790]. Stamping "now" at sign-in made every game started within
// half an hour of switching on silent.
func departureBefore(prev *store.DevicePresence, now int64) int64 {
	switch {
	case prev == nil:
		return 0
	case stateRank(prev.State) == 0, strings.ToUpper(prev.State) == "INACTIVE":
		return prev.LogoutAt
	case prev.ExpiresAt != 0 && prev.ExpiresAt <= now:
		return prev.ExpiresAt // lapsed: they left when it ran out, at the latest
	default:
		return now
	}
}

// devicePresenceWins picks between two live claims: higher rank first, then
// the more recent state change. Deterministic, so two renders of the same
// evidence agree.
func devicePresenceWins(a, b *store.DevicePresence) bool {
	ra, rb := stateRank(a.State), stateRank(b.State)
	if ra != rb {
		return ra > rb
	}
	// Between two claims that say the same thing, the one naming a game says
	// more: a bare "signed in" from a login must not take the title off
	// somebody the console says is playing (2026-09-20, a session losing
	// Kirby to a login seconds later).
	if (a.AppID != "") != (b.AppID != "") {
		return a.AppID != ""
	}
	return a.UpdatedAt > b.UpdatedAt
}

// noteDevicePresence records one device's claim when nothing says what the
// device is (a Photon game session, tests).
func (s *Service) NoteDevicePresence(u *store.User, deviceID, state, appID, appField, groupID string, acdIndex int) {
	s.NoteClientPresence(u, deviceID, "", "", state, appID, appField, groupID, acdIndex)
}

// noteClientPresence records one device's claim. state OFFLINE ends the
// device's live claim (kept as remembered departure evidence, not as a live
// one). Whether the account as a whole is anywhere is the aggregate's call.
// client is what the device is (see Presence.Client), clientOS what it runs on
// (see Presence.OS).
func (s *Service) NoteClientPresence(u *store.User, deviceID, client, clientOS, state, appID, appField, groupID string, acdIndex int) {
	// An all-zero title id is "no game", not a game whose id is zero: the
	// emulator publishes it at the menu, and it reached the core as a title
	// with players on it (2026-09-20, the status page listing
	// 0000000000000000).
	if strings.Trim(appID, "0") == "" {
		appID = ""
	}
	if strings.Trim(groupID, "0") == "" {
		groupID = ""
	}
	now := time.Now().Unix()
	lease := int64(Lease().Seconds())
	before := s.Snapshot(u.ID)
	defer func() { s.NotifyIfChanged(u.ID, before) }()
	s.Store.Update(u, func(u *store.User) {
		if u.DevicePresence == nil {
			u.DevicePresence = map[string]*store.DevicePresence{}
		}
		prev := u.DevicePresence[deviceID]
		left := departureBefore(prev, now)
		if stateRank(state) == 0 {
			u.DevicePresence[deviceID] = &store.DevicePresence{DeviceID: deviceID, State: "OFFLINE",
				UpdatedAt: now, LogoutAt: left}
		} else {
			e := &store.DevicePresence{DeviceID: deviceID, State: strings.ToUpper(state),
				AppID: appID, AppField: appField, PresenceGroupID: groupID, ACDIndex: acdIndex,
				UpdatedAt: now, ExpiresAt: now + lease, Client: client, OS: clientOS}
			if e.State == "INACTIVE" {
				// Back at HOME after a title closed: friends see this as
				// offline from now, so "last online" is now. Without it they
				// read the previous departure -- "last online 14 h ago"
				// seconds after the person put the game down (2026-10-08,
				// Harbor). Signing in at HOME from offline is not a departure
				// and keeps the old one (departureBefore): the console's
				// "is now online" pop-up needs that moment to be more than
				// 30 minutes before the game starts.
				e.LogoutAt = left
			}
			u.DevicePresence[deviceID] = e
		}
		// Shadow the old field for anything that still reads it (rollback
		// builds, scripts). The aggregate never trusts it over device entries.
		u.Presence.State = strings.ToUpper(state)
		u.Presence.UpdatedAt = now
		if (stateRank(state) == 0 || strings.ToUpper(state) == "INACTIVE") && left > 0 {
			u.Presence.LogoutAt = left
		}
		if stateRank(state) > 0 {
			u.Presence.AppID, u.Presence.AppField, u.Presence.PresenceGroupID = appID, appField, groupID
			u.Presence.ACDIndex = acdIndex
		}
	})
}

// renewDevicePresence extends a claim that is still the truth. Presence is
// published on change and on nothing else -- by the console and by the
// emulator both -- so without this a person who has not switched game in two
// minutes silently goes offline while sitting in front of the console
// (2026-09-20: an invitation naming its sender as "offline for 0 minutes").
// Only presence we are still hearing a live connection for is renewed.
func (s *Service) RenewDevicePresence(userID, deviceID string) {
	u := s.Store.User(userID)
	if u == nil {
		return
	}
	now := time.Now().Unix()
	lease := int64(Lease().Seconds())
	extend := func(e *store.DevicePresence) {
		if e == nil || e.ExpiresAt == 0 || stateRank(e.State) == 0 {
			return // never claimed, or claimed as gone: not ours to extend
		}
		if e.ExpiresAt > now { // still live: push the lease out
			e.ExpiresAt = now + lease
		}
	}
	s.Store.Update(u, func(u *store.User) {
		if deviceID != "" {
			extend(u.DevicePresence[deviceID])
			return
		}
		// No device named: a console that reconnected has published nothing on its new
		// connection, but the person it signed in is still where they said they were. Every
		// claim a real console made for them stays alive while its connection is up; an
		// emulator's claims are renewed by its own heartbeat and are left alone.
		// A claim that lapsed while the console was still connected (it publishes on change and
		// at connect, and a reconnect publishes nothing) is revived when it was HOME: nothing says
		// they left, and the last thing they said was "signed in, no game". One that was a game
		// is not: a console that crashed in a title must not come back showing it.
		for _, e := range u.DevicePresence {
			if e == nil || e.Client != "switch" {
				continue
			}
			if e.ExpiresAt != 0 && e.ExpiresAt <= now && strings.ToUpper(e.State) == "INACTIVE" {
				e.ExpiresAt = now + lease
				continue
			}
			extend(e)
		}
	})
}

// expireDevicePresence drops one device's live claim (device unlink, account
// switch): the console is gone even though it never said so. When no other
// live claim remains, the old presence field is ended with it, so an account
// switch ends the previous user's presence now rather than at lease time.
func (s *Service) ExpireDevicePresence(u *store.User, deviceID string) {
	now := time.Now().Unix()
	before := s.Snapshot(u.ID)
	defer func() { s.NotifyIfChanged(u.ID, before) }()
	s.Store.Update(u, func(u *store.User) {
		e := u.DevicePresence[deviceID]
		if e == nil || e.ExpiresAt <= now {
			return // not live; nothing to end
		}
		// Kept as departure evidence, not deleted: a deleted entry took the
		// "last online" moment with it.
		left := departedAt(e, now)
		u.DevicePresence[deviceID] = &store.DevicePresence{DeviceID: deviceID, State: "OFFLINE", UpdatedAt: now, LogoutAt: left}
		if !hasLiveDeviceClaim(u, now, Lease()) {
			u.Presence.State, u.Presence.LogoutAt, u.Presence.UpdatedAt = "OFFLINE", left, now
		}
	})
}

// hasLiveDeviceClaim answers whether any device entry still holds a live
// (non-offline, unexpired) claim. Called with the store lock held.
func hasLiveDeviceClaim(u *store.User, now int64, lease time.Duration) bool {
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

// deviceClaimLive answers whether one device holds a live claim right now.
func (s *Service) DeviceClaimLive(u *store.User, deviceID string) bool {
	s.Store.Mu.Lock()
	defer s.Store.Mu.Unlock()
	e := u.DevicePresence[deviceID]
	return e != nil && stateRank(e.State) > 0 && e.ExpiresAt > time.Now().Unix()
}

// expireDeviceEverywhere ends a device account's claim in every other user's
// record: one console holds one signed-in user at a time, so when it signs in
// as someone new, the previous account's presence for that device is a lie
// the moment the new login commits (PRE-02, account switch). The user being
// signed in is skipped — their own claim was about to be written.
func (s *Service) ExpireDeviceEverywhere(deviceID, exceptUserID string) {
	if deviceID == "" {
		return
	}
	for _, u := range s.Store.LiveUsers() {
		if u.ID == exceptUserID {
			continue
		}
		if _, ok := u.DevicePresence[deviceID]; ok {
			s.ExpireDevicePresence(s.Store.User(u.ID), deviceID)
		}
	}
}

// presenceVisible answers whether viewer may see a friend's presence (PRE-03):
// the subject's own presence permission decides — FRIENDS (the default),
// FAVORITE_FRIENDS or SELF — and a block in either direction hides presence
// outright. areFriends is the core's answer (the caller renders from the
// core's friend list); account status is enforced there too, because an
// inactive account is not delivered as a friend at all.
func Visible(viewer, subject *store.User, areFriends bool) bool {
	if viewer == nil || subject == nil {
		return false
	}
	if BlocksEither(viewer, subject) {
		return false
	}
	switch perm, _ := subject.Permissions["presence"].(string); perm {
	case "SELF":
		return viewer.ID == subject.ID
	case "FAVORITE_FRIENDS":
		return viewer.ID == subject.ID || (areFriends && subject.Pref(viewer.ID).Favorite)
	case "FRIENDS":
		return viewer.ID == subject.ID || areFriends
	default:
		// Unset is the documented default (open to friends). Anything else
		// is a stored-raw relic the console reads as SELF, so nobody else
		// sees it [friends-contract-22.5.0 §A.6, C10].
		if perm == "" {
			return viewer.ID == subject.ID || areFriends
		}
		return viewer.ID == subject.ID
	}
}

// blocksEither is the directional-block rule: a block by either side stops
// presence (and everything else social) in both directions.
func BlocksEither(a, b *store.User) bool {
	return ContainsID(a.Blocks, b.ID) || ContainsID(b.Blocks, a.ID)
}

func ContainsID(list []string, id string) bool {
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
func (s *Service) ReconcileLoop() {
	lease := Lease()
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for range t.C {
		s.ReconcileOnce(time.Now(), lease)
	}
}

func (s *Service) ReconcileOnce(now time.Time, lease time.Duration) {
	b, ok := s.Acct.(*identity.OpenpakBackend)
	if !ok {
		return // the earlier account backend keeps presence to itself
	}
	unix := now.Unix()
	for _, u := range s.Store.LiveUsers() {
		agg := Aggregate(u, unix, lease)
		switch {
		case agg.State != "OFFLINE":
			// The claim is fresh, so the console renewed within the lease:
			// keep the core session alive for it. A session id we lost (a
			// restart) is re-derived, never invented from residue.
			if s.LiveSessions[u.ID] != "" {
				// The core session carries the title and the client, so
				// switching game (or putting one down, or moving from the
				// emulator to the console) has to be re-registered: a
				// heartbeat cannot change what it says.
				if s.liveSessionTitle[u.ID] != agg.AppID || s.liveSessionClient[u.ID] != agg.Client ||
					s.liveSessionOS[u.ID] != agg.OS {
					s.expireCoreSession(b, u)
					s.registerCoreSession(b, u, agg.AppID, agg.Client, agg.OS)
					continue
				}
				s.renewCoreSession(b, u)
				continue
			}
			s.registerCoreSession(b, u, agg.AppID, agg.Client, agg.OS)
		default:
			// The aggregate is offline: end the core session at once instead
			// of waiting out its lease, and stop showing the claim locally.
			s.expireCoreSession(b, u)
			s.ExpireLocal(u, unix, lease)
		}
	}
}

// expireLocalPresence drops claims the lease has ended. Entries are replaced
// (never mutated in place), so a snapshot taken under the store lock stays
// consistent while this runs.
func (s *Service) ExpireLocal(u *store.User, now int64, lease time.Duration) {
	before := s.Snapshot(u.ID)
	defer func() { s.NotifyIfChanged(u.ID, before) }()
	s.Store.Update(u, func(u *store.User) {
		for id, e := range u.DevicePresence {
			if e.ExpiresAt != 0 && e.ExpiresAt <= now {
				// Ended, not forgotten: the entry becomes the departure, so
				// "last online" is when the lease ran out (or when it went
				// INACTIVE), not whatever older departure is left.
				u.DevicePresence[id] = &store.DevicePresence{DeviceID: id, State: "OFFLINE",
					UpdatedAt: e.ExpiresAt, LogoutAt: departedAt(e, e.ExpiresAt)}
			}
		}
		if stateRank(u.Presence.State) > 0 && now-u.Presence.UpdatedAt >= int64(lease.Seconds()) {
			u.Presence.State, u.Presence.LogoutAt = "OFFLINE", u.Presence.UpdatedAt+int64(lease.Seconds())
		}
	})
}

// registerCoreSession tells the core the account is signed in. Best effort:
// presence is never worth failing a console request over.
// registerCoreSession tells the core the account is signed in, and what it is
// playing. The core carries a title per session and every other surface reads
// it from there -- the website, the app, another console's emulator -- so a
// title left empty is the difference between "Leia is online" and "Leia is
// playing Kirby on a Switch" everywhere at once (2026-09-20).
func (s *Service) registerCoreSession(b *identity.OpenpakBackend, u *store.User, titleID, client, clientOS string) {
	accountID := b.AccountFor(u.PID)
	if accountID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := b.Sessions.RegisterSession(ctx, &accountv1.RegisterSessionRequest{
		AccountId: accountID, Namespace: b.Namespace, TitleId: titleID,
		EndpointRef: "baas", LeaseSeconds: int32(identity.OnlineLease.Seconds()), Client: client, Os: clientOS,
	})
	if err != nil {
		identity.LogErr("presence register", err)
		return
	}
	if s.LiveSessions == nil {
		s.LiveSessions = map[string]string{}
	}
	if s.liveSessionTitle == nil {
		s.liveSessionTitle = map[string]string{}
	}
	if s.liveSessionClient == nil {
		s.liveSessionClient = map[string]string{}
	}
	s.LiveSessions[u.ID] = resp.GetSessionId()
	s.liveSessionTitle[u.ID] = titleID
	if s.liveSessionOS == nil {
		s.liveSessionOS = map[string]string{}
	}
	s.liveSessionClient[u.ID] = client
	s.liveSessionOS[u.ID] = clientOS
	log.Printf("[nx-baas] presence: core session for %s namespace=%s title=%q client=%q os=%q", redact.Tag(accountID), b.Namespace, titleID, client, clientOS)
}

// renewCoreSession heartbeats the account's session so the core's shorter
// lease does not outlive a console that is merely quiet. A session the core
// no longer knows (expired, core restarted) is re-registered — the recovery
// path, not a second source of truth.
func (s *Service) renewCoreSession(b *identity.OpenpakBackend, u *store.User) {
	id := s.LiveSessions[u.ID]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := b.Sessions.Heartbeat(ctx, &accountv1.HeartbeatRequest{SessionId: id}); err == nil {
		return
	}
	delete(s.LiveSessions, u.ID)
	s.registerCoreSession(b, u, s.liveSessionTitle[u.ID], s.liveSessionClient[u.ID], s.liveSessionOS[u.ID])
}

// expireCoreSession ends the core session for an account that is offline.
func (s *Service) expireCoreSession(b *identity.OpenpakBackend, u *store.User) {
	id := s.LiveSessions[u.ID]
	if id == "" {
		return
	}
	delete(s.LiveSessions, u.ID)
	delete(s.liveSessionTitle, u.ID)
	delete(s.liveSessionClient, u.ID)
	delete(s.liveSessionOS, u.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := b.Sessions.ExpireSession(ctx, &accountv1.ExpireSessionRequest{SessionId: id}); err != nil {
		identity.LogErr("presence expire", err)
	}
}

// Service is presence over the shared state. Notify hands a presence event to Penne.
type Service struct {
	*core.Core
	Notify func(penne.Delivery) penne.Submission

	// liveSessions maps BAAS user id -> the core session the adapter registered
	// for it, so the presence reconciler can renew and expire what it created.
	// In-memory by design: a restart re-derives truth from the core (and local
	// leases), never from this map.
	LiveSessions map[string]string
	// liveSessionTitle is the title each of those sessions was registered
	// with, so a console changing game re-registers rather than leaving the
	// core reporting the game it started on.
	liveSessionTitle map[string]string
	// liveSessionClient is the client each session was registered with, for
	// the same reason: a heartbeat cannot change it.
	liveSessionClient map[string]string
	// liveSessionOS is the OS each session was registered with, likewise.
	liveSessionOS map[string]string
	// corePresence caches what the core last said about other platforms.
	corePresence *CorePresenceCache
	coreSeenOnce sync.Once
}
