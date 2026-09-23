package main

// Presence tests (PRE-01/02/03): deterministic aggregation from per-device
// claims, lease expiry over restarts and silent loss, account switch, the
// reconciler's core-session agreement, and viewer-aware visibility.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accountv1 "nx-baas/accountpb"
)

// fakeSessions is the core's session registry, the way the reconciler sees
// it: sessions with leases that expire unless heartbeated.
type fakeSessions struct {
	accountv1.SessionsClient
	mu     sync.Mutex
	leases map[string]int64 // session id -> unix expiry
	byAcct map[string]string
	titles map[string]string // the title each account's session was registered with
	clients map[string]string // the client each account's session was registered with
	// namespace is what the core reports these sessions under; another
	// platform's namespace is how a Wii U friend reads on a Switch.
	namespace string
	gone      bool // the core lost everything (restart)
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{leases: map[string]int64{}, byAcct: map[string]string{}}
}

func (x *fakeSessions) RegisterSession(ctx context.Context, r *accountv1.RegisterSessionRequest, _ ...grpc.CallOption,
) (*accountv1.RegisterSessionResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.gone {
		return nil, status.Error(codes.Unavailable, "core restarting")
	}
	id := "sess-" + r.GetAccountId()
	x.leases[id] = time.Now().Unix() + int64(r.GetLeaseSeconds())
	x.byAcct[r.GetAccountId()] = id
	if x.titles == nil {
		x.titles = map[string]string{}
	}
	x.titles[r.GetAccountId()] = r.GetTitleId()
	if x.clients == nil {
		x.clients = map[string]string{}
	}
	x.clients[r.GetAccountId()] = r.GetClient()
	return &accountv1.RegisterSessionResponse{SessionId: id, LeaseSeconds: r.GetLeaseSeconds()}, nil
}

// GetPresence: the core's side of cross-platform presence. Registered
// sessions answer for themselves; anything else is absent, which is the same
// fact as offline.
func (x *fakeSessions) GetPresence(ctx context.Context, r *accountv1.GetPresenceRequest, _ ...grpc.CallOption,
) (*accountv1.GetPresenceResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := &accountv1.GetPresenceResponse{}
	for _, id := range r.GetAccountIds() {
		sid, ok := x.byAcct[id]
		if !ok || x.leases[sid] <= time.Now().Unix() {
			continue
		}
		out.Presence = append(out.Presence, &accountv1.Presence{
			AccountId: id, Namespace: x.namespace, TitleId: x.titles[id], SinceUnix: time.Now().Unix(),
			Client: x.clients[id],
		})
	}
	return out, nil
}

func (x *fakeSessions) Heartbeat(ctx context.Context, r *accountv1.HeartbeatRequest, _ ...grpc.CallOption,
) (*accountv1.HeartbeatResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.gone {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	if exp, ok := x.leases[r.GetSessionId()]; !ok || exp <= time.Now().Unix() {
		return nil, status.Error(codes.NotFound, "session expired")
	}
	x.leases[r.GetSessionId()] = time.Now().Unix() + 30
	return &accountv1.HeartbeatResponse{LeaseSeconds: 30}, nil
}

func (x *fakeSessions) ExpireSession(ctx context.Context, r *accountv1.ExpireSessionRequest, _ ...grpc.CallOption,
) (*accountv1.ExpireSessionResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	delete(x.leases, r.GetSessionId())
	return &accountv1.ExpireSessionResponse{}, nil
}

func (x *fakeSessions) ResolveSession(ctx context.Context, r *accountv1.ResolveSessionRequest, _ ...grpc.CallOption,
) (*accountv1.ResolveSessionResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	id, ok := x.byAcct[r.GetAccountId()]
	if !ok || x.gone || x.leases[id] <= time.Now().Unix() {
		return nil, status.Error(codes.NotFound, "no live session")
	}
	return &accountv1.ResolveSessionResponse{SessionId: id}, nil
}

func (x *fakeSessions) live(id string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.leases[id] > time.Now().Unix()
}

// presenceFixture: a server with the OpenPak backend and a fake core session
// registry, with the fixture's two linked users.
func presenceFixture(t *testing.T) (*server, *fakeSessions, *User, *User) {
	t.Helper()
	s, _, users := socialServer(t)
	sess := newFakeSessions()
	if b, ok := s.acct.(*openpakBackend); ok {
		b.sessions = sess
	}
	return s, sess, users[0], users[1]
}

// patchPresence drives the console's per-device presence PATCH.
func patchPresence(t *testing.T, s *server, u *User, device, state string) *httptest.ResponseRecorder {
	t.Helper()
	r := authed("PATCH", "/1.0.0/users/"+u.ID+"/device_accounts/"+device,
		`[{"op":"replace","path":"/presence/state","value":"`+state+`"}]`, u, s)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// friendPresenceOf renders what A's friend list shows about B.
func friendPresenceOf(t *testing.T, s *server, viewer, subject *User) map[string]any {
	t.Helper()
	r := authed("GET", "/2.0.0/users/"+viewer.ID+"/friends", "", viewer, s)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var env struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	if len(env.Items) != 1 {
		t.Fatalf("list: %s", w.Body.String())
	}
	friend := env.Items[0]["friend"].(map[string]any)
	return friend["presence"].(map[string]any)
}

// Aggregation is deterministic (PRE-01): PLAYING beats ONLINE, expiry decays
// to OFFLINE with the lease deadline as the departure time.
func TestAggregatePresencePrecedence(t *testing.T) {
	s := dauthServer(t)
	s.store = loadStore(t.TempDir() + "/baas.json")
	u, _ := s.store.NewUser()
	now := time.Now().Unix()
	lease := presenceLease()

	s.store.Update(u, func(u *User) {
		u.DevicePresence = map[string]*DevicePresence{
			"dev-a": {DeviceID: "dev-a", State: "ONLINE", UpdatedAt: now - 5, ExpiresAt: now + 60},
			"dev-b": {DeviceID: "dev-b", State: "PLAYING", AppID: "0100", UpdatedAt: now - 3, ExpiresAt: now + 60},
		}
	})
	agg := aggregatePresence(s.store.User(u.ID), now, lease)
	if agg.State != "PLAYING" || agg.AppID != "0100" {
		t.Errorf("two live devices: %+v", agg)
	}

	// The playing device's lease lapses: the other console keeps the account
	// ONLINE — one device going quiet is not the person leaving.
	s.store.Update(u, func(u *User) { u.DevicePresence["dev-b"].ExpiresAt = now - 1 })
	agg = aggregatePresence(s.store.User(u.ID), now, lease)
	if agg.State != "ONLINE" {
		t.Errorf("after one device expired: %+v", agg)
	}

	// Both gone: OFFLINE, and the departure is the later lease deadline.
	s.store.Update(u, func(u *User) { u.DevicePresence["dev-a"].ExpiresAt = now - 10 })
	agg = aggregatePresence(s.store.User(u.ID), now, lease)
	if agg.State != "OFFLINE" || agg.LogoutAt != now-1 {
		t.Errorf("after all expired: %+v", agg)
	}
}

// Each device's PATCH writes its own claim; one going OFFLINE does not end
// the account while the other is still live (PRE-01, two consoles).
func TestPresencePatchIsPerDevice(t *testing.T) {
	s, _, a, b := presenceFixture(t)

	if w := patchPresence(t, s, b, "dev-1", "ONLINE"); w.Code != 200 {
		t.Fatalf("presence patch: %d %s", w.Code, w.Body.String())
	}
	if got := friendPresenceOf(t, s, a, b)["state"]; got != "ONLINE" {
		t.Errorf("after B online: %v", got)
	}
	if w := patchPresence(t, s, b, "dev-2", "PLAYING"); w.Code != 200 {
		t.Fatal("second device patch failed")
	}
	if got := friendPresenceOf(t, s, a, b)["state"]; got != "PLAYING" {
		t.Errorf("after B playing on dev-2: %v", got)
	}
	// dev-1 goes offline; dev-2 is still playing.
	if w := patchPresence(t, s, b, "dev-1", "OFFLINE"); w.Code != 200 {
		t.Fatal("offline patch failed")
	}
	if got := friendPresenceOf(t, s, a, b)["state"]; got != "PLAYING" {
		t.Errorf("after dev-1 left: %v", got)
	}
	// Both off: offline, with the departure recorded.
	if w := patchPresence(t, s, b, "dev-2", "OFFLINE"); w.Code != 200 {
		t.Fatal("second offline patch failed")
	}
	p := friendPresenceOf(t, s, a, b)
	if p["state"] != "OFFLINE" {
		t.Errorf("after both left: %v", p)
	}
}

// Stale persisted data must not override an expired session — including
// across a restart (PRE-01): deadlines are absolute timestamps.
func TestStalePresenceDoesNotSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	s := dauthServer(t)
	s.store = loadStore(dir + "/baas.json")
	u, _ := s.store.NewUser()
	past := time.Now().Unix() - 3600
	s.store.Update(u, func(u *User) {
		u.DevicePresence = map[string]*DevicePresence{
			"dev-1": {DeviceID: "dev-1", State: "PLAYING", AppID: "0100", UpdatedAt: past - 60, ExpiresAt: past},
		}
	})
	// Reload from disk, as a restarted process would.
	s.store = loadStore(dir + "/baas.json")
	agg := aggregatePresence(s.store.User(u.ID), time.Now().Unix(), presenceLease())
	if agg.State != "OFFLINE" {
		t.Errorf("a claim that lapsed an hour ago still renders: %+v", agg)
	}
}

// The subject's own presence permission and the block lists decide what a
// viewer sees (PRE-03).
func TestPresenceVisibility(t *testing.T) {
	s, _, a, b := presenceFixture(t)
	view := func() string {
		return friendPresenceOf(t, s, a, b)["state"].(string)
	}
	if w := patchPresence(t, s, b, "dev-1", "PLAYING"); w.Code != 200 {
		t.Fatal("presence patch failed")
	}
	if got := view(); got != "PLAYING" {
		t.Fatalf("fixture: viewer should see PLAYING, sees %v", got)
	}

	// B narrows presence to favourite friends only; A is not one of B's
	// favourites.
	s.store.Update(s.store.User(b.ID), func(u *User) { u.Permissions = map[string]any{"presence": "FAVORITE_FRIENDS"} })
	if got := view(); got != "OFFLINE" {
		t.Errorf("non-favourite viewer saw %v under FAVORITE_FRIENDS", got)
	}
	// B favourites A: presence flows again.
	s.store.Update(s.store.User(b.ID), func(u *User) { u.pref(a.ID).Favorite = true })
	if got := view(); got != "PLAYING" {
		t.Errorf("favourite viewer saw %v", got)
	}
	// SELF hides from everyone but the subject.
	s.store.Update(s.store.User(b.ID), func(u *User) { u.Permissions["presence"] = "SELF" })
	if got := view(); got != "OFFLINE" {
		t.Errorf("viewer saw %v under SELF", got)
	}
	s.store.Update(s.store.User(b.ID), func(u *User) { u.Permissions["presence"] = "FRIENDS" })

	// A block in either direction hides presence outright.
	s.store.Update(s.store.User(b.ID), func(u *User) { u.Blocks = []string{a.ID} })
	if got := view(); got != "OFFLINE" {
		t.Errorf("viewer saw %v while blocked by the subject", got)
	}
}

// An account switch on one device ends the previous user's claim for that
// device (PRE-02): the console is where the new login says it is.
func TestAccountSwitchEndsPreviousClaim(t *testing.T) {
	s, _, a, b := presenceFixture(t)
	const device = "dev-shared"
	if w := patchPresence(t, s, a, device, "PLAYING"); w.Code != 200 {
		t.Fatal("A presence patch failed")
	}
	// B signs in on the same device: the login handler expires the device's
	// claim everywhere before writing B's.
	s.expireDeviceEverywhere(device, b.ID)
	s.noteDevicePresence(b, device, "ONLINE", "", "", "", -1)

	lease := presenceLease()
	now := time.Now().Unix()
	if agg := aggregatePresence(s.store.User(a.ID), now, lease); agg.State != "OFFLINE" {
		t.Errorf("A still shows %v on a device B just took over", agg.State)
	}
	if agg := aggregatePresence(s.store.User(b.ID), now, lease); agg.State != "ONLINE" {
		t.Errorf("B shows %v after taking the device", agg.State)
	}
}

// The reconciler agrees with the core (PRE-02): it keeps a session alive for
// a fresh claim, recovers the session id after losing it, and tears the
// session down when the claim lapses.
func TestReconcilerAgreesWithTheCore(t *testing.T) {
	s, sess, a, b := presenceFixture(t)
	now := time.Now().Unix()
	lease := presenceLease()

	bAcct := ""
	if bb, ok := s.acct.(*openpakBackend); ok {
		bAcct = bb.accountFor(b.PID)
	}
	if bAcct == "" {
		t.Fatal("fixture: no core account for B")
	}
	sessionID := func() string {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		return sess.byAcct[bAcct]
	}

	// B comes online: the PATCH itself registers a session through
	// reportOnline; the reconciler adopts it into its own map and keeps it
	// renewed while the claim is fresh.
	if w := patchPresence(t, s, b, "dev-1", "ONLINE"); w.Code != 200 {
		t.Fatal("presence patch failed")
	}
	s.reconcilePresenceOnce(time.Unix(now, 0), lease)
	s.reconcilePresenceOnce(time.Unix(now+1, 0), lease)
	if !sess.live(sessionID()) {
		t.Error("reconciler did not renew the core session for a fresh claim")
	}

	// Silent loss: B's claim lapses, the reconciler expires it locally and
	// tears the core session down instead of waiting out its lease.
	s.store.Update(s.store.User(b.ID), func(u *User) {
		u.DevicePresence["dev-1"].ExpiresAt = now + 2
	})
	s.reconcilePresenceOnce(time.Unix(now+3, 0), lease)
	if sess.live(sessionID()) {
		t.Error("core session outlived an account the adapter considers offline")
	}
	if agg := aggregatePresence(s.store.User(b.ID), now+3, lease); agg.State != "OFFLINE" {
		t.Errorf("lapsed claim not expired: %+v", agg)
	}

	// A fresh claim after the core lost all state (a core restart): the
	// reconciler re-establishes the session — the claim is the console's,
	// the session id is the adapter's bookkeeping and is re-derived.
	if w := patchPresence(t, s, b, "dev-1", "ONLINE"); w.Code != 200 {
		t.Fatal("second presence patch failed")
	}
	sess.mu.Lock()
	sess.gone = true
	sess.mu.Unlock()
	s.reconcilePresenceOnce(time.Unix(now+4, 0), lease) // register fails; claim stays
	sess.mu.Lock()
	sess.gone = false
	sess.mu.Unlock()
	s.reconcilePresenceOnce(time.Unix(now+5, 0), lease)
	if !sess.live(sessionID()) {
		t.Error("reconciler did not re-establish the session after a core restart")
	}
	_ = a
}

// The console publishes its own catalog index beside the title id, as a number
// [firmware: the publish format is "appInfo:acdIndex":%d next to two
// "%016llx" strings], and its friends read it back off the list
// [$.items[*].friend.presence.extras.friends.appInfo:acdIndex]. So it is
// stored as sent and echoed as sent; a console that sends none gets none back.
func TestPresenceCarriesTheConsolesOwnACDIndex(t *testing.T) {
	s, _, users := socialServer(t)
	a, b := users[0], users[1]
	_, req := postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	if code, _ := answerRequest(t, s, b, "PATCH", req["id"].(string),
		`[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`); code != http.StatusOK {
		t.Fatal("accept failed")
	}

	patch := func(body string) int {
		r := authed("PATCH", "/1.0.0/users/"+a.ID+"/device_accounts/"+a.DeviceAccounts[0], body, a, s)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	friendsOf := func(u *User) map[string]any {
		r := authed("GET", "/2.0.0/users/"+u.ID+"/friends", "", u, s)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		var list struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Items) != 1 {
			t.Fatalf("friend list: %v %s", err, w.Body)
		}
		friend, _ := list.Items[0]["friend"].(map[string]any)
		presence, _ := friend["presence"].(map[string]any)
		extras, _ := presence["extras"].(map[string]any)
		got, _ := extras["friends"].(map[string]any)
		return got
	}

	if code := patch(`[{"op":"replace","path":"/presence/state","value":"PLAYING"},
		{"op":"replace","path":"/presence/extras/friends/appInfo:appId","value":"0100000000010000"},
		{"op":"replace","path":"/presence/extras/friends/appInfo:acdIndex","value":7}]`); code != http.StatusOK {
		t.Fatalf("presence patch = %d", code)
	}
	if got := friendsOf(b)["appInfo:acdIndex"]; got != float64(7) {
		t.Errorf("acdIndex = %v (%T), want 7", got, got)
	}

	// A console that publishes no index must not be given one.
	if code := patch(`[{"op":"replace","path":"/presence/state","value":"ONLINE"}]`); code != http.StatusOK {
		t.Fatalf("second patch = %d", code)
	}
	if got, present := friendsOf(b)["appInfo:acdIndex"]; present {
		t.Errorf("acdIndex invented when the console sent none: %v", got)
	}
}

// A stored-raw presence permission is what the console reads it as: anything
// but the three known values is SELF, so nobody else sees it. Unset stays the
// documented default (open to friends) [friends-contract-22.5.0 §A.6, C10].
func TestPresenceVisibleTreatsJunkPermissionAsSelf(t *testing.T) {
	viewer := &User{ID: "viewer-1"}
	junk := &User{ID: "subject-1", Permissions: map[string]any{"presence": "EVERYONE"}}
	if presenceVisible(viewer, junk, true) {
		t.Error("junk presence permission is visible to a friend; console reads SELF")
	}
	if !presenceVisible(junk, junk, true) {
		t.Error("own presence hidden from self")
	}
	unset := &User{ID: "subject-2"}
	if !presenceVisible(viewer, unset, true) {
		t.Error("unset presence permission hidden from a friend; default is open")
	}
}

// Everything outside the Switch adapter -- the website, the app, another
// console's emulator -- reads presence from the core, so the title has to go
// there: without it a friend in a game is merely "online" everywhere but the
// console that published it. Changing game re-registers, because a heartbeat
// cannot change what the session says they are playing.
func TestCoreSessionCarriesTheTitleBeingPlayed(t *testing.T) {
	s, _, users := socialServer(t)
	sess := newFakeSessions()
	b := s.acct.(*openpakBackend)
	b.sessions = sess
	u := users[1]
	account := b.accountFor(u.PID)
	if account == "" {
		t.Fatal("fixture: no core account")
	}
	title := func() string {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		return sess.titles[account]
	}
	lease := presenceLease()
	now := time.Now()

	s.noteDevicePresence(u, "dev-1", "PLAYING", "0100a5a020d5e000", "{}", "0100a5a020d5e000", -1)
	s.reconcilePresenceOnce(now, lease)
	if got := title(); got != "0100a5a020d5e000" {
		t.Fatalf("core session title = %q, want the game being played", got)
	}

	// A different game: the session is replaced, not heartbeaten.
	s.noteDevicePresence(s.store.User(u.ID), "dev-1", "PLAYING", "0100152000022000", "{}", "0100152000022000", -1)
	s.reconcilePresenceOnce(now.Add(time.Second), lease)
	if got := title(); got != "0100152000022000" {
		t.Fatalf("core session title = %q after switching game", got)
	}

	// Back to the Home menu: online, playing nothing.
	s.noteDevicePresence(s.store.User(u.ID), "dev-1", "ONLINE", "", "{}", "", -1)
	s.reconcilePresenceOnce(now.Add(2*time.Second), lease)
	if got := title(); got != "" {
		t.Fatalf("core session still names %q after the game closed", got)
	}
}

// A friend live on another platform is live to a Switch too. The core is the
// place every platform reports into, so a Wii U session reads as online here
// -- without a title, because a console can only draw its own games and a
// foreign title id would render as one it does not have.
func TestAFriendPlayingOnAnotherPlatformReadsAsOnline(t *testing.T) {
	s, _, users := socialServer(t)
	sess := newFakeSessions()
	sess.namespace = "wiiu"
	b := s.acct.(*openpakBackend)
	b.sessions = sess
	viewer, friend := users[0], users[1]

	account := b.accountFor(friend.PID)
	if account == "" {
		t.Fatal("fixture: no core account for the friend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := sess.RegisterSession(ctx, &accountv1.RegisterSessionRequest{
		AccountId: account, Namespace: "wiiu", TitleId: "0005000010101d00",
		EndpointRef: "nex", LeaseSeconds: 300,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	id, err := s.acct.Identity(viewer.PID)
	if err != nil || id == nil || len(id.Friends) == 0 {
		t.Fatalf("identity: %v", err)
	}
	var f Friend
	for _, cand := range id.Friends {
		if cand.PID == friend.PID {
			f = cand
		}
	}
	got := s.visiblePresence(viewer, f, time.Now().Unix())
	if got["state"] != "ONLINE" {
		t.Fatalf("presence = %v, want ONLINE for a friend playing elsewhere", got["state"])
	}
	ex, _ := got["extras"].(map[string]any)
	friends, _ := ex["friends"].(map[string]any)
	if _, leaked := friends["appInfo:appId"]; leaked || len(friends) != 1 {
		t.Fatalf("a foreign title reached the console: %v", friends)
	}
	// What the title id cannot say, the description does: no name is known
	// (no website in the test), so "a game", on the platform's own name.
	if friends["appField"] != `{"sys_description":"Playing a game on Wii U"}` {
		t.Fatalf("appField = %v", friends["appField"])
	}

	// And this platform's own session still names its title.
	sess.namespace = b.namespace
	s.coreSeen().byID = map[string]corePresence{}
	s.coreSeen().at = map[string]time.Time{}
	if _, err := sess.RegisterSession(ctx, &accountv1.RegisterSessionRequest{
		AccountId: account, Namespace: b.namespace, TitleId: "0100a5a020d5e000",
		EndpointRef: "baas", LeaseSeconds: 300,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	got = s.visiblePresence(viewer, f, time.Now().Unix())
	if got["state"] != "PLAYING" {
		t.Fatalf("presence = %v, want PLAYING on this platform", got["state"])
	}
}

// Two claims that say the same thing: the one naming a game says more. A
// login records a bare "signed in", and seconds after the console said what
// somebody was playing that login was taking the title away again.
func TestABareSignInDoesNotTakeTheGameAway(t *testing.T) {
	s, _, users := socialServer(t)
	u := users[1]
	s.noteDevicePresence(u, "console", "ONLINE", "0100a5a020d5e000", "{}", "0100a5a020d5e000", -1)
	s.noteDevicePresence(s.store.User(u.ID), "login", "ONLINE", "", "", "", -1)

	agg := aggregatePresence(s.store.User(u.ID), time.Now().Unix(), presenceLease())
	if agg.AppID != "0100a5a020d5e000" {
		t.Fatalf("aggregate app = %q, want the game the console named", agg.AppID)
	}

	// An all-zero title id is "no game", never a game whose id is zero.
	s.noteDevicePresence(s.store.User(u.ID), "emulator", "ONLINE", "0000000000000000", "{}", "0000000000000000", -1)
	got := s.store.User(u.ID).DevicePresence["emulator"]
	if got.AppID != "" || got.PresenceGroupID != "" {
		t.Fatalf("all-zero ids were stored as a title: %+v", got)
	}
}

// Two friends rendered back to back: the second is looked up on its own, not
// answered from the first one's cache entry (which said nothing about it).
func TestCorePresenceCacheIsPerAccount(t *testing.T) {
	s, _, users := socialServer(t)
	sess := newFakeSessions()
	b := s.acct.(*openpakBackend)
	b.sessions = sess
	offline, live := b.accountFor(users[0].PID), b.accountFor(users[1].PID)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := sess.RegisterSession(ctx, &accountv1.RegisterSessionRequest{
		AccountId: live, Namespace: "wiiu", EndpointRef: "nex", LeaseSeconds: 300,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, ok := s.corePresenceOf(offline); ok {
		t.Fatal("an account with no session read as live")
	}
	if _, ok := s.corePresenceOf(live); !ok {
		t.Fatal("a live friend read as offline because another was looked up first")
	}
}
