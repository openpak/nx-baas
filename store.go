package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// DeviceAccount is what POST /1.0.0/users hands the console: the console keeps the id+password in
// its _user.json and logs in with them forever after.
type DeviceAccount struct {
	ID       string `json:"id"`
	Password string `json:"password"`
	UserID   string `json:"userId"`
	// BoundDevice is the dauth id of the enrolled Harbor console that first signed in with this
	// account (harbor_devices.go); only that console may use it after. Empty: not bound.
	BoundDevice string `json:"boundDevice,omitempty"`
}

type Presence struct {
	State    string `json:"state"` // OFFLINE, INACTIVE, ONLINE, PLAYING
	AppField string `json:"appField"`
	// ACDIndex is the catalog index the console publishes beside the title id;
	// -1 means the console did not send one. Stored as sent, echoed as sent.
	ACDIndex        int    `json:"acdIndex,omitempty"`
	AppID           string `json:"appId"`
	PresenceGroupID string `json:"presenceGroupId"`
	UpdatedAt       int64  `json:"updatedAt"`
	LogoutAt        int64  `json:"logoutAt"`
	// Client is what the claim came from inside this namespace: "switch" for a
	// real console, "ryujinx"/"eden"/"citron" for an emulator that says so, ""
	// when nothing said. Never rendered to a console; carried to the core.
	Client string `json:"client,omitempty"`
	// OS is what the emulator said it runs on (X-OpenPak-Client "(<os>)"):
	// windows, macos, linux, android, ios; "" for a console or when unsaid.
	OS string `json:"os,omitempty"`
}

// DevicePresence is one console's claim about where its user is, with the
// lease that keeps the claim honest (PRE-01/02): a console that stops talking
// — sleep, crash, yanked cable — holds its entry only until ExpiresAt.
// Entries are keyed per device account, so a user signed in on two consoles
// is online for as long as either of them is.
// ponytail: written by the pre-lease code, which had one Presence per user and
// no device key. The aggregate in presence.go still reads that field as an
// entry with an implied lease, so old stores and the game API keep working.
type DevicePresence struct {
	DeviceID        string `json:"deviceId"` // the BAAS device account in the presence PATCH path
	State           string `json:"state"`    // OFFLINE, ONLINE, PLAYING
	AppID           string `json:"appId,omitempty"`
	AppField        string `json:"appField,omitempty"`
	ACDIndex        int    `json:"acdIndex,omitempty"`
	PresenceGroupID string `json:"presenceGroupId,omitempty"`
	UpdatedAt       int64  `json:"updatedAt"` // last state change (never moved by a render)
	ExpiresAt       int64  `json:"expiresAt"` // lease deadline; 0 = not leased (explicit offline)
	LogoutAt        int64  `json:"logoutAt"`  // set when this device said it is done
	Client          string `json:"client,omitempty"` // see Presence.Client
	OS              string `json:"os,omitempty"`     // see Presence.OS
}

// FriendPreference is one viewer's per-relationship state (SOC-02): what the
// console PATCHes on the relationship and what the list must project back.
// False must remain false, so every field keeps its own value — there is no
// "absent means true" here except onlineNotification, whose native default is
// on and which is therefore a pointer: nil = never set = alert enabled.
type FriendPreference struct {
	Favorite           bool  `json:"favorite"`
	Confirmed          bool  `json:"confirmed"`
	OnlineNotification *bool `json:"onlineNotification,omitempty"`
	// Note is the viewer's own note on this friend; the list parser reads one
	// per entry [firmware, $.items[*].friendNote]. Nothing sets it yet.
	Note      string `json:"note,omitempty"`
	UpdatedAt int64  `json:"updatedAt"`
}

// BlockDetail is one block's own state beyond the id [friends-contract-22.5.0
// §A.8]: the POST body's extras.self, served back as the item's extras.self.
type BlockDetail struct {
	CreatedAt int64          `json:"createdAt"`
	Self      map[string]any `json:"self,omitempty"`
}

// FriendRequestRecord is the durable identity of one friend request (SOC-03):
// the console cancels, rejects and accepts by this id, so it must survive a
// restart and mean the same pair on every surface that shows it. The
// friendship itself stays canonical in the account core; this is the native
// id mapping and nothing else.
type FriendRequestRecord struct {
	ID        string `json:"id"`
	FromPID   uint64 `json:"fromPid"`
	ToPID     uint64 `json:"toPid"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
	// State is empty while the request is open, then the answer it was
	// settled with. The record outlives the answer so that the console's
	// repeat of the same PATCH gets the same reply instead of a 404 it
	// reads as "this invitation is no longer valid".
	State     string `json:"state,omitempty"`
	SettledAt int64  `json:"settledAt,omitempty"`
	// Read is the receiver's extras.receiver.read, set by 30205
	// ReadFriendRequest. The console's request badge is the inbox items
	// without it [friends-contract-22.5.0 §A.4.2, §A.4.3].
	Read bool `json:"read,omitempty"`
	// Channel and the route extras are what the sending console POSTed:
	// channels[0], extras.sender (the sender's own view) and
	// extras.senderAndReceiver (both sides'). The boxes serve them back —
	// the inbox reads the route from senderAndReceiver, the outbox from
	// sender [friends-contract-22.5.0 §A.4.1, §A.4.2].
	Channel           string         `json:"channel,omitempty"`
	Sender            map[string]any `json:"extrasSender,omitempty"`
	SenderAndReceiver map[string]any `json:"extrasSenderAndReceiver,omitempty"`
}

// User is a BAAS user. PID == 0 means not yet linked to a OpenPak account; once linked its ID is
// the account's derived baasUserID so Photon/NPLN/friends all agree on one identity.
type User struct {
	ID           string `json:"id"`
	PID          uint64 `json:"pid"`
	NaID         string `json:"naId"`
	BsDid        string `json:"bsDid"` // the account server's bs:did for this user: what a console's id_token carries and the game servers report back
	Nickname     string `json:"nickname"`
	Country      string `json:"country"`
	Birthday     string `json:"birthday"`
	ThumbnailURL string `json:"thumbnailUrl"`
	NxAccount    string `json:"nxAccount"`
	// Avatar is the console's own profile picture, base64 JPEG exactly as it
	// uploaded it. Kept here because the account core has nowhere to put an
	// image yet; when it does, this moves and the console never notices.
	Avatar string `json:"avatar,omitempty"`
	// AvatarAt is when that upload happened. UpdatedAt moves for any change to
	// the user, so it cannot answer "whose picture is newer, the console's or
	// the website's" -- which is the whole question when both can be edited.
	AvatarAt       int64    `json:"avatarAt,omitempty"`
	DeviceAccounts []string `json:"deviceAccounts"`
	// Permissions are the privacy switches the console PATCHes. Values are the
	// documented ones: friends EVERYONE|FRIENDS|SELF, presence
	// FRIENDS|FAVORITE_FRIENDS|SELF. Zero values mean "never set", so userObj
	// keeps serving the defaults.
	Permissions map[string]any `json:"permissions,omitempty"`
	// Blocks is the block list the friends sysmodule manages, by BAAS user id.
	Blocks []string `json:"blocks,omitempty"`
	// BlockDetails holds what the console said about each block, by the
	// blocked user's BAAS id: when, and extras.self (reason, and the route
	// keys when a game is attached). Blocks made before this have none.
	BlockDetails map[string]*BlockDetail `json:"blockDetails,omitempty"`
	// Favourites are friends marked as such on the console. Superseded by
	// FriendPrefs, into which loadStore folds it once; kept so a store written
	// by this build still reads correctly on a rollback build.
	Favourites []string `json:"favourites,omitempty"`
	// FriendPrefs is the per-relationship preference state (SOC-02), by the
	// friend's BAAS user id: /isFavorite, /extras/self/isConfirmed and
	// /extras/self/isOnlineNotification.
	FriendPrefs map[string]*FriendPreference `json:"friendPrefs,omitempty"`
	// PlayLog is what the console PATCHed into /extras/<group>/playLog, by
	// group: a string holding a JSON array, stored as sent. Which group
	// carries it is the play-log permission [friends-contract-22.5.0 §A.6].
	// nil until the console first writes one.
	PlayLog map[string]string `json:"playLog,omitempty"`
	// DevicePresence holds the live per-device presence entries (PRE-01).
	DevicePresence map[string]*DevicePresence `json:"devicePresence,omitempty"`
	// FriendsUpdatedAt is when this user's friend graph last changed. The
	// console caches its friend list and refetches when this moves, so a
	// friendship that only exists in the core is a friend list that never
	// appears.
	FriendsUpdatedAt int64 `json:"friendsUpdatedAt,omitempty"`
	// CodeGeneratedAt gates regeneration: a new friend code is allowed once a
	// day, and asking sooner is 422 friend_code_unregenerable_state.
	CodeGeneratedAt int64    `json:"codeGeneratedAt,omitempty"`
	Presence        Presence `json:"presence"`
	CreatedAt       int64    `json:"createdAt"`
	UpdatedAt       int64    `json:"updatedAt"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	Devices  map[string]*DeviceAccount       `json:"devices"`
	Users    map[string]*User                `json:"users"`
	NaToPID  map[string]uint64               `json:"naToPid"` // Nintendo-Account id_token sub -> OpenPak PID
	Requests map[string]*FriendRequestRecord `json:"requests,omitempty"`
	// PctlDevices are the parental-controls records, keyed by the moon device id
	// as the console spells it (moon.go). Nil in a store written before they
	// existed; created on first use rather than migrated.
	PctlDevices map[string]*PctlDevice `json:"pctlDevices,omitempty"`
}

func loadStore(path string) *Store {
	s := &Store{path: path, Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, s)
	}
	// Migration: fold the old favourites list into FriendPrefs once (SOC-02).
	// Unknown fields are skipped by older binaries, so a rollback build keeps
	// working; it just will not see preferences recorded after the upgrade.
	migrated := false
	for _, u := range s.Users {
		for _, f := range u.Favourites {
			p := u.pref(f)
			if !p.Favorite {
				p.Favorite = true
				p.UpdatedAt = u.UpdatedAt
				migrated = true
			}
		}
	}
	if migrated {
		s.save()
	}
	return s
}

// pref returns the caller's preference record for one friend, creating an
// empty one when there is none. Called with the store lock held.
func (u *User) pref(friendBaasID string) *FriendPreference {
	if u.FriendPrefs == nil {
		u.FriendPrefs = map[string]*FriendPreference{}
	}
	p := u.FriendPrefs[friendBaasID]
	if p == nil {
		p = &FriendPreference{}
		u.FriendPrefs[friendBaasID] = p
	}
	return p
}

// save is called with mu held.
func (s *Store) save() {
	b, _ := json.MarshalIndent(s, "", " ")
	os.WriteFile(s.path+".tmp", b, 0o600)
	os.Rename(s.path+".tmp", s.path)
}

func (s *Store) NewUser() (*User, *DeviceAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	u := &User{ID: randHex(8), Birthday: "0000-00-00", CreatedAt: now, UpdatedAt: now, Presence: Presence{State: "OFFLINE", UpdatedAt: now}}
	d := &DeviceAccount{ID: randHex(8), Password: randPassword(), UserID: u.ID}
	u.DeviceAccounts = []string{d.ID}
	s.Users[u.ID] = u
	s.Devices[d.ID] = d
	s.save()
	return u, d
}

func (s *Store) Login(id, password string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.Devices[id]
	if d == nil && len(id) == 16 && len(password) >= 20 {
		// ponytail: trust-on-first-use. A console that already holds a device account from
		// another OpenPak deployment (the VPS) presents credentials we never issued; on a
		// private LAN we adopt them instead of forcing a console reset.
		now := time.Now().Unix()
		u := &User{ID: randHex(8), Birthday: "0000-00-00", CreatedAt: now, UpdatedAt: now, Presence: Presence{State: "OFFLINE", UpdatedAt: now}, DeviceAccounts: []string{id}}
		d = &DeviceAccount{ID: id, Password: password, UserID: u.ID}
		s.Users[u.ID] = u
		s.Devices[id] = d
		s.save()
	}
	if d != nil && d.Password == "" && len(password) >= 20 {
		// ponytail: pre-seeded device (mirror of a console's VPS device account) adopts the
		// password it presents on first login, so it binds to the seeded user, not a throwaway.
		d.Password = password
		s.save()
	}
	if d == nil || d.Password != password {
		return nil
	}
	return s.Users[d.UserID]
}

// BindDevice ties a device account to an enrolled console the first time one uses it, and
// answers whether the device `di` may use it. Unknown accounts pass (the login refuses them).
func (s *Store) BindDevice(accountID, di string, enrolled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.Devices[accountID]
	if d == nil {
		return true
	}
	if d.BoundDevice != "" {
		return d.BoundDevice == di
	}
	if enrolled {
		d.BoundDevice = di
		s.save()
	}
	return true
}

func (s *Store) User(id string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Users[id]
}

func (s *Store) UserByPID(pid uint64) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		if u.PID == pid {
			return u
		}
	}
	return nil
}

// Link = Restore User: the console just created a throwaway user + device account (POST /users)
// and federates it with the Nintendo Account; the response must be the account's canonical BAAS
// user (stable id = openpak-account's baasUserID, so every console and game server agree),
// with this console's device account added to it. Any previous throwaway is discarded.
// UserByBsDid finds the user a console identifies itself with. An unlinked user has no
// account bs:did yet and presents its own BAAS id instead.
// ponytail: linear scan -- a LAN store holds a handful of users.
func (s *Store) UserByBsDid(bsDid string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bsDid == "" {
		return nil
	}
	for _, u := range s.Users {
		if u.BsDid == bsDid || u.ID == bsDid {
			return u
		}
	}
	return nil
}

func (s *Store) Link(from *User, pid uint64, baasUserID, naID string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	fromID := from.ID // captured: the target==nil branch rewrites from.ID below, and the
	// device loop must still recognise the throwaway's old id (otherwise every device
	// account stays pointed at a deleted user and the next /login fails 2124-5002).
	target := s.Users[baasUserID]
	if target == nil {
		target = from
		delete(s.Users, from.ID)
		from.ID = baasUserID
		s.Users[from.ID] = from
	} else if target != from {
		target.DeviceAccounts = append(target.DeviceAccounts, from.DeviceAccounts...)
		delete(s.Users, from.ID)
	}
	target.PID, target.NaID = pid, naID
	for _, d := range s.Devices {
		if d.UserID == fromID || d.UserID == baasUserID {
			d.UserID = target.ID
		}
	}
	for id, u := range s.Users { // stale throwaways from failed attempts
		if u != target && u.PID == pid {
			delete(s.Users, id)
		}
	}
	target.UpdatedAt = time.Now().Unix()
	s.NaToPID[naID] = pid
	s.save()
	return target
}

func (s *Store) Update(u *User, f func(*User)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(u)
	u.UpdatedAt = time.Now().Unix()
	s.save()
}

// bumpFriendsUpdated moves the friend-list version, strictly monotonically
// (SOC-05): two mutations inside the same wall-clock second must still be
// distinguishable, or a console that refetched between them keeps the stale
// list forever. The value stays Unix-shaped, so a console comparing it against
// what it cached before the change sees nothing unusual.
func bumpFriendsUpdated(u *User, now int64) int64 {
	if now <= u.FriendsUpdatedAt {
		now = u.FriendsUpdatedAt + 1
	}
	u.FriendsUpdatedAt = now
	return now
}

// EnsureRequest returns the durable id of the request from -> to, creating
// the record on first sight. Idempotent: create, inbox and outbox all name
// the same request by the same id (SOC-03).
func (s *Store) EnsureRequest(fromPID, toPID uint64) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	if s.Requests == nil {
		s.Requests = map[string]*FriendRequestRecord{}
	}
	for id, r := range s.Requests {
		if r.State != "" {
			if now-r.SettledAt > settledRequestRetention {
				delete(s.Requests, id) // answered long ago: nobody retries that far back
			}
			continue // a settled id must not be reused for a new request
		}
		if r.FromPID == fromPID && r.ToPID == toPID {
			return r.ID, false
		}
	}
	id := randHex(8)
	for s.Requests[id] != nil { // collision with a historic id
		id = randHex(8)
	}
	s.Requests[id] = &FriendRequestRecord{ID: id, FromPID: fromPID, ToPID: toPID, CreatedAt: now, UpdatedAt: now}
	s.save()
	return id, true
}

// RequestByID returns a copy of the record: callers read it without the lock.
func (s *Store) RequestByID(id string) *FriendRequestRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.Requests[id]
	if r == nil {
		return nil
	}
	cp := *r
	return &cp
}

// MarkRequestRead records the receiver's extras.receiver.read on a request.
func (s *Store) MarkRequestRead(id string, read bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.Requests[id]
	if r == nil || r.Read == read {
		return
	}
	r.Read = read
	s.save()
}

// SetRequestRoute records how a request was sent: its channel and the route
// extras of the POST that created it.
func (s *Store) SetRequestRoute(id, channel string, sender, both map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.Requests[id]
	if r == nil {
		return
	}
	r.Channel, r.Sender, r.SenderAndReceiver = channel, sender, both
	s.save()
}

// settledRequestRetention is how long an answered request keeps answering
// repeats of its own PATCH. The core is the state of record either way; this
// is only so the console can ask twice.
const settledRequestRetention = 7 * 24 * 3600

// SettleRequest marks a request answered. The record stays so a repeat of the
// same answer replies the same way, but it can no longer authorize a second
// commit: the handler sees State and skips the core call.
func (s *Store) SettleRequest(id, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.Requests[id]
	if r == nil {
		return
	}
	now := time.Now().Unix()
	r.State, r.SettledAt, r.UpdatedAt = state, now, now
	s.save()
}

// OpenRequest reports whether an unanswered request from -> to exists.
func (s *Store) OpenRequest(fromPID, toPID uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.Requests {
		if r.State == "" && r.FromPID == fromPID && r.ToPID == toPID {
			return true
		}
	}
	return false
}

// RequestChannel is the channel an unanswered request from -> to was sent
// with, or "" when no open request names the pair.
func (s *Store) RequestChannel(fromPID, toPID uint64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.Requests {
		if r.State == "" && r.FromPID == fromPID && r.ToPID == toPID {
			return r.Channel
		}
	}
	return ""
}

// LiveUsers snapshots the users for the presence reconciler: the reconciler
// runs on its own goroutine, so it must not walk the live map while handlers
// mutate it. Entry structs are copied; their DevicePresence maps are copied
// one level deep, which is enough because entries are replaced (never mutated
// in place) under the same lock.
func (s *Store) LiveUsers() []*User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*User, 0, len(s.Users))
	for _, u := range s.Users {
		cp := *u
		if u.DevicePresence != nil {
			cp.DevicePresence = make(map[string]*DevicePresence, len(u.DevicePresence))
			for k, e := range u.DevicePresence {
				eCopy := *e
				cp.DevicePresence[k] = &eCopy
			}
		}
		out = append(out, &cp)
	}
	return out
}

func (s *Store) RememberNA(naID string, pid uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NaToPID[naID] = pid
	s.save()
}

func (s *Store) PIDForNA(naID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.NaToPID[naID]
}
