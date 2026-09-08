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
}

type Presence struct {
	State           string `json:"state"` // OFFLINE, INACTIVE, ONLINE, PLAYING
	AppField        string `json:"appField"`
	AppID           string `json:"appId"`
	PresenceGroupID string `json:"presenceGroupId"`
	UpdatedAt       int64  `json:"updatedAt"`
	LogoutAt        int64  `json:"logoutAt"`
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
	// Favourites are friends marked as such on the console.
	Favourites []string `json:"favourites,omitempty"`
	// CodeGeneratedAt gates regeneration: a new friend code is allowed once a
	// day, and asking sooner is 422 friend_code_unregenerable_state.
	CodeGeneratedAt int64    `json:"codeGeneratedAt,omitempty"`
	Presence        Presence `json:"presence"`
	CreatedAt       int64    `json:"createdAt"`
	UpdatedAt       int64    `json:"updatedAt"`
}

type Store struct {
	mu      sync.Mutex
	path    string
	Devices map[string]*DeviceAccount `json:"devices"`
	Users   map[string]*User          `json:"users"`
	NaToPID map[string]uint64         `json:"naToPid"` // Nintendo-Account id_token sub -> OpenPak PID
}

func loadStore(path string) *Store {
	s := &Store{path: path, Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, s)
	}
	return s
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
