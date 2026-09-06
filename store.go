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
	ID             string   `json:"id"`
	PID            uint64   `json:"pid"`
	NaID           string   `json:"naId"`
	Nickname       string   `json:"nickname"`
	Country        string   `json:"country"`
	Birthday       string   `json:"birthday"`
	ThumbnailURL   string   `json:"thumbnailUrl"`
	NxAccount      string   `json:"nxAccount"`
	DeviceAccounts []string `json:"deviceAccounts"`
	Presence       Presence `json:"presence"`
	CreatedAt      int64    `json:"createdAt"`
	UpdatedAt      int64    `json:"updatedAt"`
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

// Link binds user `from` (the one the console just created or logged in with) to OpenPak PID
// `pid`. The BAAS user id the console holds must never change (2124-0292 otherwise), so `from`
// keeps its id; any other user previously linked to the same PID (an earlier attempt, or the
// other console) is simply unlinked.
func (s *Store) Link(from *User, pid uint64, naID string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		if u != from && u.PID == pid {
			u.PID, u.NaID = 0, ""
		}
	}
	from.PID, from.NaID = pid, naID
	from.UpdatedAt = time.Now().Unix()
	s.NaToPID[naID] = pid
	s.save()
	return from
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
