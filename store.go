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

// Link binds the device account behind user `from` to OpenPak PID `pid`. If that PID already
// owns a BAAS user (the other console, or an earlier link) the device account moves over to it,
// like real federation merging a fresh device account into the Nintendo Account's existing user.
func (s *Store) Link(from *User, pid uint64, baasUserID, naID string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	var target *User
	for _, u := range s.Users {
		if u.PID == pid {
			target = u
			break
		}
	}
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
	for _, did := range target.DeviceAccounts {
		if d := s.Devices[did]; d != nil {
			d.UserID = target.ID
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
