package orphans

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"nx-baas/internal/store"
)

func fixture(t *testing.T) *store.Store {
	s := store.Load(filepath.Join(t.TempDir(), "baas.json"))
	s.Users["linked"] = &store.User{ID: "linked", PID: 11, NaID: "na-linked", DeviceAccounts: []string{"dev-linked"}}
	s.Users["orphan"] = &store.User{ID: "orphan", Nickname: "x", DeviceAccounts: []string{"dev-orphan"},
		FriendPrefs: map[string]*store.FriendPreference{}}
	s.Users["orphan2"] = &store.User{ID: "orphan2", DeviceAccounts: []string{"dev-orphan2"}}
	s.Users["viaNA"] = &store.User{ID: "viaNA", PID: 44, NaID: "na-via", DeviceAccounts: []string{"dev-via"}}
	s.Users["viaInv"] = &store.User{ID: "viaInv", DeviceAccounts: []string{"dev-inv"}}
	s.Users["00000000000000ab"] = &store.User{ID: "00000000000000ab", DeviceAccounts: []string{"dev-acb"}}
	s.Users["stale"] = &store.User{ID: "stale", PID: 77, DeviceAccounts: []string{"dev-stale"}}
	s.Users["linked"].FriendPrefs = map[string]*store.FriendPreference{"orphan": {Favorite: true}, "linked2": {}}
	for u, d := range map[string]string{"linked": "dev-linked", "orphan": "dev-orphan", "orphan2": "dev-orphan2",
		"viaNA": "dev-via", "viaInv": "dev-inv", "00000000000000ab": "dev-acb", "stale": "dev-stale", "nobody": "dev-dangling"} {
		s.Devices[d] = &store.DeviceAccount{ID: d, UserID: u}
	}
	s.NaToPID["na-via"] = 44
	s.Requests = map[string]*store.FriendRequestRecord{"r": {ID: "r", FromPID: 11, ToPID: 55}}
	return s
}

func linked(u *store.User) (bool, bool) {
	switch u.ID {
	case "linked":
		return true, false
	case "stale":
		return false, true
	}
	return false, false
}

func TestClassifyKeepsAnythingReferenced(t *testing.T) {
	s := fixture(t)
	r := Classify(s, linked, []byte(`{"records":[{"receiver":"viaInv"}]}`), []byte(`{"users":{"171":{}}}`))
	if r.Users != 7 || r.Linked != 1 || r.Unresolved != 1 || r.Candidates != 5 {
		t.Fatalf("classification: %+v", r)
	}
	if r.KeptNaToPID != 1 || r.KeptInvitations != 1 || r.KeptAcbaa != 1 {
		t.Fatalf("exclusions: %+v", r)
	}
	if r.Orphans != 2 || r.OrphanDevices != 2 || r.DanglingDevices != 1 {
		t.Fatalf("orphans: %+v", r)
	}
}

func TestBackupThenDelete(t *testing.T) {
	s := fixture(t)
	path := filepath.Join(t.TempDir(), "sub", "b.json")
	docs := [][]byte{[]byte(`{"x":"viaInv"}`), nil}
	r := Classify(s, linked, docs...)
	if _, _, err := Delete(s, r, path); err == nil {
		t.Fatal("deleted without a backup")
	}
	n, err := Backup(s, r, path)
	if err != nil || n != r.Orphans {
		t.Fatalf("backup %d %v", n, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 || fi.Size() == 0 {
		t.Fatalf("backup mode/size: %v", fi)
	}
	if n2, err := Backup(s, r, path); err != nil || n2 != n { // idempotent
		t.Fatalf("second backup %d %v", n2, err)
	}
	u, d, err := Delete(s, r, path)
	if err != nil || u != r.Orphans || d != r.OrphanDevices {
		t.Fatalf("delete %d %d %v", u, d, err)
	}
	if s.Users["orphan"] != nil || s.Devices["dev-orphan"] != nil {
		t.Fatal("orphan remains")
	}
	for _, id := range []string{"linked", "viaNA", "viaInv", "stale"} {
		if s.Users[id] == nil {
			t.Fatalf("%s was deleted", id)
		}
	}
	if s.Devices["dev-linked"] == nil || s.Devices["dev-dangling"] == nil || len(s.NaToPID) != 1 || len(s.Requests) != 1 {
		t.Fatal("a kept row was touched")
	}
	if _, ok := s.Users["linked"].FriendPrefs["orphan"]; ok {
		t.Fatal("a reference to a deleted orphan remains")
	}
	// Second run: nothing left to do.
	if r2 := Classify(s, linked, docs...); r2.Orphans != 0 {
		t.Fatalf("rerun finds %d", r2.Orphans)
	}
	if u, d, err := Delete(s, Classify(s, linked, docs...), path); u+d != 0 || err != nil {
		t.Fatal("rerun deleted something")
	}
}

func TestDeleteRefusesAMismatchedBackup(t *testing.T) {
	s := fixture(t)
	path := filepath.Join(t.TempDir(), "b.json")
	r := Classify(s, linked)
	if _, err := Backup(s, r, path); err != nil {
		t.Fatal(err)
	}
	s.Users["orphan3"] = &store.User{ID: "orphan3"} // the set moved after the backup
	if _, _, err := Delete(s, Classify(s, linked), path); err == nil {
		t.Fatal("deleted against a backup of another set")
	}
	if s.Users["orphan"] == nil {
		t.Fatal("rows went despite the refusal")
	}
}

func TestRecentlyTouchedUsersAreKept(t *testing.T) {
	s := fixture(t)
	s.Users["orphan"].UpdatedAt = time.Now().Unix() - 60
	r := Classify(s, linked, []byte(`{"x":"viaInv"}`))
	if r.KeptRecent != 1 || s.Users["orphan"] == nil {
		t.Fatalf("recent user not kept: %+v", r)
	}
	for _, id := range r.userIDs {
		if id == "orphan" {
			t.Fatal("recent user classified as an orphan")
		}
	}
}
