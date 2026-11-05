package store

import "testing"

func eraseFixture(t *testing.T) *Store {
	s := Load(t.TempDir() + "/baas.json")
	s.Users["gone"] = &User{ID: "gone", PID: 11, NaID: "na-gone", DeviceAccounts: []string{"dev-gone"}}
	s.Users["keep"] = &User{ID: "keep", PID: 22, NaID: "na-keep", DeviceAccounts: []string{"dev-keep"},
		Blocks:       []string{"gone", "other"},
		Favourites:   []string{"gone"},
		BlockDetails: map[string]*BlockDetail{"gone": {}, "other": {}},
		FriendPrefs:  map[string]*FriendPreference{"gone": {Favorite: true}, "other": {}}}
	s.Devices["dev-gone"] = &DeviceAccount{ID: "dev-gone", UserID: "gone"}
	s.Devices["dev-keep"] = &DeviceAccount{ID: "dev-keep", UserID: "keep"}
	s.NaToPID["na-gone"], s.NaToPID["na-keep"] = 11, 22
	s.Requests = map[string]*FriendRequestRecord{}
	s.Requests["r1"] = &FriendRequestRecord{ID: "r1", FromPID: 11, ToPID: 22}
	s.Requests["r2"] = &FriendRequestRecord{ID: "r2", FromPID: 22, ToPID: 33}
	return s
}

func TestEraseAccountRemovesOnlyThatAccount(t *testing.T) {
	s := eraseFixture(t)
	n, err := s.EraseAccount("gone", 11, "na-gone")
	if err != nil || n == 0 {
		t.Fatalf("erase = %d, %v", n, err)
	}
	if s.Users["gone"] != nil || s.Devices["dev-gone"] != nil || s.NaToPID["na-gone"] != 0 || s.Requests["r1"] != nil {
		t.Fatalf("rows of the erased account remain: %+v", s)
	}
	k := s.Users["keep"]
	if k == nil || s.Devices["dev-keep"] == nil || s.NaToPID["na-keep"] != 22 || s.Requests["r2"] == nil {
		t.Fatal("another account's rows were touched")
	}
	if len(k.Blocks) != 1 || k.Blocks[0] != "other" || len(k.Favourites) != 0 ||
		k.BlockDetails["gone"] != nil || k.BlockDetails["other"] == nil ||
		k.FriendPrefs["gone"] != nil || k.FriendPrefs["other"] == nil {
		t.Fatalf("references to the erased user remain or others lost: %+v", k)
	}
	// Durable: a reload from the stored document shows the same.
	r := Load(s.FilePath)
	if r.Users["gone"] != nil || r.Users["keep"] == nil || r.Devices["dev-gone"] != nil {
		t.Fatal("erasure did not reach the stored document")
	}
	// Idempotent.
	if n, err := s.EraseAccount("gone", 11, "na-gone"); err != nil || n != 0 {
		t.Fatalf("second erase = %d, %v", n, err)
	}
	if n, _ := s.EraseAccount("", 0, ""); n != 0 {
		t.Fatal("empty ids erased something")
	}
}
