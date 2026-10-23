package store

import "testing"

func TestLoginAdoptsSeededDevicePassword(t *testing.T) {
	s := &Store{FilePath: t.TempDir() + "/baas.json", Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	s.Users["ae575806b0efa797"] = &User{ID: "ae575806b0efa797", PID: 1800000008, DeviceAccounts: []string{"6656e0bbf2927116"}}
	s.Devices["6656e0bbf2927116"] = &DeviceAccount{ID: "6656e0bbf2927116", UserID: "ae575806b0efa797"}
	pw := "PsXq5yp32d0zFUPUD9KBTH0BpIqIZkwJnfdrpeNt"
	if u := s.Login("6656e0bbf2927116", pw); u == nil || u.PID != 1800000008 {
		t.Fatalf("seeded device did not adopt its password / bind to the seeded user: %+v", u)
	}
	if s.Login("6656e0bbf2927116", "WrongPasswordWrongPasswordWrong") != nil {
		t.Fatal("adopted password was not enforced on the second login")
	}
	if len(s.Users) != 1 {
		t.Fatalf("a throwaway user was created: %d users", len(s.Users))
	}
}

// A brand-new account mints a BAAS user id the store has never seen, so Link takes the
// target==nil branch and renames the throwaway. Its device account must follow the rename:
// if it keeps pointing at the old id, the console's next /login gets invalid_device_account
// (console 2124-5002) right after a successful federation.
func TestLinkRepointsDeviceOfRenamedThrowaway(t *testing.T) {
	s := &Store{FilePath: t.TempDir() + "/baas.json", Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, d := s.NewUser()
	throwawayID := u.ID
	linked := s.Link(u, 1849186229, "93fb5b4c4717a199", "e2d6a8df6511f680")
	if linked.ID != "93fb5b4c4717a199" {
		t.Fatalf("link target id: %q", linked.ID)
	}
	if got := s.Devices[d.ID].UserID; got != linked.ID {
		t.Fatalf("device still points at %q (throwaway %q), want %q", got, throwawayID, linked.ID)
	}
	if s.Login(d.ID, d.Password) == nil {
		t.Fatal("login after link returned nil: the console would see invalid_device_account")
	}
}
