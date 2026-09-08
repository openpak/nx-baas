package main

import "testing"

func TestLoginAdoptsSeededDevicePassword(t *testing.T) {
	s := &Store{path: t.TempDir() + "/baas.json", Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
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
	s := &Store{path: t.TempDir() + "/baas.json", Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
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

// "Add account" registers a fresh device account each time it is opened, so
// every failed attempt used to leave one behind on the linked user. Nine of
// them reached a real console on 2026-09-08 and it answered 2124-3121 to a
// reply it had accepted with one. Retrying must not grow the user object.
func TestRetriesDoNotPileUpDeviceAccounts(t *testing.T) {
	s := &Store{path: t.TempDir() + "/baas.json", Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	const console, pid, baasID, naID = "cert-dddddddddddd0001", uint64(1849186229), "93fb5b4c4717a199", "e2d6a8df6511f680"

	var last *DeviceAccount
	for i := 0; i < 9; i++ {
		u, d := s.NewUser()
		s.Login(d.ID, d.Password)
		s.NoteConsole(d.ID, console)
		s.Link(u, pid, baasID, naID)
		last = d
	}

	linked := s.Users[baasID]
	if n := len(linked.DeviceAccounts); n != 1 {
		t.Fatalf("nine attempts left %d device accounts: %v", n, linked.DeviceAccounts)
	}
	if linked.DeviceAccounts[0] != last.ID {
		t.Fatalf("kept %q, want the newest %q", linked.DeviceAccounts[0], last.ID)
	}
	if s.Login(last.ID, last.Password) == nil {
		t.Fatal("the console's current device account must still sign in")
	}
	if len(s.Devices) != 1 {
		t.Fatalf("abandoned device accounts were not deleted: %d remain", len(s.Devices))
	}
}

// A second console on the same account keeps its own device account: pruning
// leftovers must not sign the other console out.
func TestASecondConsoleKeepsItsDeviceAccount(t *testing.T) {
	s := &Store{path: t.TempDir() + "/baas.json", Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	const pid, baasID, naID = uint64(1849186229), "93fb5b4c4717a199", "e2d6a8df6511f680"

	u1, d1 := s.NewUser()
	s.Login(d1.ID, d1.Password)
	s.NoteConsole(d1.ID, "cert-console-one")
	s.Link(u1, pid, baasID, naID)

	u2, d2 := s.NewUser()
	s.Login(d2.ID, d2.Password)
	s.NoteConsole(d2.ID, "cert-console-two")
	s.Link(u2, pid, baasID, naID)

	if n := len(s.Users[baasID].DeviceAccounts); n != 2 {
		t.Fatalf("two consoles, %d device accounts: %v", n, s.Users[baasID].DeviceAccounts)
	}
	if s.Login(d1.ID, d1.Password) == nil {
		t.Fatal("the first console was signed out by the second one linking")
	}
}
