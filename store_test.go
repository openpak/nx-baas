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
