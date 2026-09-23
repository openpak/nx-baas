package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseClient(t *testing.T) {
	for in, want := range map[string]string{
		"ryujinx/1.2.3":      "ryujinx",
		"Eden/0.1":           "eden",
		" citron ":           "citron",
		"":                   "",
		"<script>/1":         "",
		"a very long name/1": "",
	} {
		if got := parseClient(in); got != want {
			t.Errorf("parseClient(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientLabels(t *testing.T) {
	for _, c := range []struct{ ns, client, want string }{
		{"switch", "", "Switch"}, {"switch", "switch", "Switch"}, {"switch", "ryujinx", "Ryujinx"},
		{"switch", "eden", "Eden"}, {"switch", "citron", "Citron"}, {"wiiu", "", "Wii U"},
		{"3ds", "", "3DS"}, {"wiiu", "cemu", "Cemu"}, {"3ds", "azahar", "Azahar"},
	} {
		if got := clientLabel(c.ns, c.client); got != c.want {
			t.Errorf("clientLabel(%q,%q) = %q, want %q", c.ns, c.client, got, c.want)
		}
	}
	if got := presenceDescription("3DS", "", ""); got != "Online on 3DS" {
		t.Errorf("title-less: %q", got)
	}
	if got := presenceDescription("Wii U", "0005000010101d00", "Mario Kart 8"); got != "Playing Mario Kart 8 on Wii U" {
		t.Errorf("named: %q", got)
	}
	if got := descriptionAppField("Playing Mario & Luigi on 3DS"); got != `{"sys_description":"Playing Mario & Luigi on 3DS"}` {
		t.Errorf("appField: %s", got)
	}
}

// An emulator names itself on the presence PATCH; the name rides on the device
// claim into the core session, both the title-less "signed in" one and the
// reconciler's.
func TestClientHeaderReachesTheCore(t *testing.T) {
	s, sess, _, u := presenceFixture(t)
	b := s.acct.(*openpakBackend)
	account := b.accountFor(u.PID)
	r := authed("PATCH", "/1.0.0/users/"+u.ID+"/device_accounts/dev-emu",
		`[{"op":"replace","path":"/presence/state","value":"PLAYING"},
		  {"op":"add","path":"/presence/extras/friends/appInfo:appId","value":"01004d300c5ae000"}]`, u, s)
	r.Header.Set("X-OpenPak-Client", "ryujinx/1.3.0")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	if got := s.store.User(u.ID).DevicePresence["dev-emu"].Client; got != "ryujinx" {
		t.Fatalf("claim client = %q", got)
	}
	client := func() string {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		return sess.clients[account]
	}
	if got := client(); got != "ryujinx" {
		t.Fatalf("title-less core session client = %q", got)
	}
	s.reconcilePresenceOnce(time.Now(), presenceLease())
	if got := client(); got != "ryujinx" {
		t.Fatalf("reconciled core session client = %q", got)
	}

	// The same person moves to a real console (Penne): the session is
	// re-registered with the new client, not heartbeaten with the old one.
	s.noteClientPresence(s.store.User(u.ID), "dev-emu", "switch", "PLAYING", "01004d300c5ae000", "{}", "01004d300c5ae000", -1)
	s.reconcilePresenceOnce(time.Now().Add(time.Second), presenceLease())
	if got := client(); got != "switch" {
		t.Fatalf("after moving to the console, core client = %q", got)
	}
}

// A friend on a 3DS with a known title: the description names it, and the
// console still gets no foreign title id.
func TestForeignFriendDescriptionNamesTheTitle(t *testing.T) {
	s, sess, viewer, friend := presenceFixture(t)
	sess.namespace = "3ds"
	b := s.acct.(*openpakBackend)
	account := b.accountFor(friend.PID)
	prev := siteTitleNames
	siteTitleNames = &titleNames{byKey: map[string]*titleNameEntry{}, fetch: func(ns, id string) (string, bool) {
		if ns == "3ds" && id == "0004000000030800" {
			return "Mario Kart 7", true
		}
		return "", true
	}}
	t.Cleanup(func() { siteTitleNames = prev })
	siteTitleNames.name("3ds", "0004000000030800") // first sight starts the fetch
	deadline := time.Now().Add(2 * time.Second)
	for siteTitleNames.name("3ds", "0004000000030800") == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	sess.mu.Lock()
	sess.byAcct[account] = "sess-x"
	sess.leases["sess-x"] = time.Now().Unix() + 60
	sess.titles = map[string]string{account: "0004000000030800"}
	sess.clients = map[string]string{account: "azahar"}
	sess.mu.Unlock()

	p := friendPresenceOf(t, s, viewer, friend)
	if p["state"] != "ONLINE" {
		t.Fatalf("state = %v", p["state"])
	}
	friends := p["extras"].(map[string]any)["friends"].(map[string]any)
	if _, leaked := friends["appInfo:appId"]; leaked {
		t.Fatalf("foreign title id reached the console: %v", friends)
	}
	if friends["appField"] != `{"sys_description":"Playing Mario Kart 7 on Azahar"}` {
		t.Fatalf("appField = %v", friends["appField"])
	}

	// The kill switch leaves the old plain ONLINE.
	t.Setenv("NX_FOREIGN_PRESENCE_DESCRIPTION", "0")
	p = friendPresenceOf(t, s, viewer, friend)
	if f, _ := p["extras"].(map[string]any)["friends"].(map[string]any); len(f) != 0 {
		t.Fatalf("description served with the switch off: %v", f)
	}
}
