package main

import (
	"net/http/httptest"
	"nx-baas/internal/identity"
	"nx-baas/internal/presence"
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
		if got := presence.ParseClient(in); got != want {
			t.Errorf("parseClient(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseClientOS(t *testing.T) {
	for in, want := range map[string]string{
		"ryujinx/1.3.2 (macOS)": "macos",
		"eden/0.1 (Windows)":    "windows",
		"citron/0.7 ( linux )":  "linux",
		"ryujinx/1.3.2":         "",
		"ryujinx/1.3.2 (beos)":  "",
		"ryujinx/1.3.2 (ios":    "",
		"":                      "",
	} {
		if got := presence.ParseClientOS(in); got != want {
			t.Errorf("parseClientOS(%q) = %q, want %q", in, got, want)
		}
	}
	if got := presence.ParseClient("ryujinx/1.3.2 (macOS)"); got != "ryujinx" {
		t.Errorf("parseClient with os = %q", got)
	}
}

func TestClientLabels(t *testing.T) {
	for _, c := range []struct{ ns, client, want string }{
		{"switch", "", "Switch"}, {"switch", "switch", "Switch"}, {"switch", "ryujinx", "Ryujinx"},
		{"switch", "eden", "Eden"}, {"switch", "citron", "Citron"}, {"wiiu", "", "Wii U"},
		{"3ds", "", "3DS"}, {"wiiu", "cemu", "Cemu"}, {"3ds", "azahar", "Azahar"},
		// A real console is its platform, an emulator is itself.
		{"np", "", "PS3"}, {"np", "pier", "Pier"}, {"xbox360", "", "Xbox 360"}, {"xbox360", "wharf", "Wharf"},
		{"switch", "harbor", "Harbor"}, {"wii", "", "Wii"}, {"wii", "dolphin", "Dolphin"},
		{"nds", "", "NDS"}, {"3ds", "3ds", "3DS"}, {"np", " Pier ", "Pier"}, {"", "", ""},
		{"np", "someemu", "Someemu"},
	} {
		if got := presence.ClientLabel(c.ns, c.client); got != c.want {
			t.Errorf("clientLabel(%q,%q) = %q, want %q", c.ns, c.client, got, c.want)
		}
	}
	if got := presence.Description("3DS", "", ""); got != "Online on 3DS" {
		t.Errorf("title-less: %q", got)
	}
	if got := presence.Description("Wii U", "0005000010101d00", "Mario Kart 8"); got != "Playing Mario Kart 8 on Wii U" {
		t.Errorf("named: %q", got)
	}
	if got := presence.DescriptionAppField("Playing Mario & Luigi on 3DS"); got != `{"sys_description":"Playing Mario & Luigi on 3DS"}` {
		t.Errorf("appField: %s", got)
	}
}

// An emulator names itself on the presence PATCH; the name rides on the device
// claim into the core session, both the title-less "signed in" one and the
// reconciler's.
func TestClientHeaderReachesTheCore(t *testing.T) {
	s, sess, _, u := presenceFixture(t)
	b := s.Acct.(*identity.OpenpakBackend)
	account := b.AccountFor(u.PID)
	r := authed("PATCH", "/1.0.0/users/"+u.ID+"/device_accounts/dev-emu",
		`[{"op":"replace","path":"/presence/state","value":"PLAYING"},
		  {"op":"add","path":"/presence/extras/friends/appInfo:appId","value":"01004d300c5ae000"}]`, u, s)
	r.Header.Set("X-OpenPak-Client", "ryujinx/1.3.0 (macOS)")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	if got := s.Store.User(u.ID).DevicePresence["dev-emu"]; got.Client != "ryujinx" || got.OS != "macos" {
		t.Fatalf("claim client = %q os = %q", got.Client, got.OS)
	}
	client := func() string {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		return sess.clients[account] + "/" + sess.oses[account]
	}
	if got := client(); got != "ryujinx/macos" {
		t.Fatalf("title-less core session client = %q", got)
	}
	// The reconciler re-registers from the stored claim: the OS survives it.
	delete(s.presenceSvc().LiveSessions, u.ID)
	s.presenceSvc().ReconcileOnce(time.Now(), presence.Lease())
	if got := client(); got != "ryujinx/macos" {
		t.Fatalf("reconciled core session client = %q", got)
	}

	// The same person moves to a real console (Penne): the session is
	// re-registered with the new client, not heartbeaten with the old one.
	s.presenceSvc().NoteClientPresence(s.Store.User(u.ID), "dev-emu", "switch", "", "PLAYING", "01004d300c5ae000", "{}", "01004d300c5ae000", -1)
	s.presenceSvc().ReconcileOnce(time.Now().Add(time.Second), presence.Lease())
	if got := client(); got != "switch/" {
		t.Fatalf("after moving to the console, core client = %q", got)
	}
}

// A friend on a 3DS with a known title: the description names it, and the
// console still gets no foreign title id.
func TestForeignFriendDescriptionNamesTheTitle(t *testing.T) {
	s, sess, viewer, friend := presenceFixture(t)
	sess.namespace = "3ds"
	b := s.Acct.(*identity.OpenpakBackend)
	account := b.AccountFor(friend.PID)
	prev := presence.SiteTitleNames
	presence.SiteTitleNames = presence.NewTitleNames(func(ns, id string) (string, bool) {
		if ns == "3ds" && id == "0004000000030800" {
			return "Mario Kart 7", true
		}
		return "", true
	})
	t.Cleanup(func() { presence.SiteTitleNames = prev })
	presence.SiteTitleNames.Name("3ds", "0004000000030800") // first sight starts the fetch
	deadline := time.Now().Add(2 * time.Second)
	for presence.SiteTitleNames.Name("3ds", "0004000000030800") == "" && time.Now().Before(deadline) {
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
