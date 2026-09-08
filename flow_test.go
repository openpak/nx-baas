package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Twice now the console has been handed a URL in a reply that our own server
// then answered 404 to: /1/default (2124-7404, both times) and a thumbnail
// that still said "default" after an upload. Nothing checked that the
// addresses we hand out are addresses we serve — that is what this does.
//
// It goes through ServeHTTP, not the BAAS handler, because host routing is
// where a working handler hides behind a missing route.
func TestEveryURLTheConsoleIsHandedIsServed(t *testing.T) {
	urlRe := regexp.MustCompile(`https://[A-Za-z0-9./_+~%:-]+`)

	for _, tc := range []struct {
		name   string
		linked bool
		avatar string
	}{
		{"a fresh device account, before any link", false, ""},
		{"linked, no picture uploaded yet", true, ""},
		{"linked, with the console's own picture", true, "/9j/4AAQSkZJRg=="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NX_DATA", t.TempDir()) // nothing hand-placed, as on a fresh deploy
			s := dauthServer(t)
			s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
			u, d := s.store.NewUser()
			if tc.linked {
				s.store.Update(u, func(u *User) { u.PID = 1; u.Nickname = "tester"; u.Avatar = tc.avatar })
				s.acct = fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
					FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did"}}
			} else {
				s.acct = fakeBackend{}
			}

			login := httptest.NewRequest("POST", "https://"+baasHost+"/1.0.0/login",
				strings.NewReader("id="+d.ID+"&password="+d.Password+"&appAuthNToken=x"))
			login.Host = baasHost
			login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, login)
			if rec.Code != http.StatusOK {
				t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
			}
			var pretty map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &pretty); err != nil {
				t.Fatalf("login reply is not JSON: %v", err)
			}

			found := map[string]bool{}
			for _, raw := range urlRe.FindAllString(rec.Body.String(), -1) {
				found[raw] = true
			}
			if len(found) == 0 {
				t.Fatal("the reply handed the console no URLs at all — has the shape changed?")
			}
			addrs := make([]string, 0, len(found))
			for a := range found {
				addrs = append(addrs, a)
			}
			sort.Strings(addrs)

			for _, addr := range addrs {
				p, err := url.Parse(addr)
				if err != nil {
					t.Errorf("unparsable URL in the reply: %q", addr)
					continue
				}
				r := httptest.NewRequest("GET", addr, nil)
				r.Host = p.Host
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				switch {
				case w.Code != http.StatusOK:
					t.Errorf("%s -> %d; the console was told to fetch this and our own server refuses it", addr, w.Code)
				case w.Body.Len() == 0:
					t.Errorf("%s -> 200 but empty", addr)
				}
			}
		})
	}
}
