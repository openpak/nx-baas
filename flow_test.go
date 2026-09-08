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

// The account's own picture, on the console. Before this the adapter only
// knew about pictures a console had uploaded, so an account with an avatar on
// the site was shown the generic default on the Switch — and every account
// has an avatar now.
func TestTheConsoleIsShownTheAccountsOwnPicture(t *testing.T) {
	jpegBytes := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	jpegBytes = append(jpegBytes, make([]byte, 512)...)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/console.jpg") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(jpegBytes)
	}))
	defer site.Close()

	t.Setenv("NX_DATA", t.TempDir())
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID = 1; u.Nickname = "tester" }) // no console upload
	s.acct = fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
		FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did",
		AvatarURL: site.URL + "/media/avatars/acct-1/console.jpg"}}

	r := httptest.NewRequest("GET", "https://cdn-image-"+baasHost+"/1/"+u.ID, nil)
	r.Host = "cdn-image-" + baasHost
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("thumbnail = %d, want the account's picture", w.Code)
	}
	if got := w.Body.Bytes(); len(got) != len(jpegBytes) {
		t.Fatalf("served %d bytes, want the %d from the website", len(got), len(jpegBytes))
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Errorf("content-type = %q", ct)
	}
}

// A picture can be changed in two places. The console only refetches when
// thumbnailUploadedAt moves, and it only sees the website's picture if the
// adapter stops preferring the one the console uploaded — so a change made on
// the site used to be invisible on a console that had ever set its own.
func TestTheNewerPictureWins(t *testing.T) {
	const consoleUpload, websiteEdit = int64(1000), int64(2000)

	newServer := func(t *testing.T, siteBody []byte, siteAt int64) (*server, *User) {
		t.Helper()
		site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write(siteBody)
		}))
		t.Cleanup(site.Close)
		t.Setenv("NX_DATA", t.TempDir())
		s := dauthServer(t)
		s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
		u, _ := s.store.NewUser()
		s.store.Update(u, func(u *User) {
			u.PID, u.Nickname = 1, "tester"
			u.Avatar, u.AvatarAt = "/9j/4AAQSkZJRg==", consoleUpload // the console's own
		})
		s.acct = fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
			FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did",
			AvatarURL: site.URL + "/console.jpg", ImageUpdatedAt: siteAt}}
		return s, u
	}

	fromSite := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, make([]byte, 400)...)

	t.Run("the website's is newer", func(t *testing.T) {
		s, u := newServer(t, fromSite, websiteEdit)
		r := httptest.NewRequest("GET", "https://cdn-image-"+baasHost+"/1/"+u.ID, nil)
		r.Host = "cdn-image-" + baasHost
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Body.Len() != len(fromSite) {
			t.Fatalf("served %d bytes, want the website's %d", w.Body.Len(), len(fromSite))
		}
		if got := s.userObj(u, s.identity(u), "")["thumbnailUploadedAt"]; got != websiteEdit {
			t.Fatalf("thumbnailUploadedAt = %v, want the website's %d — the console will not refetch", got, websiteEdit)
		}
	})

	t.Run("the console's is newer", func(t *testing.T) {
		s, u := newServer(t, fromSite, consoleUpload-1)
		r := httptest.NewRequest("GET", "https://cdn-image-"+baasHost+"/1/"+u.ID, nil)
		r.Host = "cdn-image-" + baasHost
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Body.Len() == len(fromSite) {
			t.Fatal("the website's picture overwrote a newer one from the console")
		}
		if got := s.userObj(u, s.identity(u), "")["thumbnailUploadedAt"]; got != consoleUpload {
			t.Fatalf("thumbnailUploadedAt = %v, want the console's %d", got, consoleUpload)
		}
	})
}
