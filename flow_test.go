package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"nx-baas/internal/identity"
	"nx-baas/internal/store"
	"os"
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
			s.store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
			u, d := s.store.NewUser()
			if tc.linked {
				s.store.Update(u, func(u *store.User) { u.PID = 1; u.Nickname = "tester"; u.Avatar = tc.avatar })
				s.acct = fakeBackend{id: &identity.Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
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
	s.store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *store.User) { u.PID = 1; u.Nickname = "tester" }) // no console upload
	s.acct = fakeBackend{id: &identity.Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
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

	newServer := func(t *testing.T, siteBody []byte, siteAt int64) (*server, *store.User) {
		t.Helper()
		site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write(siteBody)
		}))
		t.Cleanup(site.Close)
		t.Setenv("NX_DATA", t.TempDir())
		s := dauthServer(t)
		s.store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
		u, _ := s.store.NewUser()
		s.store.Update(u, func(u *store.User) {
			u.PID, u.Nickname = 1, "tester"
			u.Avatar, u.AvatarAt = "/9j/4AAQSkZJRg==", consoleUpload // the console's own
		})
		s.acct = fakeBackend{id: &identity.Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
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

// The exact request a console makes when someone types a friend code, captured
// from hardware on 2026-09-08. The handler looked for a "friendCode" parameter
// that no console has ever sent, so every lookup answered {"count":0} and the
// console said it could not find the user.
func TestFriendCodeLookupUsesTheQueryTheConsoleSends(t *testing.T) {
	s := dauthServer(t)
	s.store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser() // the signed-in console doing the looking up
	s.acct = codeBackend{code: "SW-1000-0000-0002", friend: &identity.Friend{
		PID: 1900000002, BaasUserID: "aaaaaaaaaaaa0002", NaID: "bbbbbbbbbbbb0002",
		FriendCode: "SW-1000-0000-0002", Nickname: "Leia"}}

	for _, target := range []string{
		"/1.0.0/users?filter.links.friendCode.id.$in=1000-0000-0002", // what hardware sends
		"/1.0.0/users?filter.links.friendCode.id.$in=SW-1000-0000-0002",
		"/1.0.0/users?friendCode=SW-1000-0000-0002", // older spelling, still honoured
	} {
		r := httptest.NewRequest("GET", "https://"+baasHost+target, nil)
		r.Host = baasHost
		r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)

		var got struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if len(got.Items) != 1 {
			t.Errorf("%s -> %s; the console says it cannot find the user", target, w.Body.String())
			continue
		}
		if got.Items[0]["id"] != "aaaaaaaaaaaa0002" {
			t.Errorf("%s returned the wrong user: %v", target, got.Items[0]["id"])
		}
		// A search result is a user. presence/isFavoriteFriend/isNewFriend
		// describe a friendship, and a console that was handed them refused
		// the user it had just found.
		for _, friendOnly := range []string{"presence", "isFavoriteFriend", "isNewFriend"} {
			if _, ok := got.Items[0][friendOnly]; ok {
				t.Errorf("%s: search result carries friend-only key %q", target, friendOnly)
			}
		}
	}

	// A code nobody holds is still an empty answer, not an error.
	r := httptest.NewRequest("GET", "https://"+baasHost+"/1.0.0/users?filter.links.friendCode.id.$in=0000-0000-0000", nil)
	r.Host = baasHost
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatalf("unknown code -> %d %s", w.Code, w.Body.String())
	}
}

// codeBackend resolves exactly one friend code, the way the projection store does.
type codeBackend struct {
	fakeBackend
	code   string
	friend *identity.Friend
}

func (b codeBackend) Resolve(q url.Values) (*identity.Friend, error) {
	if q.Get("code") == b.code || (b.friend != nil && q.Get("baas") == b.friend.BaasUserID) {
		return b.friend, nil
	}
	return nil, errNotFound
}

var errNotFound = errors.New("not found")

// What does the console expect in a user object? The one it accepted, which
// is recorded in testdata/accepted-login-shape.json. A search result used to
// carry a fifth of those keys and the console answered "unable to find user"
// to a reply that had found one.
//
// The friend object is allowed to add its own keys (presence, isNewFriend),
// and to leave out the ones that only make sense about yourself.
func TestFriendObjectCarriesWhatAUserObjectCarries(t *testing.T) {
	raw, err := os.ReadFile("testdata/accepted-login-shape.json")
	if err != nil {
		t.Fatal(err)
	}
	var accepted struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(raw, &accepted); err != nil {
		t.Fatal(err)
	}

	s := dauthServer(t)
	s.store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	obj := s.friendObj(identity.Friend{
		PID: 1900000002, BaasUserID: "aaaaaaaaaaaa0002", NaID: "bbbbbbbbbbbb0002",
		FriendCode: "SW-1000-0000-0002", Nickname: "Leia", Country: "GB", CreatedAt: 1788896080,
	}, 1788899654)

	// Only "extras.self" differs on purpose: the blob and isMediaUploaded are
	// about the signed-in user, not about a stranger.
	for key := range accepted.User {
		if _, ok := obj[key]; !ok {
			t.Errorf("missing %q — the console was given this about a user and accepted it", key)
		}
	}
	for _, empty := range []string{"thumbnailUrl", "thumbnail2Url", "nickname", "id", "etag"} {
		if v, _ := obj[empty].(string); v == "" {
			t.Errorf("%s is empty; a user the console cannot render is a user it will not accept", empty)
		}
	}
	if obj["createdAt"] == int64(0) {
		t.Error("createdAt is zero")
	}
}

// The search reply, against a capture of one a console accepted. The envelope
// is the whole point: we answered {"count":1,"users":[...]} for hours while a
// console read "items", found none, and told the person the user did not
// exist. The user object inside was already right.
func TestSearchReplyMatchesTheAcceptedShape(t *testing.T) {
	raw, err := os.ReadFile("testdata/accepted-search-shape.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}

	s := dauthServer(t)
	s.store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser() // the signed-in console doing the looking up
	s.acct = codeBackend{code: "SW-1000-0000-0002", friend: &identity.Friend{
		PID: 1900000002, BaasUserID: "aaaaaaaaaaaa0002", NaID: "bbbbbbbbbbbb0002",
		FriendCode: "SW-1000-0000-0002", Nickname: "Leia", Country: "IE", CreatedAt: 1788896080}}

	r := httptest.NewRequest("GET", "https://"+baasHost+"/1.0.0/users?filter.links.friendCode.id.$in=1000-0000-0002", nil)
	r.Host = baasHost
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing top-level %q — the console reads this and nothing else", k)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("extra top-level %q — not in a reply a console accepted", k)
		}
	}
	wi, _ := want["items"].([]any)
	gi, _ := got["items"].([]any)
	if len(wi) == 0 || len(gi) == 0 {
		t.Fatalf("no item to compare (got %s)", w.Body.String())
	}
	wu, _ := wi[0].(map[string]any)
	gu, _ := gi[0].(map[string]any)
	for k := range wu {
		if _, ok := gu[k]; !ok {
			t.Errorf("item missing %q", k)
		}
	}
	for k := range gu {
		if _, ok := wu[k]; !ok {
			t.Errorf("item carries %q, which the accepted reply does not", k)
		}
	}

	// And inside extras, where four extra keys hid for an evening: foaf and
	// self are empty about somebody else, and friends has no isChatActivated.
	we, _ := wu["extras"].(map[string]any)
	ge, _ := gu["extras"].(map[string]any)
	for group, want := range we {
		wm, _ := want.(map[string]any)
		gm, _ := ge[group].(map[string]any)
		for k := range gm {
			if _, ok := wm[k]; !ok {
				t.Errorf("extras.%s carries %q, which the accepted reply does not", group, k)
			}
		}
		for k := range wm {
			if _, ok := gm[k]; !ok {
				t.Errorf("extras.%s is missing %q", group, k)
			}
		}
	}
}

// A friend-list entry is a *relationship* in the shape the 22.5.0 parser
// counts: friendId, a nested friend user, and the viewer's own relationship
// state. The old flat entry parsed zero items, which is what an empty friend
// list looked like from the sofa with the data sitting in the reply.
func TestFriendListEntriesCarryACountry(t *testing.T) {
	s := dauthServer(t)
	s.store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *store.User) { u.PID, u.Nickname = 1, "Leia" })
	s.acct = fakeBackend{id: &identity.Identity{PID: 1, Nickname: "Leia", FriendCode: "SW-1000-0000-0002", BsDid: "did",
		Friends: []identity.Friend{{PID: 2, BaasUserID: "aaaaaaaaaaaa0001", Nickname: "hansolo",
			FriendCode: "SW-1000-0000-0001", Country: "IE", CreatedAt: 1788818380}}}}

	r := httptest.NewRequest("GET", "https://"+baasHost+"/2.0.0/users/"+u.ID+"/friends?count=300", nil)
	r.Host = baasHost
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	var got struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 {
		t.Fatalf("friends: %s", w.Body.String())
	}
	entry := got.Items[0]
	// The parser's three-field gate: an entry missing any of these never
	// reaches the list, however right the rest of it is.
	if gaps := relationshipEntryGaps(entry); len(gaps) > 0 {
		t.Errorf("entry would be dropped by the parser, missing %v", gaps)
	}
	if entry["friendId"] != "aaaaaaaaaaaa0001" {
		t.Errorf("friendId = %v, want the friend's BAAS id", entry["friendId"])
	}
	friend, _ := entry["friend"].(map[string]any)
	if friend["country"] == "" {
		t.Error("friend has no country; the console refuses a user object like that")
	}
	if friend["nickname"] == "" || friend["thumbnailUrl"] == "" {
		t.Errorf("friend is not renderable: %v", friend)
	}
	// The nested user carries presence; the relationship carries the
	// viewer's own extras.self preferences (SOC-02).
	if _, ok := friend["presence"]; !ok {
		t.Error("friend lacks presence; the applet has nothing to show")
	}
	for _, key := range []string{"isFavorite", "createdAt", "updatedAt"} {
		if _, ok := entry[key]; !ok {
			t.Errorf("relationship lacks %q", key)
		}
	}
	self, _ := entry["extras"].(map[string]any)["self"].(map[string]any)
	for _, key := range []string{"isConfirmed", "isOnlineNotification"} {
		if _, ok := self[key]; !ok {
			t.Errorf("extras.self lacks %q", key)
		}
	}
	// The old flat shape must not come back: top-level id/nickname were what
	// the parser ignored.
	for _, gone := range []string{"id", "nickname", "isFavoriteFriend", "isNewFriend"} {
		if _, ok := entry[gone]; ok {
			t.Errorf("relationship carries flat-entry key %q; the parser reads the nested shape", gone)
		}
	}
	if devs, _ := friend["deviceAccounts"].([]any); len(devs) > 1 {
		t.Errorf("friend reveals %d device accounts; a reference reply carries one", len(devs))
	}
}
