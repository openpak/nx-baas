package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
)

// fakeBackend is an account source with one account in it, so the login
// endpoint can be driven without a core.
type fakeBackend struct{ id *Identity }

func (f fakeBackend) Identity(uint64) (*Identity, error)  { return f.id, nil }
func (f fakeBackend) Resolve(url.Values) (*Friend, error) { return nil, http.ErrNoLocation }
func (f fakeBackend) LoginPID(string, string) (uint64, string, error) {
	return f.id.PID, f.id.Nickname, nil
}
func (f fakeBackend) FriendRequest(uint64, uint64) error      { return nil }
func (f fakeBackend) FriendAccept(uint64, uint64, bool) error { return nil }
func (f fakeBackend) nexToken(uint64, string) string          { return "nx2.test" }
func (f fakeBackend) nexSigningKey() []byte                   { return []byte("test") }

// The login reply is the object the console parses to decide whether an account
// was added, and when it dislikes one it says 2124-3121 and nothing else. There
// is no error text, no field name, no log on the console — so the only way to
// keep this working is to hold the shape it is known to accept and compare
// against it.
//
// testdata/accepted-login-shape.json is that shape: the keys and types of a
// reply a real console accepted, with every value stripped, so the repository
// carries the target without carrying anybody's account.
//
// This test has caught, after the fact: an extra top-level "summary" key we
// invented, extras.self losing its nxAccount, and a thumbnail that still said
// "default" after the console had uploaded a picture.
func TestLoginReplyMatchesTheShapeAConsoleAccepts(t *testing.T) {
	raw, err := os.ReadFile("testdata/accepted-login-shape.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}

	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, d := s.store.NewUser()
	// A linked user with a picture: the state a console is in right after it
	// adds an account, which is exactly when 2124-3121 appears.
	s.store.Update(u, func(u *User) {
		u.PID = 1 // linked: an unlinked user has no friend code to serve
		u.NxAccount = "AAAA"
		u.Avatar = "/9j/4AAQ"
		u.Nickname = "tester"
	})
	id := &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
		FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did"}

	// Through the real endpoint, not by building the object here: the first
	// version of this test assembled the top level itself and therefore could
	// not see the extra "summary" key the handler was adding — which is the
	// bug it existed to catch. Verified by putting that key back and watching
	// this fail.
	s.acct = fakeBackend{id: id}
	form := "id=" + d.ID + "&password=" + d.Password + "&appAuthNToken=x"
	r := httptest.NewRequest("POST", "https://"+baasHost+"/1.0.0/login", nil)
	r.Host = baasHost
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.baas(w, r, []byte(form))
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("login reply is not JSON: %v", err)
	}

	if missing, extra := compareShape(want, got, ""); len(missing)+len(extra) > 0 {
		for _, k := range missing {
			t.Errorf("missing: %s — the console was given this and accepted it", k)
		}
		for _, k := range extra {
			t.Errorf("extra: %s — not in a reply the console is known to accept", k)
		}
	}
}

// compareShape walks the expected shape and reports keys that are absent from
// the reply, and keys the reply adds. Values are not compared: ids, timestamps
// and tokens differ per account and per second, and none of that is the thing
// that breaks a parser.
func compareShape(want map[string]any, got map[string]any, path string) (missing, extra []string) {
	for k, wv := range want {
		p := k
		if path != "" {
			p = path + "." + k
		}
		gv, ok := got[k]
		if !ok {
			missing = append(missing, p)
			continue
		}
		wm, wIsMap := wv.(map[string]any)
		gm, gIsMap := gv.(map[string]any)
		if wIsMap && gIsMap {
			m, e := compareShape(wm, gm, p)
			missing, extra = append(missing, m...), append(extra, e...)
		}
	}
	for k := range got {
		p := k
		if path != "" {
			p = path + "." + k
		}
		if _, ok := want[k]; !ok && !strings.HasPrefix(p, "user.deviceAccounts") {
			extra = append(extra, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

// image_upload used to answer `{}`. So did push_channels once, and the console
// said the account could not be linked every single time until it was given a
// real object; `{}` to a console request is that failure verbatim. It is the
// last thing we answer during "add account" before 2124-3121 appears.
func TestImageUploadAnswersTheUserObjectNotAnEmptyOne(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID = 1; u.Nickname = "tester" })
	s.acct = fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
		FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did"}}

	r := httptest.NewRequest("POST", "https://"+baasHost+"/1.0.0/image_upload", nil)
	r.Host = baasHost
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	body := []byte(`{"rawContent":"/9j/4AAQSkZJRg=="}`)
	w := httptest.NewRecorder()
	s.baas(w, r, body)

	if w.Code != http.StatusOK {
		t.Fatalf("image_upload = %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("image_upload answered `{}` — the push_channels failure, verbatim")
	}
	user, ok := got["user"].(map[string]any)
	if !ok {
		user = got
	}
	if user["thumbnailUrl"] == nil || user["id"] == nil {
		t.Fatalf("the reply says nothing about where the picture went: %s", w.Body.String())
	}
	if !strings.Contains(user["thumbnailUrl"].(string), u.ID) {
		t.Fatalf("thumbnail still points at the default after an upload: %v", user["thumbnailUrl"])
	}
}
