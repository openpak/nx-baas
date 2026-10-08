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

func (f fakeBackend) Identity(uint64) (*Identity, error) { return f.id, nil }
func (f fakeBackend) friendCodeForAccount(string) (string, bool) {
	if f.id == nil || f.id.FriendCode == "" {
		return "", false
	}
	return f.id.FriendCode, true
}
func (f fakeBackend) accountForFriendCode(string) (string, bool) { return "", false }

func (f fakeBackend) RegenerateFriendCode(uint64) error { return nil }

// Resolve answers baas-id lookups with a synthetic user, so the mutation
// handlers' target resolution succeeds for whatever id a test names. Code
// lookups stay unresolvable: search tests use codeBackend, which owns that
// behaviour.
func (f fakeBackend) Resolve(q url.Values) (*Friend, error) {
	if id := q.Get("baas"); id != "" {
		return &Friend{BaasUserID: id, Nickname: "Someone", FriendCode: "SW-0000-0000-0001", Country: "IE"}, nil
	}
	return nil, http.ErrNoLocation
}
func (f fakeBackend) LoginPID(string, string) (uint64, string, error) {
	return f.id.PID, f.id.Nickname, nil
}
func (f fakeBackend) FriendRequest(uint64, uint64) error      { return nil }
func (f fakeBackend) FriendAccept(uint64, uint64, bool) error { return nil }
func (f fakeBackend) RemoveFriend(uint64, uint64) error       { return nil }
func (f fakeBackend) Block(uint64, uint64) error              { return nil }
func (f fakeBackend) Unblock(uint64, uint64) error            { return nil }
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

// The account sysmodule's profile upload, as 22.5.0 and 23.0.1 run it: POST
// image_upload, keep $.content.url, PATCH /nickname and /extras/self/nxAccount,
// then require the PATCH reply to repeat both. image_upload answered `{}` and
// then the user object; the sysmodule reads only $.content.url and
// $.content.format ("jpg") from it, so every sync ended there with 2124-3121
// (account 23.0.1 .text 0xed978) and started over on the next cycle.
func TestProfileUploadCompletesTheWayTheSysmoduleChecksIt(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID = 1; u.Nickname = "tester" })
	s.acct = fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "website name",
		FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did"}}
	bearer := "Bearer " + s.accessToken(u.ID, 2, "did", "device", "serial")
	call := func(method, path, body string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(method, "https://"+baasHost+path, nil)
		r.Host = baasHost
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", bearer)
		w := httptest.NewRecorder()
		s.baas(w, r, []byte(body))
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s = %d: %s", method, path, w.Code, w.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s %s: not JSON: %v", method, path, err)
		}
		return got
	}

	got := call("POST", "/1.0.0/image_upload", `{"rawContent":"/9j/4AAQSkZJRg==","ownerId":"`+u.ID+`","allowTransform":false}`)
	content, _ := got["content"].(map[string]any)
	url, _ := content["url"].(string)
	if url == "" || len(url) >= 0x100 {
		t.Fatalf("$.content.url = %q: the sysmodule needs a url under 256 bytes or the sync fails with 2124-3121", url)
	}
	if content["format"] != "jpg" {
		t.Fatalf(`$.content.format = %v, want "jpg": anything else is 2124-3121`, content["format"])
	}
	// The kept url is matched against later thumbnailUrls by its last path
	// segment; a different one makes the console upload the picture again.
	last := func(s string) string { return s[strings.LastIndex(s, "/")+1:] }
	if user := call("GET", "/1.0.0/users/"+u.ID, ""); last(user["thumbnailUrl"].(string)) != last(url) {
		t.Fatalf("thumbnailUrl %v does not end like the uploaded %s", user["thumbnailUrl"], url)
	}

	// The PATCH that follows the upload: its reply must carry back exactly the
	// nickname and nxAccount it sent (23.0.1 0xe8a5c), even when the console's
	// nickname is not the website's.
	const blob = "01606150AAAA"
	user := call("PATCH", "/1.0.0/users/"+u.ID, `[{"op":"replace","path":"/nickname","value":"Leia"},`+
		`{"op":"replace","path":"/extras/self/nxAccount","value":"`+blob+`"}]`)
	if user["nickname"] != "Leia" {
		t.Errorf("PATCH reply nickname = %v, want the %q the console sent", user["nickname"], "Leia")
	}
	if nx := user["extras"].(map[string]any)["self"].(map[string]any)["nxAccount"]; nx != blob {
		t.Errorf("PATCH reply nxAccount = %v, want the blob the console sent", nx)
	}
	// And the next sync's GET agrees with the console, so it has nothing to do.
	if again := call("GET", "/1.0.0/users/"+u.ID, ""); again["nickname"] != "Leia" {
		t.Errorf("GET after the PATCH says nickname %v; the console would upload again", again["nickname"])
	}
}

// The shape test above seeds a blob the console had already uploaded, so it
// never noticed that production served extras.self without nxAccount or
// isMediaUploaded at all -- which is the state a console is in the first time
// it links, and exactly what the accepted capture does NOT look like.
func TestExtrasSelfIsNeverBareForALinkedUser(t *testing.T) {
	t.Setenv("NX_TEST_NXACCOUNT", "01606150mCH48QS0EACctpGPncaKYw")

	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, d := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID = 1; u.Nickname = "tester" }) // no blob: the console never uploaded one
	s.acct = fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
		FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did"}}

	r := httptest.NewRequest("POST", "https://"+baasHost+"/1.0.0/login", nil)
	r.Host = baasHost
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.baas(w, r, []byte("id="+d.ID+"&password="+d.Password+"&appAuthNToken=x"))

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	self := got["user"].(map[string]any)["extras"].(map[string]any)["self"].(map[string]any)
	if self["nxAccount"] == nil || self["isMediaUploaded"] != true {
		t.Fatalf("extras.self went out bare: %v", self)
	}
}

// Every unlinked user's thumbnail points at /1/default, and a 404 there is
// console 2124-7404 in the middle of "add account". The picture used to be a
// file someone put in NX_DATA by hand; the deployed volume did not have one,
// so the console hit the 404 on a live link tonight.
func TestDefaultThumbnailIsServedWithNoDataDirectory(t *testing.T) {
	t.Setenv("NX_DATA", t.TempDir()) // empty: nothing hand-placed
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}

	for _, p := range []string{"/1/default", "/2/default"} {
		r := httptest.NewRequest("GET", "https://cdn-image-"+baasHost+p, nil)
		r.Host = "cdn-image-" + baasHost
		w := httptest.NewRecorder()
		s.baas(w, r, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 (this is 2124-7404 on a console)", p, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "image/jpeg" {
			t.Errorf("%s content-type = %q", p, ct)
		}
		if b := w.Body.Bytes(); len(b) < 1000 || b[0] != 0xFF || b[1] != 0xD8 {
			t.Errorf("%s did not serve a JPEG (%d bytes)", p, len(b))
		}
	}
}
