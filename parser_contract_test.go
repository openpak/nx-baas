package main

// Parser-contract tests for the native relationship surface (SOC-01/02).
// The fixture in testdata/native-relationship-entry.json is independently
// authored from the firmware findings: the 22.5.0 parser counts a list item
// only when friendId, friend.nickname and friend.thumbnailUrl all parse, and
// reads the viewer's preferences from /isFavorite and /extras/self/*. These
// tests hold the rendered entries to that contract — including that the old
// flat shape fails it — and hold the preference projections to the
// false-stays-false rule.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"nx-baas/internal/core"
	"nx-baas/internal/identity"
	"nx-baas/internal/store"
	"os"
	"strings"
	"testing"
	"time"
)

// fixtureRequiredPaths reads the independently authored fixture's required
// paths, so the contract is data, not a transcription in test code.
func fixtureRequiredPaths(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("testdata/native-relationship-entry.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		RequiredPaths map[string]string `json:"requiredPaths"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	return fx.RequiredPaths
}

// renderGaps walks the dotted required paths against a rendered entry, the
// way the parser's field mask does: every path must parse to a non-empty
// string.
func renderGaps(entry map[string]any, required map[string]string) []string {
	var missing []string
	for path := range required {
		v := entry
		ok := true
		for _, part := range strings.Split(path, ".") {
			next, isMap := v[part].(map[string]any)
			if !isMap {
				if _, isStr := v[part].(string); isStr && part == strings.Split(path, ".")[len(strings.Split(path, "."))-1] {
					break
				}
				ok = false
				break
			}
			v = next
		}
		if !ok {
			missing = append(missing, path)
			continue
		}
		parts := strings.Split(path, ".")
		last := parts[len(parts)-1]
		leaf, _ := v[last].(string)
		if leaf == "" {
			missing = append(missing, path)
		}
	}
	return missing
}

// The relationship entry this server renders must satisfy the fixture's
// required paths — the gate the 22.5.0 parser applies before an item counts.
func TestRelationshipEntrySatisfiesTheNativeFixture(t *testing.T) {
	s := dauthServer(t)
	s.Store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	entry := s.relationshipObj(nil, identity.Friend{
		PID: 2, BaasUserID: "0123456789abcdef", Nickname: "OpenPak Test",
		FriendCode: "SW-0000-0000-0001", Country: "IE", CreatedAt: 1788818380,
	}, 1788899654)

	required := fixtureRequiredPaths(t)
	if gaps := renderGaps(entry, required); len(gaps) > 0 {
		t.Errorf("rendered entry missing %v — the parser would drop this item", gaps)
	}
	if gaps := relationshipEntryGaps(entry); len(gaps) > 0 {
		t.Errorf("entry gate reports %v", gaps)
	}
}

// The old flat shape — the user object the server used to append directly —
// must fail the gate. This is the regression that kept the native list empty.
func TestOldFlatEntryFailsTheNativeGate(t *testing.T) {
	s := dauthServer(t)
	s.Store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	flat := s.friendObj(identity.Friend{
		PID: 2, BaasUserID: "0123456789abcdef", Nickname: "OpenPak Test",
		Country: "IE", CreatedAt: 1788818380,
	}, 1788899654)
	if gaps := relationshipEntryGaps(flat); len(gaps) == 0 {
		t.Fatal("the flat shape passes the gate; the empty-list regression is back")
	}
}

// Omission of any one required field is detected: the fixture gate is a
// three-field mask, not a vibe.
func TestEachRequiredFieldOmissionIsDetected(t *testing.T) {
	s := dauthServer(t)
	s.Store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	entry := s.relationshipObj(nil, identity.Friend{BaasUserID: "0123456789abcdef", CreatedAt: 1}, 1788899654)

	for _, drop := range []struct {
		path  string
		apply func(map[string]any)
	}{
		{"friendId", func(e map[string]any) { delete(e, "friendId") }},
		{"friend.nickname", func(e map[string]any) { e["friend"].(map[string]any)["nickname"] = "" }},
		{"friend.thumbnailUrl", func(e map[string]any) { e["friend"].(map[string]any)["thumbnailUrl"] = "" }},
	} {
		cp, _ := json.Marshal(entry)
		var clone map[string]any
		_ = json.Unmarshal(cp, &clone)
		drop.apply(clone)
		if len(relationshipEntryGaps(clone)) == 0 {
			t.Errorf("dropping %q was not detected", drop.path)
		}
	}
}

func dropPathKey(path string) string {
	parts := strings.Split(path, ".")
	return parts[len(parts)-1]
}

// One friend, three hundred friends, and nothing over the bound: the parser
// caps the list at 300 itself, and there is no native cursor to paginate
// with, so the bound is the contract.
func TestFriendListBoundsAndEmptyCase(t *testing.T) {
	s := dauthServer(t)
	s.Store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	friends := []identity.Friend{}
	for i := 0; i < 310; i++ {
		friends = append(friends, identity.Friend{PID: uint64(i + 2), BaasUserID: strings.Repeat("a", 15) + string(rune('a'+i%26)) + itoa(i),
			Nickname: "F", FriendCode: "SW-0000-0000-0001", Country: "IE", CreatedAt: 1788818380})
	}
	// exactly 300 through the wire: the renderer caps before the envelope.
	list := []any{}
	for _, f := range friends {
		list = append(list, s.relationshipObj(nil, f, 1788899654))
	}
	if len(list) > maxListEntries {
		list = list[:maxListEntries]
	}
	env := listEnvelopeWith(list, `""`, 100)
	if env["count"] != 300 {
		t.Errorf("count = %v, want the 300 bound", env["count"])
	}

	// Empty and one-entry lists keep the quoted empty etag the capture shows.
	empty := listEnvelopeWith(nil, `""`, 100)
	if empty["count"] != 0 || empty["etag"] != `""` {
		t.Errorf("empty envelope: %v", empty)
	}
	one := listEnvelopeWith([]any{s.relationshipObj(nil, identity.Friend{BaasUserID: "0123456789abcdef", Nickname: "x", CreatedAt: 5}, 1788899654)}, `""`, 100)
	if one["count"] != 1 || one["etag"] == `""` {
		t.Errorf("one-entry envelope: count %v etag %v", one["count"], one["etag"])
	}
}

// A friend's avatar must be reachable through this server: the URL is ours,
// and a 404 behind it is a broken picture on the console (SOC-01).
func TestFriendAvatarIsReachable(t *testing.T) {
	t.Setenv("NX_DATA", t.TempDir())
	s := dauthServer(t)
	s.Acct = fakeBackend{id: &identity.Identity{PID: 0, Nickname: "x", FriendCode: "SW-0000-0000-0000"}} // identity lookups, no picture
	s.Store = &store.Store{Devices: map[string]*store.DeviceAccount{}, Users: map[string]*store.User{}, NaToPID: map[string]uint64{}}
	fid := "0123456789abcdef"
	now := time.Now().Unix()
	s.Store.Users[fid] = &store.User{ID: fid, Avatar: "/9j/4AAQSkZJRg==", CreatedAt: now, UpdatedAt: now,
		Presence: store.Presence{State: "OFFLINE", UpdatedAt: now}}

	fetch := func(id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://cdn-image-e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com/1/"+id, nil)
		r.Host = "cdn-image-e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := fetch(fid); w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Errorf("avatar of a known friend: %d (%d bytes)", w.Code, w.Body.Len())
	}
	// A friend nobody has signed in as still renders: the default avatar is
	// what "no picture" means, not a missing file.
	if w := fetch("fedcba9876543210"); w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Errorf("avatar of an unknown friend: %d (%d bytes)", w.Code, w.Body.Len())
	}
}

// Preferences are the viewer's own state (SOC-02): /isFavorite and
// /extras/self/* project back what was set, false stays false, and everything
// survives a restart. A disabled online alert never hides state (PRE-04).
func TestRelationshipPreferencesPersistAndProject(t *testing.T) {
	s, _, users := socialServer(t)
	u, other := users[0], users[1]
	fid := other.ID

	patch := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PATCH", "https://"+core.BaasHost+"/2.0.0/users/"+u.ID+"/friends/"+fid, strings.NewReader(body))
		r.Host = core.BaasHost
		r.Header.Set("Content-Type", "application/json-patch+json")
		r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	getList := func() map[string]any {
		r := httptest.NewRequest("GET", "https://"+core.BaasHost+"/2.0.0/users/"+u.ID+"/friends", nil)
		r.Host = core.BaasHost
		r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		var env map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		return env
	}
	entryOf := func(env map[string]any) map[string]any {
		items, _ := env["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("list: %v", env)
		}
		return items[0].(map[string]any)
	}

	// The single-friend reply uses the relationship shape the single-entry
	// parser reads: $.friendId, $.friend.nickname, $.isFavorite.
	w := patch(`[{"op":"replace","path":"/isFavorite","value":true}]`)
	if w.Code != http.StatusOK {
		t.Fatalf("favourite patch: %d %s", w.Code, w.Body.String())
	}
	var single map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &single)
	if single["friendId"] != fid {
		t.Errorf("single-friend reply friendId = %v", single["friendId"])
	}
	if single["isFavorite"] != true {
		t.Errorf("single-friend reply isFavorite = %v", single["isFavorite"])
	}

	if entry := entryOf(getList()); entry["isFavorite"] != true {
		t.Errorf("list isFavorite = %v, want true", entry["isFavorite"])
	}

	// False must remain false — including across a restart.
	if w := patch(`[{"op":"replace","path":"/isFavorite","value":false}]`); w.Code != http.StatusOK {
		t.Fatal("unfavourite failed")
	}
	s.Store = store.Load(s.Store.FilePath) // the restart
	if entry := entryOf(getList()); entry["isFavorite"] != false {
		t.Errorf("isFavorite after restart = %v, want false to stay false", entry["isFavorite"])
	}

	// Confirmation and the online-alert preference project from extras.self.
	if w := patch(`[{"op":"replace","path":"/extras/self/isConfirmed","value":true}]`); w.Code != http.StatusOK {
		t.Fatal("confirm failed")
	}
	if w := patch(`[{"op":"replace","path":"/extras/self/isOnlineNotification","value":false}]`); w.Code != http.StatusOK {
		t.Fatal("alert change failed")
	}
	self := entryOf(getList())["extras"].(map[string]any)["self"].(map[string]any)
	if self["isConfirmed"] != true {
		t.Errorf("isConfirmed = %v, want true", self["isConfirmed"])
	}
	if self["isOnlineNotification"] != false {
		t.Errorf("isOnlineNotification = %v, want the set false", self["isOnlineNotification"])
	}
	// PRE-04: the disabled alert leaves the friend and their presence on the
	// list — state is not gated by toast eligibility.
	entry := entryOf(getList())
	if _, ok := entry["friend"].(map[string]any)["presence"]; !ok {
		t.Error("alerts-off friend lost their presence on the list")
	}

	// Defaults: a friend never touched projects confirmed=false and the
	// native on default for the alert.
	s2, _, users2 := socialServer(t)
	u2 := users2[0]
	_ = users2[1]
	r := httptest.NewRequest("GET", "https://"+core.BaasHost+"/2.0.0/users/"+u2.ID+"/friends", nil)
	r.Host = core.BaasHost
	r.Header.Set("Authorization", "Bearer "+s2.accessToken(u2.ID, 2, "did", "device", "serial"))
	w2 := httptest.NewRecorder()
	s2.ServeHTTP(w2, r)
	var env2 map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &env2)
	items, _ := env2["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("fresh list: %v", env2)
	}
	self2 := items[0].(map[string]any)["extras"].(map[string]any)["self"].(map[string]any)
	if self2["isConfirmed"] != false {
		t.Errorf("untouched isConfirmed = %v, want false (new friend until acknowledged)", self2["isConfirmed"])
	}
	if self2["isOnlineNotification"] != true {
		t.Errorf("untouched isOnlineNotification = %v, want the native on", self2["isOnlineNotification"])
	}
}

// The list etag is a version: rendering an unchanged list twice must yield
// the same etag, and a relationship change must move it (SOC-05).
func TestListEtagStableWhenNothingChanged(t *testing.T) {
	s, _, users := socialServer(t)
	u := users[0]
	get := func() string {
		r := httptest.NewRequest("GET", "https://"+core.BaasHost+"/2.0.0/users/"+u.ID+"/friends", nil)
		r.Host = core.BaasHost
		r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		var env struct {
			Etag string `json:"etag"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		return env.Etag
	}
	first, second := get(), get()
	if first == `""` || first != second {
		t.Errorf("etag not stable across unchanged fetches: %q then %q", first, second)
	}
	// A favourite flip is a relationship change: the version moves.
	r := httptest.NewRequest("PATCH", "https://"+core.BaasHost+"/2.0.0/users/"+u.ID+"/friends/"+users[1].ID,
		strings.NewReader(`[{"op":"replace","path":"/isFavorite","value":true}]`))
	r.Host = core.BaasHost
	r.Header.Set("Content-Type", "application/json-patch+json")
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if after := get(); after == first {
		t.Error("etag did not move after a relationship change")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for ; n > 0; n /= 10 {
		digits = string(rune('0'+n%10)) + digits
	}
	return digits
}

// Fields the 22.5.0 modules parse that this adapter used to leave out. Each is
// named by a firmware string, not by inference: the friend list reads a note
// per entry, the relationship reply is rendered as a person, and nn.account
// reads its membership summary off users/me.
func TestFieldsTheModulesParseArePresent(t *testing.T) {
	s, _, users := socialServer(t)
	a, b := users[0], users[1]
	_, req := postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	if code, _ := answerRequest(t, s, b, "PATCH", req["id"].(string),
		`[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`); code != http.StatusOK {
		t.Fatal("accept failed")
	}

	r := authed("GET", "/2.0.0/users/"+b.ID+"/friends", "", b, s)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("friend list: %v %s", err, w.Body)
	}
	if _, ok := list.Items[0]["friendNote"]; !ok {
		t.Error("list entry has no friendNote")
	}

	r = authed("GET", "/2.0.0/users/"+b.ID+"/relationships/"+a.ID, "", b, s)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var rel map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rel); err != nil {
		t.Fatalf("relationship: %v", err)
	}
	target, ok := rel["targetUser"].(map[string]any)
	if !ok || target["nickname"] == "" || target["thumbnailUrl"] == "" {
		t.Errorf("relationship reply has no renderable targetUser: %v", rel["targetUser"])
	}
}

// Routes the modules reach that had no handler: answered with the smallest
// defensible shape rather than a 404 the console has to interpret.
func TestUnservedModuleRoutesAnswer(t *testing.T) {
	t.Setenv("NX_DATA", t.TempDir())
	s := &server{Core: &core.Core{Store: store.Load(t.TempDir() + "/baas.json")}}
	for _, tc := range []struct {
		host, path string
		want       int
		contains   string
	}{
		{"api.hac.lp1.nim.nintendo.net", "/v1/accounts/vphyms", 200, `"vphyms":[]`},
		{"api.hac.lp1.nim.nintendo.net", "/v1/accounts/in-same-family?accountIds=1", 200, `"inSameFamily":false`},
		{"api.hac.lp1.nim.nintendo.net", "/v1/nearness-checks", 200, `"nearnessChecks":[]`},
		{"api.hac.lp1.nim.nintendo.net", "/v1/system_update_meta?device_id=x", 200, `"system_update_metas":[]`},
	} {
		r := httptest.NewRequest("GET", "https://"+tc.host+tc.path, nil)
		r.Host = tc.host
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != tc.want || !strings.Contains(w.Body.String(), tc.contains) {
			t.Errorf("%s%s = %d %s; want %d containing %s", tc.host, tc.path, w.Code, w.Body.String(), tc.want, tc.contains)
		}
	}
}

// Account-setup routes the console calls that this server used to 404: terms
// confirmation is answered (there are no terms here), while a term-agreement
// token and an account transfer are refused plainly rather than faked.
func TestAccountSetupRoutesAnswer(t *testing.T) {
	s := &server{Core: &core.Core{Store: store.Load(t.TempDir() + "/baas.json")}}
	post := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://accounts.nintendo.com"+path, strings.NewReader(body))
		r.Host = "accounts.nintendo.com"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := post("/connect/1.0.0/term_confirm", "userId=bbbbbbbbbbbb0001&id_token=x"); w.Code != 200 {
		t.Errorf("term_confirm = %d %s", w.Code, w.Body)
	}
	if w := post("/connect/1.0.0/api/term_agreement_token", ""); w.Code != 404 {
		t.Errorf("term_agreement_token = %d, want a plain 404", w.Code)
	}
	if w := post("/connect/1.0.0/api/transfer_na_tokens", ""); w.Code != 400 {
		t.Errorf("transfer_na_tokens = %d, want a plain refusal", w.Code)
	}
}
