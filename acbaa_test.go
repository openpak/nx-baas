package main

// The acbaa surface has one job the game can tell apart from a failure: hand
// back a msgpack land record for the island it posts. Before this, the call
// fell into the catch-all 404 and ACNH errored (2219-xxxx) before ever
// reaching NEX. These pin the observed bytes and the answer shape; the game's
// next request is the oracle for the rest of the API.

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The exact 65 bytes ACNH 3.0.3 posted on 2026-09-21 (island "lovely "):
// fixmap(5){name, display_id:2, in_app_id:2720403009, region:0, hemisphere:0}.
var acbaaObservedLand = []byte("\x85\xa4name\xa7lovely " +
	"\xaadisplay_id\x02" +
	"\xa9in_app_id\xd3\x00\x00\x00\x00\xa2&\x0eA" +
	"\xa6region\x00" +
	"\xaahemisphere\x00")

func TestAcbaaDecodeReadsTheObservedLandPost(t *testing.T) {
	if len(acbaaObservedLand) != 65 {
		t.Fatalf("fixture is %d bytes, want the observed 65", len(acbaaObservedLand))
	}
	v, err := msgpackDecode(acbaaObservedLand)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	land, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("body is %T, want map", v)
	}
	if land["name"] != "lovely " {
		t.Errorf("name = %#v, want %q", land["name"], "lovely ")
	}
	if land["display_id"] != int64(2) {
		t.Errorf("display_id = %#v, want 2", land["display_id"])
	}
	if land["in_app_id"] != int64(2720403009) {
		t.Errorf("in_app_id = %#v, want 2720403009", land["in_app_id"])
	}
	if land["region"] != int64(0) || land["hemisphere"] != int64(0) {
		t.Errorf("region/hemisphere = %#v/%#v, want 0/0", land["region"], land["hemisphere"])
	}
}

func TestAcbaaDecodeRefusesGarbage(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"truncated map", []byte("\x85\xa4name")},
		{"trailing bytes", append(bytes.Clone(acbaaObservedLand), 0x00)},
		{"unknown tag", []byte("\xd4\x01\x00")},
		{"non-string key", []byte("\x81\x01\x02")},
	} {
		if _, err := msgpackDecode(tc.body); err == nil {
			t.Errorf("%s: decoded without error", tc.name)
		}
	}
}

// The posted island must come back as a msgpack record carrying a server id,
// or the game stays on its 2219-xxxx error. Routed through ServeHTTP, not the
// handler, because reaching the handler at all (past the catch-all) is half
// of this fix.
func TestAcbaaRegisterLandAnswersThePostedIsland(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/lands",
		bytes.NewReader(acbaaObservedLand))
	r.Header.Set("Content-Type", "application/x-msgpack")
	r.Header.Set("Authorization", "Bearer fake")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-msgpack" {
		t.Fatalf("content-type %q, want msgpack", ct)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("answer is not msgpack: %v", err)
	}
	land, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("answer is %T, want map", v)
	}
	// Exactly the documented shape, {id: Uint64, password: String} — a
	// nested land record was tried here and the flow never advanced past
	// setup, so the test pins the documented bytes only.
	if id := msgpackReadUintOf(land["id"]); id != 2720403009 {
		t.Errorf("id = %v, want the island's in_app_id", land["id"])
	}
	pw, ok := land["password"].(string)
	if !ok || pw == "" {
		t.Fatalf("password = %#v, want a non-empty string", land["password"])
	}
	if len(land) != 2 {
		t.Errorf("answer has %d fields, want exactly id+password", len(land))
	}
}

// The exact 39 bytes ACNH 3.0.3 posted on 2026-09-21 (player "hansolo",
// born June 9): fixmap(3){name, birth_month:6, birth_date:9}.
var acbaaObservedUser = []byte("\x83\xa4name\xa7hansolo" +
	"\xabbirth_month\x06" +
	"\xaabirth_date\x09")

// POST /api/v1/users answers {id, password}: the game asked for it the
// moment /lands stopped 404ing, and surfaces our error code as its own
// (2219-3004 on the loud 404).
func TestAcbaaRegisterUserAnswersIdAndPassword(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/users",
		bytes.NewReader(acbaaObservedUser))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("answer is not msgpack: %v", err)
	}
	user, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("answer is %T, want map", v)
	}
	if msgpackReadUintOf(user["id"]) == 0 {
		t.Errorf("id = %#v, want non-zero", user["id"])
	}
	if pw, _ := user["password"].(string); pw == "" {
		t.Errorf("password = %#v, want non-empty", user["password"])
	}
	if len(user) != 2 {
		t.Errorf("answer has %d fields, want exactly id+password", len(user))
	}
}

// The user id is the BAAS account's own numeric id (Bearer sub, hex): same
// account, same ACNH user, nothing stored.
func TestAcbaaUserIdBindsToBearerSub(t *testing.T) {
	s := &server{}
	post := func(tok string) map[string]any {
		r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/users",
			bytes.NewReader(acbaaObservedUser))
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("status %d, want 200", w.Code)
		}
		v, err := msgpackDecode(w.Body.Bytes())
		if err != nil {
			t.Fatalf("answer is not msgpack: %v", err)
		}
		return v.(map[string]any)
	}
	// sub aaaaaaaaaaaa0001 is the production BAAS user from the live capture.
	tok := "eyJhbGciOiJSUzI1NiIsImtpZCI6IngifQ." +
		"eyJzdWIiOiJhYWFhYWFhYWFhYWEwMDAxIn0.c2ln"
	first := post(tok)
	if id := msgpackReadUintOf(first["id"]); id != 0xaaaaaaaaaaaa0001 {
		t.Errorf("id = %#x, want the Bearer sub", id)
	}
	again := post(tok)
	if msgpackReadUintOf(again["id"]) != msgpackReadUintOf(first["id"]) ||
		again["password"] != first["password"] {
		t.Errorf("repeat post moved id/password: %#v vs %#v", again, first)
	}
}

// POST /api/v1/auth_token swaps the {id, password} from /users for a call
// token: the game asked for it the moment /users stopped 404ing.
func TestAcbaaAuthTokenMintsVerifiableToken(t *testing.T) {
	s := &server{}
	id := uint64(0xaaaaaaaaaaaa0001)
	body := msgpackOrdered("id", id, "password", acbaaUserPassword(id))
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/auth_token",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("answer is not msgpack: %v", err)
	}
	resp, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("answer is %T, want map", v)
	}
	token, _ := resp["token"].(string)
	if token == "" {
		t.Fatalf("token = %#v, want non-empty", resp["token"])
	}
	if exp := msgpackReadIntOf(resp["expire_at"]); exp <= 0 {
		t.Errorf("expire_at = %#v, want a future timestamp", resp["expire_at"])
	}
	if got, ok := acbaaVerifyToken(token); !ok || got != id {
		t.Errorf("verify(%q) = (%d, %v), want (%d, true)", token, got, ok, id)
	}
}

// A wrong password is the documented 401/4001 (invalid authorization) —
// which is also the 2219-4001 the game shows when its stored credentials go
// stale. Tampered tokens verify false the same way.
func TestAcbaaAuthTokenRefusesBadCredentials(t *testing.T) {
	s := &server{}
	body := msgpackOrdered("id", uint64(0xaaaaaaaaaaaa0001), "password", "wrong")
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/auth_token",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("status %d, want 401", w.Code)
	}
	if _, ok := acbaaVerifyToken("v1.deadbeef.0123456789abcdef0123456789abcdef"); ok {
		t.Errorf("tampered token verified")
	}
	if _, ok := acbaaVerifyToken("garbage"); ok {
		t.Errorf("garbage token verified")
	}
}

// PUT /api/v1/users/<uid>/land binds the player to their island with the
// land's {id, password} presented back verbatim. Success is a bare 200 (no
// body is documented for any PUT here); strangers and wrong passwords get
// 401/4001.
func TestAcbaaBindUserLand(t *testing.T) {
	s := &server{}
	uid := uint64(0xaaaaaaaaaaaa0001)
	land := uint64(2720403009)
	path := "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/users/12297829382472990721/land"
	if uid != 12297829382472990721 {
		t.Fatalf("fixture uid mismatch: %#x", uid)
	}
	put := func(tok string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PUT", path, bytes.NewReader(body))
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	good := msgpackOrdered("id", land, "password", acbaaLandPassword(land))
	mine := acbaaMintToken(uid)
	if w := put(mine, good); w.Code != 200 {
		t.Fatalf("own token + land creds: status %d, want 200", w.Code)
	} else if w.Body.Len() != 0 {
		t.Errorf("bind answer is %d bytes, want empty", w.Body.Len())
	}
	if w := put("Bearer "+jwtWithSub("aaaaaaaaaaaa0001"), good); w.Code != 200 {
		t.Errorf("baas sub + land creds: status %d, want 200", w.Code)
	}
	bad := msgpackOrdered("id", land, "password", "nope")
	if w := put(mine, bad); w.Code != 401 {
		t.Errorf("wrong land password: status %d, want 401", w.Code)
	}
	other := acbaaMintToken(12345)
	if w := put(other, good); w.Code != 401 {
		t.Errorf("another user's token: status %d, want 401", w.Code)
	}
	if w := put("", good); w.Code != 401 {
		t.Errorf("no auth: status %d, want 401", w.Code)
	}
}

// jwtWithSub builds an unsigned JWT carrying a sub claim: bearerSub reads
// claims, never signatures, so the signature segment is filler.
func jwtWithSub(sub string) string {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"x"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `"}`))
	return head + "." + body + ".sig"
}

// GET /api/v1/friends answers the (currently empty) friend list. The game
// surfaces our error code as its own (2219-3004 on the loud 404).
func TestAcbaaFriendsEmpty(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("GET", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/friends", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("answer is not msgpack: %v", err)
	}
	list, ok := v.(map[string]any)
	if !ok || msgpackReadIntOf(list["count"]) != 0 {
		t.Fatalf("answer = %#v, want empty count", v)
	}
	if friends, _ := list["friends"].([]any); len(friends) != 0 {
		t.Errorf("friends = %#v, want empty", friends)
	}
}

// the stub backend — the game reads a C string out of the zeroed buffer).
// Bare 200; the token is logged per user for a future push backend.
func TestAcbaaNotificationTokenAccepted(t *testing.T) {
	s := &server{}
	body := msgpackOrdered("token", "")
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/notification_tokens",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body %d bytes, want empty", w.Body.Len())
	}
	bad := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/notification_tokens",
		strings.NewReader("nope"))
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, bad)
	if w2.Code != 400 {
		t.Errorf("bad body: status %d, want 400", w2.Code)
	}
}

// Message cards, profile status and profile upload: the game reads the
// first two and posts the third in one breath after binding. Empty shelves
// and empty statuses are true statements for a fresh account.
func TestAcbaaMessageCardsEmpty(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("GET", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/message_cards?offset=0&limit=30", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("answer is not msgpack: %v", err)
	}
	list, ok := v.(map[string]any)
	if !ok || msgpackReadIntOf(list["total"]) != 0 || msgpackReadIntOf(list["count"]) != 0 {
		t.Fatalf("answer = %#v, want empty total/count", v)
	}
	if headers, _ := list["headers"].([]any); len(headers) != 0 {
		t.Errorf("headers = %#v, want empty", headers)
	}
}

func TestAcbaaProfileStatusAndUpload(t *testing.T) {
	s := &server{}
	host := "https://api.hac.lp1.acbaa.srv.nintendo.net"
	uidPath := host + "/api/v1/users/12297829382472990721/profile_status"
	get := func() map[string]any {
		r := httptest.NewRequest("GET", uidPath, nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("status: %d, want 200", w.Code)
		}
		v, err := msgpackDecode(w.Body.Bytes())
		if err != nil {
			t.Fatalf("status answer is not msgpack: %v", err)
		}
		status, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("status answer is %T, want map", v)
		}
		return status
	}
	// Fresh account, before any upload: "ok"/"ok". An "ng" here latches the
	// Code-of-Conduct refusal in the game until the passport changes.
	if status := get(); status["user_profile"] != "ok" || status["land_profile"] != "ok" {
		t.Fatalf("fresh status = %#v, want ok/ok", status)
	}
	upBody := []byte("\x81\xa4name\xa7hansolo")
	up := httptest.NewRequest("PUT", host+"/api/v1/users/12297829382472990721/profile",
		bytes.NewReader(upBody))
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, up)
	if w2.Code != 200 {
		t.Fatalf("upload status %d, want 200", w2.Code)
	}
	// The upload answer carries the stored record: id echoes the user,
	// digest is the 40-hex SHA1 the game's 0x29 buffer takes, created_at a
	// unix time. An empty answer fails the whole setup client-side.
	v, err := msgpackDecode(w2.Body.Bytes())
	if err != nil {
		t.Fatalf("upload answer is not msgpack: %v", err)
	}
	rec, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("upload answer is %T, want map", v)
	}
	if msgpackReadUintOf(rec["id"]) != 12297829382472990721 {
		t.Errorf("record id = %#v, want the user", rec["id"])
	}
	digest, _ := rec["digest"].(string)
	if len(digest) != 40 {
		t.Errorf("digest = %#v, want 40-hex SHA1", rec["digest"])
	}
	if msgpackReadIntOf(rec["created_at"]) <= 0 {
		t.Errorf("created_at = %#v, want unix time", rec["created_at"])
	}
	// Uploading never changes the answer: nothing here reports anyone.
	if status := get(); status["user_profile"] != "ok" || status["land_profile"] != "ok" {
		t.Fatalf("after user upload status = %#v, want ok/ok", status)
	}
	// Bind the user to a land: land side flips to "ok" (island registered),
	// even before a separate lands/<id>/profile upload (which the game
	// never calls in the observed flow).
	bind := httptest.NewRequest("PUT", host+"/api/v1/users/12297829382472990721/land",
		bytes.NewReader(msgpackOrdered("id", uint64(2720403009), "password", acbaaLandPassword(2720403009))))
	bind.Header.Set("Authorization", "Bearer "+acbaaMintToken(12297829382472990721))
	w3 := httptest.NewRecorder()
	s.ServeHTTP(w3, bind)
	if w3.Code != 200 {
		t.Fatalf("bind status %d, want 200", w3.Code)
	}
	if status := get(); status["user_profile"] != "ok" || status["land_profile"] != "ok" {
		t.Fatalf("after bind status = %#v, want ok/ok", status)
	}
	lp := httptest.NewRequest("PUT", host+"/api/v1/lands/2720403009/profile",
		bytes.NewReader(upBody))
	w4 := httptest.NewRecorder()
	s.ServeHTTP(w4, lp)
	if w4.Code != 200 {
		t.Fatalf("land upload status %d, want 200", w4.Code)
	}
	// Same record shape as the player profile: id echoes the land,
	// digest is 40-hex, created_at a unix time.
	lv, lerr := msgpackDecode(w4.Body.Bytes())
	if lerr != nil {
		t.Fatalf("land upload answer is not msgpack: %v", lerr)
	}
	lrec := lv.(map[string]any)
	if lrec == nil {
		t.Fatalf("land upload answer is %T, want map", lv)
	}
	if msgpackReadUintOf(lrec["id"]) != 2720403009 {
		t.Errorf("record id = %#v, want the land", lrec["id"])
	}
	if digest, _ := lrec["digest"].(string); len(digest) != 40 {
		t.Errorf("digest = %#v, want 40-hex", lrec["digest"])
	}
	if msgpackReadIntOf(lrec["created_at"]) <= 0 {
		t.Errorf("created_at = %#v, want unix time", lrec["created_at"])
	}
	if status := get(); status["user_profile"] != "ok" || status["land_profile"] != "ok" {
		t.Fatalf("after land upload status = %#v, want ok/ok", status)
	}
	// Bad land id and bad body are refused, not stored.
	bad := httptest.NewRequest("PUT", host+"/api/v1/lands/0/profile", bytes.NewReader(upBody))
	w5 := httptest.NewRecorder()
	s.ServeHTTP(w5, bad)
	if w5.Code != 404 {
		t.Errorf("bad land id: status %d, want 404", w5.Code)
	}
	garbage := httptest.NewRequest("PUT", host+"/api/v1/lands/2720403009/profile",
		strings.NewReader("nope"))
	w6 := httptest.NewRecorder()
	s.ServeHTTP(w6, garbage)
	if w6.Code != 400 {
		t.Errorf("bad body: status %d, want 400", w6.Code)
	}
}

// A warm client still carrying its pre-single-identity uid must read and
// write the records migration moved to its NEX PID: profile_status by the
// legacy path answers ok (regression: it answered ng/ng for records on
// file, observed 2026-09-21), uploads land canonical, and the land bind
// accepts a legacy token against a legacy path.
func TestAcbaaLegacyUIDResolvesForward(t *testing.T) {
	const oldUID = uint64(12297829382472990721)
	const newPID = uint64(1900000001)
	s := &server{
		acbaaProfiles: map[uint64]acbaaProfile{newPID: {SHA: "abc", Size: 124642}},
		acbaaNames:    map[uint64]acbaaNames{newPID: {User: "hansolo", Land: "lovely "}},
		acbaaUIDMap:   map[uint64]uint64{oldUID: newPID},
	}
	host := "https://api.hac.lp1.acbaa.srv.nintendo.net"
	get := func(path string) map[string]any {
		r := httptest.NewRequest("GET", host+path, nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("GET %s: status %d, want 200", path, w.Code)
		}
		v, err := msgpackDecode(w.Body.Bytes())
		if err != nil {
			t.Fatalf("GET %s: not msgpack: %v", path, err)
		}
		status, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("GET %s: answer is %T, want map", path, v)
		}
		return status
	}
	legacy := "/api/v1/users/12297829382472990721/profile_status"
	if status := get(legacy); status["user_profile"] != "ok" || status["land_profile"] != "ok" {
		t.Fatalf("legacy status = %#v, want ok/ok", status)
	}
	// Upload under the legacy path lands on the canonical record and the
	// answer echoes the id the game sent.
	upBody := []byte("\x81\xa4name\xa7hansolo")
	up := httptest.NewRequest("PUT", host+"/api/v1/users/12297829382472990721/profile",
		bytes.NewReader(upBody))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, up)
	if w.Code != 200 {
		t.Fatalf("legacy upload: status %d, want 200", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("legacy upload: not msgpack: %v", err)
	}
	if rec, ok := v.(map[string]any); !ok || msgpackReadUintOf(rec["id"]) != oldUID {
		t.Fatalf("legacy upload answer = %#v, want id echo %d", v, oldUID)
	}
	if _, found := s.acbaaProfiles[newPID]; !found {
		t.Fatalf("legacy upload did not land on pid %d: %#v", newPID, s.acbaaProfiles)
	}
	if _, stranded := s.acbaaProfiles[oldUID]; stranded {
		t.Fatalf("legacy upload stranded a second record under %d", oldUID)
	}
	// Bind with a legacy token against the legacy path links the canonical id.
	bind := httptest.NewRequest("PUT", host+"/api/v1/users/12297829382472990721/land",
		bytes.NewReader(msgpackOrdered("id", uint64(2720403009), "password", acbaaLandPassword(2720403009))))
	bind.Header.Set("Authorization", "Bearer "+acbaaMintToken(oldUID))
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, bind)
	if w2.Code != 200 {
		t.Fatalf("legacy bind: status %d, want 200", w2.Code)
	}
	if s.acbaaUserLand[newPID] != 2720403009 {
		t.Fatalf("legacy bind linked %#v, want user_land[%d]=2720403009", s.acbaaUserLand, newPID)
	}
}

// Rewards and the web_service_resources syncs: the game pulls the first and
// uploads a burst of the second (emoticon, catalog, unlocks, land_memory…)
// on every online entry. Empty shelves and accepted uploads keep it moving.
func TestAcbaaRewardsEmpty(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("GET", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/rewards?limit=4", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("answer is not msgpack: %v", err)
	}
	list, ok := v.(map[string]any)
	if !ok || msgpackReadIntOf(list["total"]) != 0 || msgpackReadIntOf(list["count"]) != 0 {
		t.Fatalf("answer = %#v, want empty total/count", v)
	}
}

func TestAcbaaWebResourcesAcceptedAndRemembered(t *testing.T) {
	s := &server{}
	tok := acbaaMintToken(12297829382472990721)
	post := func(name string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PUT",
			"https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/web_service_resources/"+name,
			bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	landMemory := msgpackOrdered("data", map[string]any{"mVer": 1})
	if w := post("land_memory", landMemory); w.Code != 200 {
		t.Errorf("land_memory: status %d, want 200", w.Code)
	}
	if w := post("emoticon", msgpackOrdered("data", map[string]any{})); w.Code != 200 {
		t.Errorf("emoticon: status %d, want 200", w.Code)
	}
	if got := s.acbaaResources[12297829382472990721]["land_memory"]; !bytes.Equal(got, landMemory) {
		t.Errorf("land_memory not remembered")
	}
	if w := post("land_memory", []byte("garbage")); w.Code != 400 {
		t.Errorf("bad body: status %d, want 400", w.Code)
	}
	if w := post("has/slash", landMemory); w.Code != 404 {
		t.Errorf("nested name: status %d, want 404", w.Code)
	}
}

// The profile bytes survive a restart through the file store.
func TestAcbaaProfilesSurviveRestart(t *testing.T) {
	path := t.TempDir() + "/acbaa.json"
	s := &server{acbaaPath: path}
	upBody := []byte("\x81\xa4name\xa7hansolo")
	up := httptest.NewRequest("PUT", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/users/12297829382472990721/profile",
		bytes.NewReader(upBody))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, up)
	if w.Code != 200 {
		t.Fatalf("upload status %d, want 200", w.Code)
	}
	if s.acbaaProfileSHA(12297829382472990721) == "" {
		t.Fatalf("no digest remembered")
	}
	// A fresh server on the same file kept the bytes' digest.
	s2 := &server{acbaaPath: path}
	s2.acbaaLoad()
	if got := s2.acbaaProfileSHA(12297829382472990721); got != s.acbaaProfileSHA(12297829382472990721) {
		t.Errorf("restored digest = %#v, want the upload digest", got)
	}
}

// Registered names survive a restart in the store (status itself now
// answers ok/ng; the names remain for anything that reads who is who).
func TestAcbaaNamesSurviveRestart(t *testing.T) {
	path := t.TempDir() + "/acbaa.json"
	s := &server{acbaaPath: path}
	host := "https://api.hac.lp1.acbaa.srv.nintendo.net"
	post := func(path string, body []byte) {
		r := httptest.NewRequest("POST", host+path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+jwtWithSub("aaaaaaaaaaaa0001"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("POST %s: status %d, want 200", path, w.Code)
		}
	}
	post("/api/v1/lands", acbaaObservedLand)
	post("/api/v1/users", acbaaObservedUser)
	s2 := &server{acbaaPath: path}
	s2.acbaaLoad()
	if got := s2.acbaaNames[12297829382472990721]; got.User != "hansolo" || got.Land != "lovely " {
		t.Errorf("restored names = %#v, want the registered pair", got)
	}
}

// POST /api/v1/lands/updated_addresses: the game's online-setup function
// calls this before validating profiles; an unanswered here aborts the
// whole flow. Empty directory, current timestamp.
func TestAcbaaUpdatedAddressesEmpty(t *testing.T) {
	s := &server{}
	body := msgpackOrdered("user_ids", []any{uint64(12297829382472990721)}, "since", int64(0))
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/lands/updated_addresses",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("answer is not msgpack: %v", err)
	}
	resp, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("answer is %T, want map", v)
	}
	if _, ok := resp["accessed_at"]; !ok {
		t.Errorf("answer has no accessed_at: %#v", resp)
	}
	if addrs, _ := resp["addresses"].([]any); len(addrs) != 0 {
		t.Errorf("addresses = %#v, want empty", addrs)
	}
	bad := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/lands/updated_addresses",
		strings.NewReader("nope"))
	w2 := httptest.NewRecorder()
	s.ServeHTTP(w2, bad)
	if w2.Code != 400 {
		t.Errorf("bad body: status %d, want 400", w2.Code)
	}
}

// GET /api/v1/friend_requests answers the empty queue: no one is waiting.
// The game surfaces our error code as its own (2219-3004 on the loud 404),
// so this is what unblocked friend visits.
func TestAcbaaFriendRequestsEmpty(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("GET", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/friend_requests?type=received", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("answer is not msgpack: %v", err)
	}
	list, ok := v.(map[string]any)
	if !ok || msgpackReadIntOf(list["count"]) != 0 {
		t.Fatalf("answer = %#v, want empty count", v)
	}
	if reqs, _ := list["friend_requests"].([]any); len(reqs) != 0 {
		t.Errorf("friend_requests = %#v, want empty", reqs)
	}
}

// POST /api/v1/users answers the account's NEX PID — the same number
// switch-nexd resolves the login token to — so web identity and NEX
// identity are one principal and participant lookups resolve.
func TestAcbaaRegisterUserAnswersNEXPID(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{key: key, store: loadStore(t.TempDir() + "/baas.json")}
	s.store.Users["acnh-probe"] = &User{ID: "acnh-probe", PID: 1800000042}
	now := time.Now().Unix()
	tok := signJWT(map[string]any{"alg": "RS256", "kid": "x", "typ": "JWT"}, map[string]any{
		"typ": "id_token", "iss": baasIssuer, "sub": "acnh-probe",
		"exp": now + 3600, "iat": now,
	}, key)
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/users",
		bytes.NewReader(acbaaObservedUser))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("answer is not msgpack: %v", err)
	}
	user, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("answer is %T, want map", v)
	}
	if id := msgpackReadUintOf(user["id"]); id != 1800000042 {
		t.Errorf("id = %v, want the account's NEX PID", user["id"])
	}
}

// A legacy BAAS-derived id migrates to the NEX PID on sight: stored
// profiles, resources, names and the user→land link move with it, so one
// account never holds two islands.
func TestAcbaaLegacyIDMigratesToNEXPID(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{key: key, store: loadStore(t.TempDir() + "/baas.json"), acbaaPath: t.TempDir() + "/acbaa.json"}
	s.store.Users["acnh-mig"] = &User{ID: "acnh-mig", PID: 1800000043}
	now := time.Now().Unix()
	tok := signJWT(map[string]any{"alg": "RS256", "kid": "x", "typ": "JWT"}, map[string]any{
		"typ": "id_token", "iss": baasIssuer, "sub": "acnh-mig",
		"exp": now + 3600, "iat": now,
	}, key)
	// Legacy id for sub "acnh-mig" is not parseable hex, so it hashes the
	// posted name instead; seed records under whatever it is (the body
	// carries name "hansolo").
	legacy := acbaaLegacyID("Bearer "+tok, "hansolo")
	s.acbaaNames = map[uint64]acbaaNames{legacy: {User: "somebody", Land: "somewhere"}}
	s.acbaaProfiles = map[uint64]acbaaProfile{legacy: {SHA: "abc", Size: 7}}
	s.acbaaUserLand = map[uint64]uint64{legacy: 99}
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/users",
		bytes.NewReader(acbaaObservedUser))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if _, ok := s.acbaaNames[1800000043]; !ok {
		t.Errorf("names not migrated to NEX PID")
	}
	if _, ok := s.acbaaProfiles[1800000043]; !ok {
		t.Errorf("profiles not migrated to NEX PID")
	}
	if s.acbaaUserLand[1800000043] != 99 {
		t.Errorf("user→land link not migrated to NEX PID")
	}
	if _, ok := s.acbaaNames[legacy]; ok {
		t.Errorf("legacy names key still present")
	}
}

// A second POST of the same island is the same island, not an error: the game
// posts on every online entry, not just the first. The password must be
// stable — PUT users/<id>/land will present it back alongside the id.
func TestAcbaaRegisterLandIsIdempotent(t *testing.T) {
	s := &server{}
	passwords := map[string]bool{}
	for i := range 2 {
		r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/lands",
			bytes.NewReader(acbaaObservedLand))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("post %d: status %d, want 200", i, w.Code)
		}
		v, err := msgpackDecode(w.Body.Bytes())
		if err != nil {
			t.Fatalf("post %d: answer is not msgpack: %v", i, err)
		}
		pw, _ := v.(map[string]any)["password"].(string)
		passwords[pw] = true
	}
	if len(passwords) != 1 || passwords[""] {
		t.Fatalf("passwords across posts = %v, want one stable non-empty value", passwords)
	}
}

// Garbage in is a 400, not a 200 with a zeroed island and not a 500.
func TestAcbaaRegisterLandRejectsBadMsgpack(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/lands",
		strings.NewReader("not msgpack"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status %d, want 400", w.Code)
	}
}

// An unmapped route on these hosts is a 404 with the documented error shape
// ({category, code}, not a bare {}), so the game can report it properly.
// Each new endpoint the game asks for must surface here next.
func TestUnknownAcbaaRouteIs404(t *testing.T) {
	s := &server{}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET",
		"https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/whatever", nil))
	if w.Code != 404 {
		t.Fatalf("status %d, want 404", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatalf("error body is not msgpack: %v", err)
	}
	errBody, ok := v.(map[string]any)
	if !ok || errBody["category"] != "lib" || errBody["code"] != "3004" {
		t.Fatalf("error body = %#v, want {category:lib, code:3004}", v)
	}
}

// Best friends: A asks B (pending, listed on both sides with the meta the
// phone attached), B accepts, both list each other. B asking A while A's
// request is pending is approved on the spot.
func TestAcbaaBestFriends(t *testing.T) {
	s := testServer(t)
	host := "https://api.hac.lp1.acbaa.srv.nintendo.net"
	a, b := uint64(12297829382472990721), uint64(12297829382472990722)
	do := func(method, path string, uid uint64, body []byte) map[string]any {
		req := httptest.NewRequest(method, host+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+acbaaMintToken(uid))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s %s: status %d", method, path, w.Code)
		}
		v, err := msgpackDecode(w.Body.Bytes())
		if err != nil {
			t.Fatalf("%s %s: not msgpack: %v", method, path, err)
		}
		return v.(map[string]any)
	}
	meta := []byte{0x81, 0xa6, 'm', 'M', 't', 'V', 'e', 'r', 0x02}
	sent := do("POST", "/api/v1/friend_requests?target_user_id=12297829382472990722", a, msgpack(map[string]any{"meta": meta}))
	if sent["approved"] != false {
		t.Fatalf("first request approved = %#v, want false", sent["approved"])
	}
	inbox := do("GET", "/api/v1/friend_requests?type=receive", b, nil)
	items := inbox["friend_requests"].([]any)
	if len(items) != 1 {
		t.Fatalf("B's inbox has %d, want 1", len(items))
	}
	entry := items[0].(map[string]any)
	if msgpackReadUintOf(entry["user_id"]) != a || !bytes.Equal(entry["meta"].([]byte), meta) {
		t.Fatalf("inbox entry = %#v", entry)
	}
	if out := do("GET", "/api/v1/friend_requests?type=send", a, nil); msgpackReadIntOf(out["count"]) != 1 {
		t.Fatalf("A's outbox = %#v", out)
	}
	id := msgpackReadUintOf(entry["id"])
	do("PUT", "/api/v1/friend_requests/"+strconv.FormatUint(id, 10), b, msgpack(map[string]any{"action": "accept"}))
	for _, who := range []uint64{a, b} {
		fr := do("GET", "/api/v1/friends", who, nil)
		if msgpackReadIntOf(fr["count"]) != 1 {
			t.Fatalf("%d's friends = %#v", who, fr)
		}
	}
	if left := do("GET", "/api/v1/friend_requests?type=receive", b, nil); msgpackReadIntOf(left["count"]) != 0 {
		t.Fatalf("accepted request still listed: %#v", left)
	}
	// Mutual: C asks D, D asks C -> approved immediately.
	c, d := uint64(11), uint64(12)
	do("POST", "/api/v1/friend_requests?target_user_id=12", c, msgpack(map[string]any{"meta": meta}))
	if got := do("POST", "/api/v1/friend_requests?target_user_id=11", d, msgpack(map[string]any{"meta": meta})); got["approved"] != true {
		t.Fatalf("mutual request approved = %#v, want true", got["approved"])
	}
}
