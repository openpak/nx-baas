package main

// Phase 0 has one job beyond logging: refuse in the shape pctl recognises, and
// leave the rest of the host alone. Both are asserted here because getting either
// wrong makes the hardware log -- the whole point of the phase -- unreadable.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
)

func moonCall(t *testing.T, method, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	s := &server{store: pctlStore(t)}
	r := httptest.NewRequest(method, "https://api-lp1.pctl.srv.nintendo.net"+path, nil)
	r.Host = "api-lp1.pctl.srv.nintendo.net"
	w := httptest.NewRecorder()
	s.moon(w, r, nil)

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, w.Body.String())
	}
	return w, got
}

func TestMoonRefusalNamesAnIdentityPctlCarries(t *testing.T) {
	// A path with no handler at all: the refusal must name a literal the
	// firmware carries, or the client cannot classify what went wrong.
	w, got := moonCall(t, "GET", "/moon/v1/nothing-here")

	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", w.Code)
	}
	if got["type"] != "https://moon.nintendo.com/errors/v1/404/resource_is_not_found" {
		t.Fatalf("type %q -- must be the firmware's own literal", got["type"])
	}
	if got["status"] != float64(http.StatusNotFound) {
		t.Fatalf("status field %v, want 404 -- the type URI and the status line must agree", got["status"])
	}
}

func TestUnknownPairingCodeIsAnEmptyListNotAnError(t *testing.T) {
	// "Which device has this code" is a question; "none" answers it. A 404 here
	// would read to the console as the service being broken.
	w, got := moonCall(t, "GET", "/moon/v1/devices?filter.links.pairingCode.code.$eq=NOSUCH")

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if got["count"] != float64(0) {
		t.Fatalf("count %v, want 0", got["count"])
	}
	if items, ok := got["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("items %v -- must be an empty list, never absent", got["items"])
	}
}

func TestMoonLeavesTheRestOfThePctlHostAlone(t *testing.T) {
	// Before moon.go every path here answered "service available". Only
	// /moon/v1 is being taken over, so a stray path must still get that.
	w, got := moonCall(t, "GET", "/v1/status")

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if got["status"] != "available" {
		t.Fatalf("body %v -- non-moon paths must keep the service-status answer", got)
	}
}

func TestMoonStatusComesFromTheIdentity(t *testing.T) {
	for slug, want := range map[string]int{
		moonNotFound:         404,
		moonMethodNotAllowed: 405,
		moonInvalidToken:     401,
		moonOverTheTimeLimit: 409,
		moonDevicesMaxed:     400,
		moonInternalError:    500,
		"nonsense":           500,
	} {
		w := httptest.NewRecorder()
		moonError(w, slug)
		if w.Code != want {
			t.Fatalf("%s -> %d, want %d", slug, w.Code, want)
		}
	}
}

// ---------- the pairing store ----------

func pctlStore(t *testing.T) *Store {
	t.Helper()
	// The guessing cap is process-wide, so every test starts with a clean minute
	// rather than inheriting the previous one's misses.
	pctlSearchMisses.Lock()
	pctlSearchMisses.window, pctlSearchMisses.n = time.Now(), 0
	pctlSearchMisses.Unlock()
	return &Store{path: filepath.Join(t.TempDir(), "store.json")}
}

func TestPairingCodeIsGoodOnceAndOnlyBeforeItExpires(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")

	if got := st.PctlByPairingCode(d.PairingCode); got == nil || got.MoonID != d.MoonID {
		t.Fatalf("a live code must find its record")
	}
	if st.PctlByPairingCode("NOTACODE") != nil {
		t.Fatalf("an unknown code found a record")
	}

	// Activation burns it: a second console must not be able to walk in on the
	// same code.
	if st.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa") == nil {
		t.Fatalf("activation with the record's own console failed")
	}
	if st.PctlByPairingCode(d.PairingCode) != nil {
		t.Fatalf("the code still resolves after activation")
	}
	if st.PctlByDauth("cert-aaaaaaaaaaaaaaaa") == nil {
		t.Fatalf("the activated console cannot be found by its bearer's device id")
	}
	// Retry of the same activation is fine; a different console is not.
	if st.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa") == nil {
		t.Fatalf("re-activating the same console must be idempotent, not a loss")
	}
	if st.PctlActivate(d.Hex(), "cert-bbbbbbbbbbbbbbbb") != nil {
		t.Fatalf("a second console took over an activated record")
	}
}

func TestExpiredPairingCodeIsNotAWayIn(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("")
	d.PairingExpires = time.Now().Add(-time.Second).Unix()

	if st.PctlByPairingCode(d.PairingCode) != nil {
		t.Fatalf("an expired code still paired")
	}
	if st.PctlActivate(d.Hex(), "") != nil {
		t.Fatalf("activation with no device id must refuse")
	}
}

func TestSettingETagTracksTheDocument(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")

	// The store hands back the live record, so hold the tag as a string: reading
	// it off the pointer later would only ever show the newest value.
	first := st.PctlSetSetting(d.Hex(), map[string]any{"ratingAge": 12, "snsPostRestriction": true}).ETag
	if first == "" {
		t.Fatalf("a stored setting must carry an ETag -- the console's If-None-Match has nothing to compare otherwise")
	}
	// Same document, keys written the other way round: the validator must not
	// move, or every poll re-downloads.
	same := st.PctlSetSetting(d.Hex(), map[string]any{"snsPostRestriction": true, "ratingAge": 12}).ETag
	if same != first {
		t.Fatalf("ETag moved for an unchanged document: %s -> %s", first, same)
	}
	changed := st.PctlSetSetting(d.Hex(), map[string]any{"ratingAge": 18, "snsPostRestriction": true}).ETag
	if changed == first {
		t.Fatalf("ETag stayed put while the document changed -- the console would keep the old restriction")
	}
	if st.PctlSetSetting("0000000000000000", map[string]any{}) != nil {
		t.Fatalf("a setting was stored against a device that does not exist")
	}
}

func TestPairingRouteMintsACodeTheConsoleCouldType(t *testing.T) {
	s := &server{store: pctlStore(t)}
	r := httptest.NewRequest("POST", "/internal/pctl/pairing", strings.NewReader(`{"account_id":"acct-parent"}`))
	w := httptest.NewRecorder()
	s.pctlPairing(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var got struct {
		MoonID string `json:"moon_id"`
		Code   string `json:"pairing_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(got.MoonID) != 16 {
		t.Fatalf("moon_id %q -- the console's paths spell it as 16 hex digits", got.MoonID)
	}
	// The console's entry field takes six digits and nothing else, so a letter
	// here is a code nobody can type (hardware, 2026-09-27).
	if len(got.Code) != pctlPairingCodeDigits || strings.TrimFunc(got.Code, unicode.IsDigit) != "" {
		t.Fatalf("code %q -- must be exactly %d digits", got.Code, pctlPairingCodeDigits)
	}
	if s.store.PctlByPairingCode(got.Code) == nil {
		t.Fatalf("the minted code does not resolve in the store")
	}
}

func TestMovieIsA404UntilOneIsConfigured(t *testing.T) {
	t.Setenv("PCTL_MOVIE", "")
	s := &server{}
	r := httptest.NewRequest("GET", "http://parentalcontrols-movie-lp1.cdn.nintendo.net/default/switchpc_en.mp4", nil)
	r.Host = "parentalcontrols-movie-lp1.cdn.nintendo.net"
	w := httptest.NewRecorder()
	s.pctlMovie(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 while no clip is configured", w.Code)
	}

	dir := t.TempDir()
	clip := filepath.Join(dir, "switchpc_en.mp4")
	os.WriteFile(clip, []byte("not really an mp4, but a body with a length"), 0o600)
	t.Setenv("PCTL_MOVIE", clip)
	w = httptest.NewRecorder()
	s.pctlMovie(w, r)
	if w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Fatalf("status %d, %d bytes -- a configured clip must be served", w.Code, w.Body.Len())
	}
	if ct := w.Header().Get("Content-Type"); ct != "video/mp4" {
		t.Fatalf("Content-Type %q", ct)
	}
}

func TestDeviceListIsScopedAndHidesADeadCode(t *testing.T) {
	st := pctlStore(t)
	mine := st.PctlNewPairing("acct-parent")
	st.PctlNewPairing("acct-someone-else")

	s := &server{store: st}
	list := func() []map[string]any {
		r := httptest.NewRequest("GET", "/internal/pctl/devices?account_id=acct-parent", nil)
		w := httptest.NewRecorder()
		s.pctlDeviceList(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d", w.Code)
		}
		var got struct {
			Devices []map[string]any `json:"devices"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("body: %v", err)
		}
		return got.Devices
	}

	devices := list()
	if len(devices) != 1 {
		t.Fatalf("%d devices -- another account's record leaked into this list", len(devices))
	}
	if devices[0]["pairing_code"] != mine.PairingCode {
		t.Fatalf("a live code must be shown: %v", devices[0]["pairing_code"])
	}
	if devices[0]["paired"] != false {
		t.Fatalf("an unclaimed record must not read as paired")
	}

	// Expired: the record stays, the code does not travel -- a dead code on a
	// screen is worse than none, because someone types it.
	mine.PairingExpires = time.Now().Add(-time.Minute).Unix()
	if _, shown := list()[0]["pairing_code"]; shown {
		t.Fatalf("an expired code was still sent to the app")
	}

	st.PctlActivate(mine.Hex(), "cert-aaaaaaaaaaaaaaaa")
	if list()[0]["paired"] != true {
		t.Fatalf("an activated record must read as paired")
	}

	r := httptest.NewRequest("GET", "/internal/pctl/devices", nil)
	w := httptest.NewRecorder()
	s.pctlDeviceList(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d -- a list with no account would be every household's", w.Code)
	}
}

// ---------- the console's own flow ----------

// moonServer is a server a console can actually talk to: the bearer on every
// moon request is a dauth device token this key signed, so it needs one.
func moonServer(t *testing.T) (*server, func(device string) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{key: key, idKid: "test-kid", store: pctlStore(t)}
	return s, func(device string) string { return s.deviceToken(device, "pctl-test") }
}

func moonReq(t *testing.T, s *server, method, path, token, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, "https://api-lp1.pctl.srv.nintendo.net"+path, strings.NewReader(body))
	r.Host = "api-lp1.pctl.srv.nintendo.net"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.moon(w, r, []byte(body))
	out := map[string]any{}
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w, out
}

// The whole pairing walk, in the order the console's executors run it.
func TestAConsolePairsAndSyncs(t *testing.T) {
	s, token := moonServer(t)
	tok := token("cert-aaaaaaaaaaaaaaaa")
	minted := s.store.PctlNewPairing("acct-parent")

	// 1. RequestPairing: find the record by the code typed on the console.
	_, found := moonReq(t, s, "GET", "/moon/v1/devices?filter.links.pairingCode.code.$eq="+minted.PairingCode, tok, "")
	items, _ := found["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("search found %v", found)
	}
	// A number, not a string: the console read a hex string as zero and asked
	// for /devices/0000000000000000/owners (hardware, 2026-09-27).
	num, ok := items[0].(map[string]any)["deviceId"].(float64)
	if !ok {
		t.Fatalf("deviceId %#v is not a JSON number -- the console parses it as one", items[0].(map[string]any)["deviceId"])
	}
	if uint64(num) != minted.MoonID {
		t.Fatalf("deviceId %v, want %d", num, minted.MoonID)
	}
	// And the console asks with %016llx of that number, which must resolve.
	id := fmt.Sprintf("%016x", uint64(num))
	if id != minted.Hex() {
		t.Fatalf("hex of the number is %q, want %q", id, minted.Hex())
	}

	// 2. AuthorizePairing/activate: the console claims it, using the id our own
	// answer gave it.
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+id+"/activate", tok, "{}"); w.Code != 200 {
		t.Fatalf("activate status %d", w.Code)
	}
	if got := s.store.PctlByDauth("cert-aaaaaaaaaaaaaaaa"); got == nil {
		t.Fatalf("activation did not bind the console")
	}

	// 3. RetrieveSettings: an empty document means no restrictions, and it
	// carries an ETag so the next poll can be a 304.
	w, doc := moonReq(t, s, "GET", "/moon/v1/devices/"+id+"/parental_control_setting", tok, "")
	etag := w.Header().Get("ETag")
	if w.Code != 200 || etag == "" {
		t.Fatalf("setting status %d etag %q", w.Code, etag)
	}
	// Nothing was set by a parent, so the document states "nothing restricted"
	// in full. An empty one is what the console answered 2142-0234 to: its check
	// refuses when the allowed age is unset (hardware, 2026-09-27).
	if doc["safetyLevel"] != "NONE" || doc["ratingAge"] != float64(18) {
		t.Fatalf("default setting %v -- silence reads as block-everything on the console", doc)
	}

	// 4. The same poll again, with the validator: no body, no restriction churn.
	r := httptest.NewRequest("GET", "https://api-lp1.pctl.srv.nintendo.net/moon/v1/devices/"+id+"/parental_control_setting", nil)
	r.Host = "api-lp1.pctl.srv.nintendo.net"
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	s.moon(w, r, nil)
	if w.Code != http.StatusNotModified {
		t.Fatalf("status %d, want 304 -- an unchanged document must not be re-sent every poll", w.Code)
	}

	// 5. A parent sets a limit: the ETag moves, so the console's next poll is a
	// 200 with the new document.
	s.store.PctlSetSetting(id, map[string]any{"ratingAge": 12})
	w, doc = moonReq(t, s, "GET", "/moon/v1/devices/"+id+"/parental_control_setting", tok, "")
	if w.Header().Get("ETag") == etag {
		t.Fatalf("ETag did not move after a parent changed the setting")
	}
	if doc["ratingAge"] != float64(12) {
		t.Fatalf("doc %v", doc)
	}

	// 6. Owners and events, the two writes the console makes on its own.
	if w, _ := moonReq(t, s, "PUT", "/moon/v1/devices/"+id+"/owners/bbbbbbbbbbbb0001", tok, "{}"); w.Code != 200 {
		t.Fatalf("owner link status %d", w.Code)
	}
	_, owners := moonReq(t, s, "GET", "/moon/v1/devices/"+id+"/owners", tok, "")
	if owners["count"] != float64(1) {
		t.Fatalf("owners %v", owners)
	}
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+id+"/events", tok, `{"items":[{"eventType":"AppEvent"}]}`); w.Code != 200 {
		t.Fatalf("events status %d", w.Code)
	}
	if got := s.store.PctlByMoonID(id); len(got.Events) != 1 {
		t.Fatalf("%d events held", len(got.Events))
	}
}

func TestAnotherConsoleCannotReadOrTakeAPairedRecord(t *testing.T) {
	s, token := moonServer(t)
	mine, theirs := token("cert-aaaaaaaaaaaaaaaa"), token("cert-bbbbbbbbbbbbbbbb")
	d := s.store.PctlNewPairing("acct-parent")
	id := d.Hex()

	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+id+"/activate", mine, "{}"); w.Code != 200 {
		t.Fatalf("first activate %d", w.Code)
	}
	// A second console with a valid token of its own: the record is not its.
	if w, got := moonReq(t, s, "POST", "/moon/v1/devices/"+id+"/activate", theirs, "{}"); w.Code != http.StatusForbidden {
		t.Fatalf("second activate %d %v -- a claimed record must not change hands", w.Code, got)
	}
	if w, _ := moonReq(t, s, "GET", "/moon/v1/devices/"+id+"/parental_control_setting", theirs, ""); w.Code != http.StatusForbidden {
		t.Fatalf("stranger read %d -- one household would read another's restrictions", w.Code)
	}
	// No bearer at all is not a way in either.
	if w, _ := moonReq(t, s, "GET", "/moon/v1/devices/"+id, "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("anonymous read %d", w.Code)
	}
}

// The id shape is the one thing the firmware's strings could not settle (study
// §7 P2): the path is `%016llx`, but whether the console re-renders our number
// as decimal is unproven. Both resolve, so a wrong guess costs a log line and
// not a failed pairing.
func TestADeviceIdResolvesInEitherSpelling(t *testing.T) {
	s, token := moonServer(t)
	tok := token("cert-aaaaaaaaaaaaaaaa")
	d := s.store.PctlNewPairing("acct-parent")

	if got := s.store.PctlByMoonID(d.Hex()); got == nil {
		t.Fatalf("hex id did not resolve")
	}
	decimal := strconv.FormatUint(d.MoonID, 10)
	if got := s.store.PctlByMoonID(decimal); got == nil {
		t.Fatalf("decimal id %q did not resolve", decimal)
	}
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+decimal+"/activate", tok, "{}"); w.Code != 200 {
		t.Fatalf("activate by decimal id %d", w.Code)
	}
}

func TestPairingCodesAreTypableAndSpreadAcrossTheSpace(t *testing.T) {
	seen := map[string]int{}
	first := map[byte]int{}
	for i := 0; i < 300; i++ {
		c := pctlPairingCode()
		if len(c) != pctlPairingCodeDigits || strings.TrimFunc(c, unicode.IsDigit) != "" {
			t.Fatalf("code %q is not %d digits", c, pctlPairingCodeDigits)
		}
		seen[c]++
		first[c[0]]++
	}
	if len(seen) < 295 {
		t.Fatalf("%d distinct codes in 300 -- too many collisions for a million-wide space", len(seen))
	}
	// Leading zeros must survive, and the first digit must not favour a slice of
	// the range: modulo over random bytes would show up here.
	if len(first) < 8 {
		t.Fatalf("first digit only took %d of 10 values across 300 codes", len(first))
	}
}

func TestBlindGuessingIsCapped(t *testing.T) {
	st := pctlStore(t)
	mine := st.PctlNewPairing("acct-parent")
	s := &server{store: st}

	search := func(code string) map[string]any {
		r := httptest.NewRequest("GET", "https://api-lp1.pctl.srv.nintendo.net/moon/v1/devices?filter.links.pairingCode.code.$eq="+code, nil)
		r.Host = "api-lp1.pctl.srv.nintendo.net"
		w := httptest.NewRecorder()
		s.moon(w, r, nil)
		out := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}

	// A household's own mistakes stay well inside the budget.
	for i := 0; i < pctlSearchMissBudget; i++ {
		search(fmt.Sprintf("%06d", i))
	}
	// Past it, even the right code is refused for the rest of the minute: the
	// guesser learns nothing, and the parent can mint another in a moment.
	if got := search(mine.PairingCode); got["count"] != float64(0) {
		t.Fatalf("a real code answered %v while throttled -- enumeration would walk the whole space", got)
	}

	// The window is what lifts it, so a later minute works again.
	pctlSearchMisses.Lock()
	pctlSearchMisses.window = time.Now().Add(-2 * time.Minute)
	pctlSearchMisses.Unlock()
	if got := search(mine.PairingCode); got["count"] != float64(1) {
		t.Fatalf("after the window the real code must resolve: %v", got)
	}
}

// The id must survive a reader that keeps JSON numbers in a double: past 2^53
// the console would round it and ask for a device that does not exist.
func TestDeviceIdsStayExactInADouble(t *testing.T) {
	for i := 0; i < 200; i++ {
		id := randU64()
		if id > 1<<53 {
			t.Fatalf("id %d is past the exact range of a double", id)
		}
		if float64(id) != float64(uint64(float64(id))) || uint64(float64(id)) != id {
			t.Fatalf("id %d does not round-trip through a double", id)
		}
		if len(fmt.Sprintf("%016x", id)) != 16 {
			t.Fatalf("id %d is not sixteen hex digits", id)
		}
	}
}

// The device object carries what pctl's own strings name and nothing else. The
// build that added an `id` key beside `deviceId` came back as 2142-0234 with no
// request behind it -- a parse, not a network failure -- so an unknown field is
// treated as a fault here rather than as harmless generosity.
func TestTheDeviceObjectHasNoFieldPctlDoesNotName(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")
	obj := moonDeviceObj(d)

	// Every name here appears in pctl's rodata (the docs-repo study, §4).
	// Every name here is one pctl's own field tables carry (the docs-repo study;
	// the device table reads language, region, serialNumber, firmwareVersion,
	// displayedVersion, internalVersion, activated, lastOnlineCheckedAt,
	// parentalControlSetting, unlockCode).
	known := map[string]bool{
		"deviceId": true, "nickname": true, "pairingActive": true, "updatedAt": true,
		"etag": true, "owners": true, "synchronizedAt": true, "links": true,
		"activated": true, "unlockCode": true, "parentalControlSetting": true,
	}
	for k := range obj {
		if !known[k] {
			t.Fatalf("field %q is not one pctl names -- it is what 2142-0234 looked like", k)
		}
	}
	if _, ok := obj["deviceId"].(uint64); !ok {
		t.Fatalf("deviceId is %T, must stay a number", obj["deviceId"])
	}
}

// The console lifts a restriction with an eight-digit code: pctl copies at most
// eight bytes into its PIN slot and validates the eighth as a digit.
func TestUnlockCodesAreEightDigits(t *testing.T) {
	st := pctlStore(t)
	for i := 0; i < 50; i++ {
		d := st.PctlNewPairing(fmt.Sprintf("acct-%d", i))
		if len(d.UnlockCode) != 8 || strings.TrimFunc(d.UnlockCode, unicode.IsDigit) != "" {
			t.Fatalf("unlock code %q is not eight digits", d.UnlockCode)
		}
	}
}

// The embedded setting and the polled document are the same thing: two answers
// would mean the console applying one and the app editing the other.
func TestTheEmbeddedSettingIsThePolledOne(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")
	st.PctlSetSetting(d.Hex(), map[string]any{"safetyLevel": "OLDER_TEENS", "ratingAge": 16})

	obj := moonDeviceObj(st.PctlByMoonID(d.Hex()))
	embedded, _ := obj["parentalControlSetting"].(map[string]any)
	if embedded["safetyLevel"] != "OLDER_TEENS" || embedded["ratingAge"] != 16 {
		t.Fatalf("embedded setting %v is not what the parent stored", embedded)
	}
}
