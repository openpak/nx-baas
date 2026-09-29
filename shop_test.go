package main

// Store workstream tests (prds/native-switch-store-prd.md, SHP-01..05).
//
// These cover the server-side contracts: catalog rendering and language fallback,
// idempotent durable acquisition, ownership states, the beach/dragons rights surfaces and
// the atum content delivery with its edge-token gates. They deliberately do NOT close any
// native acceptance gate: a Go test cannot prove the applet parsed a page or NIM installed
// content. Hardware gates stay pending until reproduced on the declared 22.5.0 setup.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testTitleID = "0f9f0c0ffee00000"
const testNAID = "aabbccdd11223344"
const testDevice = "6265ca40780b1c0d"

// consoleUA is the SDK User-Agent shape the adapter already parses (did: extraction).
func consoleUA() string {
	return "NintendoSDK Firmware/22.5.0-1.0 (platform:NX; did:" + testDevice + "; eid:lp1)"
}

func shopServerFor(t *testing.T) *server {
	t.Helper()
	s := dauthServer(t)
	s.shop = newShopState(t.TempDir())
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID = 7; u.Nickname = "tester" })
	s.store.RememberNA(testNAID, 7)
	s.acct = fakeBackend{id: &Identity{PID: 7, NaID: testNAID, Nickname: "tester"}}
	return s
}

// naIDTokenFor mints the NA id token the storefront's identify() step would deliver.
func naIDTokenFor(s *server) string {
	return s.naIDToken(naCode{NaID: testNAID, ClientID: "test-client"}, "access", "")
}

func shopReq(s *server, method, path, token string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://bugyo.hac.lp1.eshop.nintendo.net"+path, strings.NewReader(body))
	req.Host = "bugyo.hac.lp1.eshop.nintendo.net"
	req.Header.Set("User-Agent", consoleUA())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("reply is not JSON: %v: %s", err, rec.Body.String())
	}
	return m
}

// The storefront entry point must be routed and rendered: a working handler behind a
// missing route is the failure class this repository has hit before (flow_test's rule).
func TestShopEntryAndDiagPagesServeThroughRouting(t *testing.T) {
	s := shopServerFor(t)
	for _, path := range []string{"/ashigaru/", "/ashigaru/diag"} {
		rec := shopReq(s, "GET", path, "", "")
		if rec.Code != 200 {
			t.Errorf("%s = %d, want 200", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "window.nx") {
			t.Errorf("%s does not mention the bridge it probes", path)
		}
	}
}

// SHP-02: catalog listing with language fallback. The fixture carries en-US and ja; a
// Japanese request gets Japanese, a French request falls back to the entry's default.
func TestShopCatalogLanguageFallback(t *testing.T) {
	s := shopServerFor(t)

	rec := shopReq(s, "GET", "/ashigaru/api/v1/catalog?lang=ja", "", "")
	body := decodeBody(t, rec)
	titles := body["titles"].([]any)
	if len(titles) != 1 {
		t.Fatalf("catalog has %d titles, want 1", len(titles))
	}
	if got := titles[0].(map[string]any)["name"]; got != "OpenPak ストア テスト" {
		t.Errorf("ja name = %q", got)
	}

	rec = shopReq(s, "GET", "/ashigaru/api/v1/catalog?lang=fr-FR", "", "")
	if got := decodeBody(t, rec)["titles"].([]any)[0].(map[string]any)["name"]; got != "OpenPak Store Test Title" {
		t.Errorf("fr-FR did not fall back to the default lang: %q", got)
	}

	// The primary-subtag fallback: ja-JP (unlisted) resolves to ja.
	rec = shopReq(s, "GET", "/ashigaru/api/v1/catalog?lang=ja-JP", "", "")
	if got := decodeBody(t, rec)["titles"].([]any)[0].(map[string]any)["name"]; got != "OpenPak ストア テスト" {
		t.Errorf("ja-JP did not fall back to ja: %q", got)
	}
}

// SHP-02: a title with size, version, compatibility and distribution permission renders in
// the details; a catalog entry without a recorded distribution permission must not be
// listed at all.
func TestShopCatalogDetailsAndPermissionGate(t *testing.T) {
	s := shopServerFor(t)
	rec := shopReq(s, "GET", "/ashigaru/api/v1/catalog/"+testTitleID+"?lang=en-US", "", "")
	d := decodeBody(t, rec)
	for _, k := range []string{"size_bytes", "version_label", "compatibility", "distribution", "description"} {
		if _, ok := d[k]; !ok {
			t.Errorf("details missing %q", k)
		}
	}

	// A catalog.json entry without distribution permission is dropped, not listed.
	dir := s.shop.dir
	catalog := `[{"title_id":"0f9f0c0ffee00010","localized":{"en-US":{"name":"No Permission"}}}]`
	if err := os.WriteFile(filepath.Join(dir, "catalog.json"), []byte(catalog), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := newShopState(dir)
	if _, ok := s2.Catalog["0f9f0c0ffee00010"]; ok {
		t.Error("an entry without a recorded distribution permission was listed")
	}
}

// SHP-03: acquisition is idempotent and durable — twice in one process and across a
// restart, the same elicense id comes back, and the entitlement survives.
func TestAcquireIsIdempotentAndDurable(t *testing.T) {
	s := shopServerFor(t)
	tok := naIDTokenFor(s)

	first := shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	if first.Code != 200 {
		t.Fatalf("acquire = %d: %s", first.Code, first.Body.String())
	}
	b1 := decodeBody(t, first)
	if b1["already_owned"] != false {
		t.Errorf("first acquire says already_owned=%v", b1["already_owned"])
	}
	second := shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	b2 := decodeBody(t, second)
	if b2["elicense_id"] != b1["elicense_id"] {
		t.Errorf("second acquire minted a different elicense id: %v vs %v", b1["elicense_id"], b2["elicense_id"])
	}
	if b2["already_owned"] != true {
		t.Errorf("second acquire says already_owned=%v", b2["already_owned"])
	}

	// Restart: a fresh server over the same directory keeps the entitlement and catalog.
	s2 := &server{key: s.key, idKid: s.idKid, jwks: s.jwks, shop: newShopState(s.shop.dir),
		store: s.store, acct: s.acct}
	rec := shopReq(s2, "GET", "/ashigaru/api/v1/ownership", tok, "")
	ent := decodeBody(t, rec)["entitlements"].([]any)
	if len(ent) != 1 {
		t.Fatalf("after restart there are %d entitlements, want 1", len(ent))
	}
	if got := ent[0].(map[string]any)["elicense_id"]; got != b1["elicense_id"] {
		t.Errorf("after restart elicense id changed: %v vs %v", b1["elicense_id"], got)
	}
}

// Principal binding: without a verified account identity, acquisition and ownership reads
// are refused, and the catalog does not claim an ownership state at all.
func TestShopAcquireRequiresAccountIdentity(t *testing.T) {
	s := shopServerFor(t)

	rec := shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", "", "")
	if rec.Code != 401 {
		t.Errorf("unauthenticated acquire = %d, want 401", rec.Code)
	}
	rec = shopReq(s, "GET", "/ashigaru/api/v1/ownership", "", "")
	if rec.Code != 401 {
		t.Errorf("unauthenticated ownership = %d, want 401", rec.Code)
	}
	// A token from another issuer does not become an account here.
	forged := signJWT(map[string]any{"alg": "RS256", "typ": "JWT"},
		map[string]any{"iss": "https://evil.example", "sub": testNAID, "exp": timeNowUnix() + 900}, s.key)
	rec = shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", forged, "")
	if rec.Code != 401 {
		t.Errorf("foreign-issuer token acquire = %d, want 401", rec.Code)
	}
	// The anonymous catalog carries no ownership field (nothing to claim).
	rec = shopReq(s, "GET", "/ashigaru/api/v1/catalog?lang=en-US", "", "")
	item := decodeBody(t, rec)["titles"].([]any)[0].(map[string]any)
	if _, ok := item["ownership"]; ok {
		t.Error("anonymous catalog claims an ownership state")
	}
}

// SHP-05: the ownership lifecycle — revoke surfaces, and neither ownership nor tasks lie.
func TestRevokedEntitlementGrantsNothing(t *testing.T) {
	s := shopServerFor(t)
	tok := naIDTokenFor(s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")

	// An operator-side revoke (dragons is where it happens in the native flow).
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "https://dragons.hac.lp1.dragons.nintendo.net/v2/elicenses/revoke",
		strings.NewReader(`{"elicense_ids":["`+s.shop.entitlementFor(testNAID, testTitleID).ELicenseID+`"]}`))
	req.Host = "dragons.hac.lp1.dragons.nintendo.net"
	s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("revoke = %d", w.Code)
	}

	// Details now say revoked, and a download task is refused: no false ownership.
	d := decodeBody(t, shopReq(s, "GET", "/ashigaru/api/v1/catalog/"+testTitleID, tok, ""))
	if d["ownership"] != "revoked" {
		t.Errorf("ownership = %v, want revoked", d["ownership"])
	}
	w = shopReq(s, "POST", "/ashigaru/api/v1/tasks", tok, `{"title_id":"`+testTitleID+`"}`)
	if w.Code != 403 {
		t.Errorf("task for revoked title = %d, want 403", w.Code)
	}

	// Re-acquiring revives the same entitlement (the purchase stands).
	w = shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	if w.Code != 200 || decodeBody(t, w)["status"] != "active" {
		t.Errorf("re-acquire did not revive: %d %s", w.Code, w.Body.String())
	}
}

// SHP-04/05: update — the catalog's version moved, the entitlement's installed version
// lags until the new download completes; completing the task moves the installed version.
func TestUpdateFlowMovesInstalledVersionOnCompletion(t *testing.T) {
	s := shopServerFor(t)
	tok := naIDTokenFor(s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")

	// The operator publishes an update: catalog version 1.0.0 -> 1.1.0.
	s.shop.mu.Lock()
	s.shop.Catalog[testTitleID].Version = 69632 // 1.1.0 in Nintendo's encoding
	s.shop.Catalog[testTitleID].VersionLabel = "1.1.0"
	s.shop.mu.Unlock()

	// Ownership still reports the old installed version: the update exists but is not
	// installed — a store that claimed the new version here would be lying.
	d := decodeBody(t, shopReq(s, "GET", "/ashigaru/api/v1/catalog/"+testTitleID, tok, ""))
	if d["version_owned"].(float64) != 65536 {
		t.Errorf("version_owned = %v before the update installed", d["version_owned"])
	}

	// A task for the update targets the NEW version; completing it moves the install.
	rec := shopReq(s, "POST", "/ashigaru/api/v1/tasks", tok, `{"title_id":"`+testTitleID+`"}`)
	taskID := decodeBody(t, rec)["id"].(string)
	if v := decodeBody(t, rec)["version"].(float64); v != 69632 {
		t.Fatalf("update task targets version %v, want 69632", v)
	}
	if t2 := s.shop.updateTask(taskID, testNAID, "completed", ""); t2.State != "completed" {
		t.Fatalf("complete = %s", t2.State)
	}
	d = decodeBody(t, shopReq(s, "GET", "/ashigaru/api/v1/catalog/"+testTitleID, tok, ""))
	if d["version_owned"].(float64) != 69632 {
		t.Errorf("version_owned = %v after completion, want 69632", d["version_owned"])
	}
}

// SHP-05: account switch — another account's ownership view is independent; removing a
// title from the console (redownload case) is a fresh task on the same entitlement.
func TestAccountSwitchAndRedownload(t *testing.T) {
	s := shopServerFor(t)
	tokA := naIDTokenFor(s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tokA, "")

	// Account B is linked on the same console.
	const naB = "bbaa445599887766"
	uB, _ := s.store.NewUser()
	s.store.Update(uB, func(u *User) { u.PID = 9 })
	s.store.RememberNA(naB, 9)
	tokB := s.naIDToken(naCode{NaID: naB, ClientID: "test-client"}, "access", "")

	d := decodeBody(t, shopReq(s, "GET", "/ashigaru/api/v1/catalog/"+testTitleID, tokB, ""))
	if d["ownership"] != "not_owned" {
		t.Errorf("account B sees ownership = %v, want not_owned", d["ownership"])
	}

	// Account B cannot create a task for A's title: entitlements do not leak across
	// accounts on a shared console.
	rec := shopReq(s, "POST", "/ashigaru/api/v1/tasks", tokB, `{"title_id":"`+testTitleID+`"}`)
	if rec.Code != 403 {
		t.Errorf("account B task = %d, want 403", rec.Code)
	}

	// Redownload after removal: A deletes the console copy; a fresh task on the same
	// entitlement is exactly the same acquisition returned again.
	e := s.shop.entitlementFor(testNAID, testTitleID)
	rec = shopReq(s, "POST", "/ashigaru/api/v1/tasks", tokA, `{"title_id":"`+testTitleID+`"}`)
	if rec.Code != 200 {
		t.Fatalf("redownload task = %d", rec.Code)
	}
	if s.shop.entitlementFor(testNAID, testTitleID).ELicenseID != e.ELicenseID {
		t.Error("redownload minted a second entitlement")
	}
}

// SHP-04/05: task lifecycle — one open task per title, cancel is terminal, backend
// restart keeps state.
func TestTaskLifecycle(t *testing.T) {
	s := shopServerFor(t)
	tok := naIDTokenFor(s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")

	var create = func() map[string]any {
		rec := shopReq(s, "POST", "/ashigaru/api/v1/tasks", tok, `{"title_id":"`+testTitleID+`"}`)
		if rec.Code != 200 {
			t.Fatalf("task create = %d: %s", rec.Code, rec.Body.String())
		}
		return decodeBody(t, rec)
	}
	first := create()
	dup := create()
	if first["id"] != dup["id"] {
		t.Errorf("two open tasks for one title: %v and %v", first["id"], dup["id"])
	}

	// Cancel is terminal: a second cancel does not resurrect or duplicate.
	id := first["id"].(string)
	rec := shopReq(s, "POST", "/ashigaru/api/v1/tasks/"+id+"/cancel", tok, "")
	if rec.Code != 200 || decodeBody(t, rec)["state"] != "canceled" {
		t.Fatalf("cancel = %d %s", rec.Code, rec.Body.String())
	}
	if t2 := s.shop.task(id, testNAID); t2.State != "canceled" {
		t.Fatalf("state = %s", t2.State)
	}
	_ = create() // the canceled task no longer blocks a fresh one

	// Restart keeps the task history.
	s2 := &server{key: s.key, idKid: s.idKid, jwks: s.jwks, shop: newShopState(s.shop.dir),
		store: s.store, acct: s.acct}
	tasks := s2.shop.tasksFor(testNAID)
	if len(tasks) != 2 {
		t.Errorf("after restart %d tasks, want 2", len(tasks))
	}
}

// The storefront's corner picture: the signed-in user's avatar on the shop's own origin
// (the default picture when they have none); nobody without a token.
func TestShopAvatarIsTheSignedInUsers(t *testing.T) {
	s := shopServerFor(t)
	if rec := shopReq(s, "GET", "/ashigaru/api/v1/me/avatar", "", ""); rec.Code != 404 {
		t.Errorf("no token = %d, want 404", rec.Code)
	}
	rec := shopReq(s, "GET", "/ashigaru/api/v1/me/avatar", naIDTokenFor(s), "")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/jpeg" || rec.Body.Len() == 0 {
		t.Errorf("avatar = %d %s %d bytes", rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len())
	}
}

// A game asking nn::account for a Nintendo Account token gets the id_token validated, unlike
// the console's own client which tolerates a loose one. Don't Starve Together died on exactly
// that ("[NX] GetResultWithInteractionIfRequired failed. (41)" in its own log, 2124-0041 on
// screen), so the three claims that validation turns on are asserted here.
func TestNaIDTokenCarriesNonceAndCodeHash(t *testing.T) {
	s := dauthServer(t)
	c := naCode{NaID: testNAID, ClientID: "f4e5f2f3e022208b", Nonce: "abc123"}

	claimsOf := func(tok string) map[string]any {
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Fatalf("not a JWT: %q", tok)
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	// The hybrid flow: a code comes back beside the token, so the token must tie itself to it.
	hybrid := claimsOf(s.naIDToken(c, "", "thecode"))
	if hybrid["nonce"] != "abc123" {
		t.Errorf("nonce = %v, want the one the client sent", hybrid["nonce"])
	}
	sum := sha256.Sum256([]byte("thecode"))
	if hybrid["c_hash"] != b64url(sum[:16]) {
		t.Errorf("c_hash = %v, want the left half of SHA-256 of the code", hybrid["c_hash"])
	}
	if _, ok := hybrid["at_hash"]; ok {
		t.Error("at_hash present with no access token; it used to be the hash of the empty string")
	}

	// The token endpoint: an access token exists, no code is returned with it.
	tokened := claimsOf(s.naIDToken(c, "theaccesstoken", ""))
	asum := sha256.Sum256([]byte("theaccesstoken"))
	if tokened["at_hash"] != b64url(asum[:16]) {
		t.Errorf("at_hash = %v, want the left half of SHA-256 of the access token", tokened["at_hash"])
	}
	if _, ok := tokened["c_hash"]; ok {
		t.Error("c_hash present with no code")
	}
}
