package main

// The 22.5.0 eShop surface: the savanna storefront, the NIM download/update hosts (pushmo,
// tagaya, superfly, veer), the d4c metadata hosts that must not reach atum, and the rights
// arrays NIM reads. Shapes are the firmware facts recorded in eshop_nim.go and shop.go.

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hostReq(s *server, host, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	req.Host = host
	req.Header.Set("User-Agent", consoleUA())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

const savannaHost = "hac.lp1.savanna.srv.nintendo.net"

// Every scene path systemWeb builds renders the storefront, whatever query the applet
// adds; the page API and icons answer on savanna too, so the page works on either host.
func TestSavannaServesEverySceneAndTheSharedAPI(t *testing.T) {
	s := shopServerFor(t)
	for _, path := range []string{
		"/top", "/top?landing_page=sale&mode=full", "/detail/" + testTitleID + "?dst_app_id=x&news_id=1&edition=2",
		"/detail/application_items/0100000000010000/dlc_items", "/catalog_tickets/123",
		"/search/result/conditions?q=a", "/my?tab=owned", "/membership?pwl_reason=1&pwl_app_id=2",
		"/redeem/input", "/shelf", "/",
	} {
		rec := hostReq(s, savannaHost, "GET", path, "", "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "requestNaIdToken") {
			t.Errorf("savanna %s = %d, want the storefront", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "eshop://success") {
			t.Errorf("savanna %s: no way to close the shop", path)
		}
	}
	if rec := hostReq(s, savannaHost, "GET", "/ashigaru/api/v1/catalog", "", ""); rec.Code != 200 {
		t.Errorf("page API on savanna = %d", rec.Code)
	}
	if rec := hostReq(s, savannaHost, "GET", "/favicon.ico", "", ""); rec.Code != 404 {
		t.Errorf("unknown savanna path = %d, want a recorded 404", rec.Code)
	}
	// bugyo stays an alias.
	if rec := shopReq(s, "GET", "/ashigaru/", "", ""); rec.Code != 200 {
		t.Errorf("bugyo alias = %d", rec.Code)
	}
}

// The browser has no client certificate: savanna (and Lhub) must never be asked for one.
func TestSavannaIsNotAskedForAClientCertificate(t *testing.T) {
	for _, sni := range []string{savannaHost, "lp1.nso.nintendo.net", "pushmo.hac.lp1.eshop.nintendo.net",
		"web-lp1.znc.srv.nintendo.net", "idbe-hac.cdn.nintendo.net", "bvc-hac-lp1.cdn.nintendo.net"} {
		if c, _ := clientCertFor(&tls.ClientHelloInfo{ServerName: sni}, &tls.Config{}); c != nil {
			t.Errorf("%s is asked for a client certificate", sni)
		}
	}
}

// The diagnostic page probes the 22.5.0 names and no longer the ones absent from it.
func TestDiagPageProbesThe2250BridgeNames(t *testing.T) {
	s := shopServerFor(t)
	body := shopReq(s, "GET", "/ashigaru/diag", "", "").Body.String()
	for _, want := range []string{"requestNaIdToken", "setNsaIdTokenAvailableCallback", "requestSyncRights",
		"requestDownloadTaskListOnEnd", "getFreeSizeUsb", "requestSignedDeviceIdentifierForNintendoAccount"} {
		if !strings.Contains(body, want) {
			t.Errorf("diag page does not probe %s", want)
		}
	}
	for _, gone := range []string{"requestNaAuthToken", "setNaAuthTokenAvailableCallback", "requestRegisterDeviceAccount",
		"getDeviceAccountInfo", "clearNaAuthTokenCache"} {
		if strings.Contains(body, gone) {
			t.Errorf("diag page still probes %s, which 22.5.0 does not have", gone)
		}
	}
}

// The page may identify with the NSA id token our BAAS issues; it names the account the
// user carries.
func TestShopPrincipalAcceptsOurNsaIDToken(t *testing.T) {
	s := shopServerFor(t)
	u := s.store.UserByPID(7)
	s.store.Update(u, func(u *User) { u.NaID = testNAID })
	tok := s.idToken(u, nil, "tester", map[string]any{})
	rec := shopReq(s, "GET", "/ashigaru/api/v1/ownership", tok, "")
	if rec.Code != 200 {
		t.Fatalf("ownership with an NSA id token = %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------- updates: catalog with a patch ----------

const testPatchID = "0f9f0c0ffee00800"

// withPatch publishes an update for the test title, as an operator editing catalog.json.
func withPatch(t *testing.T, s *server, version uint32) {
	t.Helper()
	dir := s.shop.dir
	if err := os.WriteFile(filepath.Join(dir, "patch.nca"), []byte("patch-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries := []*ShopTitle{{
		TitleID: testTitleID, Publisher: "OpenPak", Version: 0, VersionLabel: "1.0.0",
		Distribution: ShopDistribution{Source: "test", Permission: "test"},
		Localized:    map[string]ShopText{"en-US": {Name: "Patched"}},
		UpdatedAt:    int64(version),
		Patch: &ShopPatch{Version: version, VersionLabel: "1.0.1", Content: []ShopContent{{
			ContentID: "aa00000000000000000000000000000a", File: "patch.nca", Size: 11,
		}}},
	}}
	b, _ := json.Marshal(entries)
	path := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	// A distinct mtime per publish, as a real edit has.
	mt := time.Unix(1_700_000_000+int64(version), 0)
	os.Chtimes(path, mt, mt)
}

// The version list carries every title's newest version, with an ETag that holds until a
// version is published and then changes.
func TestTagayaVersionListFollowsPublishedUpdates(t *testing.T) {
	s := shopServerFor(t)
	const host = "tagaya.hac.lp1.eshop.nintendo.net"
	rec := hostReq(s, host, "GET", "/tagaya/hac_versionlist", "", "")
	if rec.Code != 200 {
		t.Fatalf("versionlist = %d", rec.Code)
	}
	var doc struct {
		LastModified int64 `json:"last_modified"`
		Titles       []struct {
			ID              string `json:"id"`
			Version         uint32 `json:"version"`
			RequiredVersion uint32 `json:"required_version"`
		} `json:"titles"`
	}
	json.Unmarshal(rec.Body.Bytes(), &doc)
	if len(doc.Titles) != 1 || doc.Titles[0].ID != testTitleID || doc.Titles[0].Version != 65536 {
		t.Fatalf("versionlist = %s", rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	req := httptest.NewRequest("GET", "https://"+host+"/tagaya/hac_versionlist", nil)
	req.Host = host
	req.Header.Set("If-None-Match", etag)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusNotModified {
		t.Errorf("unchanged list with If-None-Match = %d, want 304", w.Code)
	}

	withPatch(t, s, 131072)
	rec = hostReq(s, host, "GET", "/tagaya/hac_versionlist", "", "")
	json.Unmarshal(rec.Body.Bytes(), &doc)
	if doc.Titles[0].Version != 131072 {
		t.Errorf("published update not in the list: %s", rec.Body.String())
	}
	if rec.Header().Get("ETag") == etag {
		t.Errorf("ETag did not change when a version was published")
	}
}

// superfly's dv answers the recovered array shape: the application and its patch.
func TestSuperflyVersionLookupAnswersFromTheCatalog(t *testing.T) {
	s := shopServerFor(t)
	withPatch(t, s, 131072)
	rec := hostReq(s, "superfly.hac.lp1.d4c.nintendo.net", "GET", "/v1/a/"+testTitleID+"/dv", "", "")
	if rec.Code != 200 {
		t.Fatalf("dv = %d: %s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("dv is not a JSON array: %s", rec.Body.String())
	}
	if len(got) != 2 || got[0]["title_type"] != "Application" || got[1]["title_type"] != "Patch" ||
		got[1]["title_id"] != testPatchID || got[1]["version"] != float64(131072) {
		t.Errorf("dv = %v", got)
	}
	if rec := hostReq(s, "superfly.hac.lp1.d4c.nintendo.net", "GET", "/v1/a/0100000000010000/dv", "", ""); rec.Code != 404 {
		t.Errorf("dv for a title we do not carry = %d, want 404", rec.Code)
	}
}

// pushmo lists the account's open download tasks — the application and its update — with
// a stable ETag and 304 on a repeat.
func TestPushmoListsOpenTasksWithETags(t *testing.T) {
	s := shopServerFor(t)
	withPatch(t, s, 131072)
	tok := naIDTokenFor(s)
	linkConsole(t, s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	if rec := shopReq(s, "POST", "/ashigaru/api/v1/tasks", tok, `{"title_id":"`+testTitleID+`"}`); rec.Code != 200 {
		t.Fatalf("task = %d: %s", rec.Code, rec.Body.String())
	}
	const host = "pushmo.hac.lp1.eshop.nintendo.net"
	rec := hostReq(s, host, "GET", "/pushmo/d/"+testDevice+".json", "", "")
	if rec.Code != 200 {
		t.Fatalf("pushmo d = %d", rec.Code)
	}
	var doc struct {
		Tasks []struct {
			ID     string `json:"id"`
			Owner  string `json:"owner_application"`
			Titles []struct {
				ID      string `json:"id"`
				Version uint32 `json:"version"`
				Type    string `json:"type"`
			} `json:"titles"`
		} `json:"tasks"`
	}
	json.Unmarshal(rec.Body.Bytes(), &doc)
	if len(doc.Tasks) != 1 || len(doc.Tasks[0].ID) != 36 || doc.Tasks[0].Owner != testTitleID ||
		len(doc.Tasks[0].Titles) != 2 || doc.Tasks[0].Titles[1].Type != "Patch" || doc.Tasks[0].Titles[1].ID != testPatchID {
		t.Fatalf("pushmo d = %s", rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	if etag == "" || hostReq(s, host, "GET", "/pushmo/d/"+testDevice+".json", "", "").Header().Get("ETag") != etag {
		t.Errorf("ETag missing or unstable")
	}
	req := httptest.NewRequest("GET", "https://"+host+"/pushmo/d/"+testDevice+".json", nil)
	req.Host = host
	req.Header.Set("If-None-Match", etag)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusNotModified {
		t.Errorf("If-None-Match = %d, want 304", w.Code)
	}
	if rec := hostReq(s, host, "GET", "/pushmo/p/"+testDevice+".json", "", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"tasks":[]`) {
		t.Errorf("pushmo p = %d %s", rec.Code, rec.Body.String())
	}
}

// An update's content is served under its application's token.
func TestAtumServesPatchContentUnderTheApplicationToken(t *testing.T) {
	s := shopServerFor(t)
	withPatch(t, s, 131072)
	tok := naIDTokenFor(s)
	linkConsole(t, s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	rec := dragonsReq(s, "dragonst.hac.lp1.dragons.nintendo.net", "POST", "/v2/edge_token/issue",
		`{"title_ids":["`+testTitleID+`","`+testPatchID+`"]}`)
	edge := decodeBody(t, rec)["dragons_edge_token"].(string)
	req := httptest.NewRequest("GET", "https://atum.hac.lp1.d4c.nintendo.net/c2/"+testPatchID+"/c/c/aa00000000000000000000000000000a", nil)
	req.Host = "atum.hac.lp1.d4c.nintendo.net"
	req.Header.Set("User-Agent", consoleUA())
	req.Header.Set("X-Nintendo-DenebEdgeToken", "Bearer "+edge)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 || w.Body.String() != "patch-bytes" {
		t.Errorf("patch content = %d %q", w.Code, w.Body.String())
	}
}

// veer picks atum, in the recovered {ttl, weights[{vendor, weight}]} shape.
func TestVeerPolicyChoosesAtum(t *testing.T) {
	s := shopServerFor(t)
	rec := hostReq(s, "veer.hac.lp1.d4c.nintendo.net", "GET", "/v5/policy.json?context=0", "", "")
	d := decodeBody(t, rec)
	ws, _ := d["weights"].([]any)
	if rec.Code != 200 || d["ttl"] == nil || len(ws) != 1 || ws[0].(map[string]any)["vendor"] != "atum" {
		t.Errorf("veer = %d %s", rec.Code, rec.Body.String())
	}
}

// sun, aqua and superfly share atum's domain and used to be answered by it with a 404.
func TestNimMetadataHostsDoNotReachAtum(t *testing.T) {
	s := shopServerFor(t)
	rec := hostReq(s, "sun.hac.lp1.d4c.nintendo.net", "GET", "/v1/system_update_meta?device_id="+testDevice, "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"system_update_metas":[]`) {
		t.Errorf("sun = %d %s", rec.Code, rec.Body.String())
	}
	rec = hostReq(s, "aqua.hac.lp1.d4c.nintendo.net", "GET", "/required_system_update_meta?device_id="+testDevice, "", "")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "no required system update") {
		t.Errorf("aqua = %d %s", rec.Code, rec.Body.String())
	}
	rec = hostReq(s, "atumn.hac.lp1.d4c.nintendo.net", "GET", "/whatever", "", "")
	if strings.Contains(rec.Body.String(), "content route") {
		t.Errorf("atumn reached atum: %s", rec.Body.String())
	}
}

// Beach's device questions that NIM asks there, answered in beach rather than its 404.
// With no bundle anywhere: both flags false (nothing redeemed), an empty collection.
func TestBeachAnswersRedeemTargetAndBundleRoutes(t *testing.T) {
	s := shopServerFor(t)
	const host = "beach.hac.lp1.eshop.nintendo.net"
	// NIM requires both booleans in redeemed_status; missing either fails the call.
	rec := hostReq(s, host, "GET", "/v1/devices/redeemed_status", "", "")
	var st map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st["digital_bundle"] != false || st["pre_install"] != false {
		t.Errorf("redeemed_status = %d %s", rec.Code, rec.Body.String())
	}
	// target/set is an account act: without an account it is refused, not faked.
	if rec := hostReq(s, host, "POST", "/v1/devices/target/set", "", ""); rec.Code != 401 {
		t.Errorf("target/set without an account = %d, want 401", rec.Code)
	}
	for _, p := range []string{"/v1/devices/target/set", "/v1/devices/target/clear"} {
		if rec := hostReq(s, host, "POST", p, naIDTokenFor(s), ""); rec.Code != 200 {
			t.Errorf("%s = %d %s", p, rec.Code, rec.Body.String())
		}
	}
	// The bundle lookup is an empty collection: $.contents [] and $.redeemed false.
	rec = hostReq(s, host, "GET", "/v1/devices/digital_bundle/contents?shop_id=4", "", "")
	var b struct {
		Contents []any `json:"contents"`
		Redeemed *bool `json:"redeemed"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &b) != nil || b.Contents == nil || len(b.Contents) != 0 || b.Redeemed == nil || *b.Redeemed {
		t.Errorf("digital_bundle = %d %s", rec.Code, rec.Body.String())
	}
}

const (
	testBundledID  = "0f9f0c0ffee10000"
	testUpgradeID  = "0f9f0c0ffee20000"
	testUnlistedID = "0f9f0c0ffee30000"
)

// withBundle gives the test title a bundle of two published titles and one that is not
// in the catalog.
func withBundle(t *testing.T, s *server) {
	t.Helper()
	s.shop.mu.Lock()
	defer s.shop.mu.Unlock()
	for _, id := range []string{testBundledID, testUpgradeID} {
		s.shop.Catalog[id] = &ShopTitle{TitleID: id, Publisher: "OpenPak",
			Distribution: ShopDistribution{Source: "test", Permission: "test"},
			Localized:    map[string]ShopText{"en-US": {Name: "Bundled " + id}}}
	}
	parent := *s.shop.Catalog[testTitleID]
	parent.Bundle = []ShopBundleItem{{ApplicationID: testBundledID}, {ApplicationID: testUpgradeID, IsUpgradeEdition: true},
		{ApplicationID: testUnlistedID}}
	s.shop.Catalog[testTitleID] = &parent
}

type bundleReply struct {
	Contents []struct {
		ApplicationID    string `json:"application_id"`
		IsUpgradeEdition bool   `json:"is_upgrade_edition"`
		Redeemed         bool   `json:"redeemed"`
	} `json:"contents"`
	Redeemed bool `json:"redeemed"`
}

func bundleState(t *testing.T, s *server) (redeemedStatus bool, b bundleReply) {
	t.Helper()
	const host = "beach.hac.lp1.eshop.nintendo.net"
	var st struct {
		DigitalBundle *bool `json:"digital_bundle"`
		PreInstall    *bool `json:"pre_install"`
	}
	rec := hostReq(s, host, "GET", "/v1/devices/redeemed_status", "", "")
	if json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.DigitalBundle == nil || st.PreInstall == nil {
		t.Fatalf("redeemed_status = %d %s", rec.Code, rec.Body.String())
	}
	rec = hostReq(s, host, "GET", "/v1/devices/digital_bundle/contents?shop_id=4", "", "")
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &b) != nil {
		t.Fatalf("contents = %d %s", rec.Code, rec.Body.String())
	}
	return *st.DigitalBundle, b
}

// A title's bundle reaches the device that owns it; target/set redeems it into real
// rights (edge tokens follow), and target/clear takes back only what it granted.
func TestDigitalBundleRedemptionGrantsRights(t *testing.T) {
	s := shopServerFor(t)
	withBundle(t, s)
	const host = "beach.hac.lp1.eshop.nintendo.net"

	// Not owned yet: no bundle.
	linkConsole(t, s)
	if st, b := bundleState(t, s); st || len(b.Contents) != 0 {
		t.Fatalf("bundle before owning the title: %v %+v", st, b)
	}

	// Owning the title brings its published bundled titles, unredeemed.
	if _, _, err := s.shop.acquire(testNAID, "", testTitleID, testDevice, 0); err != nil {
		t.Fatal(err)
	}
	st, b := bundleState(t, s)
	if st || b.Redeemed || len(b.Contents) != 2 {
		t.Fatalf("owned, unredeemed: status %v, %+v", st, b)
	}
	if b.Contents[0].ApplicationID != testBundledID || b.Contents[0].IsUpgradeEdition || b.Contents[0].Redeemed ||
		b.Contents[1].ApplicationID != testUpgradeID || !b.Contents[1].IsUpgradeEdition {
		t.Errorf("contents = %+v", b.Contents)
	}
	edge := func() string {
		return dragonsReq(s, "dragonst.hac.lp1.dragons.nintendo.net", "POST", "/v2/edge_token/issue",
			`{"title_ids":["`+testBundledID+`","`+testUpgradeID+`"]}`).Body.String()
	}
	if strings.Contains(edge(), testBundledID) {
		t.Fatal("a bundled title was tokenized before redemption")
	}

	// Redeem.
	if rec := hostReq(s, host, "POST", "/v1/devices/target/set", naIDTokenFor(s), ""); rec.Code != 200 {
		t.Fatalf("target/set = %d %s", rec.Code, rec.Body.String())
	}
	st, b = bundleState(t, s)
	if !st || !b.Redeemed || len(b.Contents) != 2 || !b.Contents[0].Redeemed || !b.Contents[1].Redeemed {
		t.Fatalf("after redemption: status %v, %+v", st, b)
	}
	if e := s.shop.entitlementFor(testNAID, testBundledID); e == nil || e.Status != "active" || e.Source != "bundle:"+testTitleID {
		t.Fatalf("bundled entitlement = %+v", e)
	}
	if out := edge(); !strings.Contains(out, testBundledID) || !strings.Contains(out, testUpgradeID) {
		t.Errorf("edge token after redemption = %s", out)
	}
	// Redeeming again changes nothing and grants nothing twice.
	hostReq(s, host, "POST", "/v1/devices/target/set", naIDTokenFor(s), "")
	if n := len(s.shop.Redemptions); n != 2 {
		t.Errorf("redemptions after a second set = %d, want 2", n)
	}

	// A restart keeps the redemption.
	s2 := &server{key: s.key, idKid: s.idKid, jwks: s.jwks, store: s.store, acct: s.acct, shop: newShopState(s.shop.dir)}
	withBundle(t, s2)
	if st, _ := bundleState(t, s2); !st {
		t.Error("the redemption did not survive a restart")
	}

	// Clear revokes what the redemption granted and makes the bundle redeemable again.
	if rec := hostReq(s, host, "POST", "/v1/devices/target/clear", naIDTokenFor(s), ""); rec.Code != 200 {
		t.Fatalf("target/clear = %d", rec.Code)
	}
	if e := s.shop.entitlementFor(testNAID, testBundledID); e == nil || e.Status != "revoked" {
		t.Errorf("after clear the bundled entitlement = %+v", e)
	}
	if st, b := bundleState(t, s); st || b.Redeemed || b.Contents[0].Redeemed {
		t.Errorf("after clear: status %v, %+v", st, b)
	}
}

// A bundled title the account already bought is recorded as redeemed but never revoked by
// a clear: the purchase is not the bundle's to take back.
func TestDigitalBundleClearKeepsPurchases(t *testing.T) {
	s := shopServerFor(t)
	withBundle(t, s)
	linkConsole(t, s)
	s.shop.acquire(testNAID, "", testTitleID, testDevice, 0)
	s.shop.acquire(testNAID, "", testBundledID, testDevice, 0)
	const host = "beach.hac.lp1.eshop.nintendo.net"
	hostReq(s, host, "POST", "/v1/devices/target/set", naIDTokenFor(s), "")
	hostReq(s, host, "POST", "/v1/devices/target/clear", naIDTokenFor(s), "")
	if e := s.shop.entitlementFor(testNAID, testBundledID); e == nil || e.Status != "active" || e.Source != "" {
		t.Errorf("purchased title after clear = %+v", e)
	}
	if e := s.shop.entitlementFor(testNAID, testUpgradeID); e == nil || e.Status != "revoked" {
		t.Errorf("granted title after clear = %+v", e)
	}
}

// idbe: the icon-data format is not recovered, so a store title and an unknown title both
// get the logged 404, and the host never falls into the catch-all.
func TestIdbeIsARecordedNotFound(t *testing.T) {
	s := shopServerFor(t)
	for _, p := range []string{
		"/icondata/00/" + strings.ToUpper(testTitleID) + ".idbe",
		"/icondata/00/" + strings.ToUpper(testTitleID) + "-65536.idbe",
		"/icondata/10/0100000000011000.idbe",
		"/other",
	} {
		rec := hostReq(s, "idbe-hac.cdn.nintendo.net", "GET", p, "", "")
		if rec.Code != 404 || !strings.Contains(rec.Body.String(), "no icon data") {
			t.Errorf("idbe %s = %d %s", p, rec.Code, rec.Body.String())
		}
	}
}

// bvc: NIM treats a 200 as "this firmware is refused" and a 404 as "not listed". Only
// what the operator listed is refused, and both answers look like Akamai's.
func TestBvcServesTheOperatorBlocklist(t *testing.T) {
	s := shopServerFor(t)
	const host = "bvc-hac-lp1.cdn.nintendo.net"
	for _, p := range []string{"/22-5-0", "/0-0-0", "/"} {
		rec := hostReq(s, host, "GET", p, "", "")
		if rec.Code != 404 || rec.Body.String() != "Not found\n" || rec.Header().Get("Server") != "AkamaiNetStorage" ||
			rec.Header().Get("Content-Type") != "" {
			t.Errorf("bvc %s = %d %q %v, want Akamai's 10-byte 404", p, rec.Code, rec.Body.String(), rec.Header())
		}
	}
	s.shop.BlockedFirmware = []BlockedFirmware{{Version: "13-0-0", AddedAt: 1714521760}}
	rec := hostReq(s, host, "GET", "/13-0-0", "", "")
	if rec.Code != 200 || rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "text/plain" ||
		rec.Header().Get("ETag") != `"d41d8cd98f00b204e9800998ecf8427e:1714521760.000000"` {
		t.Errorf("listed bvc = %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	if rec := hostReq(s, host, "GET", "/13-0-1", "", ""); rec.Code != 404 {
		t.Errorf("unlisted 13-0-1 = %d", rec.Code)
	}
}

// pearljam stays a recorded refusal: neither path's contract is recovered.
func TestPearljamStaysRefused(t *testing.T) {
	s := shopServerFor(t)
	for _, p := range []string{"/civil", "/sugar", "/civil/v1/x"} {
		rec := hostReq(s, "pearljam.hac.lp1.eshop.nintendo.net", "POST", p, "", "{}")
		if rec.Code != 404 || !strings.Contains(rec.Body.String(), "not implemented") {
			t.Errorf("pearljam %s = %d %s", p, rec.Code, rec.Body.String())
		}
	}
}

// The vermillion gateway sends NIM's routes to their own answers, not a bare {}.
func TestVermillionGatewayDispatchesNimRoutes(t *testing.T) {
	s := shopServerFor(t)
	rec := hostReq(s, "gw.hac.lp1.vermillion.srv.nintendo.net", "GET", "/v1/nearness-checks", "", "")
	if !strings.Contains(rec.Body.String(), `"nearnessChecks":[]`) {
		t.Errorf("gw nearness-checks = %s", rec.Body.String())
	}
}

// NIM reads accepted/skipped rights arrays off the rights replies; every id lands in one.
func TestDragonsRightsRepliesCarryAcceptedAndSkipped(t *testing.T) {
	s := shopServerFor(t)
	tok := naIDTokenFor(s)
	linkConsole(t, s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	owned, other := rightsIDFor(testTitleID), "0100000000010003"
	for _, path := range []string{"/v2/rights/publish_elicenses", "/v2/rights/available_elicenses"} {
		d := decodeBody(t, dragonsReq(s, "dragons.hac.lp1.dragons.nintendo.net", "POST", path,
			`{"rights_ids":["`+owned+`","`+other+`"]}`))
		acc, _ := d["accepted_rights_ids"].([]any)
		sk, _ := d["skipped_rights_ids"].([]any)
		if len(acc) != 1 || acc[0] != owned || len(sk) != 1 || sk[0] != other {
			t.Errorf("%s: accepted %v skipped %v", path, d["accepted_rights_ids"], d["skipped_rights_ids"])
		}
	}
}

// The edge token is issued on dragons. and tigers. as well as dragonst.
func TestEdgeTokenIssuedOnEveryRightsHost(t *testing.T) {
	s := shopServerFor(t)
	tok := naIDTokenFor(s)
	linkConsole(t, s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	for _, host := range []string{"dragonst.hac.lp1.dragons.nintendo.net", "dragons.hac.lp1.dragons.nintendo.net", "tigers.hac.lp1.dragons.nintendo.net"} {
		rec := dragonsReq(s, host, "POST", "/v2/edge_token/issue", `{"title_ids":["`+testTitleID+`"]}`)
		if rec.Code != 200 || decodeBody(t, rec)["dragons_edge_token"] == nil {
			t.Errorf("%s edge_token/issue = %d %s", host, rec.Code, rec.Body.String())
		}
	}
}
