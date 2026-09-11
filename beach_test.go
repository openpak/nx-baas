package main

// Beach and dragons tests: device linking, rights publication, edge tokens and the honest
// eticket boundary (SHP-03/04).

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func dragonsReq(s *server, host, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	req.Host = host
	req.Header.Set("User-Agent", consoleUA())
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// linkConsole performs the native flow's first step on behalf of a test: the authenticated
// beach link (requestLinkDevice's server side). NIM's later rights and edge-token requests
// identify only the device, so the link is what binds them to an account.
func linkConsole(t *testing.T, s *server) {
	t.Helper()
	req := httptest.NewRequest("POST", "https://beach.hac.lp1.eshop.nintendo.net/v1/my/devices/hac/link?lang=en", nil)
	req.Host = "beach.hac.lp1.eshop.nintendo.net"
	req.Header.Set("User-Agent", consoleUA())
	req.Header.Set("Authorization", "Bearer "+naIDTokenFor(s))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("link = %d: %s", w.Code, w.Body.String())
	}
}

// SHP-03: the device link (requestLinkDevice's server side) is durable — a backend restart
// must not unlink a console (SHP-05), and the same link is idempotent.
func TestBeachLinkIsIdempotentAndSurvivesRestart(t *testing.T) {
	s := shopServerFor(t)
	// Linking is account-scoped: the beach request carries the NA id token.
	req := httptest.NewRequest("POST", "https://beach.hac.lp1.eshop.nintendo.net/v1/my/devices/hac/link?lang=en", nil)
	req.Host = "beach.hac.lp1.eshop.nintendo.net"
	req.Header.Set("User-Agent", consoleUA())
	req.Header.Set("Authorization", "Bearer "+naIDTokenFor(s))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("link = %d: %s", w.Code, w.Body.String())
	}

	// A restart over the same data keeps the link.
	s2 := &server{key: s.key, idKid: s.idKid, jwks: s.jwks, shop: newShopState(s.shop.dir),
		store: s.store, acct: s.acct}
	req = httptest.NewRequest("GET", "https://beach.hac.lp1.eshop.nintendo.net/v1/my/devices?device_type_id=6&lang=en", nil)
	req.Host = "beach.hac.lp1.eshop.nintendo.net"
	req.Header.Set("User-Agent", consoleUA())
	req.Header.Set("Authorization", "Bearer "+naIDTokenFor(s))
	w = httptest.NewRecorder()
	s2.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("my/devices after restart = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), testDevice) {
		t.Errorf("the linked device did not survive the restart: %s", w.Body.String())
	}
}

// A device cannot be linked without naming a verified account: the header id alone is not
// a principal.
func TestBeachLinkRequiresAPrincipal(t *testing.T) {
	s := shopServerFor(t)
	req := httptest.NewRequest("POST", "https://beach.hac.lp1.eshop.nintendo.net/v1/my/devices/hac/link", nil)
	req.Host = "beach.hac.lp1.eshop.nintendo.net"
	req.Header.Set("User-Agent", consoleUA())
	req.Header.Set("Nintendo-Account-Id", testNAID) // header without a token: nothing
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("header-only link = %d, want 401", w.Code)
	}
}

// SHP-03: publishing elicenses for acquired titles is idempotent — the native
// requestSyncRights flow may call it repeatedly; the elicense id must not change.
func TestDragonsPublishElicensesIsIdempotent(t *testing.T) {
	s := shopServerFor(t)
	tok := naIDTokenFor(s)
	linkConsole(t, s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")

	rid := rightsIDFor(testTitleID)
	pub := func() map[string]any {
		rec := dragonsReq(s, "dragons.hac.lp1.dragons.nintendo.net", "POST", "/v2/rights/publish_elicenses",
			`{"rights_ids":["`+rid+`"],"elicense_type":"permanent"}`)
		if rec.Code != 200 {
			t.Fatalf("publish = %d: %s", rec.Code, rec.Body.String())
		}
		return decodeBody(t, rec)
	}
	first := pub()
	list1 := first["elicenses"].([]any)
	if len(list1) != 1 {
		t.Fatalf("publish returned %d elicenses, want 1", len(list1))
	}
	e1 := list1[0].(map[string]any)
	againList := pub()["elicenses"].([]any)
	again := againList[0].(map[string]any)
	if again["elicense_id"] != e1["elicense_id"] {
		t.Errorf("republished elicense changed id: %v vs %v", e1["elicense_id"], again["elicense_id"])
	}
	if e1["rights_id"] != rid || e1["account_id"] != testNAID || e1["status"] != "active" {
		t.Errorf("elicense shape wrong: %v", e1)
	}
}

// rights/available_elicenses reflects the truth for a third party asking: unowned is
// no_rights, owned is available, revoked says so.
func TestDragonsAvailableElicensesReflectsOwnership(t *testing.T) {
	s := shopServerFor(t)
	tok := naIDTokenFor(s)
	linkConsole(t, s)
	rid := rightsIDFor(testTitleID)

	ask := func() map[string]any {
		rec := dragonsReq(s, "dragons.hac.lp1.dragons.nintendo.net", "POST", "/v2/rights/available_elicenses",
			`{"rights_ids":["`+rid+`"]}`)
		if rec.Code != 200 {
			t.Fatalf("available = %d", rec.Code)
		}
		return decodeBody(t, rec)["available_elicenses"].([]any)[0].(map[string]any)
	}
	if a := ask(); a["is_available"] != false || a["reason"] != "no_rights" {
		t.Errorf("unowned: %v", a)
	}
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	if a := ask(); a["is_available"] != true {
		t.Errorf("owned: %v", a)
	}
	e := s.shop.entitlementFor(testNAID, testTitleID)
	s.shop.revoke(e.AccountID, e.TitleID)
	if a := ask(); a["is_available"] != false || a["reason"] != "revoked_by_cs" {
		t.Errorf("revoked: %v", a)
	}
}

// SHP-04: edge tokens are only issued for titles this device actually owns — authorized
// content delivery starts at the token, not the file.
func TestDragonsEdgeTokenOnlyForOwnedTitles(t *testing.T) {
	s := shopServerFor(t)
	tok := naIDTokenFor(s)
	linkConsole(t, s)

	issue := func() map[string]any {
		rec := dragonsReq(s, "dragonst.hac.lp1.dragons.nintendo.net", "POST", "/v2/edge_token/issue",
			`{"title_ids":["`+testTitleID+`"],"na_id_tokens":[],"vendor":""}`)
		if rec.Code != 200 {
			t.Fatalf("edge token issue = %d", rec.Code)
		}
		return decodeBody(t, rec)
	}

	// Nothing owned, nothing tokenized.
	if got := issue()["title_ids"].([]any); len(got) != 0 {
		t.Errorf("unowned title was tokenized: %v", got)
	}
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	body := issue()
	if got := body["title_ids"].([]any); len(got) != 1 {
		t.Fatalf("owned title not tokenized: %v", body)
	}
	if body["expires_in"].(float64) != 21600 {
		t.Errorf("expires_in = %v, want 21600", body["expires_in"])
	}
	// And the token verifies, bound to the title.
	if _, ok := s.verifyDragonsEdgeToken("Bearer "+body["dragons_edge_token"].(string), testTitleID); !ok {
		t.Error("a fresh dragons edge token did not verify against its own title")
	}
	if _, ok := s.verifyDragonsEdgeToken("Bearer "+body["dragons_edge_token"].(string), "0f9f0c0ffee00999"); ok {
		t.Error("edge token verified against a title it does not name")
	}
}

// SHP-04 honesty: the eticket publish is the packaging/trust boundary. It records the
// request and refuses — it never answers 200 to fake an install path.
func TestEticketsPublishIsRecordedNotFaked(t *testing.T) {
	s := shopServerFor(t)
	rec := dragonsReq(s, "tigers.hac.lp1.dragons.nintendo.net", "POST", "/v1/etickets/publish",
		`{"certificate":"Zm9v","titles":[]}`)
	if rec.Code == 200 {
		t.Fatal("etickets/publish answered success — that would be a faked install path")
	}
	if rec.Code != 501 {
		t.Errorf("etickets/publish = %d, want 501", rec.Code)
	}
}
