package main

// The identity and penne APIs the split-out services call (internal_identity.go,
// internal_penne.go), and the forwarding that hands a moved family to its service (split.go).
// The field names asserted here are github.com/openpak/nx-common/nxapi's: this repository does
// not import that module, so these tests are what keeps the two in step.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func identityDo(t *testing.T, s *server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://nx-baas:20070"+path, strings.NewReader(body))
	req.Header.Set("X-Internal-Key", "test-internal-key")
	rec := httptest.NewRecorder()
	s.gameAPI().ServeHTTP(rec, req)
	return rec
}

func TestIdentityAPIRequiresTheKey(t *testing.T) {
	s := shopServerFor(t)
	t.Setenv("NX_INTERNAL_KEY", "")
	t.Setenv("OPENPAK_INTERNAL_KEY", "")
	if rec := identityDo(t, s, "GET", "/internal/identity/na/"+testNAID, ""); rec.Code != 503 {
		t.Fatalf("no key configured: %d, want 503 (nobody gets in)", rec.Code)
	}
	t.Setenv("NX_INTERNAL_KEY", "another-key")
	for _, p := range []string{"/internal/identity/na/" + testNAID, "/internal/identity/users/x", "/internal/penne/registrations/x"} {
		if rec := identityDo(t, s, "GET", p, ""); rec.Code != 401 {
			t.Fatalf("%s with the wrong key: %d", p, rec.Code)
		}
	}
}

func TestIdentityAPIAnswersWhatShopPrincipalComputed(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "test-internal-key")
	s := shopServerFor(t)
	u := s.store.UserByPID(7)
	s.store.Update(u, func(u *User) { u.NaID = testNAID })

	rec := identityDo(t, s, "GET", "/internal/identity/users/"+u.ID, "")
	got := decodeBody(t, rec)
	if rec.Code != 200 || got["id"] != u.ID || got["na_id"] != testNAID || got["pid"] != float64(7) || got["nickname"] != "tester" {
		t.Fatalf("user = %d %v", rec.Code, got)
	}
	if _, ok := got["lock"]; !ok {
		t.Fatalf("user reply has no lock field: %v", got)
	}
	if rec := identityDo(t, s, "GET", "/internal/identity/users/nobody", ""); rec.Code != 404 {
		t.Fatalf("unknown user: %d", rec.Code)
	}

	got = decodeBody(t, identityDo(t, s, "GET", "/internal/identity/na/"+testNAID, ""))
	if got["baas_user_id"] != u.ID || got["pid"] != float64(7) || got["lock"] != "" {
		t.Fatalf("na = %v", got)
	}
	// An NA id with no console behind it still names an account: 200, no BAAS user.
	rec = identityDo(t, s, "GET", "/internal/identity/na/ffffffffffffffff", "")
	got = decodeBody(t, rec)
	if rec.Code != 200 || got["baas_user_id"] != "" || got["na_id"] != "ffffffffffffffff" {
		t.Fatalf("unlinked na = %d %v", rec.Code, got)
	}

	// The picture is the cdn-image host's own answer.
	rec = identityDo(t, s, "GET", "/internal/identity/users/"+u.ID+"/avatar", "")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "image/") {
		t.Fatalf("avatar = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}

	got = decodeBody(t, identityDo(t, s, "GET", "/internal/identity/users/"+u.ID+"/friends/someone/preference", ""))
	if got["online_notification"] != true {
		t.Fatalf("default preference = %v", got)
	}
}

func TestIdentityPresenceIsTheFrontlinesPublish(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "test-internal-key")
	s := shopServerFor(t)
	u := s.store.UserByPID(7)
	rec := identityDo(t, s, "POST", "/internal/identity/presence",
		`{"user_id":"`+u.ID+`","device":"dev1","state":"PLAYING","app_id":"0100000000010000","app_field":"","group_id":"","acd_index":-1}`)
	if rec.Code != 204 {
		t.Fatalf("presence = %d %s", rec.Code, rec.Body)
	}
	agg := aggregatePresence(s.store.User(u.ID), time.Now().Unix(), presenceLease())
	if agg.State != "PLAYING" || agg.AppID != "0100000000010000" || agg.Client != "switch" {
		t.Fatalf("presence not recorded as the console's: %+v", agg)
	}
	if rec := identityDo(t, s, "POST", "/internal/identity/presence/renew", `{"user_id":"`+u.ID+`","device":"dev1"}`); rec.Code != 204 {
		t.Fatalf("renew = %d", rec.Code)
	}
	if rec := identityDo(t, s, "POST", "/internal/identity/presence", `{"user_id":"nobody","state":"ONLINE"}`); rec.Code != 404 {
		t.Fatalf("unknown user's presence = %d", rec.Code)
	}
}

func TestPenneRegistrationsAPI(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "test-internal-key")
	s := shopServerFor(t)
	u := s.store.UserByPID(7)
	id, _ := s.notifStore().Register("dev1", u.ID, "", time.Now())
	got := decodeBody(t, identityDo(t, s, "GET", "/internal/penne/registrations/"+id, ""))
	if got["live"] != true || got["user_id"] != u.ID || got["penne_id"] != id {
		t.Fatalf("registration = %v", got)
	}
	got = decodeBody(t, identityDo(t, s, "GET", "/internal/penne/registrations/unknown", ""))
	if got["live"] != false {
		t.Fatalf("unknown registration = %v", got)
	}
}

// With NX_SHOP_URL set the eShop's hosts, its path-routed requests and the store admin API
// all reach nx-shop with the console's Host intact, and nothing else does.
func TestMovedShopIsForwarded(t *testing.T) {
	type seen struct{ host, path, body, key string }
	got := make(chan seen, 16)
	shop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.Host, r.URL.Path, string(b), r.Header.Get("X-Internal-Key")}
		w.Header().Set("X-From", "nx-shop")
		w.WriteHeader(299)
	}))
	defer shop.Close()
	t.Setenv("NX_SHOP_URL", shop.URL)
	s := shopServerFor(t)
	s.forwardersFromEnv()

	for _, c := range []struct{ host, path, body string }{
		{"hac.lp1.savanna.srv.nintendo.net", "/top", ""},
		{"atum.hac.lp1.d4c.nintendo.net", "/c2/a/d/0100000000010000", ""},
		{"superfly.hac.lp1.d4c.nintendo.net", "/v1/a/0100000000010000/dv", ""},
		{"pushmo.hac.lp1.eshop.nintendo.net", "/pushmo/p/x.json", ""},
		{"dragonst.hac.lp1.dragons.nintendo.net", "/v2/edge_token/issue", `{"title_ids":[]}`},
		{"dragons.hac.lp1.dragons.nintendo.net", "/v1/rights/publish_elicenses", `{"rights_ids":[]}`},
		{"beach.hac.lp1.eshop.nintendo.net", "/v1/my/devices", ""},
		{"c-lp1.accounts.nintendo.com", "/v1/apps/0100000000010000/catalog.json", ""},
		{"gw.hac.lp1.vermillion.srv.nintendo.net", "/v1/a/0100000000010000/dv", ""},
		{"unknown.example.nintendo.net", "/v1/acds/search", ""},
	} {
		req := httptest.NewRequest("POST", "https://"+c.host+c.path, strings.NewReader(c.body))
		req.Host = c.host
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != 299 {
			t.Fatalf("%s%s answered %d here, want it forwarded", c.host, c.path, rec.Code)
		}
		if g := <-got; g.host != c.host || g.path != c.path || g.body != c.body {
			t.Fatalf("%s%s reached nx-shop as %+v", c.host, c.path, g)
		}
	}

	// dragons. keeps its licence answers here; only the store rights routes moved.
	req := httptest.NewRequest("POST", "https://dragons.hac.lp1.dragons.nintendo.net/v1/elicenses/exercise", nil)
	req.Host = "dragons.hac.lp1.dragons.nintendo.net"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Header().Get("X-From") != "" {
		t.Fatalf("dragons exercise = %d from %q; it must stay here", rec.Code, rec.Header().Get("X-From"))
	}

	// The store admin API: the website's key travels through unchanged.
	t.Setenv("NX_INTERNAL_KEY", "test-internal-key")
	rec = identityDo(t, s, "GET", "/internal/store/titles", "")
	if rec.Code != 299 {
		t.Fatalf("store admin = %d, want it forwarded", rec.Code)
	}
	if g := <-got; g.path != "/internal/store/titles" || g.key != "test-internal-key" {
		t.Fatalf("store admin reached nx-shop as %+v", g)
	}

	// A moved shop is not read here: the forwarder replaced it, and an unrelated host still
	// answers locally.
	req = httptest.NewRequest("GET", "https://m-lp1.baas.nintendo.com/1.0.0/certificates", nil)
	req.Host = "m-lp1.baas.nintendo.com"
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var jwks map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &jwks) != nil {
		t.Fatalf("baas certificates = %d", rec.Code)
	}
}
