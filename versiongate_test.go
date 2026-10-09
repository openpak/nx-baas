package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An excerpt of titledb's versions.json: MK8D's latest is 0x00160000 (1441792).
const versionsFixture = `{
 "0100152000022000": {"1245184": "2024-09-13", "1376256": "2025-06-10", "1441792": "2026-09-01"},
 "010090100e334000": {"1966080": "2026-05-20", "2031616": "2026-08-16"}
}`

func gateFromFixture(t *testing.T, overrides string) *versionGate {
	t.Helper()
	o, err := parseVersionOverrides(overrides)
	if err != nil {
		t.Fatal(err)
	}
	g := &versionGate{on: true, overrides: o, fetch: func(string) ([]byte, error) { return []byte(versionsFixture), nil }}
	if err := g.refresh(); err != nil {
		t.Fatal(err)
	}
	return g
}

func aauthRequest(t *testing.T, s *server, appID, appVer string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"application_id": {appID}, "application_version": {appVer}}.Encode()
	r := httptest.NewRequest(http.MethodPost, "/v5/application_auth_token", strings.NewReader(form))
	r.Host = "aauth-lp1.ndas.srv.nintendo.net"
	w := httptest.NewRecorder()
	s.dauth(w, r, []byte(form))
	return w
}

func wantUpdateRequired(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"0111"`) ||
		!strings.Contains(w.Body.String(), "Application update is required.") {
		t.Fatalf("got %d %s, want 400 with 0111", w.Code, w.Body.String())
	}
}

func wantToken(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "application_auth_token") {
		t.Fatalf("got %d %s, want 200 with a token", w.Code, w.Body.String())
	}
}

func TestVersionGateAauth(t *testing.T) {
	s := dauthServer(t)
	s.versions = gateFromFixture(t, "")

	wantUpdateRequired(t, aauthRequest(t, s, "0100152000022000", "00000000")) // MK8D 1.0.0
	wantUpdateRequired(t, aauthRequest(t, s, "0100152000022000", "00150000")) // one behind
	wantToken(t, aauthRequest(t, s, "0100152000022000", "00160000"))          // latest
	wantToken(t, aauthRequest(t, s, "0100152000022000", "00170000"))          // newer than the table
	wantToken(t, aauthRequest(t, s, "0100000000ABC000", "00000000"))          // unknown title
	wantToken(t, aauthRequest(t, s, "0100152000022000", "3.0.5"))             // Harbor's display string
	wantToken(t, aauthRequest(t, s, "0100152000022000", ""))                  // nothing sent
	wantUpdateRequired(t, aauthRequest(t, s, "0100152000022800", "00000000")) // the update id names the base
}

func TestVersionGateOff(t *testing.T) {
	s := dauthServer(t)
	s.versions = gateFromFixture(t, "")
	s.versions.on = false
	wantToken(t, aauthRequest(t, s, "0100152000022000", "00000000"))
	s.versions = nil
	wantToken(t, aauthRequest(t, s, "0100152000022000", "00000000"))
}

func TestVersionGateOverrides(t *testing.T) {
	s := dauthServer(t)
	s.versions = gateFromFixture(t, "0100152000022000=00150000, 010090100E334000=all,0100000000abc000=00010000")

	wantToken(t, aauthRequest(t, s, "0100152000022000", "00150000")) // pinned below the table's latest
	wantUpdateRequired(t, aauthRequest(t, s, "0100152000022000", "00130000"))
	wantToken(t, aauthRequest(t, s, "010090100E334000", "00000000"))          // allow all
	wantUpdateRequired(t, aauthRequest(t, s, "0100000000ABC000", "00000000")) // pinned, not in the table

	for _, bad := range []string{"0100152000022000", "0100152000022000=3.0.5", "123=00010000"} {
		if _, err := parseVersionOverrides(bad); err == nil {
			t.Errorf("override %q accepted", bad)
		}
	}
}

func TestVersionGateKeepsLastGoodTable(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "title-versions.json")
	g := &versionGate{on: true, cachePath: cache, fetch: func(string) ([]byte, error) { return []byte(versionsFixture), nil }}
	if err := g.refresh(); err != nil {
		t.Fatal(err)
	}
	if g.size() != 2 {
		t.Fatalf("table has %d titles, want 2", g.size())
	}

	for _, fail := range []func(string) ([]byte, error){
		func(string) ([]byte, error) { return nil, errors.New("HTTP 503") },
		func(string) ([]byte, error) { return []byte("<html>rate limited</html>"), nil },
		func(string) ([]byte, error) { return []byte("{}"), nil },
	} {
		g.fetch = fail
		if err := g.refresh(); err == nil {
			t.Fatal("a bad fetch was accepted")
		}
		if need, ok := g.required(0x0100152000022000); !ok || need != 0x00160000 || g.size() != 2 {
			t.Fatalf("table lost after a failed refresh: %08x %v size %d", need, ok, g.size())
		}
	}
	if b, _ := os.ReadFile(cache); string(b) != versionsFixture {
		t.Fatal("a failed refresh overwrote the cache")
	}

	// A restart with no network starts from the cache.
	g2 := &versionGate{on: true, cachePath: cache}
	g2.loadCache()
	if need, ok := g2.required(0x0100152000022000); !ok || need != 0x00160000 {
		t.Fatalf("cache load: %08x %v", need, ok)
	}
}

// The game servers' question gets the same answer aauth gives the console.
func TestTitleVersionAPI(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k")
	s := dauthServer(t)
	s.versions = gateFromFixture(t, "010090100E334000=all")

	ask := func(key, query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/internal/title-version?"+query, nil)
		r.Header.Set("X-Internal-Key", key)
		w := httptest.NewRecorder()
		s.gameAPI().ServeHTTP(w, r)
		return w
	}
	cases := []struct{ query, want string }{
		{"title=0100152000022000&version=00150000", `"latest":"00160000","title":"0100152000022000","update_required":true,"version":"00150000"`},
		{"title=0100152000022000&version=00160000", `"latest":"00160000","title":"0100152000022000","update_required":false`},
		{"title=0100152000022000&version=3.0.5", `"latest":"00160000","title":"0100152000022000","update_required":false`},
		{"title=0100152000022000&version=", `"update_required":false`},
		{"title=0100000000ABC000&version=00000000", `"latest":"","title":"0100000000abc000","update_required":false`},
		{"title=010090100E334000&version=00000000", `"latest":"","title":"010090100e334000","update_required":false`},
	}
	for _, c := range cases {
		w := ask("k", c.query)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: got %d %s, want %s", c.query, w.Code, w.Body.String(), c.want)
		}
	}
	if w := ask("k", "title=nope&version=00000000"); w.Code != http.StatusBadRequest {
		t.Errorf("bad title: got %d", w.Code)
	}
	if w := ask("wrong", "title=0100152000022000&version=00150000"); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: got %d", w.Code)
	}
	s.versions.on = false
	if w := ask("k", "title=0100152000022000&version=00000000"); !strings.Contains(w.Body.String(), `"latest":"","title":"0100152000022000","update_required":false`) {
		t.Errorf("gate off: %s", w.Body.String())
	}
	s.versions = nil
	if w := ask("k", "title=0100152000022000&version=00000000"); !strings.Contains(w.Body.String(), `"update_required":false`) {
		t.Errorf("no gate: %s", w.Body.String())
	}
}
