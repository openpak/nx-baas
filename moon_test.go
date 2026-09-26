package main

// Phase 0 has one job beyond logging: refuse in the shape pctl recognises, and
// leave the rest of the host alone. Both are asserted here because getting either
// wrong makes the hardware log -- the whole point of the phase -- unreadable.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func moonCall(t *testing.T, method, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	s := &server{}
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
	w, got := moonCall(t, "GET", "/moon/v1/devices?filter.links.pairingCode.code.$eq=ABCDEF")

	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", w.Code)
	}
	// The literal in the firmware, byte for byte: a different string is a
	// refusal the client cannot classify.
	if got["type"] != "https://moon.nintendo.com/errors/v1/404/resource_is_not_found" {
		t.Fatalf("type %q -- must be the firmware's own literal", got["type"])
	}
	if got["status"] != float64(http.StatusNotFound) {
		t.Fatalf("status field %v, want 404 -- the type URI and the status line must agree", got["status"])
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
	return &Store{path: filepath.Join(t.TempDir(), "store.json")}
}

func TestPairingCodeIsGoodOnceAndOnlyBeforeItExpires(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("naid-parent")

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
	d := st.PctlNewPairing("naid-parent")

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
	r := httptest.NewRequest("POST", "/internal/pctl/pairing", strings.NewReader(`{"na_id":"naid-parent"}`))
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
	if got.Code == "" || strings.ContainsAny(got.Code, "OI01") {
		t.Fatalf("code %q -- must exist and stay out of the ambiguous glyphs", got.Code)
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
