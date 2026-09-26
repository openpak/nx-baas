package main

// Phase 0 has one job beyond logging: refuse in the shape pctl recognises, and
// leave the rest of the host alone. Both are asserted here because getting either
// wrong makes the hardware log -- the whole point of the phase -- unreadable.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
