package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The vermillion gateway's device id is read by the client as a URL path segment and stored as
// its device identity. Three things have to hold at once or the client never leaves its
// bootstrap: the key is camelCase, the value decodes to 16 bytes, and the encoding contains no
// "/". Answering "{}" -- what this endpoint did before -- is the failure this guards.
func TestVermillionDeviceIDIsUsableAsAPathSegment(t *testing.T) {
	const ua = "NintendoSDK Firmware/20.1.5-4.0 (platform:NX; did:0123456789abcdef; eid:lp1)"

	r := httptest.NewRequest("GET", "/v1/devices/vermillion-device-id", nil)
	r.Host = "gw.hac.lp1.vermillion.srv.nintendo.net"
	r.Header.Set("User-Agent", ua)
	w := httptest.NewRecorder()
	(&server{}).penne(w, r, nil)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body does not decode: %v", err)
	}
	id, ok := got["vermillionDeviceId"].(string)
	if !ok {
		t.Fatalf("no string vermillionDeviceId in %v", got)
	}
	if strings.Contains(id, "/") {
		t.Errorf("device id %q contains a /, which crashes the client using it as a path segment", id)
	}
	raw, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("device id %q is not base64: %v", id, err)
	}
	if len(raw) != 16 {
		t.Errorf("device id decodes to %d bytes, want 16", len(raw))
	}

	// Stable for the same console: the client keeps the value, so a fresh one per request
	// would make it re-register forever.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/v1/devices/vermillion-device-id", nil)
	r2.Host = r.Host
	r2.Header.Set("User-Agent", ua)
	(&server{}).penne(w2, r2, nil)
	if w2.Body.String() != w.Body.String() {
		t.Errorf("device id is not stable: %s then %s", w.Body.String(), w2.Body.String())
	}
}
