package main

import (
	"bytes"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A request that carries a console's ids, a pairing code, an e-mail address, a bearer token,
// a device id in its user agent and a client address must leave none of them in the log: the
// path and the query are tagged or reduced to names, and the header values are never logged.
func TestLogsCarryNoPersonalData(t *testing.T) {
	const (
		userID = "8a2b3c4d5e6f7081"
		pid    = "73400125"
		code   = "483920"
		email  = "leia.organa@example.test"
		token  = "tok-9f8e7d6c5b4a39281706"
		device = "6b1f2e3d4c5a6978"
		addr   = "203.0.113.77"
	)
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	s := testServer(t)
	r := httptest.NewRequest("GET", "https://account.example.test/1.0.0/users/"+userID+"/friends/"+pid+
		"?pairingCode="+code+"&email="+email, nil)
	r.RemoteAddr = addr + ":44312"
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("User-Agent", "NintendoSDK Firmware/23.0.1-1.0 (platform:NX; did:"+device+")")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	got := logged.String()
	if !strings.Contains(got, "[nx-baas]") || !strings.Contains(got, "~") {
		t.Fatalf("no tagged request line in the log:\n%s", got)
	}
	for _, secret := range []string{userID, pid, code, email, token, device, addr, "44312"} {
		if strings.Contains(got, secret) {
			t.Errorf("log contains %q:\n%s", secret, got)
		}
	}
}
