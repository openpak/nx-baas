package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"
)

// Team17's backend (T17BE) is what Moving Out 2 asks for before it ever reaches Photon
// Fusion: `directory.t17service.com` hands out an auth token and a `websocketUrl`, and the
// game then talks JSON over that socket (/sessions/*, /friends/*, /storage/*, /live/*).
// OpenPak answers none of it yet, so the redirect exists only to read the protocol: log the
// request, pass it to the real service, log the reply.
//
// The protocol as far as it is known: docs/t17-backend.md.
//
// ponytail: a capture spike, not a service. It lives here because Traefik already sends
// unrouted SNI to nx-baas and the on-demand cert already covers the name; it moves to
// servers/t17 the moment OpenPak answers for itself. `T17_PASSTHROUGH=0` stops the
// forwarding and answers 404, which still records what the game asked for.
func (s *server) t17(w http.ResponseWriter, r *http.Request, body []byte) {
	dump(r, body, ">>> t17")
	if t17Directory(w, r) || s.t17Socket(w, r) || s.t17GetToken(w, r, body) {
		return
	}
	if os.Getenv("T17_PASSTHROUGH") == "0" {
		writeJSON(w, 404, map[string]any{})
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	t17Proxy().ServeHTTP(w, r)
}

// The real service, reached by the box's own resolver — only consoles are redirected — and
// verified against the public roots like any other client of Team17's.
var t17Proxy = sync.OnceValue(func() http.Handler {
	return &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme, r.URL.Host = "https", hostOf(r)
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		ModifyResponse: func(res *http.Response) error {
			b, _ := io.ReadAll(res.Body)
			res.Body = io.NopCloser(bytes.NewReader(b))
			log.Printf("[t17] <<< %d %s %s body(%d)=%s", res.StatusCode, res.Request.Host, res.Request.URL.RequestURI(), len(b), b)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[t17] !! upstream %s%s: %v", hostOf(r), r.URL.Path, err)
			writeJSON(w, 502, map[string]any{})
		},
	}
})

// The directory is the whole of Team17's addressing: one GET, and its `game.url` is where the
// game takes every other request. Answering it ourselves points the title at OpenPak without
// redirecting anything else — notably not `*.execute-api.eu-west-1.amazonaws.com`, which is
// far too broad a family to put in the ceiling.
//
// Captured from the real service 2026-09-25 (Moving Out 2, `Api-Title: ProjectJourney`,
// `Api-Platform: nxswitch`, `Api-Tier: dev`): it answers `{"game":{"url":"http:///"},
// "xplayurl":"https://<aws>/prod/","AllowXPlay":"1","ga":{"ga":"0"}}`. That `game.url` has an
// empty host — Team17 has no backend configured for this tier, which is why the game stops
// with "An error has occurred connecting to T17 services" before it ever reaches Photon.
//
// T17_SELF_HOST is the domain to hand back (e.g. `t17service.com` → `game.t17service.com`);
// both land back here because the whole family is redirected and the cert is minted on demand.
// Unset keeps the passthrough, which is how the capture above was taken.
func t17Directory(w http.ResponseWriter, r *http.Request) bool {
	host := os.Getenv("T17_SELF_HOST")
	if host == "" || r.URL.Path != "/" || !strings.HasPrefix(hostOf(r), "directory.") {
		return false
	}
	log.Printf("[t17] directory: title=%q platform=%q tier=%q -> game.%s", r.Header.Get("Api-Title"),
		r.Header.Get("Api-Platform"), r.Header.Get("Api-Tier"), host)
	writeJSON(w, 200, map[string]any{
		"game":       map[string]any{"url": "https://game." + host + "/"},
		"xplayurl":   "https://xplay." + host + "/prod/",
		"AllowXPlay": "1",
		"ga":         map[string]any{"ga": "0"},
	})
	return true
}

// getToken is the whole of T17BE's authentication: one POST carrying the console's own BAAS
// id_token, answered with the addressing the native SDK needs. Captured 2026-09-25 from
// Moving Out 2:
//
//	POST <xplayurl>auth/get-token
//	{"coreVersion":"1.0.6.0.0","platformId":"nintendo","deviceId":"nintendo-switch",
//	 "gameId":"ProjectJourney","authType":"nintendo-switch","displayName":"hansolo",
//	 "nintendoSwitchAccessToken":"<JWT>"}
//
// The JWT is one WE signed (`kid: openpak-baas-key-1`), because OpenPak is the BAAS the console
// logged into — so the backend verifies its own token rather than asking Nintendo, the same way
// servers/demonware does.
//
// The reply's field names are not guesses, and neither is the list: T17BE_Transport::PreInitialise
// carries one "Backend Missing required <field>!!!!" string per field it demands, and there are
// exactly ten — token, websocketUrl, displayName, platformId, deviceId, globalPlayerId,
// blockList, role, exp, ttl. Answering with only six left the game authenticated and then
// silent: it never opened the socket. `role` is one of client / server / service
// (T17BE_Account::Initialise refuses anything else).
func (s *server) t17GetToken(w http.ResponseWriter, r *http.Request, body []byte) bool {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/auth/get-token") {
		return false
	}
	var in struct {
		PlatformID  string `json:"platformId"`
		DeviceID    string `json:"deviceId"`
		GameID      string `json:"gameId"`
		DisplayName string `json:"displayName"`
		Token       string `json:"nintendoSwitchAccessToken"`
	}
	_ = json.Unmarshal(body, &in)

	// The id_token names the player; without a readable one there is nobody to be.
	claims, err := parseJWT(in.Token, &s.key.PublicKey)
	if err != nil {
		log.Printf("[t17] get-token: id_token rejected: %v", err)
		writeJSON(w, 401, map[string]any{"error": "invalid token"})
		return true
	}
	id := str(claims, "sub")
	name := in.DisplayName
	if name == "" {
		name = id
	}
	log.Printf("[t17] get-token: game=%s player=%s (%s) platform=%s", in.GameID, name, id, in.PlatformID)
	const ttl = 12 * time.Hour
	fields := map[string]any{
		"token":          "t17-" + id + "-" + randHex(16),
		"websocketUrl":   "wss://game." + os.Getenv("T17_SELF_HOST") + "/socket",
		"displayName":    name,
		"platformId":     in.PlatformID,
		"deviceId":       in.DeviceID,
		"globalPlayerId": id,
		// An array. The C# field is declared `array[]` (metadata field table, Team17.CrossPlay.Auth)
		// and `JsonUtility.FromJsonOverwrite` — the deserialiser, called from
		// `WebRequest::UpdateWaitForResponse` at 0x4c0fefc — throws on a type mismatch, which
		// kills the whole auth step silently. It is the *native* side that wants a stringified
		// chunk, and it never sees this JSON: C# rebuilds one for it in GetT17AuthJson.
		"blockList": []any{},
		"role":      "client",
		"exp":       time.Now().Add(ttl).Unix(),
		"ttl":       int(ttl.Seconds()),
		// The C# model is the real gate, not the native SDK: `BE_PreInitialise` is a P/Invoke
		// stub that hands native ONE string, and `GetT17AuthJson` rebuilds that string from the
		// managed object. So this reply has to match the C# response class in
		// Team17.CrossPlay.Auth exactly — its twelve fields, read out of the metadata field
		// table, are websocketUrl, token, exp, ttl, displayName, globalPlayerId, role,
		// blockList, version, deviceId, platformId, killSwitchActive. Nothing else belongs
		// here: `apiVersion` is a field of SimpleCorePreInitData, a different class.
		"killSwitchActive": false,
		// T17BE_Transport::PreInitialise (0x68f2c0 in the 1.3.315 binary)
		// parses the root object and looks its keys up in a fixed order, twice: a validation
		// pass that emits "Backend Missing required <field>" for the ten above, then a fill
		// pass that re-reads them and ends at `version` (0x6901a4, key length 7) with no error
		// string of its own — which is why the ten-field reply was accepted over HTTP and then
		// dropped in silence. Copied as a string like its neighbours in that pass.
		"version": "1",
	}
	writeJSON(w, 200, fields)
	return true
}
