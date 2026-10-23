package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"nx-baas/internal/httpx"
	"nx-baas/redact"
	"strconv"
	"strings"
)

// The vermillion gateway (gw.hac.<env>.vermillion.srv.nintendo.net): the online-licence gate
// and a title's bootstrap (accounts/config, vphyms, vermillion-device-id). It sits beside
// Penne in the console's sequence but is not push: it is stateless, a 404 here restarts a
// title's whole bootstrap, and it stays in nx-baas while Penne itself (god, val, fro-) is
// nx-penne's (split.go). Shapes per kinnay's Penne-Servers page and the hardware trace.
func (s *server) vermillion(w http.ResponseWriter, r *http.Request, body []byte) {
	host, p := httpx.HostOf(r), r.URL.Path
	if s.key != nil && s.store != nil {
		// Nothing here needs the account, but the bearer check logs why a token does not
		// name one, and that diagnostic has always come with these requests.
		s.bearerUser(r)
	}
	// The console reports its own last frontline attempt back on its Penne-family
	// requests: X-Fro-Result carries the result code it recorded, X-Login-Try how many
	// times it has tried, X-Npc and X-Execution its own state counters [firmware header
	// set, npns 0x1239e5 region]. Logged whenever it is not the all-zero value.
	if fro := r.Header.Get("X-Fro-Result"); fro != "" && fro != "000-0000" {
		log.Printf("[nx-baas] penne: console reports last frontline result %s (try %s, npc %s, exec %s) on %s",
			fro, r.Header.Get("X-Login-Try"), r.Header.Get("X-Npc"),
			r.Header.Get("X-Execution"), redact.Path(p))
	}
	switch {
	case strings.HasPrefix(host, "gw.") && p == "/v1/accounts/config":
		httpx.WriteJSON(w, 200, payloadEnvelope(map[string]any{"online_license": map[string]any{"is_available": true}})) // the online gate; is_available:false parks the game at the lobby with 2321-4992
	case strings.HasPrefix(host, "gw.") && strings.Contains(p, "/accounts/vphyms"):
		httpx.WriteJSON(w, 200, payloadEnvelope(map[string]any{})) // 404 makes the title restart its whole bootstrap with a new penne id, forever
	case strings.HasPrefix(host, "gw.") && (r.Method == "PUT" || r.Method == "POST") && strings.HasPrefix(p, "/v1/devices/"):
		w.WriteHeader(204)
	case strings.HasPrefix(host, "gw.") && p == "/v1/devices/vermillion-device-id":
		httpx.WriteJSON(w, 200, map[string]any{"vermillionDeviceId": vermillionDeviceID(deviceIDFromUA(r.UserAgent()))})
	// The vermillion gateway also carries NIM's family, nearness and notify routes
	// (eshop_unserved.go); those get their own answers rather than a bare {}.
	case strings.HasPrefix(host, "gw.") && s.nimUnserved(w, r, body):
	case strings.HasPrefix(host, "gw.") && r.Method == "GET" && strings.HasPrefix(p, "/v1/devices/"):
		httpx.WriteJSON(w, 200, map[string]any{}) // /v1/devices/<id>
	case strings.HasPrefix(host, "gw."):
		// Kept as the old 200 {} (a title that gets a 404 on this gateway restarts its
		// bootstrap), but no longer silent: it is the one answer here nobody chose.
		httpx.Dump(r, body, "!! UNHANDLED vermillion gw (answered 200 {})")
		httpx.WriteJSON(w, 200, map[string]any{})
	default:
		httpx.Dump(r, body, "!! UNHANDLED penne/npns")
		httpx.WriteJSON(w, 404, map[string]any{})
	}
	log.Printf("[nx-baas] penne %s %s%s -> handled", r.Method, host, redact.Path(p))
}

// payloadEnvelope wraps an object the way the vermillion account endpoints return it:
// {"payload": "<base64 of the object's JSON>"}. A bare 404 (or a "{}") on one of these reads as
// account setup failed, and the title restarts its whole bootstrap with a fresh penne id --
// forever. An empty inner object is fine; the 200 with an envelope is what breaks the loop.
func payloadEnvelope(inner map[string]any) map[string]any {
	b, _ := json.Marshal(inner)
	return map[string]any{"payload": base64.StdEncoding.EncodeToString(b)}
}

// deviceIDFromUA pulls the console's own device id out of the SDK's User-Agent,
// which is where the SDK puts it: "NintendoSDK Firmware/<ver> (platform:NX; did:<hex>; eid:lp1)".
func deviceIDFromUA(ua string) string {
	i := strings.Index(ua, "did:")
	if i < 0 {
		return ""
	}
	rest := ua[i+len("did:"):]
	if j := strings.IndexAny(rest, "; )"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// The id the vermillion gateway hands back for a device: 16 bytes, base64. The client uses the
// value as a URL path segment, so an encoding containing "/" crashes it -- keep re-deriving
// until one has none. Answering the wrong key, or "{}", leaves the client with no device id and
// it loops its bootstrap forever.
//
// ponytail: derived from the console's own device id rather than stored, so it is stable across
// reboots with no state at all. A stored per-device value is the upgrade if a console ever
// stops carrying "did:" in its User-Agent -- every such console shares one id here.
func vermillionDeviceID(did string) string {
	for i := 0; ; i++ {
		sum := sha256.Sum256([]byte("openpak/vermillion-device-id/" + did + "/" + strconv.Itoa(i)))
		if v := base64.StdEncoding.EncodeToString(sum[:16]); !strings.Contains(v, "/") {
			return v
		}
	}
}
