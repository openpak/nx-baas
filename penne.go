package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Push-notification registration the console performs right after a user is imported
// (NPNS sysmodule, system 18+): Penne id, notification token, account link, plus the Beach and
// Vermillion registrations that sit in the same sequence. Shapes per kinnay's Penne-Servers page
// and the Fix_Experimental hardware trace; the persistent frontline connection is not served.
func (s *server) penne(w http.ResponseWriter, r *http.Request, body []byte) {
	host, p := hostOf(r), r.URL.Path
	var in map[string]any
	json.Unmarshal(body, &in)
	now := time.Now().Unix()
	params := map[string]any{
		"awake": map[string]any{"count": 2, "idle": 60, "interval": 10}, "ignore_rst": true, "retry_count": 2,
		"sleep": map[string]any{"count": 1440, "idle": 60, "interval": 10}, "wait_sec": 3600,
	}
	const frontline = "fro-3.hac.lp1.penne.srv.nintendo.net"
	switch {
	case strings.HasPrefix(host, "god.") && p == "/v1/penne_ids":
		writeJSON(w, 200, map[string]any{"id": "p" + randHex(16), "password": randHex(16)})
	case strings.HasPrefix(host, "god.") && p == "/v1/immigrate":
		writeJSON(w, 404, map[string]any{})
	case strings.HasPrefix(host, "god.") && strings.HasSuffix(p, "/notification_tokens"):
		writeJSON(w, 200, map[string]any{"notification_token": randHex(18)})
	case strings.HasPrefix(host, "god.") && strings.HasSuffix(p, "/links"):
		nsa := ""
		if cl, err := parseJWT(str(in, "nsa_id_token"), nil); err == nil {
			nsa = str(cl, "sub")
		}
		writeJSON(w, 200, map[string]any{"nsa_id": nsa})
	case strings.HasPrefix(host, "god.") && r.Method == "DELETE":
		writeJSON(w, 200, map[string]any{"result": "ok"})
	case strings.HasPrefix(host, "val.") && p == "/v1/frontlines":
		writeJSON(w, 200, map[string]any{"current_time": now, "frontline_fqdn": frontline, "persistent_connection_params_simple": params})
	case strings.HasPrefix(host, "val.") && p == "/v1/login_tickets":
		writeJSON(w, 200, map[string]any{"expires_at": now + 4*86400, "frontline_fqdn": frontline, "issued_at": now, "persistent_connection_params_simple": params, "ticket": randHex(32)})
	case strings.HasPrefix(host, "fro-"):
		s.frontline(w, r)
	// Beach moved to beach.go (store workstream): the `{}` placeholder could not carry the
	// device/link/rights state the native store journey needs. The router sends beach hosts
	// straight there; this handler no longer sees them.
	case strings.HasPrefix(host, "gw.") && p == "/v1/accounts/config":
		writeJSON(w, 200, payloadEnvelope(map[string]any{"online_license": map[string]any{"is_available": true}})) // the online gate; is_available:false parks the game at the lobby with 2321-4992
	case strings.HasPrefix(host, "gw.") && strings.Contains(p, "/accounts/vphyms"):
		writeJSON(w, 200, payloadEnvelope(map[string]any{})) // 404 makes the title restart its whole bootstrap with a new penne id, forever
	case strings.HasPrefix(host, "gw.") && (r.Method == "PUT" || r.Method == "POST") && strings.HasPrefix(p, "/v1/devices/"):
		w.WriteHeader(204)
	case strings.HasPrefix(host, "gw.") && p == "/v1/devices/vermillion-device-id":
		writeJSON(w, 200, map[string]any{"vermillionDeviceId": vermillionDeviceID(deviceIDFromUA(r.UserAgent()))})
	case strings.HasPrefix(host, "gw."):
		writeJSON(w, 200, map[string]any{}) // /v1/devices/<id>
	default:
		dump(r, body, "!! UNHANDLED penne/npns")
		writeJSON(w, 404, map[string]any{})
	}
	log.Printf("[nx-baas] penne %s %s%s -> handled", r.Method, host, p)
}

// frontlineHeartbeat is how often the held-open frontline connection emits a keepalive chunk.
var frontlineHeartbeat = 30 * time.Second

// frontline answers the Penne persistent "frontline" POST (fro-N.hac.lp1.penne...). The client
// holds this connection open for room-code registration and push notifications; closing it
// immediately errors the client (the Splatoon 2 form of the failure is 2307-2103). So we accept
// it 200, stream chunked, and emit a keepalive until the console goes away, instead of 404-ing.
//
// ponytail: the held-open + chunked + heartbeat SHAPE is the recorded fact
// (servers/splatoon-3/docs/provenance.md); the heartbeat's CONTENT is not captured, so a benign
// newline stands in and nothing is actually pushed yet. A capture of the real frontline frame is
// the upgrade -- swap the write payload, the connection lifecycle stays as is.
func (s *server) frontline(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 200, map[string]any{"status": "connected"}) // never {} -- an empty reply is the failure class here
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(200)
	fl.Flush() // let the client see the connection accepted before the first heartbeat
	t := time.NewTicker(frontlineHeartbeat)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done(): // console hung up
			return
		case <-t.C:
			if _, err := w.Write([]byte("\n")); err != nil {
				return
			}
			fl.Flush()
		}
	}
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
