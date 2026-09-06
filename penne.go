package main

import (
	"encoding/json"
	"log"
	"net/http"
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
	case strings.HasPrefix(host, "beach."):
		writeJSON(w, 200, map[string]any{}) // /contents, /penne_id/register, /set: observed 200 {}
	case strings.HasPrefix(host, "gw.") && strings.Contains(p, "/accounts/vphyms"):
		writeJSON(w, 404, map[string]any{})
	case strings.HasPrefix(host, "gw.") && (r.Method == "PUT" || r.Method == "POST") && strings.HasPrefix(p, "/v1/devices/"):
		w.WriteHeader(204)
	case strings.HasPrefix(host, "gw."):
		writeJSON(w, 200, map[string]any{}) // /v1/devices/<id>, /v1/accounts/config
	default:
		dump(r, body, "!! UNHANDLED penne/npns")
		writeJSON(w, 404, map[string]any{})
	}
	log.Printf("[nx-baas] penne %s %s%s -> handled", r.Method, host, p)
}
