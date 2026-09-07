package main

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Device authentication, the first step of the console's chain: the console proves it is a
// console to dauth, gets a device_auth_token, and /1.0.0/application/token then trades that
// for an application token. Shapes per kinnay's DAuth-Server page.
//
//	dauth-lp1.ndas.srv.nintendo.net  POST /v8/challenge, /v8/device_auth_tokens, /v8/edge_tokens
//	dcert-lp1.ndas.srv.nintendo.net  GET  /keys
//
// The console verifies these tokens against the JWKS dcert serves, and that JWKS is ours, so
// the challenge/MAC the console computes is never checked: there is no Nintendo key here to
// check it with, and a private network gains nothing by pretending otherwise.
//
// ponytail: challenge data is random and unverified. Add real MAC verification only if a
// title is ever found that depends on it.
func (s *server) dauth(w http.ResponseWriter, r *http.Request, body []byte) {
	host, p := hostOf(r), r.URL.Path

	// dcert: the verification keys for everything signed below.
	if strings.HasPrefix(host, "dcert") {
		if p == "/keys" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(s.jwks)
			return
		}
		http.NotFound(w, r)
		return
	}

	form, _ := url.ParseQuery(string(body))
	switch {
	case p == "/v8/challenge" && r.Method == "POST":
		// The console mixes this into the MAC it sends back with the token request.
		writeJSON(w, 200, map[string]any{
			"challenge": randB64(33),
			"data":      randB64(16),
		})

	case p == "/v8/device_auth_tokens" && r.Method == "POST":
		// One token per requested client_id: the console asks for several at once
		// (system, applet and title clients) and expects them keyed by client_id.
		ids := form["client_id"]
		if len(ids) == 0 {
			ids = []string{form.Get("client_id")}
		}
		serial := form.Get("system_version") // not a serial; kept only for the log line
		device := deviceIDFrom(form)
		out := make([]any, 0, len(ids))
		for _, id := range ids {
			if id == "" {
				continue
			}
			out = append(out, map[string]any{
				"client_id":         id,
				"device_auth_token": s.deviceToken(device, id),
				"expires_in":        86400,
			})
		}
		log.Printf("[dauth] device %s -> %d token(s) (sysver %q)", device, len(out), serial)
		writeJSON(w, 200, map[string]any{"device_auth_tokens": out})

	case p == "/v8/edge_tokens" && r.Method == "POST":
		device := deviceIDFrom(form)
		writeJSON(w, 200, map[string]any{
			"edge_token": s.deviceToken(device, form.Get("client_id")),
			"expires_in": 86400,
		})

	default:
		log.Printf("[dauth] !! UNHANDLED %s %s%s", r.Method, host, p)
		http.NotFound(w, r)
	}
}

// deviceIDFrom picks the console's identifier out of whichever field this firmware sent.
// Falls back to a stable placeholder so a missing field cannot wedge the login.
func deviceIDFrom(form url.Values) string {
	for _, k := range []string{"device_id", "did", "device_account_id"} {
		if v := form.Get(k); v != "" {
			return v
		}
	}
	return "openpak-device"
}

// deviceToken is what /1.0.0/application/token consumes: it reads "sub" as the device id and
// nintendo.sn as the serial, so those two fields are the contract between the services.
func (s *server) deviceToken(deviceID, clientID string) string {
	now := time.Now().Unix()
	return signJWT(
		map[string]any{"alg": "RS256", "jku": "https://dcert-lp1.ndas.srv.nintendo.net/keys", "kid": s.idKid, "typ": "JWT"},
		map[string]any{
			"iss":       "https://dauth-lp1.ndas.srv.nintendo.net",
			"jti":       randHex(16),
			"iat":       now,
			"exp":       now + 86400,
			"sub":       deviceID,
			"aud":       clientID,
			"nintendo":  map[string]any{"sn": "", "did": deviceID},
			"client_id": clientID,
		}, s.key)
}
