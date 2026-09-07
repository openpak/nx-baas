package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// What the console posts to /v8/device_auth_tokens (captured from a real console, firmware
// 22.2.0.0): JSON, with one entry per client id it wants a token for. There is no device
// identifier anywhere in it — the real service knows the console from its TLS client
// certificate, which is why deviceID falls back to the connection below.
type edgeTokenRequest struct {
	TokenRequests []struct {
		ClientID string `json:"client_id"`
		VendorID string `json:"vendor_id"`
	} `json:"token_requests"`
}

type deviceTokenRequest struct {
	SystemVersion string `json:"system_version"`
	FWRevision    string `json:"fw_revision"`
	KeyGeneration int    `json:"key_generation"`
	Challenge     string `json:"challenge"`
	MAC           string `json:"mac"`
	IST           bool   `json:"ist"`
	TokenRequests []struct {
		ClientID string `json:"client_id"`
	} `json:"token_requests"`
}

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

	// aauth shares this handler: it is the next step of the same chain.
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
		var req deviceTokenRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Printf("[dauth] token request is not JSON: %v", err)
			http.Error(w, `{"errors":[{"code":"1000","message":"malformed request"}]}`, http.StatusBadRequest)
			return
		}
		device := deviceID(r, req)
		out := make([]any, 0, len(req.TokenRequests))
		for _, tr := range req.TokenRequests {
			if tr.ClientID == "" {
				continue
			}
			out = append(out, map[string]any{
				"client_id":         tr.ClientID,
				"device_auth_token": s.deviceToken(device, tr.ClientID),
				"expires_in":        86400,
			})
		}
		log.Printf("[dauth] device %s (fw %s) -> %d token(s)", device, req.SystemVersion, len(out))
		// The console reads "results"; anything else and it fails the link with 2124-4798
		// after retrying the whole chain.
		writeJSON(w, 200, map[string]any{"results": out})

	case p == "/v8/edge_tokens" && r.Method == "POST":
		// Edge tokens gate the CDN, not our services: the console wants an Akamai-style
		// signed string rather than a JWT, one per requested client/vendor pair.
		var req edgeTokenRequest
		_ = json.Unmarshal(body, &req)
		device := deviceID(r, deviceTokenRequest{})
		exp := time.Now().Unix() + 86400
		out := make([]any, 0, len(req.TokenRequests))
		for _, tr := range req.TokenRequests {
			out = append(out, map[string]any{
				"client_id":  tr.ClientID,
				"vendor_id":  tr.VendorID,
				"dtoken":     edgeDToken(exp, device),
				"expires_in": 86400,
			})
		}
		writeJSON(w, 200, map[string]any{"results": out})

	case p == "/v5/application_auth_token" && r.Method == "POST":
		// aauth: the console asks for a per-title token once dauth has vouched for the device.
		appID, appVer := form.Get("application_id"), form.Get("application_version")
		log.Printf("[aauth] application %s version %s", appID, appVer)
		writeJSON(w, 200, map[string]any{
			"application_auth_token": s.applicationToken(appID, appVer),
			"expires_in":             86400,
			"settings":               []any{},
			// Every account on this network has a membership; nothing here sells one.
			"online_play_policy": "MEMBERSHIP_REQUIRED",
			"policy_handler":     "SYSTEM",
		})

	// dragons: the licence service the console talks to during account setup. A 404 here stops
	// the setup with 2124-3121, so both endpoints answer plausibly; nothing on this network
	// sells or revokes licences, so there is nothing to check.
	case strings.HasPrefix(host, "dragons") && strings.HasSuffix(p, "/elicense_archives/publish"):
		log.Printf("[dragons] elicense archive published")
		writeJSON(w, 200, map[string]any{"id": randHex(16), "published_at": time.Now().Unix()})

	case strings.HasPrefix(host, "dragons") && strings.Contains(p, "contents_authorization_token"):
		appID := r.Header.Get("Nintendo-Application-Id")
		log.Printf("[dragons] contents authorization token for %q", appID)
		writeJSON(w, 200, map[string]any{"contents_authorization_token": s.applicationToken(appID, "")})

	default:
		log.Printf("[dauth] !! UNHANDLED %s %s%s", r.Method, host, p)
		http.NotFound(w, r)
	}
}

// edgeDToken builds the CDN's token format: fields joined by ~, with an HMAC the CDN would
// check. Nothing of ours verifies it, so the digest is random rather than pretend-signed.
func edgeDToken(exp int64, device string) string {
	return fmt.Sprintf("exp=%d~acl=%%2F%%2A~data=sub=%s.pc=HAC.id=%s~hmac=%s",
		exp, device, randHex(16), randHex(32))
}

// applicationToken is what aauth hands back for a title.
func (s *server) applicationToken(appID, appVersion string) string {
	now := time.Now().Unix()
	return signJWT(
		map[string]any{"alg": "RS256", "jku": "https://dcert-lp1.ndas.srv.nintendo.net/keys", "kid": s.idKid, "typ": "JWT"},
		map[string]any{
			"iss": "https://aauth-lp1.ndas.srv.nintendo.net",
			"jti": randHex(16),
			"iat": now,
			"exp": now + 86400,
			"sub": appID,
			"aud": appID,
			"nintendo": map[string]any{
				"ai": appID,
				"av": appVersion,
			},
		}, s.key)
}

// deviceID identifies the console. Nothing in the request body says which console it is, so the
// TLS client certificate is used when the console presents one — that is how the real service
// tells consoles apart. Without a certificate every console on this network would share one
// device account, so the fallback is logged rather than silently accepted.
func deviceID(r *http.Request, req deviceTokenRequest) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		c := r.TLS.PeerCertificates[0]
		sum := sha256.Sum256(c.Raw)
		return "cert-" + hex.EncodeToString(sum[:8])
	}
	log.Printf("[dauth] WARNING: no client certificate; consoles cannot be told apart (fw %s)", req.SystemVersion)
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
