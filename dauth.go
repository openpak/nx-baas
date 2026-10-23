package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"nx-baas/internal/httpx"
	"nx-baas/internal/token"
	"nx-baas/redact"
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
	host, p := httpx.HostOf(r), r.URL.Path

	// aauth shares this handler: it is the next step of the same chain.
	// dcert: the verification keys for everything signed below.
	if strings.HasPrefix(host, "dcert") || strings.HasPrefix(host, "acert") {
		if p == "/keys" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(s.JWKS)
			return
		}
		http.NotFound(w, r)
		return
	}

	// Harbor device enrolment (harbor_devices.go), on this host because it is where a console
	// presents its TLS client certificate.
	if strings.HasPrefix(host, "dauth") && strings.HasPrefix(p, "/harbor/v1/devices") {
		s.harborDevicesHandler(w, r, body)
		return
	}

	form, _ := url.ParseQuery(string(body))
	switch {
	case p == "/v8/challenge" && r.Method == "POST":
		// The console mixes this into the MAC it sends back with the token request.
		httpx.WriteJSON(w, 200, map[string]any{
			"challenge": token.RandB64(33),
			"data":      token.RandB64(16),
		})

	case p == "/v8/device_auth_tokens" && r.Method == "POST":
		var req deviceTokenRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Printf("[dauth] token request is not JSON: %v", redact.Err(err))
			http.Error(w, `{"errors":[{"code":"1000","message":"malformed request"}]}`, http.StatusBadRequest)
			return
		}
		device, serial, err := s.dauthIdentity(r, req)
		if err != nil {
			log.Printf("[dauth] refused: another console is live with this device id")
			writeDeviceInUse(w)
			return
		}
		out := make([]any, 0, len(req.TokenRequests))
		for _, tr := range req.TokenRequests {
			if tr.ClientID == "" {
				continue
			}
			out = append(out, map[string]any{
				"client_id":         tr.ClientID,
				"device_auth_token": s.deviceTokenFor(device, serial, tr.ClientID),
				"expires_in":        86400,
			})
		}
		log.Printf("[dauth] fw %s -> %d token(s)", req.SystemVersion, len(out))
		// The console reads "results"; anything else and it fails the link with 2124-4798
		// after retrying the whole chain.
		httpx.WriteJSON(w, 200, map[string]any{"results": out})

	case p == "/v8/edge_tokens" && r.Method == "POST":
		// Edge tokens gate the CDN, not our services: the console wants an Akamai-style
		// signed string rather than a JWT, one per requested client/vendor pair.
		var req edgeTokenRequest
		_ = json.Unmarshal(body, &req)
		device, serial, err := s.dauthIdentity(r, deviceTokenRequest{})
		if err != nil {
			writeDeviceInUse(w)
			return
		}
		exp := time.Now().Unix() + 86400
		out := make([]any, 0, len(req.TokenRequests))
		for _, tr := range req.TokenRequests {
			out = append(out, map[string]any{
				"client_id":  tr.ClientID,
				"vendor_id":  tr.VendorID,
				"dtoken":     edgeDTokenFor(exp, device, serial),
				"expires_in": 86400,
			})
		}
		httpx.WriteJSON(w, 200, map[string]any{"results": out})

	case p == "/v5/application_auth_token" && r.Method == "POST":
		// aauth: the console asks for a per-title token once dauth has vouched for the device.
		appID, appVer := form.Get("application_id"), form.Get("application_version")
		log.Printf("[aauth] application %s version %s", appID, appVer)
		if s.versions.refuse(appID, appVer) {
			// 0111 -> 2124-3001 "A software update is required" (Restart / Later).
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{
				"errors": []any{map[string]any{"code": "0111", "message": "Application update is required."}},
			})
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{
			"application_auth_token": s.applicationToken(appID, appVer),
			"expires_in":             86400,
			"settings":               aauthSettings(appID),
			// Every account on this network has a membership; nothing here sells one.
			"online_play_policy": "MEMBERSHIP_REQUIRED",
			"policy_handler":     "SYSTEM",
		})

	// dragons: the licence service the console talks to during account setup. A 404 on any of
	// these stops the setup (2124-3121 / "cannot use online features"), so each one answers
	// plausibly; nothing on this network sells or revokes licences, so there is nothing to
	// check. The two archive endpoints are the ones the console calls while importing a user.
	case strings.HasPrefix(host, "dragons") && strings.Contains(p, "contents_authorization_token"):
		appID := r.Header.Get("Nintendo-Application-Id")
		if appID == "" {
			appID = "0100f8f0000a2000"
		}
		log.Printf("[dragons] contents authorization token for %q", appID)
		httpx.WriteJSON(w, 200, map[string]any{"contents_authorization_token": s.applicationToken(appID, "")})

	case strings.HasPrefix(host, "dragons") && strings.HasSuffix(p, "/elicense_archives/publish"),
		strings.HasPrefix(host, "dragons") && strings.HasSuffix(p, "/rights/publish_device_linked_elicenses"):
		// Nothing is waiting to be published: an empty list is the "all done" answer.
		log.Printf("[dragons] %s -> no archives", redact.Path(p))
		httpx.WriteJSON(w, 200, map[string]any{"elicense_archives": []any{}})

	case strings.HasPrefix(host, "dragons") && strings.HasSuffix(p, "/report"):
		httpx.WriteJSON(w, 200, map[string]any{})

	// Exercising a licence is how the console asks "may this user play online?". The real
	// service answers 200 with no body; a 404 reads as "no entitlement".
	case strings.HasPrefix(host, "dragons") && strings.HasSuffix(p, "/elicenses/exercise"):
		w.WriteHeader(http.StatusOK)

	case strings.HasPrefix(host, "dragons") && strings.HasSuffix(p, "/elicenses/migration_state"):
		httpx.WriteJSON(w, 200, map[string]any{"state": "COMPLETED", "migration_state": "NONE"})

	case strings.HasPrefix(host, "dragons") && strings.HasSuffix(p, "/penne_id"):
		httpx.WriteJSON(w, 200, map[string]any{"id": "opk" + token.RandHex(16), "password": token.RandB64(24)})

	default:
		log.Printf("[dauth] !! UNHANDLED %s %s%s", r.Method, host, redact.Path(p))
		http.NotFound(w, r)
	}
}

// edgeDToken builds the CDN's token format: fields joined by ~, with an HMAC the CDN would
// check. Nothing of ours verifies it, so the digest is random rather than pretend-signed.
func edgeDToken(exp int64, device string) string {
	return edgeDTokenFor(exp, device, consoleSerial(device))
}

func edgeDTokenFor(exp int64, device, serial string) string {
	return fmt.Sprintf("exp=%d~acl=%%2F%%2A~data=sub=%s.sn=%s.pc=HAC.id=%s~hmac=%s",
		exp, device, serial, token.UUID4(), token.RandHex(32))
}

// applicationToken is what aauth hands back for a title. Its jku is acert, not dcert: the
// console fetches the application key from there, and both hosts serve our one JWKS.
func (s *server) applicationToken(appID, appVersion string) string {
	now := time.Now().Unix()
	device := "openpak-device"
	serial := consoleSerial(device)
	return token.SignJWT(
		map[string]any{"alg": "RS256", "jku": "https://acert-lp1.ndas.srv.nintendo.net/keys", "kid": s.IDKid, "typ": "JWT"},
		map[string]any{
			"iss": "aauth-lp1.ndas.srv.nintendo.net",
			"jti": token.UUID4(),
			"iat": now - 600,
			"exp": now + 86400,
			"sub": appID,
			"typ": "application_auth_token",
			"dvc": map[string]any{"di": device, "sn": serial},
			"nintendo": map[string]any{
				"ai": appID, "av": appVersion, "at": now,
				"edi": token.RandB64(60), "tbn": token.RandB64(16), "tbh": token.RandB64(32),
				"opp": "MEMBERSHIP_REQUIRED", "ph": "SYSTEM",
				"di": device, "sn": serial, "pc": "HAC", "dt": "NX Prod 1",
				"ist": false, "esv": token.RandB64(33),
			},
		}, s.Key)
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
	return s.deviceTokenFor(deviceID, consoleSerial(deviceID), clientID)
}

// deviceTokenFor is deviceToken with the serial given: an enrolled Harbor console's own, read
// off its enrolment as the real service reads a console's off its certificate.
func (s *server) deviceTokenFor(deviceID, serial, clientID string) string {
	now := time.Now().Unix()
	return token.SignJWT(
		map[string]any{"alg": "RS256", "jku": "https://dcert-lp1.ndas.srv.nintendo.net/keys", "kid": s.IDKid, "typ": "JWT"},
		map[string]any{
			"iss": "dauth-lp1.ndas.srv.nintendo.net",
			"jti": token.UUID4(),
			"iat": now - 600,
			"exp": now + 86400,
			"sub": deviceID,
			"aud": clientID,
			"nintendo": map[string]any{
				"sn": serial, "did": deviceID, "pc": "HAC", "dt": "NX Prod 1",
				"ist": false, "esv": token.RandB64(33), "x5t#S256": deviceThumbprint,
			},
			"client_id": clientID,
		}, s.Key)
}

// deviceThumbprint is the x5t#S256 the console's own tokens carry; BAAS relays it into the
// anonymous access token, so dauth and BAAS must agree on one value.
const deviceThumbprint = "lkYHqHf2uXjNZ2UeDnW83GT_wa3-dH1KtPLVgxao3Rs"

// consoleSerial: the real service reads the serial off the console's certificate. We have no
// PRODINFO to read, so it is derived from the device id — stable per console, and shaped like
// the serial the console puts in its own headers (three letters, eleven digits). An empty
// serial travels into the BAAS access token and the console rejects the result.
func consoleSerial(deviceID string) string {
	sum := sha256.Sum256([]byte("serial:" + deviceID))
	n := binary.BigEndian.Uint64(sum[:8]) % 100000000000
	return fmt.Sprintf("XKJ%011d", n)
}

// aauthSettings is where a title's Nintendo Account client comes from. The account module
// reads exactly $.settings[0].nas:client_id (16 hex digits) and $.settings[0].nas:redirect_uri
// (under 256 bytes) out of this response [firmware, account module 0x2402e0], and with no
// client id it refuses the title's authorization request before any network request
// (0x1fb270: client id 0 -> 2124-0041). Nintendo assigns these per title; here the title id
// is the client id, so an id_token's aud names the title it was issued to.
func aauthSettings(appID string) []any {
	id := strings.ToLower(appID)
	// System titles (0100000000000xxx/1xxx) have their client ids compiled in.
	if len(id) != 16 || strings.HasPrefix(id, "01000000000") {
		return []any{}
	}
	return []any{map[string]any{"nas:client_id": id, "nas:redirect_uri": "npf" + id + "://auth"}}
}
