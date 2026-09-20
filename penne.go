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
// and the Fix_Experimental hardware trace.
//
// Everything below persists through the penne store (NTF-01): a registration is durable, a
// token or ticket inherits its binding, and revocation kills everything minted under it.
// Request-side credential field names are not yet captured; where a request carries none, the
// binding falls back to the device association the console already established (flagged in
// docs/penne-protocol.md as provisional until a capture shows the real shapes).
func (s *server) penne(w http.ResponseWriter, r *http.Request, body []byte) {
	host, p := hostOf(r), r.URL.Path
	var in map[string]any
	json.Unmarshal(body, &in)
	now := time.Now()
	store := s.notifStore()
	deviceID := deviceIDFromUA(r.UserAgent())
	// The console signs Penne calls with the token it has: on the frontline
	// bootstrap that is the console's device token, whose subject is the device
	// certificate and not an account. Keep the two apart — one names a console,
	// the other an account the outbox is keyed by.
	userID := ""
	if s.key != nil {
		if c := s.bearer(r); c != nil {
			userID = str(c, "sub")
		}
	}
	if s.key != nil && s.store != nil {
		if u := s.bearerUser(r); u != nil {
			userID = u.ID
		}
	}
	// The 128-bit account id the console puts in the path: two 64-bit words,
	// "%016llx%016llx" [firmware, npns 0x120f4b]. The friends module discards
	// any event that does not arrive addressed to one of these, so it is
	// recorded wherever the console shows it to us.
	accountID := penneAccountID(p)
	// The console reports its own last frontline attempt back to us on every
	// Penne request: X-Fro-Result carries the result code it recorded,
	// X-Login-Try how many times it has tried, X-Npc and X-Execution its own
	// state counters [firmware header set, npns 0x1239e5 region]. That is the
	// console telling us why it dropped the previous connection, which is the
	// one diagnostic here that needs no guesswork — so it is logged whenever
	// it is not the all-zero "nothing to report" value.
	if fro := r.Header.Get("X-Fro-Result"); fro != "" && fro != "000-0000" {
		log.Printf("[nx-baas] penne: console reports last frontline result %s (try %s, npc %s, exec %s) on %s",
			fro, r.Header.Get("X-Login-Try"), r.Header.Get("X-Npc"),
			r.Header.Get("X-Execution"), p)
	}
	params := map[string]any{
		// Horizon 22.5.0 validates every child before accepting this object.
		// Defaults recovered from NPNS RVA 0xb82e0; omitting these fields
		// leaves login incomplete even when the HTTP response is successful.
		"awake":      map[string]any{"count": 2, "idle": 60, "interval": 10, "disable": false},
		"sleep":      map[string]any{"count": 1440, "idle": 60, "interval": 10, "disable": true},
		"ignore_rst": true, "retry_count": 2, "wait_sec": 3600,
		"wowl_timeout": 410, "rtt_max": 300,
	}
	const frontline = "fro-3.hac.lp1.penne.srv.nintendo.net"
	switch {
	case strings.HasPrefix(host, "god.") && p == "/v1/penne_ids":
		// Registration always mints; a supplied id alone authorizes nothing.
		// With id+password both present it is a rotation: prove the pair,
		// retire everything minted under it, mint fresh.
		//
		// An id this store never minted is NOT a denial. A console keeps its
		// registration in its own `npns:` save data and presents it forever, so
		// a console that registered against a different server -- or against a
		// store that has since been replaced -- arrives here with credentials
		// nothing can verify. Answering 403 leaves it with an id we reject and
		// no way to obtain one we accept: it never opens a frontline, and every
		// notification for it is undeliverable for the life of the console.
		// Minting a fresh pair is the recovery, and the console stores it.
		// Only a KNOWN id with a wrong password is an attacker.
		if id := penneCred(in); id != "" {
			switch _, err := store.CheckAssoc(id, str(in, "password"), now); {
			case err == nil:
				store.Revoke(id, now)
			case store.KnowsAssoc(id):
				log.Printf("[nx-baas] penne: rotation denied for a known id (%v)", err)
				writeJSON(w, 403, map[string]any{"status": 403, "title": "forbidden"})
				return
			default:
				log.Printf("[nx-baas] penne: console presented an id this store never minted (device %s, user %s); minting a fresh registration", deviceID, userID)
			}
		}
		id, password := store.Register(deviceID, userID, "", now)
		writeJSON(w, 200, map[string]any{"id": id, "password": password})
	case strings.HasPrefix(host, "god.") && p == "/v1/immigrate":
		writeJSON(w, 404, map[string]any{}) // nothing to migrate from legacy NPNS
	case strings.HasPrefix(host, "god.") && strings.HasSuffix(p, "/notification_tokens"):
		assoc, ok := s.penneAuthedAssoc(store, in, userID, deviceID, now)
		if ok {
			// ResolveUser: the bearer here is usually the console's device
			// token, whose subject is the certificate, and AccountUsers is
			// keyed by the BAAS account the outbox delivers to. Recorded as a
			// cert it is an address no delivery can ever find.
			store.NoteAccount(assoc.ID, accountID, store.ResolveUser(userID))
			log.Printf("[nx-baas] penne: notification token for console account %s (registration %s, first guess %q)", accountID, assoc.ID, store.ResolveUser(userID))
		}
		if !ok {
			writeJSON(w, 401, map[string]any{"status": 401, "title": "authentication required"})
			return
		}
		tok, err := store.NotificationTokenFor(assoc, accountID, now)
		if err != nil {
			writeJSON(w, 401, map[string]any{"status": 401, "title": "authentication failed"})
			return
		}
		writeJSON(w, 200, map[string]any{"notification_token": tok})
	case strings.HasPrefix(host, "god.") && strings.HasSuffix(p, "/links"):
		nsa := ""
		if cl, err := parseJWT(str(in, "nsa_id_token"), nil); err == nil {
			nsa = str(cl, "sub")
		}
		if assoc, ok := s.penneAuthedAssoc(store, in, userID, deviceID, now); ok && nsa != "" {
			store.LinkNSA(assoc.ID, nsa, now)
			// The id token names this profile's own account.
			store.NoteAccount(assoc.ID, accountID, "")
			if store.BindAccount(accountID, nsa) {
				log.Printf("[nx-baas] penne: console account %s is %s (links)", accountID, nsa)
			}
		}
		writeJSON(w, 200, map[string]any{"nsa_id": nsa})
	case strings.HasPrefix(host, "god.") && r.Method == "DELETE":
		// Revocation: the association being deleted must belong to the
		// requesting device, or carry its own valid credentials.
		revoked := 0
		if id := penneCred(in); id != "" {
			if _, err := store.CheckAssoc(id, str(in, "password"), now); err == nil {
				revoked = store.Revoke(id, now)
			} else if a := store.AssocForDevice(deviceID); a != nil && a.ID == id {
				revoked = store.Revoke(id, now)
			}
		} else if a := store.AssocForDevice(deviceID); a != nil {
			revoked = store.Revoke(a.ID, now)
			store.RevokeDevice(deviceID, now)
		}
		log.Printf("[nx-baas] penne: DELETE revoked %d credential(s) for device %s", revoked, deviceID)
		writeJSON(w, 200, map[string]any{"result": "ok"})
	case strings.HasPrefix(host, "val.") && p == "/v1/frontlines":
		writeJSON(w, 200, map[string]any{"current_time": now.Unix(), "frontline_fqdn": frontline, "persistent_connection_params_simple": params})
	case strings.HasPrefix(host, "val.") && p == "/v1/login_tickets":
		assoc, ok := s.penneAuthedAssoc(store, in, userID, deviceID, now)
		if !ok {
			writeJSON(w, 401, map[string]any{"status": 401, "title": "authentication required"})
			return
		}
		ticketRec, ticket, err := store.IssueTicketFor(assoc, now, 4*24*time.Hour)
		if err != nil {
			writeJSON(w, 401, map[string]any{"status": 401, "title": "authentication failed"})
			return
		}
		_ = ticketRec
		// The module knows this header by name [firmware, npns 0x1239cd]; it
		// carries the lifetime the body already states.
		w.Header().Set("X-LoginTicket-TTL", strconv.FormatInt(ticketRec.ExpiresAt-ticketRec.IssuedAt, 10))
		writeJSON(w, 200, map[string]any{"expires_at": ticketRec.ExpiresAt, "frontline_fqdn": frontline, "issued_at": ticketRec.IssuedAt, "persistent_connection_params_simple": params, "ticket": ticket})
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

// penneCred reads the Penne id out of a request body. The firmware carries two
// spellings of the same credential — "id" on the login-ticket path and
// "penne_id" on the account-scoped ones [firmware, npns request templates] —
// and a call spelling it the second way authenticated as nobody here.
func penneCred(in map[string]any) string {
	if id := str(in, "id"); id != "" {
		return id
	}
	return str(in, "penne_id")
}

// penneAccountID pulls the console's 128-bit account id out of an
// /v1/accounts/<32 hex>/... path, and returns "" for any other shape.
func penneAccountID(p string) string {
	rest, ok := strings.CutPrefix(p, "/v1/accounts/")
	if !ok {
		return ""
	}
	id, _, _ := strings.Cut(rest, "/")
	if len(id) != 32 {
		return ""
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return ""
		}
	}
	return id
}

// penneAuthedAssoc resolves the registration a Penne REST call acts on. The
// order is: explicit id+password in the body (the one shape that authorizes a
// supplied id), then the access token's account, then the device's newest
// association. The last fallback keeps the console's bootstrap moving when its
// request shape carries no credentials; it is recorded as provisional.
func (s *server) penneAuthedAssoc(store *penneStore, in map[string]any, userID, deviceID string, now time.Time) (*penneAssoc, bool) {
	if id := penneCred(in); id != "" {
		pw := str(in, "password")
		if a, err := store.CheckAssoc(id, pw, now); err == nil {
			return a, true
		}
		// The console names its registration WITHOUT a password on these
		// routes. Captured from hardware, 2026-09-12:
		//
		//	POST /v1/accounts/<accountId>/notification_tokens
		//	{"penne_id":"pzxi…","application_id":"0x010000000000003e"}
		//	Authorization: Bearer <token this server minted>
		//
		// There is no password field to get wrong: the request is already
		// authenticated by the bearer, and the penne_id selects which
		// registration the call is about. Demanding a password here 401'd a
		// console presenting its own live id, on every attempt, which is why
		// account_users stayed empty and no delivery address was ever learned.
		// One penne_id is shared by every user account on the console, so this
		// cannot be narrowed to the account the bearer names either.
		if pw == "" {
			if a := store.AssocIfLive(id); a != nil {
				return a, true
			}
		}
		// An id this store never minted, from a console that registered against
		// the old build: adopt it under the account the request already proved.
		if a, ok := store.Adopt(id, pw, deviceID, store.ResolveUser(userID), now); ok {
			log.Printf("[nx-baas] penne: adopted a pre-existing id for user %s device %s", userID, deviceID)
			return a, true
		}
		// A known id with a wrong password is a denial, never a fallback.
		log.Printf("[nx-baas] penne: supplied id denied (bad credentials)")
		return nil, false
	}
	if userID != "" {
		if id := store.AssocIDForUser(userID); id != "" {
			if a := store.AssocByID(id); a != nil {
				return a, true
			}
		}
	}
	if a := store.AssocForDevice(deviceID); a != nil {
		return a, true
	}
	return nil, false
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
