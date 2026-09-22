package main

// Animal Crossing web API (acbaa), as ACNH 3.0.3 actually speaks it.
//
// Observed on the wire 2026-09-21 (Ryujinx against OpenPak, island "lovely "):
//
//	POST https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/lands
//	UA: libcurl/7.64.1 (HAC; nnEns; SDK 20.5.4.0)
//	Content-Type: application/x-msgpack, Authorization: Bearer <JWT>
//	body(65) = fixmap(5){name:"lovely ", display_id:2,
//	                     in_app_id:2720403009 (u64, = the island's LocalVid),
//	                     region:0, hemisphere:0}
//
// Two facts fall out of that capture. First, result module 219 is nnEns, the
// HTTP layer: its failures ARE the 2219-xxxx family (2219-2404 on this call).
// Second, this call runs before anything NEX: until it answers, switch-nexd
// sees zero ACNH traffic, so no NEX-side fix can move the game past it.
// Previously it fell into the ServeHTTP catch-all 404 ({}), and the game
// errored half a second after the TLS handshake.
//
// The response shape is documented, not guessed: kinnay's AC:NH Server page
// (facts only — field names, types and endpoint list) records POST
// /api/v1/lands taking {name, display_id, in_app_id, region, hemisphere}
// and answering {id: Uint64, password: String}. The password is land-scoped
// credentials: PUT /api/v1/users/<id>/land later sends {id, password} to
// bind a player to their island, so it must be stable per land. It is
// derived, not stored: a registry belongs here the day a second endpoint
// needs to look a land up (Dodo-code visits).
//
// Error bodies follow the same page: {category: String, code: String} with
// the HTTP status naming the failure (404/3004 unmapped route, 401/4001 bad
// authorization). Unmapped routes stay loud so each new call the game makes
// surfaces in the log with its path.

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// acbaa serves api.hac.<env>.acbaa.srv.nintendo.net. Anything that is not a
// mapped route is a 404 that names itself in the log, not a plausible-looking
// empty object: an unmapped acbaa route that returns 200 is indistinguishable
// from one that works.
func (s *server) acbaa(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/lands" {
		s.acbaaRegisterLand(w, r, body)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/users" {
		s.acbaaRegisterUser(w, r, body)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth_token" {
		s.acbaaAuthToken(w, r, body)
		return
	}
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/users/") &&
		strings.HasSuffix(r.URL.Path, "/land") {
		s.acbaaBindUserLand(w, r, body)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/notification_tokens" {
		s.acbaaNotificationToken(w, r, body)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/lands/updated_addresses" {
		s.acbaaUpdatedAddresses(w, r, body)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/message_cards" {
		s.acbaaMessageCards(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/friend_requests" {
		s.acbaaFriendRequests(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/friends" {
		s.acbaaFriends(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/rewards" {
		s.acbaaRewards(w, r)
		return
	}
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/web_service_resources/") {
		s.acbaaWebResource(w, r, body)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/users/") && strings.HasSuffix(r.URL.Path, "/profile_status") {
		s.acbaaProfileStatus(w, r)
		return
	}
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/users/") &&
		strings.HasSuffix(r.URL.Path, "/profile") {
		s.acbaaUploadProfile(w, r, body)
		return
	}
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/lands/") &&
		strings.HasSuffix(r.URL.Path, "/profile") {
		s.acbaaUploadLandProfile(w, r, body)
		return
	}
	log.Printf("[acbaa] unmapped route: %s %s (acbaa.go)", r.Method, r.URL.Path)
	acbaaError(w, 404, "3004")
}

// acbaaError writes the documented error shape: {category, code} in msgpack
// with the HTTP status carrying the failure.
func acbaaError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(status)
	w.Write(msgpack(map[string]any{"category": "lib", "code": code}))
}

// acbaaRegisterLand records the island the game posts and answers it back.
// Stateless by design: the answer is a deterministic function of the request
// (echo plus id), so there is nothing a restart can lose. A registry belongs
// here the day a second endpoint needs to look a land up (Dodo-code visits).
func (s *server) acbaaRegisterLand(w http.ResponseWriter, r *http.Request, body []byte) {
	v, err := msgpackDecode(body)
	if err != nil {
		log.Printf("[acbaa] POST /api/v1/lands: bad msgpack (%dB): %v", len(body), err)
		http.Error(w, "bad msgpack", 400)
		return
	}
	land, ok := v.(map[string]any)
	if !ok {
		log.Printf("[acbaa] POST /api/v1/lands: body is %T, want map", v)
		http.Error(w, "want map", 400)
		return
	}
	name, _ := land["name"].(string)
	displayID := msgpackReadIntOf(land["display_id"])
	inAppID := msgpackReadUintOf(land["in_app_id"])
	region := msgpackReadIntOf(land["region"])
	hemisphere := msgpackReadIntOf(land["hemisphere"])
	password := acbaaLandPassword(inAppID)
	uid := s.acbaaResolveUID(acbaaBearerID(r.Header.Get("Authorization")))
	s.mu.Lock()
	if s.acbaaNames == nil {
		s.acbaaNames = map[uint64]acbaaNames{}
	}
	rec := s.acbaaNames[uid]
	rec.Land = name
	s.acbaaNames[uid] = rec
	s.acbaaSaveLocked()
	s.mu.Unlock()
	log.Printf("[acbaa] register land name=%q display_id=%d in_app_id=%d region=%d hemisphere=%d bearer=%s",
		name, displayID, inAppID, region, hemisphere, bearerSummary(r.Header.Get("Authorization")))
	// Answer exactly {id, password} per the documented shape. A nested land
	// record was tried here and the flow never advanced past setup, so back
	// to the documented bytes: anything extra risks a strict reader.
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpackOrdered(
		"id", inAppID,
		"password", password,
	))
}

// acbaaLandPassword mints the land-scoped password PUT users/<id>/land will
// later present alongside the id. Derived (sha256, hex, truncated), not
// stored: the same island always gets the same password, restarts included,
// with nothing to persist or collide. The length and alphabet are OpenPak's
// choice — retail's are unrecorded — kept to plain ASCII so no encoding the
// game does not expect can garble it.
func acbaaLandPassword(inAppID uint64) string {
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], inAppID)
	sum := sha256.Sum256([]byte("openpak-acbaa-land:" + string(seed[:])))
	return hex.EncodeToString(sum[:12])
}

// msgpackOrdered encodes a string-keyed map with caller-chosen key order,
// unlike msgpack() in bcat.go which sorts. Takes an even list of key, value.
func msgpackOrdered(pairs ...any) []byte {
	if len(pairs)%2 != 0 {
		panic("msgpackOrdered: odd pair count")
	}
	out := msgpackLen(0x80, 0, 0xde, 0xdf, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		k, ok := pairs[i].(string)
		if !ok {
			panic("msgpackOrdered: non-string key")
		}
		out = append(out, msgpack(k)...)
		out = append(out, msgpack(pairs[i+1])...)
	}
	return out
}

// acbaaRegisterUser registers the player: POST /api/v1/users takes
// {name, birth_month, birth_date} (observed 2026-09-21: "hansolo", 6, 9)
// and answers {id: Uint64, password: String} per the documented shape.
// The id is the account's NEX PID — the same number switch-nexd resolves
// the login token to — so the web identity and the NEX identity are one:
// FindMatchmakeSessionByParticipant looks for the number the game knows.
// (Minting the BAAS-sub number instead gave every account two identities
// and every island visit answered empty.) The password is derived like the
// land's, under its own domain separator.
func (s *server) acbaaRegisterUser(w http.ResponseWriter, r *http.Request, body []byte) {
	v, err := msgpackDecode(body)
	if err != nil {
		log.Printf("[acbaa] POST /api/v1/users: bad msgpack (%dB): %v", len(body), err)
		http.Error(w, "bad msgpack", 400)
		return
	}
	user, ok := v.(map[string]any)
	if !ok {
		log.Printf("[acbaa] POST /api/v1/users: body is %T, want map", v)
		http.Error(w, "want map", 400)
		return
	}
	name, _ := user["name"].(string)
	auth := r.Header.Get("Authorization")
	id := acbaaUserID(s, auth, name)
	password := acbaaUserPassword(id)
	s.mu.Lock()
	if s.acbaaNames == nil {
		s.acbaaNames = map[uint64]acbaaNames{}
	}
	rec := s.acbaaNames[id]
	rec.User = name
	s.acbaaNames[id] = rec
	s.acbaaSaveLocked()
	s.mu.Unlock()
	log.Printf("[acbaa] register user name=%q id=%d bearer=%s",
		name, id, bearerSummary(r.Header.Get("Authorization")))
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpackOrdered(
		"id", id,
		"password", password,
	))
}

// acbaaUserID binds the ACNH user to the proven BAAS account: the Bearer
// sub is that account's id in hex. A token without a usable sub falls back
// to a name hash — same name, same id — rather than refusing: refusing here
// would lock the player out of online entirely on a token-shape surprise.
// acbaaUserID binds the ACNH user to the proven BAAS account's NEX PID —
// the same number switch-nexd puts in the kerberos ticket for this login,
// so the web identity and the NEX identity are one principal and
// FindMatchmakeSessionByParticipant resolves. A token that will not prove
// (or names an unknown account) falls back to the legacy derivations
// rather than refusing: refusing here would lock the player out of online
// entirely on a token-shape surprise. Legacy ids are migrated to the NEX
// PID on sight (acbaaMigrateUID) so one account never holds two islands.
func acbaaUserID(s *server, auth, name string) uint64 {
	tok := strings.TrimPrefix(auth, "Bearer ")
	// Keyless test servers cannot prove tokens; the fallback below covers
	// them. Production always has both.
	if s != nil && s.key != nil && s.store != nil {
		if pid, genuine := s.pidForIDToken(tok); genuine && pid != 0 {
			if legacy := acbaaLegacyID(auth, name); legacy != 0 && legacy != pid {
				s.acbaaMigrateUID(legacy, pid)
			}
			return pid
		}
	}
	return acbaaLegacyID(auth, name)
}

// acbaaLegacyID is the pre-single-identity derivation: the Bearer sub as a
// number, else a name hash. Kept as the fallback and as the migration
// source, not as an identity.
func acbaaLegacyID(auth, name string) uint64 {
	if sub := bearerSub(auth); sub != "" {
		if id, err := strconv.ParseUint(sub, 16, 64); err == nil && id != 0 {
			return id
		}
	}
	h := fnv.New64a()
	h.Write([]byte("openpak-acbaa-user:" + name))
	if id := h.Sum64(); id != 0 {
		return id
	}
	return 1
}

// acbaaMigrateUID moves one account's stored records from a legacy ACNH id
// to its NEX PID: profiles, resources, names and the user→land link. The
// game re-registers (POST /users) on every online entry, so the move
// happens before anything reads the new id, and the old key is left empty
// rather than deleted so a rollback build finds nothing contradictory.
func (s *server) acbaaMigrateUID(oldUID, newPID uint64) {
	s.mu.Lock()
	if s.migrateUIDLocked(oldUID, newPID) {
		log.Printf("[acbaa] migrated uid=%d to NEX pid=%d", oldUID, newPID)
	}
	s.acbaaSaveLocked()
	s.mu.Unlock()
}

// migrateUIDLocked is the move itself: the caller holds s.mu. It also
// records the mapping so path uids from warm clients (still carrying the
// old id their token was minted for) resolve forward. True when anything
// moved.
func (s *server) migrateUIDLocked(oldUID, newPID uint64) bool {
	moved := false
	if p, ok := s.acbaaProfiles[oldUID]; ok {
		if s.acbaaProfiles == nil {
			s.acbaaProfiles = map[uint64]acbaaProfile{}
		}
		if _, taken := s.acbaaProfiles[newPID]; !taken {
			s.acbaaProfiles[newPID] = p
			moved = true
		}
		delete(s.acbaaProfiles, oldUID)
	}
	if res, ok := s.acbaaResources[oldUID]; ok {
		if s.acbaaResources == nil {
			s.acbaaResources = map[uint64]map[string][]byte{}
		}
		if _, taken := s.acbaaResources[newPID]; !taken {
			s.acbaaResources[newPID] = res
			moved = true
		}
		delete(s.acbaaResources, oldUID)
	}
	if n, ok := s.acbaaNames[oldUID]; ok {
		if s.acbaaNames == nil {
			s.acbaaNames = map[uint64]acbaaNames{}
		}
		if cur, taken := s.acbaaNames[newPID]; !taken || cur.User == "" {
			s.acbaaNames[newPID] = n
			moved = true
		}
		delete(s.acbaaNames, oldUID)
	}
	if land, ok := s.acbaaUserLand[oldUID]; ok {
		if s.acbaaUserLand == nil {
			s.acbaaUserLand = map[uint64]uint64{}
		}
		if _, taken := s.acbaaUserLand[newPID]; !taken {
			s.acbaaUserLand[newPID] = land
			moved = true
		}
		delete(s.acbaaUserLand, oldUID)
	}
	if moved {
		if s.acbaaUIDMap == nil {
			s.acbaaUIDMap = map[uint64]uint64{}
		}
		s.acbaaUIDMap[oldUID] = newPID
	}
	return moved
}

// acbaaResolveUID follows a migrated id forward: path uids minted before
// the single-identity change still address the same account. Every handler
// that takes a user id from the path or the bearer token resolves through
// here, so a warm client still carrying its legacy id reads and writes the
// same records as a freshly registered one — without this a migrated
// account's profile_status answers ng/ng for records that are on file
// (observed 2026-09-21: profile under the NEX PID, status asked by legacy
// uid).
func (s *server) acbaaResolveUID(uid uint64) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if next, ok := s.acbaaUIDMap[uid]; ok && next != 0 {
		return next
	}
	return uid
}

// acbaaUserPassword mints the user-scoped password later calls present
// (auth_token, users/<id>/land). Same derive-don't-store shape as lands,
// separate domain so a land password is never a user password.
func acbaaUserPassword(id uint64) string {
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], id)
	sum := sha256.Sum256([]byte("openpak-acbaa-user:" + string(seed[:])))
	return hex.EncodeToString(sum[:12])
}

// acbaaAuthToken mints the call token: POST /api/v1/auth_token takes the
// {id, password} the game got from /users and answers {token: String,
// expire_at: Sint64} per the documented shape. The password is checked
// against the derivation — a mismatch is the documented 401/4001 (invalid
// authorization), which is also what the game shows when its stored
// credentials go stale. The token is self-verifying (id plus an
// authenticator), so later endpoints resolve the caller with no store.
func (s *server) acbaaAuthToken(w http.ResponseWriter, r *http.Request, body []byte) {
	v, err := msgpackDecode(body)
	if err != nil {
		log.Printf("[acbaa] POST /api/v1/auth_token: bad msgpack (%dB): %v", len(body), err)
		http.Error(w, "bad msgpack", 400)
		return
	}
	cred, ok := v.(map[string]any)
	if !ok {
		log.Printf("[acbaa] POST /api/v1/auth_token: body is %T, want map", v)
		http.Error(w, "want map", 400)
		return
	}
	id := msgpackReadUintOf(cred["id"])
	password, _ := cred["password"].(string)
	if id == 0 || subtle.ConstantTimeCompare([]byte(password), []byte(acbaaUserPassword(id))) != 1 {
		log.Printf("[acbaa] POST /api/v1/auth_token: bad credentials for id=%d", id)
		acbaaError(w, 401, "4001")
		return
	}
	token := acbaaMintToken(id)
	log.Printf("[acbaa] auth token for id=%d expires in 1h", id)
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpackOrdered(
		"token", token,
		"expire_at", time.Now().Unix()+3600,
	))
}

// acbaaMintToken builds a bearer token for later acbaa calls: the user id in
// hex plus an authenticator over id and the user's password, so verification
// is a recomputation, not a lookup.
func acbaaMintToken(id uint64) string {
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], id)
	mac := sha256.Sum256([]byte("openpak-acbaa-token:" + string(seed[:]) + acbaaUserPassword(id)))
	return "v1." + hex.EncodeToString(seed[:]) + "." + hex.EncodeToString(mac[:16])
}

// acbaaVerifyToken resolves a token minted above back to its user id. False
// when the shape or authenticator is wrong — callers answer 401/4001.
func acbaaVerifyToken(token string) (uint64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return 0, false
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil || len(raw) != 8 {
		return 0, false
	}
	id := binary.BigEndian.Uint64(raw)
	if token != acbaaMintToken(id) {
		return 0, false
	}
	return id, true
}

// acbaaBindUserLand binds the player to their island: PUT
// /api/v1/users/<uid>/land takes the land's {id, password} (the pair the
// game got from /lands and presents back verbatim — observed 2026-09-21).
// No response body is documented for any PUT on this API; success is a bare
// 200. Both halves of the binding are checked: the land password must match
// the derivation, and the caller must own the path's user id (either via our
// v1 token or the BAAS sub it was minted from). Anything else is the
// documented 401/4001.
func (s *server) acbaaBindUserLand(w http.ResponseWriter, r *http.Request, body []byte) {
	seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(seg) != 5 {
		acbaaError(w, 404, "3004")
		return
	}
	uid, err := strconv.ParseUint(seg[3], 10, 64)
	if err != nil || uid == 0 {
		log.Printf("[acbaa] PUT %s: bad user id", r.URL.Path)
		acbaaError(w, 404, "3004")
		return
	}
	uid = s.acbaaResolveUID(uid)
	if !s.acbaaCallerOwns(r.Header.Get("Authorization"), uid) {
		log.Printf("[acbaa] PUT %s: caller does not own uid=%d", r.URL.Path, uid)
		acbaaError(w, 401, "4001")
		return
	}
	v, err := msgpackDecode(body)
	if err != nil {
		log.Printf("[acbaa] PUT %s: bad msgpack (%dB): %v", r.URL.Path, len(body), err)
		http.Error(w, "bad msgpack", 400)
		return
	}
	link, ok := v.(map[string]any)
	if !ok {
		log.Printf("[acbaa] PUT %s: body is %T, want map", r.URL.Path, v)
		http.Error(w, "want map", 400)
		return
	}
	landID := msgpackReadUintOf(link["id"])
	password, _ := link["password"].(string)
	if landID == 0 || subtle.ConstantTimeCompare([]byte(password), []byte(acbaaLandPassword(landID))) != 1 {
		log.Printf("[acbaa] PUT %s: bad land credentials for land=%d", r.URL.Path, landID)
		acbaaError(w, 401, "4001")
		return
	}
	log.Printf("[acbaa] bind user=%d to land=%d", uid, landID)
	s.mu.Lock()
	if s.acbaaUserLand == nil {
		s.acbaaUserLand = map[uint64]uint64{}
	}
	s.acbaaUserLand[uid] = landID
	s.acbaaSaveLocked()
	s.mu.Unlock()
	// Bare 200: no response body is documented for any PUT on this API.
	// A land record was tried here and the flow never advanced past setup,
	// so back to the documented silence.
	w.WriteHeader(200)
}

// acbaaCallerOwns reports whether the Authorization header proves the caller
// is uid: either our v1 token minted for that id, or the BAAS JWT whose sub
// hex-decodes to it (the same account both ways). Both sides resolve through
// the uid map, so a legacy token against a migrated path (or the reverse)
// still matches the one account.
func (s *server) acbaaCallerOwns(auth string, uid uint64) bool {
	tok := strings.TrimPrefix(auth, "Bearer ")
	if id, ok := acbaaVerifyToken(tok); ok {
		return s.acbaaResolveUID(id) == uid
	}
	if id, err := strconv.ParseUint(bearerSub(auth), 16, 64); err == nil {
		return s.acbaaResolveUID(id) == uid
	}
	return false
}

// terminus already vouches the caller is an OpenPak-issued token holder at
// the transport, and binding decisions live in the id derivation, not here.
// acbaaUpdatedAddresses answers which islands changed: POST
// /api/v1/lands/updated_addresses takes {user_ids: [Uint64], since: Sint64}
// and answers {accessed_at, addresses[]} per the documented shape, each
// address carrying {user_id, id, name, display_id, in_app_id}. OpenPak
// tracks no address book: the list is empty and accessed_at is now —
// "nothing changed", which is true for a server holding no directory.
// (The game's online-setup function calls this before validating profiles;
// an unanswered here aborts the whole flow.)
func (s *server) acbaaUpdatedAddresses(w http.ResponseWriter, r *http.Request, body []byte) {
	v, err := msgpackDecode(body)
	if err != nil {
		log.Printf("[acbaa] POST /api/v1/lands/updated_addresses: bad msgpack (%dB): %v", len(body), err)
		http.Error(w, "bad msgpack", 400)
		return
	}
	params, ok := v.(map[string]any)
	if !ok {
		log.Printf("[acbaa] POST /api/v1/lands/updated_addresses: body is %T, want map", v)
		http.Error(w, "want map", 400)
		return
	}
	n := 0
	if ids, ok := params["user_ids"].([]any); ok {
		n = len(ids)
	}
	log.Printf("[acbaa] updated addresses for %d user(s)", n)
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpack(map[string]any{"accessed_at": time.Now().Unix(), "addresses": []any{}}))
}

// /api/v1/notification_tokens takes {token: String} (observed 2026-09-21:
// the game uploads whatever npns:u CreateToken handed it — empty here, the
// stub zero-fills and the game reads a C string). Answered with a bare 200;
// no response body is documented. Logged per user for the day a push
// backend wants to know whom a token belongs to; nothing is delivered.
func (s *server) acbaaNotificationToken(w http.ResponseWriter, r *http.Request, body []byte) {
	v, err := msgpackDecode(body)
	if err != nil {
		log.Printf("[acbaa] POST /api/v1/notification_tokens: bad msgpack (%dB): %v", len(body), err)
		http.Error(w, "bad msgpack", 400)
		return
	}
	tok, ok := v.(map[string]any)
	if !ok {
		log.Printf("[acbaa] POST /api/v1/notification_tokens: body is %T, want map", v)
		http.Error(w, "want map", 400)
		return
	}
	token, _ := tok["token"].(string)
	log.Printf("[acbaa] push token len=%d auth=%s", len(token), bearerSummary(r.Header.Get("Authorization")))
	w.WriteHeader(200)
}

// terminus already vouches the caller is an OpenPak-issued token holder at
// the transport, and binding decisions live in the id derivation, not here.
// acbaaRewards lists seasonal/login rewards: GET /api/v1/rewards?limit=.
// Undocumented shape; answered like the other list endpoints
// ({total, count, headers}, empty) — the game sails past it either way, and
// a wrong guess here would be the next 2219-xxxx with the game's thanks.
func (s *server) acbaaRewards(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpack(map[string]any{"total": 0, "count": 0, "headers": []any{}}))
}

// acbaaWebResource takes companion-app sync uploads: PUT
// /api/v1/web_service_resources/<name> with {data: {...}} — observed names
// so far: emoticon, catalog, reward_unlock, resort_unlock, life_support,
// land_memory (2026-09-21). Fire-and-forget island/app state for the NookLink
// side; answered with a bare 200 and remembered per user for the day a GET
// for them appears.
func (s *server) acbaaWebResource(w http.ResponseWriter, r *http.Request, body []byte) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/web_service_resources/")
	if name == "" || strings.Contains(name, "/") {
		acbaaError(w, 404, "3004")
		return
	}
	v, err := msgpackDecode(body)
	if err != nil {
		log.Printf("[acbaa] PUT web resource %s: bad msgpack (%dB): %v", name, len(body), err)
		http.Error(w, "bad msgpack", 400)
		return
	}
	doc, ok := v.(map[string]any)
	if !ok {
		log.Printf("[acbaa] PUT web resource %s: body is %T, want map", name, v)
		http.Error(w, "want map", 400)
		return
	}
	if _, ok := doc["data"]; !ok {
		log.Printf("[acbaa] PUT web resource %s: no data key", name)
		http.Error(w, "want data", 400)
		return
	}
	sum := sha256.Sum256(body)
	uid := s.acbaaResolveUID(acbaaBearerID(r.Header.Get("Authorization")))
	s.mu.Lock()
	if s.acbaaResources == nil {
		s.acbaaResources = map[uint64]map[string][]byte{}
	}
	user := s.acbaaResources[uid]
	if user == nil {
		user = map[string][]byte{}
		s.acbaaResources[uid] = user
	}
	user[name] = bytes.Clone(body)
	s.acbaaSaveLocked()
	s.mu.Unlock()
	log.Printf("[acbaa] web resource %s %dB sha256=%x", name, len(body), sum[:8])
	w.WriteHeader(200)
}

// acbaaBearerID resolves the caller to its ACNH user id through either
// credential the game presents: our v1 token, or the BAAS JWT sub it was
// minted from. Zero when neither parses — resources for an unknown caller
// are kept under 0 rather than refused, so a token-shape surprise logs
// instead of locking online out.
func acbaaBearerID(auth string) uint64 {
	tok := strings.TrimPrefix(auth, "Bearer ")
	if id, ok := acbaaVerifyToken(tok); ok {
		return id
	}
	if id, err := strconv.ParseUint(bearerSub(auth), 16, 64); err == nil {
		return id
	}
	return 0
}

// acbaaDisk is the file form of the acbaa memory: profiles, per-user web
// resources, registered names, island profiles and the user→land links.
type acbaaDisk struct {
	Profiles     map[uint64]acbaaProfile      `json:"profiles"`
	Resources    map[uint64]map[string][]byte `json:"resources"`
	Names        map[uint64]acbaaNames        `json:"names"`
	LandProfiles map[uint64]acbaaProfile      `json:"land_profiles"`
	UserLand     map[uint64]uint64            `json:"user_land"`
	UIDMap       map[uint64]uint64            `json:"uid_map"`
}

// acbaaNames is what the game told us about who plays where: echoed back
// by profile_status so the game can confirm the server knows it.
type acbaaNames struct {
	User string `json:"user"`
	Land string `json:"land"`
}

// acbaaLoad reads the store file if there is one; a missing file is a fresh
// account, not an error. Called once at startup, before serving.
func (s *server) acbaaLoad() {
	if s.acbaaPath == "" {
		return
	}
	b, err := os.ReadFile(s.acbaaPath)
	if err != nil {
		return
	}
	var disk acbaaDisk
	if json.Unmarshal(b, &disk) != nil {
		log.Printf("[acbaa] store %s unreadable, starting fresh", s.acbaaPath)
		return
	}
	s.mu.Lock()
	s.acbaaProfiles = disk.Profiles
	s.acbaaResources = disk.Resources
	s.acbaaNames = disk.Names
	s.acbaaLandProfiles = disk.LandProfiles
	s.acbaaUserLand = disk.UserLand
	s.acbaaUIDMap = disk.UIDMap
	s.acbaaUIDMap = disk.UIDMap
	n := len(disk.Profiles)
	// Proactive migration: every BAAS account whose legacy ACNH id differs
	// from its NEX PID gets its records moved now, not when the game
	// happens to re-register (warm boots reuse the cached token and never
	// POST /users, so lazy migration can wait forever while lookups miss).
	if s.store != nil {
		s.store.mu.Lock()
		for sub, u := range s.store.Users {
			if legacy, err := strconv.ParseUint(sub, 16, 64); err == nil && legacy != 0 && u != nil && u.PID != 0 && legacy != u.PID {
				s.migrateUIDLocked(legacy, u.PID)
			}
		}
		s.store.mu.Unlock()
	}
	s.mu.Unlock()
	log.Printf("[acbaa] store %s: %d profile(s) restored", s.acbaaPath, n)
}

// acbaaSaveLocked writes the store atomically (tmp + rename, like the main
// store). The caller holds s.mu. Skipped when no path is configured, which
// is how direct handler tests run.
func (s *server) acbaaSaveLocked() {
	if s.acbaaPath == "" {
		return
	}
	b, err := json.Marshal(acbaaDisk{Profiles: s.acbaaProfiles, Resources: s.acbaaResources, Names: s.acbaaNames, LandProfiles: s.acbaaLandProfiles, UserLand: s.acbaaUserLand, UIDMap: s.acbaaUIDMap})
	if err != nil {
		log.Printf("[acbaa] store marshal: %v", err)
		return
	}
	if err := os.WriteFile(s.acbaaPath+".tmp", b, 0o600); err != nil {
		log.Printf("[acbaa] store write: %v", err)
		return
	}
	if err := os.Rename(s.acbaaPath+".tmp", s.acbaaPath); err != nil {
		log.Printf("[acbaa] store rename: %v", err)
	}
}

// acbaaProfile is a remembered player-profile upload, kept for the day
// anything reads a profile back (visitors' passports).
type acbaaProfile struct {
	SHA  string `json:"sha"` // hex sha256 of the uploaded body
	Size int    `json:"size"`
}

func (s *server) acbaaRememberProfile(uid uint64, body []byte) string {
	sum := sha256.Sum256(body)
	p := acbaaProfile{SHA: hex.EncodeToString(sum[:]), Size: len(body)}
	s.mu.Lock()
	if s.acbaaProfiles == nil {
		s.acbaaProfiles = map[uint64]acbaaProfile{}
	}
	s.acbaaProfiles[uid] = p
	s.acbaaSaveLocked()
	s.mu.Unlock()
	return p.SHA
}

func (s *server) acbaaProfileSHA(uid uint64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acbaaProfiles[uid].SHA
}

// acbaaFriends lists ACNH friends: GET /api/v1/friends answers
// {count, friends} per the documented shape (entries carry user_id).
// Empty until friend links are recorded server-side; the Dodo-code path
// does not need it. (POST friend_requests / accept flows come when the
// game asks.)
func (s *server) acbaaFriends(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpack(map[string]any{"count": 0, "friends": []any{}}))
}

// acbaaFriendRequests lists pending ACNH friend requests: GET
// /api/v1/friend_requests?type= answers {count, friend_requests} per the
// /api/v1/friend_requests?type= answers {count, friend_requests} per the
// documented shape (entries carry id, user_id, sent_at, meta). OpenPak has
// no request queue yet, so the list is empty — no one is waiting, which is
// true. (POST/PUT for sending/accepting come when the game asks.)
func (s *server) acbaaFriendRequests(w http.ResponseWriter, r *http.Request) {
	log.Printf("[acbaa] friend requests type=%q", r.URL.Query().Get("type"))
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpack(map[string]any{"count": 0, "friend_requests": []any{}}))
}

// acbaaMessageCards lists the player's message cards: GET

// acbaaUserOf parses /api/v1/users/<uid>/... paths.
func acbaaUserOf(path string) (uint64, bool) {
	seg := strings.Split(strings.Trim(path, "/"), "/")
	if len(seg) != 5 || seg[0] != "api" || seg[1] != "v1" || seg[2] != "users" {
		return 0, false
	}
	uid, err := strconv.ParseUint(seg[3], 10, 64)
	if err != nil || uid == 0 {
		return 0, false
	}
	return uid, true
}

// /api/v1/message_cards?offset=&limit= answers {total, count, headers}
// per the documented shape. OpenPak delivers no cards, so the list is
// empty — a true statement (no saved cards), not a placeholder.
func (s *server) acbaaMessageCards(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpack(map[string]any{"total": 0, "count": 0, "headers": []any{}}))
}

// acbaaProfileStatus reports profile presence: GET users/<id>/profile_status
// answers {user_profile, land_profile} per the documented shape. The values
// are literally "ok" or "ng" — the game compares the first two bytes
// (main 0x5a73ec: "ok"→1, "ng"→0, anything else→0x2adb failure surfaced as
// 2219-0021). Anything we returned before (empty, digest, timestamp, names)
// falls into the failure arm, which is why every shape failed identically.
// "ok" exactly when that side was uploaded; the land side turns "ok" via
// PUT lands/<id>/profile, which the game calls when it needs it.
func (s *server) acbaaProfileStatus(w http.ResponseWriter, r *http.Request) {
	uid, ok := acbaaUserOf(r.URL.Path)
	user, land := "ng", "ng"
	if ok {
		uid = s.acbaaResolveUID(uid)
		s.mu.Lock()
		if _, found := s.acbaaProfiles[uid]; found {
			user = "ok"
		}
		// Land side is "ok" as soon as the island is registered and bound,
		// not only after a separate lands/<id>/profile upload (which the
		// game never calls in the observed flow). The bind link is primary;
		// the registered island name is the fallback: warm runs skip the
		// bind POST entirely, and stores written before the link field
		// existed carry the name but no link.
		if landID, linked := s.acbaaUserLand[uid]; linked && landID != 0 {
			land = "ok"
		} else if rec, hasNames := s.acbaaNames[uid]; hasNames && rec.Land != "" {
			land = "ok"
		}
		s.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	// kinnay's field order (user_profile first): the shared encoder sorts
	// keys, and a positional reader would swap the two on a sorted map.
	// Exactly these two keys: the game byte-compares their values, and this
	// answer is read on every online entry, warm or fresh.
	w.Write(msgpackOrdered(
		"user_profile", user,
		"land_profile", land,
	))
}

// acbaaUploadProfile takes the player profile: PUT users/<id>/profile with a
// ~124KB msgpack body (passport image and data, observed 2026-09-21). The
// answer is a msgpack record, not an empty body: the game reads $.id,
// $.digest and $.created_at out of it (decompiled 3.0.3 FUN_006adbc4) and
// fails the whole online setup (2219-0021) on an empty answer. The digest
// buffer is 0x29 bytes, i.e. a 40-hex digest (SHA1); the bytes are
// remembered by SHA256 for profile_status, which only needs presence.
func (s *server) acbaaUploadProfile(w http.ResponseWriter, r *http.Request, body []byte) {
	uid, ok := acbaaUserOf(r.URL.Path)
	if !ok {
		acbaaError(w, 404, "3004")
		return
	}
	pathUID := uid
	uid = s.acbaaResolveUID(uid)
	if _, err := msgpackDecode(body); err != nil {
		log.Printf("[acbaa] profile upload uid=%d: bad msgpack (%dB): %v", uid, len(body), err)
		http.Error(w, "bad msgpack", 400)
		return
	}
	sha := s.acbaaRememberProfile(uid, body)
	sum1 := sha1.Sum(body)
	now := time.Now().Unix()
	log.Printf("[acbaa] profile upload uid=%d %dB sha256=%s", uid, len(body), sha[:16])
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpackOrdered(
		"id", pathUID,
		"digest", hex.EncodeToString(sum1[:]),
		"created_at", now,
	))
}

// acbaaUploadLandProfile takes the island profile: PUT lands/<id>/profile.
// Same standing as the player profile (bare 200, remembered by digest for
// profile_status). Unobserved as of 2026-09-21 — the game has never called
// it in any captured flow — but profile_status reads its side, so the
// endpoint exists for the day hosting asks for it.
func (s *server) acbaaUploadLandProfile(w http.ResponseWriter, r *http.Request, body []byte) {
	seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(seg) != 5 {
		acbaaError(w, 404, "3004")
		return
	}
	landID, err := strconv.ParseUint(seg[3], 10, 64)
	if err != nil || landID == 0 {
		log.Printf("[acbaa] PUT %s: bad land id", r.URL.Path)
		acbaaError(w, 404, "3004")
		return
	}
	if _, err := msgpackDecode(body); err != nil {
		log.Printf("[acbaa] land profile upload land=%d: bad msgpack (%dB): %v", landID, len(body), err)
		http.Error(w, "bad msgpack", 400)
		return
	}
	sum := sha256.Sum256(body)
	s.mu.Lock()
	if s.acbaaLandProfiles == nil {
		s.acbaaLandProfiles = map[uint64]acbaaProfile{}
	}
	s.acbaaLandProfiles[landID] = acbaaProfile{SHA: hex.EncodeToString(sum[:]), Size: len(body)}
	s.acbaaSaveLocked()
	s.mu.Unlock()
	log.Printf("[acbaa] land profile upload land=%d %dB", landID, len(body))
	// Answer the stored record like the player profile does: the game reads
	// the same $.id/$.digest/$.created_at shape out of it (observed: the
	// first land upload immediately followed the fixed player-profile
	// answer, same call family).
	sum1 := sha1.Sum(body)
	now := time.Now().Unix()
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpackOrdered(
		"id", landID,
		"digest", hex.EncodeToString(sum1[:]),
		"created_at", now,
	))
}

// bearerSub returns the Bearer JWT's sub claim without verifying: the TLS
// terminus already vouches the caller is an OpenPak-issued token holder at
// the transport, and binding decisions live in the id derivation, not here.
func bearerSub(auth string) string {
	tok := strings.TrimPrefix(auth, "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var payload map[string]any
	if json.Unmarshal(b, &payload) != nil {
		return ""
	}
	sub, _ := payload["sub"].(string)
	return sub
}

// bearerSummary names the caller without printing the token: the JWT header's
// kid plus the payload's iss/sub when they decode, never the signature. A
// token that will not decode is still accepted — binding ACNH tokens to
// OpenPak accounts is unmapped work, and failing closed here would trade this
// 404 for a lockout with no evidence.
func bearerSummary(auth string) string {
	tok := strings.TrimPrefix(auth, "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "unparseable"
	}
	head, payload := map[string]any{}, map[string]any{}
	if b, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
		_ = json.Unmarshal(b, &head)
	}
	if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		_ = json.Unmarshal(b, &payload)
	}
	kid, _ := head["kid"].(string)
	iss, _ := payload["iss"].(string)
	sub, _ := payload["sub"].(string)
	if kid == "" && iss == "" && sub == "" {
		return "opaque"
	}
	return fmt.Sprintf("kid=%s iss=%s sub=%s", kid, iss, sub)
}

// msgpackReadIntOf reads the small integers the game sends (posfixint through
// int64) as int64. Anything else is 0 — the caller logs the raw map on the
// error paths that matter, so a mistyped field reads as zero, not a refusal.
func msgpackReadIntOf(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case uint64:
		if t <= math.MaxInt64 {
			return int64(t)
		}
	}
	return 0
}

// msgpackReadUintOf is the unsigned sibling, for ids that may one day set the top
// bit. Today in_app_id fits either way; the response encodes it unsigned.
func msgpackReadUintOf(v any) uint64 {
	switch t := v.(type) {
	case uint64:
		return t
	case int64:
		if t >= 0 {
			return uint64(t)
		}
	}
	return 0
}

// msgpackDecode reads the subset of msgpack the game and these documents use:
// nil, booleans, integers through 64 bits, floats (kept whole), strings,
// binary, arrays and string-keyed maps. It is the mirror of msgpack() in
// bcat.go, which only encodes. Unknown type tags are an error, not a guess:
// silently skipping a field would register a different island than the game
// posted.
func msgpackDecode(b []byte) (any, error) {
	v, rest, err := msgpackValue(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("msgpack: %d trailing bytes", len(rest))
	}
	return v, nil
}

func msgpackValue(b []byte) (any, []byte, error) {
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("msgpack: empty")
	}
	c := b[0]
	switch {
	case c <= 0x7f: // posfixint
		return int64(c), b[1:], nil
	case c >= 0xe0: // negfixint
		return int64(int8(c)), b[1:], nil
	case c >= 0xa0 && c <= 0xbf: // fixstr
		return msgpackBytes(b, 1, int(c&0x1f), true)
	case c >= 0x90 && c <= 0x9f: // fixarray
		return msgpackArray(b, 1, int(c&0x0f))
	case c >= 0x80 && c <= 0x8f: // fixmap
		return msgpackMap(b, 1, int(c&0x0f))
	}
	switch c {
	case 0xc0:
		return nil, b[1:], nil
	case 0xc2:
		return false, b[1:], nil
	case 0xc3:
		return true, b[1:], nil
	case 0xca: // float32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: float32 truncated")
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b[1:]))), b[5:], nil
	case 0xcb: // float64
		if len(b) < 9 {
			return nil, nil, fmt.Errorf("msgpack: float64 truncated")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b[1:])), b[9:], nil
	case 0xcc:
		return msgpackReadUint(b, 2)
	case 0xcd:
		return msgpackReadUint(b, 3)
	case 0xce:
		return msgpackReadUint(b, 5)
	case 0xcf:
		return msgpackReadUint(b, 9)
	case 0xd0:
		return msgpackReadInt(b, 2)
	case 0xd1:
		return msgpackReadInt(b, 3)
	case 0xd2:
		return msgpackReadInt(b, 5)
	case 0xd3:
		return msgpackReadInt(b, 9)
	case 0xd9: // str8
		if len(b) < 2 {
			return nil, nil, fmt.Errorf("msgpack: str8 truncated")
		}
		return msgpackBytes(b, 2, int(b[1]), true)
	case 0xda: // str16
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: str16 truncated")
		}
		return msgpackBytes(b, 3, int(binary.BigEndian.Uint16(b[1:])), true)
	case 0xdb: // str32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: str32 truncated")
		}
		n := binary.BigEndian.Uint32(b[1:])
		if n > math.MaxInt32 {
			return nil, nil, fmt.Errorf("msgpack: str32 absurd length %d", n)
		}
		return msgpackBytes(b, 5, int(n), true)
	case 0xc4: // bin8
		if len(b) < 2 {
			return nil, nil, fmt.Errorf("msgpack: bin8 truncated")
		}
		return msgpackBytes(b, 2, int(b[1]), false)
	case 0xc5: // bin16
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: bin16 truncated")
		}
		return msgpackBytes(b, 3, int(binary.BigEndian.Uint16(b[1:])), false)
	case 0xc6: // bin32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: bin32 truncated")
		}
		n := binary.BigEndian.Uint32(b[1:])
		if n > math.MaxInt32 {
			return nil, nil, fmt.Errorf("msgpack: bin32 absurd length %d", n)
		}
		return msgpackBytes(b, 5, int(n), false)
	case 0xdc: // array16
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: array16 truncated")
		}
		return msgpackArray(b, 3, int(binary.BigEndian.Uint16(b[1:])))
	case 0xdd: // array32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: array32 truncated")
		}
		n := binary.BigEndian.Uint32(b[1:])
		if n > 1<<20 {
			return nil, nil, fmt.Errorf("msgpack: array32 absurd length %d", n)
		}
		return msgpackArray(b, 5, int(n))
	case 0xde: // map16
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: map16 truncated")
		}
		return msgpackMap(b, 3, int(binary.BigEndian.Uint16(b[1:])))
	case 0xdf: // map32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: map32 truncated")
		}
		n := binary.BigEndian.Uint32(b[1:])
		if n > 1<<20 {
			return nil, nil, fmt.Errorf("msgpack: map32 absurd length %d", n)
		}
		return msgpackMap(b, 5, int(n))
	}
	return nil, nil, fmt.Errorf("msgpack: unknown tag 0x%02x", c)
}

// msgpackReadUint reads an unsigned integer whose tag plus width is n bytes.
func msgpackReadUint(b []byte, n int) (any, []byte, error) {
	if len(b) < n {
		return nil, nil, fmt.Errorf("msgpack: uint truncated")
	}
	switch n {
	case 2:
		return int64(b[1]), b[2:], nil
	case 3:
		return int64(binary.BigEndian.Uint16(b[1:])), b[3:], nil
	case 5:
		return int64(binary.BigEndian.Uint32(b[1:])), b[5:], nil
	default:
		return binary.BigEndian.Uint64(b[1:]), b[9:], nil
	}
}

// msgpackReadInt reads a signed integer whose tag plus width is n bytes.
func msgpackReadInt(b []byte, n int) (any, []byte, error) {
	if len(b) < n {
		return nil, nil, fmt.Errorf("msgpack: int truncated")
	}
	switch n {
	case 2:
		return int64(int8(b[1])), b[2:], nil
	case 3:
		return int64(int16(binary.BigEndian.Uint16(b[1:]))), b[3:], nil
	case 5:
		return int64(int32(binary.BigEndian.Uint32(b[1:]))), b[5:], nil
	default:
		return int64(binary.BigEndian.Uint64(b[1:])), b[9:], nil
	}
}

// msgpackBytes reads n content bytes at offset off. str is whether the bytes
// must be valid UTF-8 (msgpack str) as opposed to opaque binary.
func msgpackBytes(b []byte, off, n int, str bool) (any, []byte, error) {
	if n < 0 || len(b)-off < n {
		return nil, nil, fmt.Errorf("msgpack: string/binary truncated")
	}
	raw := bytes.Clone(b[off : off+n])
	if str {
		return string(raw), b[off+n:], nil
	}
	return raw, b[off+n:], nil
}

// msgpackArray reads n elements.
func msgpackArray(b []byte, off, n int) (any, []byte, error) {
	if n < 0 || n > 1<<20 {
		return nil, nil, fmt.Errorf("msgpack: absurd array length %d", n)
	}
	rest := b[off:]
	out := make([]any, 0, n)
	for range n {
		var v any
		var err error
		v, rest, err = msgpackValue(rest)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, v)
	}
	return out, rest, nil
}

// msgpackMap reads n string-keyed pairs. A non-string key is an error: every
// document on this host is a JSON-shaped record, and a positional map would
// decode into the wrong island.
func msgpackMap(b []byte, off, n int) (any, []byte, error) {
	if n < 0 || n > 1<<20 {
		return nil, nil, fmt.Errorf("msgpack: absurd map length %d", n)
	}
	rest := b[off:]
	out := make(map[string]any, n)
	for range n {
		var k any
		var err error
		k, rest, err = msgpackValue(rest)
		if err != nil {
			return nil, nil, err
		}
		ks, ok := k.(string)
		if !ok {
			return nil, nil, fmt.Errorf("msgpack: non-string map key %T", k)
		}
		var v any
		v, rest, err = msgpackValue(rest)
		if err != nil {
			return nil, nil, err
		}
		out[ks] = v
	}
	return out, rest, nil
}
