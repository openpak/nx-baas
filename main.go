// nx-baas: the BAAS (baas.nintendo.com) and Nintendo Account (accounts.nintendo.com) servers a
// real CFW Switch talks to, backed by openpak-account for identity and the friend graph.
//
// Flow the console drives (account sysmodule, then the friends sysmodule with the same device
// account):  dauth -> POST /1.0.0/application/token -> POST /1.0.0/users (first boot) ->
// POST /1.0.0/login -> [Link: browser GET /connect/1.0.0/authorize -> POST /connect/1.0.0/api/token
// -> POST /1.0.0/federation] -> GET/PATCH /1.0.0/users/<id> -> /2.0.0 friends + presence.
//
// Everything unknown is logged in full (method, host, path, headers, body): the console teaches us
// the undocumented parts (the friend-invitation endpoint above all).
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	baasHost   = "e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com"
	baasIssuer = "https://" + baasHost
	// jku host for BAAS tokens: the console caches key sets per URL and had the VPS's set cached
	// for the e0d67c... URLs (different RSA key) -> 2124-3121. m-lp1 is the host firmware 21+
	// talks to anyway, and a URL it has not cached, so it fetches ours.
	baasJku      = "https://m-lp1.baas.nintendo.com"
	baasAudience = "ed9e2f05d286f7b8" // what citron's id_token carries; the game servers accept it
	naIssuer     = "https://accounts.nintendo.com"
)

//go:embed assets/default.jpg
var defaultAvatar []byte

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type server struct {
	store   *Store
	acct    accountBackend
	key     *rsa.PrivateKey
	idKid   string // kid of id_tokens (openpak-baas-key-1: what Photon/NPLN/S2 already trust)
	accKid  string // kid of BAAS access tokens (/1.0.0/internal_certificates)
	naKid   string // kid of Nintendo-Account tokens: the console binds kid<->issuer and rejects a kid shared with BAAS (2124-3121)
	jwks    []byte
	mu      sync.Mutex
	codes   map[string]naCode // NA authorization codes / session tokens -> who logged in
	device  map[string]string // device id -> serial, from the dauth assertion
	links   *linkStore        // pending QR console links, by code
	guesses *guesses          // wrong-code attempts, per account
	phones  *phoneStore       // signed-in phones entering a code
	// saves forwards the scsi hosts (save-data cloud) to the saves service, with the
	// console's proven account attached. nil answers the empty-cloud fallback instead.
	saves    *httputil.ReverseProxy
	savesKey string
	// news forwards the News list and topic routes to the news service
	// (NEWS_INTERNAL_URL, news.go). nil keeps bcat.go's own answers.
	news *newsForwarder
	// liveSessions maps BAAS user id -> the core session the adapter registered
	// for it, so the presence reconciler can renew and expire what it created.
	// In-memory by design: a restart re-derives truth from the core (and local
	// leases), never from this map.
	liveSessions map[string]string
	// liveSessionTitle is the title each of those sessions was registered
	// with, so a console changing game re-registers rather than leaving the
	// core reporting the game it started on.
	liveSessionTitle map[string]string
	// liveSessionClient is the client each session was registered with, for
	// the same reason: a heartbeat cannot change it.
	liveSessionClient map[string]string
	// corePresence caches what the core last said about other platforms.
	corePresence *corePresenceCache
	coreSeenOnce sync.Once
	// Penne notification channel (workstream B): durable push-channel state
	// (registrations, tokens, tickets, subscriptions, delivery outbox) and the
	// live frontline session registry. notifStore() lazily creates in-memory
	// versions when unset, so direct handler tests keep working.
	penneState *penneStore
	penneHub   *penneHub
	// acbaaProfiles remembers uploaded ACNH player profiles by ACNH user id
	// so profile_status reflects them after a PUT, and acbaaResources the
	// per-user web_service_resources uploads. Both file-backed (acbaaPath)
	// because a restart must not blank them: a warm client that already
	// registered checks status without re-uploading, and blanks read as a
	// failure (2219-0021). Lazily created so direct handler tests work.
	acbaaProfiles  map[uint64]acbaaProfile
	acbaaResources map[uint64]map[string][]byte
	acbaaNames     map[uint64]acbaaNames
	// acbaaLandProfiles remembers uploaded island profiles by land
	// in_app_id, and acbaaUserLand links each user to their land (set at
	// bind time). profile_status reports "ok" per side exactly when that
	// side was uploaded — the game byte-compares for "ok"/"ng".
	acbaaLandProfiles map[uint64]acbaaProfile
	acbaaUserLand     map[uint64]uint64
	// acbaaUIDMap records legacy ACNH id -> NEX PID moves, so path uids
	// minted before the single-identity change keep addressing the same
	// account on warm clients.
	acbaaUIDMap map[uint64]uint64
	// ACNH best friends: pending requests by id, and each user's confirmed
	// best-friend list (symmetric). Persisted with the rest.
	acbaaFriendReqs map[uint64]acbaaFriendReq
	acbaaFriendList map[uint64][]uint64
	acbaaPath       string
	// shop is the store workstream's state (catalog, entitlements, tasks, beach links);
	// shopUI holds the storefront's in-memory diagnostics ring.
	shop   *shopState
	shopUI *shopUI
	// Penne record store: what this server has written to each account's
	// records, and its digests (penne_records.go).
	recordStore *penneRecordStore
	recordsOnce sync.Once
	// Ban state (bans.go): a short cache of the core's answer, and a test stand-in for it.
	bans      *banCache
	bansOnce  sync.Once
	banSource banSource
	// reports is the console error-report spool (errorreport.go).
	reports *reportSpool
}

type naCode struct {
	PID      uint64
	Username string
	ClientID string
	NaID     string
}

// ---------- errors / helpers ----------

func baasErr(w http.ResponseWriter, r *http.Request, status int, code, title, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"status": status, "errorCode": code, "title": title, "detail": detail,
		"instance": r.URL.Path, "type": fmt.Sprintf("https://baas.nintendo.com/errors/1.0.0/%d/%s", status, code),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// Captured from a reference reply, which sends both beside the no-cache
	// this already had.
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Vary", "Accept-Encoding,Origin")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func hostOf(r *http.Request) string {
	h := r.Host
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

func dump(r *http.Request, body []byte, tag string) {
	var hdr strings.Builder
	for k, v := range r.Header {
		if k == "Authorization" && len(v) > 0 && len(v[0]) > 40 {
			fmt.Fprintf(&hdr, " %s: %s...;", k, v[0][:40])
			continue
		}
		fmt.Fprintf(&hdr, " %s: %s;", k, strings.Join(v, ","))
	}
	log.Printf("[nx-baas] %s %s %s%s?%s hdr{%s} body(%d)=%q", tag, r.Method, hostOf(r), r.URL.Path, r.URL.RawQuery, hdr.String(), len(body), body)
	if len(body) > 0 && !json.Valid(body) && !strings.Contains(r.Header.Get("Content-Type"), "form") {
		log.Printf("[nx-baas] %s body hex: %s", tag, hex.EncodeToString(body))
	}
}

// bearer returns the claims of our own access token on the request, or nil.
func (s *server) bearer(r *http.Request) map[string]any {
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, "Bearer ") {
		return nil
	}
	c, err := parseJWT(strings.TrimPrefix(a, "Bearer "), &s.key.PublicKey)
	if err != nil {
		return nil
	}
	return c
}

// validBearer returns the claims of our own *live* access token: signature,
// issuer, type and expiry all checked. bearer() above only checked the
// signature, which let an expired token — or a refresh or Nintendo-Account
// token, which we also sign with this key — spend itself as a credential.
func (s *server) validBearer(r *http.Request) map[string]any {
	c := s.bearer(r)
	if c == nil {
		return nil
	}
	if str(c, "typ") != "token" || str(c, "iss") != baasIssuer {
		return nil
	}
	exp, ok := c["exp"].(float64)
	if !ok || int64(exp) <= time.Now().Unix() {
		return nil
	}
	return c
}

// bearerUser resolves the user an authenticated request acts as, or nil.
//
// Says WHY when it refuses. Every rejection here used to be the same opaque
// 401, and telling "no header" from "the wrong one of two tokens this server
// itself minted" cost a debugging round trip with a client author on
// 2026-09-12: the application token from /1.0.0/application/token and the
// access token from /1.0.0/login both carry typ "token" and the same issuer,
// but the first has the DEVICE id as its subject and the second the BAAS user
// id. Only the second can act as a user.
func (s *server) bearerUser(r *http.Request) *User {
	c := s.validBearer(r)
	if c == nil {
		if a := r.Header.Get("Authorization"); !strings.HasPrefix(a, "Bearer ") {
			log.Printf("[nx-baas] auth: %s %s carries no bearer", r.Method, r.URL.Path)
		} else if raw := s.bearer(r); raw == nil {
			log.Printf("[nx-baas] auth: %s %s bearer does not verify against this server's key", r.Method, r.URL.Path)
		} else if str(raw, "typ") != "token" || str(raw, "iss") != baasIssuer {
			log.Printf("[nx-baas] auth: %s %s bearer is typ=%q iss=%q, want typ=token from this issuer",
				r.Method, r.URL.Path, str(raw, "typ"), str(raw, "iss"))
		} else {
			log.Printf("[nx-baas] auth: %s %s bearer has expired", r.Method, r.URL.Path)
		}
		return nil
	}
	sub := str(c, "sub")
	u := s.store.User(sub)
	if u == nil {
		// The give-away: an application token's subject is the device id.
		log.Printf("[nx-baas] auth: %s %s bearer names sub=%q, which is not a user "+
			"(an application token from /1.0.0/application/token has the DEVICE id as its subject; "+
			"a user-scoped call needs the accessToken from /1.0.0/login)", r.Method, r.URL.Path, sub)
	}
	return u
}

// requireCaller enforces the principal binding on a user-scoped path: the
// path may only name the authenticated user. Returns false having written
// the error when it does not.
func (s *server) requireCaller(w http.ResponseWriter, r *http.Request, pathUserID string) *User {
	me := s.bearerUser(r)
	if me == nil {
		baasErr(w, r, 401, "invalid_token", "Invalid token", "a current access token is required")
		return nil
	}
	if pathUserID != "" && pathUserID != me.ID {
		// Cross-account denial: a valid token for someone else must not read
		// or write this user's social state, ever.
		baasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "the token does not belong to this user")
		return nil
	}
	return me
}

// ---------- tokens ----------

// accessToken/idToken: claim for claim what a real console accepted from the VPS
// (capture 2026-09-06, /1.0.0/login). Anonymous (grant 1) tokens carry the device block;
// user tokens (grant 2) do not.
func (s *server) accessToken(sub string, grant int, bsDid, di, sn string) string {
	now := time.Now().Unix()
	claims := map[string]any{
		"aud": baasAudience, "bs:did": bsDid, "bs:grt": grant, "exp": now + 10800, "iat": now,
		"iss": baasIssuer, "jti": uuid4(), "sub": sub, "typ": "token",
	}
	if grant == 1 {
		claims["bs:pid"] = "pz" + randHex(15)
		claims["bs:sts"] = []int64{1188950301625811329}
		claims["nintendo"] = map[string]any{"di": di, "dt": "NX Prod 1", "ist": false, "pc": "HAC", "sn": sn, "x5t#S256": deviceThumbprint}
	} else {
		claims["bs:sts"] = []int64{10415858080830506, 272640, 9, 0, 0, 19316357715722240, 16}
	}
	return signJWT(map[string]any{"alg": "RS256", "jku": baasJku + "/1.0.0/internal_certificates", "kid": s.accKid, "typ": "JWT"}, claims, s.key)
}

func (s *server) idToken(u *User, id *Identity, username string, app map[string]any) string {
	now := time.Now().Unix()
	// VPS parity: the id_token carries an APPLICATION block (ai/at/av/edi/tbh/tbn), taken from
	// the appAuthNToken when the console sends one, else the VPS defaults.
	ai, av := "0100f8f0000a2000", "0033"
	if n, ok := app["nintendo"].(map[string]any); ok {
		if v := str(n, "ai"); v != "" {
			ai = v
		}
		if v := str(n, "av"); v != "" {
			av = v
		}
	}
	claims := map[string]any{
		"aud": baasAudience, "bs:did": u.ID, "exp": now + 10800, "iat": now, "iss": baasIssuer, "jti": uuid4(),
		"nintendo": map[string]any{"ai": ai, "at": now, "av": av, "edi": randB64(60), "tbh": randB64(32), "tbn": randB64(16)},
		"sub":      u.ID, "typ": "id_token",
	}
	if id != nil {
		claims["bs:did"] = id.BsDid
		if t := s.acct.nexToken(id.PID, username); t != "" {
			claims["openpak"] = t
		}
	}
	return signJWT(map[string]any{"alg": "RS256", "jku": baasJku + "/1.0.0/certificates", "kid": s.idKid, "typ": "JWT"}, claims, s.key)
}

func (s *server) naHeader() map[string]any {
	return map[string]any{"alg": "RS256", "jku": naIssuer + "/1.0.0/certificates", "kid": s.naKid, "typ": "JWT"}
}

func (s *server) naRefreshToken(c naCode) string {
	now := time.Now().Unix()
	return signJWT(s.naHeader(), map[string]any{"aud": c.ClientID, "exp": now + 365*86400, "iat": now, "iss": naIssuer, "jti": uuid4(), "sub": c.NaID, "typ": "refresh"}, s.key)
}

func (s *server) naAccessToken(c naCode) string {
	now := time.Now().Unix()
	return signJWT(s.naHeader(), map[string]any{
		"ac:grt": 4, "ac:scp": []int{0, 1, 4, 5, 8, 9, 10, 11, 12, 13, 23, 28},
		"aud": c.ClientID, "exp": now + 900, "iat": now, "iss": naIssuer, "jti": uuid4(), "sub": c.NaID, "typ": "token",
	}, s.key)
}

// bindNotificationChannel records which BAAS account is signed in on the console a
// device authentication token names — the same bind the /1.0.0/login handler performs
// (BindConsole at the login case). It belongs on the NA token paths as well because an
// awake console's steady state is the refresh, not a login: sleep/wake and days-long
// play sessions reuse the Nintendo-Account session, so /1.0.0/login may not recur for
// a very long time, and an unbound console is one no notification can be addressed to.
func (s *server) bindNotificationChannel(deviceAuthenticationToken, baasUserID string) {
	if baasUserID == "" {
		return
	}
	if dt, err := parseJWT(deviceAuthenticationToken, &s.key.PublicKey); err == nil {
		s.notifStore().BindConsole(str(dt, "sub"), baasUserID)
	}
}

func (s *server) naIDToken(c naCode, accessToken string) string {
	now := time.Now().Unix()
	sum := sha256.Sum256([]byte(accessToken))
	return signJWT(s.naHeader(), map[string]any{
		"at_hash": b64url(sum[:16]), "aud": c.ClientID, "exp": now + 900, "iat": now, "iss": naIssuer, "jti": uuid4(), "sub": c.NaID,
	}, s.key)
}

// ---------- user objects ----------

func (s *server) identity(u *User) *Identity {
	if u == nil || u.PID == 0 {
		return nil
	}
	id, err := s.acct.Identity(u.PID)
	logErr("identity", err)
	// Remember the account's bs:did: it is what a console's id_token carries and what the
	// Photon server reports back on /internal/photon-room, which has no PID of its own.
	if id != nil && id.BsDid != "" && u.BsDid != id.BsDid {
		s.store.Update(u, func(u *User) { u.BsDid = id.BsDid })
	}
	return id
}

const cdnHost = "https://cdn-image-e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com"

// avatarURL: the console wants an https URL, never inline data. openpak-account hands us the
// raw base64 JPEG; we serve it at /avatar/<pid>.jpg on the cdn-image host (in our cert + route).
func avatarURL(pid uint64, b64 string, updatedAt int64) string {
	if b64 == "" {
		return ""
	}
	return fmt.Sprintf("%s/avatar/%d.jpg?v=%d", cdnHost, pid, updatedAt)
}

// friendCodeID: BAAS friend codes are "1234-5678-9012"; OpenPak displays them as "SW-...".
func friendCodeID(fc string) string { return strings.TrimPrefix(fc, "SW-") }

// codeRegen reports the friend-code regeneration state the console shows:
// regenerableAt is the "next issuable" time and regenerable whether a new
// code may be issued now. A new code is allowed once a day from the last
// issue — generate_code enforces the same 24 h — so advertising +30 d showed
// a date the enforcement never kept [friends-contract-22.5.0 §A.6, C11].
// A code that was never issued is issuable now.
func codeRegen(codeGeneratedAt, fallback int64) (regenerableAt int64, regenerable bool) {
	if codeGeneratedAt <= 0 {
		return fallback, true
	}
	at := codeGeneratedAt + 24*3600
	return at, time.Now().Unix() >= at
}

func extras() map[string]any {
	return map[string]any{"self": map[string]any{}, "favoriteFriends": map[string]any{}, "friends": map[string]any{}, "foaf": map[string]any{}, "everyone": map[string]any{}}
}

func presenceObj(p Presence) map[string]any {
	ex := extras()
	if p.AppID == "" && p.AppField != "" && p.AppField != "{}" {
		// No title, but words: a friend on another platform (presenceFromCore).
		// Never a foreign title id in appInfo; the description carries it.
		ex["friends"] = map[string]any{"appField": p.AppField}
	}
	if p.AppID != "" {
		friends := map[string]any{"appField": appFieldOrEmpty(p.AppField), "appInfo:appId": p.AppID, "appInfo:presenceGroupId": p.PresenceGroupID}
		if p.ACDIndex >= 0 {
			// Read back by the friend list's numeric parser
			// [firmware, $.items[*].friend.presence.extras.friends.appInfo:acdIndex].
			friends["appInfo:acdIndex"] = p.ACDIndex
		}
		ex["friends"] = friends
	}
	return map[string]any{"state": p.State, "extras": ex, "updatedAt": p.UpdatedAt, "logoutAt": p.LogoutAt}
}

func (s *server) userObj(u *User, id *Identity, devicePassword string) map[string]any {
	devs := []map[string]any{}
	for _, d := range u.DeviceAccounts {
		m := map[string]any{"id": d}
		if devicePassword != "" {
			m["password"] = devicePassword
		}
		devs = append(devs, m)
	}
	nickname, country := u.Nickname, u.Country
	links := map[string]any{}
	self := map[string]any{"playLog": ""}
	// The console uploads its own profile blob (PATCH /extras/self/nxAccount) after linking, and
	// a foreign blob makes it drop the profile to local-only. Serve nothing until it writes one:
	// the global constant we briefly served came from a capture of our own probe value, not from
	// the service, and every account importing one stranger's profile is not a fixture worth
	// keeping.
	nx := u.NxAccount
	if nx == "" && id != nil {
		// The reply a console accepted carries extras.self.nxAccount and
		// isMediaUploaded; ours carried neither, because the console only
		// PATCHes its own blob after a link it never completes. Serving the
		// captured constant is what the stack did when links worked, so it is
		// back -- env-gated, so it can be taken away again in one restart.
		nx = os.Getenv("NX_TEST_NXACCOUNT")
	}
	if nx != "" {
		self["isMediaUploaded"] = true
		self["nxAccount"] = nx
	} else if u.Avatar != "" {
		self["isMediaUploaded"] = true
	}
	friendsEx := map[string]any{"isChatActivated": true, "isChatInvitable": true, "playLog": ""}
	everyone := map[string]any{"playLog": ""}
	thumb1, thumb2, thumbAt := cdnHost+"/1/default", cdnHost+"/2/default", int64(0) // VPS parity for unlinked users
	etag := randHex(8)
	if id != nil {
		etag = id.BsDid // VPS parity: user.etag == the token bs:did for a linked user
		nickname = id.Nickname
		links["nintendoAccount"] = map[string]any{"id": id.NaID, "createdAt": u.CreatedAt, "updatedAt": u.CreatedAt}
		if !minimal {
			regenAt, regen := codeRegen(u.CodeGeneratedAt, u.CreatedAt)
			links["friendCode"] = map[string]any{"id": friendCodeID(id.FriendCode), "createdAt": u.CreatedAt, "updatedAt": u.CreatedAt, "regenerableAt": regenAt, "regenerable": regen}
			if pl, ok := id.PlayLog.(string); ok && pl != "" && pl != "null" && u.PlayLog == nil {
				friendsEx["playLog"], everyone["playLog"] = pl, pl
			}
			if at := newerPicture(u, id); at > 0 {
				// A picture can be changed in two places, and the console only
				// refetches when this timestamp moves. It is the newer of the
				// two: the console's own upload, or the account's picture on
				// the website.
				thumbAt = at
				thumb1, thumb2 = cdnHost+"/1/"+u.ID, cdnHost+"/2/"+u.ID
			} else if u.Avatar != "" {
				// The console's own upload. Without this the reply to an
				// upload still points at /1/default with an uploaded-at of
				// zero, which is the service telling the console that the
				// picture it just sent does not exist.
				thumbAt = u.UpdatedAt
				thumb1, thumb2 = cdnHost+"/1/"+u.ID, cdnHost+"/2/"+u.ID
			}
		}
	}
	if thumbAt > 0 {
		// The console caches images by URL: an avatar change must change the
		// URL, or friends keep the old picture after the kind-6 refetch
		// [friends-contract-22.5.0 §A.11, C21]. ?v= is the versioning the
		// /avatar/ URLs already ship, and the route matches on the path, so
		// the query is ignored on fetch.
		thumb1 += fmt.Sprintf("?v=%d", thumbAt)
		thumb2 += fmt.Sprintf("?v=%d", thumbAt)
	}
	// Serve what the account actually holds, and nothing more: a captured working response
	// carries "birthday":"0000-00-00" with the console perfectly happy, so the invented
	// defaults we used to substitute were fixing a problem that was never demonstrated.
	if country == "" && id != nil {
		country = id.Country
	}
	if country == "" {
		// The Nintendo Account object cannot carry an empty country, so it
		// falls back; if this one stayed empty the console would be told two
		// different things about the same person in the same flow. Matching
		// that fallback is not inventing a fact — it is refusing to contradict
		// ourselves.
		country = getenv("NA_FALLBACK_COUNTRY", "GB")
	}
	birthday := u.Birthday
	if (birthday == "" || birthday == "0000-00-00") && id != nil && id.Birthday != "" {
		birthday = id.Birthday
	}
	favoriteFriends := map[string]any{"playLog": ""}
	if u.PlayLog != nil {
		// What the console wrote, group by group: the group carrying the log
		// is its play-log permission, and an empty answer makes it write an
		// initial "[]" on every sync [friends-contract-22.5.0 §A.6, C9].
		for g, ex := range map[string]map[string]any{"self": self, "favoriteFriends": favoriteFriends, "friends": friendsEx, "everyone": everyone} {
			ex["playLog"] = u.PlayLog[g]
		}
	}
	return map[string]any{
		"birthday": birthday, "blocksUpdatedAt": u.CreatedAt, "country": country, "createdAt": u.CreatedAt, "deleted": false,
		"deviceAccounts": devs, "etag": fmt.Sprintf("\"%s\"", etag),
		"extras":           map[string]any{"everyone": everyone, "favoriteFriends": favoriteFriends, "foaf": map[string]any{"playLog": ""}, "friends": friendsEx, "self": self},
		"friendsUpdatedAt": friendsUpdatedAt(u), "id": u.ID, "links": links, "nickname": nickname, "nicknameUpdatedAt": u.UpdatedAt,
		"permissions":   permissionsOf(u),
		"thumbnail2Url": thumb2, "thumbnailUploadedAt": thumbAt, "thumbnailUrl": thumb1, "updatedAt": u.UpdatedAt,
	}
}

// friendObj: a *user* about somebody else. This is the nested renderer — the
// value inside a relationship's "friend", and the whole item of a search
// result. Relationship-level state (friendId, isFavorite, extras.self) and
// presence are the relationship renderer's job (social.go), which is also
// why none of them appear here: a search result carrying them was refused by
// the console, the same way it refused a login reply with an extra
// "summary".
//
// Every timestamp is derived from state we hold, never from the render, so
// rendering the same person twice yields the same object and a stable list
// etag (SOC-05).
func (s *server) friendObj(f Friend, now int64) map[string]any {
	// The same object the console accepts for itself, about somebody else.
	// A search result carrying only id/nickname/links parses into a user the
	// console then refuses to use: it answered "unable to find user" to a
	// reply that had found one. Every key here is in a capture a console
	// accepted; TestFriendObjectCarriesWhatAUserObjectCarries keeps it that
	// way.
	created := f.CreatedAt
	if created == 0 {
		created = now
	}
	// What this server already knows about them beats what the lookup carried:
	// the console PATCHes country and uploads a picture here, and a user object
	// that says country "" and owns no device accounts is not one the console
	// accepts. updatedAt follows the local record's own clock when there is
	// one — a lookup-time constant is not a state change.
	updatedAt := created
	country, devices := f.Country, []map[string]any{}
	local := s.store.User(f.BaasUserID)
	if local != nil {
		if local.Country != "" {
			country = local.Country
		}
		if local.UpdatedAt > updatedAt {
			updatedAt = local.UpdatedAt
		}
		// One, as the reference search result carries. Eleven of them is this
		// server telling a console about every profile that ever registered,
		// and nothing that reads a friend expects that.
		if n := len(local.DeviceAccounts); n > 0 {
			devices = append(devices, map[string]any{"id": local.DeviceAccounts[n-1]})
		}
	}
	// The next-issuable time of their code, when this server knows when it
	// was issued; otherwise the same 24 h rule from what the lookup carried.
	var codeGen int64
	if local != nil {
		codeGen = local.CodeGeneratedAt
	}
	regenAt, regen := codeRegen(codeGen, created)
	// Their picture's version, when this server holds their record: the
	// console caches images by URL, so a new picture must come with a new
	// URL or friends keep the old one [friends-contract-22.5.0 §A.11, C21].
	picAt, picKnown := created, false
	if local != nil {
		if at := newerPicture(local, nil); at > 0 {
			picAt, picKnown = at, true
		}
	}
	thumbURL, thumb2URL := cdnHost+"/1/"+f.BaasUserID, cdnHost+"/2/"+f.BaasUserID
	if picKnown {
		thumbURL += fmt.Sprintf("?v=%d", picAt)
		thumb2URL += fmt.Sprintf("?v=%d", picAt)
	}
	obj := map[string]any{
		"id":        f.BaasUserID,
		"nickname":  f.Nickname,
		"country":   country,
		"birthday":  "0000-00-00",
		"deleted":   false,
		"etag":      strconv.Quote(f.BaasUserID),
		"createdAt": created,
		"updatedAt": updatedAt,
		// Always a real address: every account has a picture, and an empty
		// string here is a user the console cannot render. The avatar route
		// answers this address with the account's picture, or the default
		// when it has none — a URL in a reply this server 404s is how a
		// "reachable avatar" becomes a broken one.
		"thumbnailUrl":        thumbURL,
		"thumbnail2Url":       thumb2URL,
		"thumbnailUploadedAt": picAt,
		"nicknameUpdatedAt":   created,
		"friendsUpdatedAt":    created,
		"blocksUpdatedAt":     created,
		"deviceAccounts":      devices,
		"links": map[string]any{
			"friendCode": map[string]any{
				"id": friendCodeID(f.FriendCode), "createdAt": created, "updatedAt": created,
				"regenerable": regen, "regenerableAt": regenAt,
			},
			"nintendoAccount": map[string]any{"id": f.NaID, "createdAt": created, "updatedAt": created},
		},
		"permissions": map[string]any{
			"friendRequestReception": true, "friends": "EVERYONE",
			"personalAnalytics": true, "personalAnalyticsUpdatedAt": created,
			"personalNotification": true, "personalNotificationUpdatedAt": created,
			"presence": "FRIENDS", "presenceUpdatedAt": created,
		},
		// Exactly the groups a reference reply carries about somebody else:
		// foaf and self are empty, and friends has no isChatActivated. self is
		// the visibility group only its owner sees, so putting anything in it
		// for a stranger is both wrong and, to this console, unparsable.
		"extras": map[string]any{
			"self":            map[string]any{},
			"favoriteFriends": map[string]any{"playLog": ""},
			"friends":         map[string]any{"isChatInvitable": true, "playLog": ""},
			"foaf":            map[string]any{},
			"everyone":        map[string]any{"playLog": ""},
		},
	}
	// A play log in the everyone group is anyone's to see; the viewer-bound
	// groups are the relationship renderer's and the search's job.
	group, pl := s.visiblePlayLog(nil, s.store.User(f.BaasUserID), false)
	setPlayLog(obj, group, pl)
	return obj
}

// searchUserObj is a user, not a friend. The friend-list keys — friendId,
// presence, the viewer's own extras — belong to the relationship renderer,
// and a stranger you have just looked up is not one. The console refused a
// search result that carried them, the same way it refused a login reply
// that carried an extra "summary"; the exact-match test
// TestSearchReplyMatchesTheAcceptedShape keeps it that way.
func (s *server) searchUserObj(f Friend, now int64) map[string]any {
	return s.friendObj(f, now)
}

// ---------- BAAS handlers ----------

// reportOnline tells the core that this account is signed in, which is a
// different claim from playing something and is counted separately. Only the
// OpenPak backend has a core to tell; the OpenPak one keeps presence to
// itself, so this is a type assertion rather than another interface method
// that one of the two would have to no-op.
//
// client is what the request said it came from (X-OpenPak-Client). When it
// said nothing, the client of the account's live claim is used, so a real
// console's title-less session says "switch" once Penne has told us so.
func (s *server) reportOnline(ctx context.Context, u *User, client string) {
	if u == nil || u.PID == 0 {
		return
	}
	if client == "" {
		client = aggregatePresence(u, time.Now().Unix(), presenceLease()).Client
	}
	if b, ok := s.acct.(*openpakBackend); ok {
		b.Online(ctx, u.PID, client)
	}
}

// reportOffline ends the session immediately when someone says they are going,
// rather than leaving them online until the lease runs out.
func (s *server) reportOffline(ctx context.Context, u *User) {
	if u == nil || u.PID == 0 {
		return
	}
	if b, ok := s.acct.(*openpakBackend); ok {
		b.Offline(ctx, u.PID)
	}
}

func (s *server) baas(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	form, _ := url.ParseQuery(string(body))
	seg := strings.Split(strings.Trim(p, "/"), "/")

	// A banned account's live access token stops working at once: every user-scoped call
	// (profile, presence, friends) answers banned_user, which the console shows as
	// 2124-5110 (bans.go). Pictures and key sets stay public.
	if strings.HasPrefix(p, "/1.0.0/users/") || strings.HasPrefix(p, "/2.0.0/") {
		if c := s.validBearer(r); c != nil {
			if lock := s.userLock(s.store.User(str(c, "sub"))); lock != "" {
				baasLocked(w, r, lock)
				return
			}
		}
	}

	switch {
	case strings.HasPrefix(p, "/1/") || strings.HasPrefix(p, "/2/") || strings.HasPrefix(p, "/avatar/"):
		var pid uint64
		if strings.HasPrefix(p, "/1/default") || strings.HasPrefix(p, "/2/default") {
			// Every unlinked user's thumbnail points here, and a 404 is
			// console 2124-7404 during "add account". It used to be a file
			// hand-placed in NX_DATA, which the deployed volume did not have;
			// the picture now ships inside the binary, so no deployment can be
			// missing it. A file in NX_DATA still wins if someone wants their
			// own.
			img, err := os.ReadFile(getenv("NX_DATA", "/data") + "/default.jpg")
			if err != nil {
				img = defaultAvatar
			}
			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Write(img)
			return
		}
		if strings.HasPrefix(p, "/avatar/") {
			pid, _ = strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(p, "/avatar/"), ".jpg"), 10, 64)
		} else if u := s.store.User(p[3:]); u != nil {
			pid = u.PID
		}
		id, err := s.acct.Identity(pid)
		avatar := ""
		if err == nil {
			avatar = id.Avatar
		}
		if avatar == "" && !strings.HasPrefix(p, "/avatar/") {
			// What the console uploaded -- but only while it is the newer of
			// the two. Serving it unconditionally meant a picture changed on
			// the website could never reach a console that had ever set one
			// of its own.
			if u := s.store.User(p[3:]); u != nil {
				if err != nil || id.ImageUpdatedAt <= newerPicture(u, nil) {
					avatar = u.Avatar
				}
			}
		}
		if avatar == "" && err == nil && id.AvatarURL != "" {
			// Fetched here and nowhere else: a login must not wait on the
			// website, but a console asking for a thumbnail can.
			if img, ferr := fetchAvatar(id.AvatarURL); ferr == nil {
				w.Header().Set("Content-Type", "image/jpeg")
				w.Header().Set("Cache-Control", "public, max-age=300")
				w.Write(img)
				return
			} else {
				log.Printf("[nx-baas] avatar fetch %s: %v", id.AvatarURL, ferr)
			}
		}
		if avatar == "" {
			if strings.HasPrefix(p, "/1/") || strings.HasPrefix(p, "/2/") {
				// The URL came out of a reply this server wrote, so a 404 here
				// is our own left hand failing our own right: the console shows
				// a friend with a broken picture. The default avatar is what an
				// account without a picture means (SOC-01: a reachable avatar).
				img, derr := os.ReadFile(getenv("NX_DATA", "/data") + "/default.jpg")
				if derr != nil {
					img = defaultAvatar
				}
				w.Header().Set("Content-Type", "image/jpeg")
				w.Header().Set("Cache-Control", "public, max-age=300")
				w.Write(img)
				return
			}
			w.WriteHeader(404)
			return
		}
		img, err := base64.StdEncoding.DecodeString(avatar)
		if err != nil {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(img)
		return

	case p == "/1.0.0/certificates" || p == "/1.0.0/internal_certificates":
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.jwks)
		return

	case p == "/1.0.0/application/token" && r.Method == "POST":
		// The assertion is nx-dauth's device token; we trust it as-is (dauth already gated).
		claims, _ := parseJWT(form.Get("assertion"), nil)
		di := str(claims, "sub")
		sn := ""
		if n, ok := claims["nintendo"].(map[string]any); ok {
			sn = str(n, "sn")
		}
		if di == "" {
			baasErr(w, r, 400, "invalid_params", "Invalid Params", "assertion is not a device token")
			return
		}
		s.mu.Lock()
		s.device[di] = sn
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"accessToken": s.accessToken(di, 1, randHex(8), di, sn), "tokenType": "Bearer", "expiresIn": 10800})
		return

	case p == "/1.0.0/image_upload" && r.Method == "POST":
		// The console uploads its profile picture while adding an account and
		// stops with 2124-5104 if this 404s. It was removed once on the
		// grounds that the older stack never answered it — but that stack was
		// never asked, and this endpoint had already been observed working.
		var img struct {
			RawContent string `json:"rawContent"`
		}
		_ = json.Unmarshal(body, &img)
		tok := s.validBearer(r)
		if uid := str(tok, "sub"); uid != "" && img.RawContent != "" {
			if raw, err := base64.StdEncoding.DecodeString(img.RawContent); err != nil {
				log.Printf("[nx-baas] image_upload: not base64 (%d bytes): %v", len(img.RawContent), err)
			} else if u := s.store.User(uid); u != nil {
				s.store.Update(u, func(u *User) { u.Avatar, u.AvatarAt = img.RawContent, time.Now().Unix() })
				log.Printf("[nx-baas] image_upload: stored %d bytes for %s", len(raw), uid)
				// And on to the account, so the picture a person set on their
				// console is the one the website and the app show.
				s.shareAvatar(u.ID, img.RawContent)
			}
		}
		// NOT an empty object. `{}` to a console request is the push_channels
		// failure verbatim -- that one answered `{}` and the console said the
		// account could not be linked, every time, until it was given the real
		// object. This is the last thing we answer during "add account" before
		// the console gives up with 2124-3121, and it was answering `{}`.
		//
		// The user object is what every other mutation here returns, and it
		// carries what the console needs after an upload: the new thumbnail
		// URLs and the time they changed.
		if uid := str(s.bearer(r), "sub"); uid != "" {
			if u := s.store.User(uid); u != nil {
				writeJSON(w, 200, s.userObj(u, s.identity(u), ""))
				return
			}
		}
		baasErr(w, r, 401, "invalid_token", "Invalid token", "no user for this token")
		return

	case p == "/1.0.0/users" && r.Method == "POST":
		u, d := s.store.NewUser()
		log.Printf("[nx-baas] new device account %s for user %s", d.ID, u.ID)
		w.Header().Set("Location", "/1.0.0/users/"+u.ID)
		writeJSON(w, 201, s.userObj(u, nil, d.Password))
		return

	case (p == "/1.0.0/login" || p == "/1.0.0/federation") && r.Method == "POST":
		u := s.store.Login(form.Get("id"), form.Get("password"))
		if u == nil {
			baasErr(w, r, 400, "invalid_device_account", "Invalid Device Account", "Device Account's id or password is invalid")
			return
		}
		tok := s.bearer(r)
		di, sn := str(tok, "sub"), ""
		if n, ok := tok["nintendo"].(map[string]any); ok {
			sn = str(n, "sn")
		}
		if p == "/1.0.0/federation" {
			var err error
			if u, err = s.link(u, form.Get("idToken")); err != nil {
				if errors.Is(err, errAccountLocked) {
					baasLocked(w, r, s.naLockOfToken(form.Get("idToken")))
					return
				}
				log.Printf("[nx-baas] federation failed: %v", err)
				baasErr(w, r, 400, "invalid_idp_account", "Invalid IdP Account", "IdP account is invalid")
				return
			}
		}
		// A console whose device account is linked to a banned account signs in to nothing:
		// no token, no presence, no notification binding.
		if lock := s.userLock(u); lock != "" {
			log.Printf("[nx-baas] %s refused: user=%s pid=%d is %s", seg[1], u.ID, u.PID, lock)
			baasLocked(w, r, lock)
			return
		}
		app, _ := parseJWT(form.Get("appAuthNToken"), nil)
		id := s.identity(u)
		username := u.Nickname
		if id != nil {
			username = id.Nickname
		}
		// Signed in on this device: a per-device presence claim with a lease
		// (PRE-01/02). If the same device account was signed in as someone
		// else a moment ago, that person's claim ends here — an account
		// switch is a departure for whoever held the console before.
		// Penne sees only the console's device token, whose subject is the
		// certificate; this is where both halves are in hand, so the account
		// behind the console is recorded for the notification channel.
		s.notifStore().BindConsole(di, u.ID)
		s.expireDeviceEverywhere(form.Get("id"), u.ID)
		// A console re-logs in every hour while it plays; the login knows no
		// title, so it must not overwrite the one the device already published
		// (2026-09-22: a game dropping off the friend list at each login).
		client := requestClient(r)
		if !s.deviceClaimLive(u, form.Get("id")) {
			s.noteClientPresence(u, form.Get("id"), client, "ONLINE", "", "", "", -1)
		}
		s.reportOnline(r.Context(), u, client)
		res := map[string]any{
			"expiresIn": 10800, "user": s.userObj(u, id, ""), "idToken": s.idToken(u, id, username, app),
			"accessToken": s.accessToken(u.ID, 2, func() string {
				if id != nil {
					return id.BsDid
				}
				return randHex(8)
			}(), di, sn), "tokenType": "Bearer",
		}
		// No "summary": the login reply a console accepted carries exactly
		// accessToken, expiresIn, idToken, tokenType and user. Membership is
		// answered on capi's memberships endpoint, which is where the console
		// actually asks.
		log.Printf("[nx-baas] %s user=%s pid=%d ua=%s", seg[1], u.ID, u.PID, r.UserAgent())
		writeJSON(w, 200, res)
		return

	case len(seg) == 3 && seg[0] == "1.0.0" && seg[1] == "users":
		u := s.store.User(seg[2])
		if u == nil {
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		// Reading or writing a user object binds to the authenticated user:
		// a profile is not a public page (the friend list carries what
		// friends may see about a person).
		if s.requireCaller(w, r, seg[2]) == nil {
			return
		}
		switch r.Method {
		case "GET":
			writeJSON(w, 200, s.userObj(u, s.identity(u), ""))
		case "PATCH":
			var ops []struct {
				Op, Path string
				Value    any
			}
			json.Unmarshal(body, &ops)
			s.store.Update(u, func(u *User) {
				for _, o := range ops {
					v, _ := o.Value.(string)
					switch o.Path {
					case "/nickname":
						u.Nickname = v
					case "/country":
						u.Country = v
					case "/birthday":
						u.Birthday = v
					case "/thumbnailUrl":
						u.ThumbnailURL = v
					case "/extras/self/nxAccount":
						u.NxAccount = v
					case "/extras/self/playLog", "/extras/favoriteFriends/playLog",
						"/extras/friends/playLog", "/extras/everyone/playLog":
						// 30812/30830 and the sync's upload: four ops, the
						// chosen group holding the log string and the other
						// three "" [friends-contract-22.5.0 §A.6]. Stored as
						// sent; the group that holds it is the permission.
						if _, ok := o.Value.(string); ok {
							if u.PlayLog == nil {
								u.PlayLog = map[string]string{}
							}
							u.PlayLog[strings.TrimSuffix(strings.TrimPrefix(o.Path, "/extras/"), "/playLog")] = v
						}
					case "/permissions/presence":
						// 30810 ChangePresencePermission: only SELF,
						// FAVORITE_FRIENDS and FRIENDS exist; anything else,
						// including EVERYONE, is what the console reads as
						// SELF, so that is what is kept
						// [friends-contract-22.5.0 §A.6, C10].
						if u.Permissions == nil {
							u.Permissions = map[string]any{}
						}
						u.Permissions["presence"] = normalizePresencePermission(o.Value)
					case "/permissions/friendRequestReception":
						// 30811 ChangeFriendRequestReception: a bool. Anything
						// else is not a switch position and is ignored [C10].
						if b, ok := o.Value.(bool); ok {
							if u.Permissions == nil {
								u.Permissions = map[string]any{}
							}
							u.Permissions["friendRequestReception"] = b
						}
					case "/permissions/personalAnalytics", "/permissions/personalNotification",
						"/permissions/friends":
						// The remaining privacy switches. Documented as
						// patchable and silently dropped here until now, so
						// turning one off on the console lasted until the next
						// reply.
						if u.Permissions == nil {
							u.Permissions = map[string]any{}
						}
						u.Permissions[strings.TrimPrefix(o.Path, "/permissions/")] = o.Value
					}
				}
			})
			// ponytail: nickname/mii changes are not pushed back to openpak-account
			// (/internal/profile-sync) yet; the website keeps the account's own name.
			writeJSON(w, 200, s.userObj(u, s.identity(u), ""))
		default:
			baasErr(w, r, 405, "method_not_allowed", "Method Not Allowed", "Method Not Allowed")
		}
		return

	case len(seg) == 4 && seg[0] == "1.0.0" && seg[1] == "users":
		u := s.store.User(seg[2])
		if u == nil {
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		switch seg[3] {
		case "link":
			nu, err := s.link(u, form.Get("idToken"))
			if err != nil {
				log.Printf("[nx-baas] link failed: %v", err)
				baasErr(w, r, 400, "invalid_idp_account", "Invalid IdP Account", "IdP account is invalid")
				return
			}
			writeJSON(w, 200, s.userObj(nu, s.identity(nu), ""))
		case "unlink":
			s.store.Update(u, func(u *User) { u.PID, u.NaID = 0, "" })
			writeJSON(w, 200, s.userObj(u, nil, ""))
		case "generate_code":
			if s.requireCaller(w, r, seg[2]) == nil {
				return
			}
			// The wiki is explicit: a new code, and no new one for 24 hours.
			// This used to answer "there is nothing to regenerate" and hand
			// back the same code, which is a lie a console cannot see through.
			if u.CodeGeneratedAt > 0 && time.Now().Unix()-u.CodeGeneratedAt < 24*3600 {
				baasErr(w, r, 422, "friend_code_unregenerable_state", "Friend Code Unregenerable State", "")
				return
			}
			if err := s.acct.RegenerateFriendCode(u.PID); err != nil {
				log.Printf("[nx-baas] generate_code: %v", err)
				baasErr(w, r, 500, "internal_server_error", "Internal Server Error", "Internal Server Error")
				return
			}
			s.store.Update(u, func(u *User) { u.CodeGeneratedAt = time.Now().Unix() })
			writeJSON(w, 200, s.userObj(u, s.identity(u), ""))
		case "device_histories":
			if s.requireCaller(w, r, seg[2]) == nil {
				return
			}
			// Every console this user has signed in on. We keep no history, and
			// an empty list is a true answer; a 404 here is not.
			writeJSON(w, 200, map[string]any{"count": 0, "deviceHistories": []any{}})
		case "blocks":
			switch r.Method {
			case "POST":
				// {"targetUserId":"%016llx","extras":{"self":{"reason":…}}}
				// is what the console sends [friends-contract-22.5.0 §A.8];
				// userId and id are what this server read before, kept.
				target := bodyField(body, form, "targetUserId", "userId", "id")
				if target == "" {
					baasErr(w, r, 400, "invalid_params", "Invalid Params", "invalid params")
					return
				}
				if s.requireCaller(w, r, seg[2]) == nil {
					return
				}
				other := s.resolveFriend(target)
				if other == nil {
					baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
					return
				}
				// Blocks commit in the core, which owns enforcement for every
				// adapter (SOC-03); the local mirror only feeds this server's
				// own reads.
				if err := s.setBlock(u, other, true); err != nil {
					log.Printf("[nx-baas] block failed user=%s target=%s: %v", u.ID, target, err)
					status, code, title, detail := baasFailure(err)
					baasErr(w, r, status, code, title, detail)
					return
				}
				var in struct {
					Extras struct {
						Self map[string]any `json:"self"`
					} `json:"extras"`
				}
				_ = json.Unmarshal(body, &in)
				now := time.Now().Unix()
				s.store.Update(u, func(u *User) {
					if u.BlockDetails == nil {
						u.BlockDetails = map[string]*BlockDetail{}
					}
					u.BlockDetails[other.BaasUserID] = &BlockDetail{CreatedAt: now, Self: in.Extras.Self}
				})
				// The console ignores this body; it re-syncs the list.
				writeJSON(w, 200, s.blockObj(u, other.BaasUserID, now))
			default:
				if s.requireCaller(w, r, seg[2]) == nil {
					return
				}
				// $.items[*].targetUserId + targetUser, not {"blocks":[{"id"}]}:
				// the old envelope failed every block sync, so each block and
				// unblock reported an error after it had worked, and the
				// friend-list re-sync that follows a block never ran
				// [friends-contract-22.5.0 §A.8, C14].
				now := time.Now().Unix()
				list := []any{}
				for _, b := range u.Blocks {
					if len(list) == maxBlockEntries {
						break
					}
					list = append(list, s.blockObj(u, b, now))
				}
				writeJSON(w, 200, listEnvelope(list))
			}
		case "friends", "friend_requests", "relationships":
			s.friends(w, r, u, seg[3:], body)
		default:
			dump(r, body, "!! UNHANDLED user sub-resource")
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
		}
		return

	case len(seg) == 5 && seg[0] == "1.0.0" && seg[1] == "users" && seg[3] == "blocks" && r.Method == "DELETE":
		u := s.store.User(seg[2])
		if u == nil {
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if s.requireCaller(w, r, seg[2]) == nil {
			return
		}
		other := s.resolveFriend(seg[4])
		if other == nil {
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if err := s.setBlock(u, other, false); err != nil {
			log.Printf("[nx-baas] unblock failed user=%s target=%s: %v", u.ID, seg[4], err)
			status, code, title, detail := baasFailure(err)
			baasErr(w, r, status, code, title, detail)
			return
		}
		w.WriteHeader(204)
		return

	case len(seg) == 5 && seg[0] == "1.0.0" && seg[1] == "users" && seg[3] == "device_accounts":
		u := s.store.User(seg[2])
		if u == nil {
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if s.requireCaller(w, r, seg[2]) == nil {
			return
		}
		// seg[4] names the device account whose presence this is (PRE-01):
		// two consoles signed in as the same user hold two claims, and one
		// of them going quiet must not end the other's.
		device := seg[4]
		switch r.Method {
		case "DELETE":
			// The device unlinks itself (or the account switches): its claim
			// ends now, not when a lease happens to run out.
			s.expireDevicePresence(u, device)
			s.expireDeviceEverywhere(device, u.ID)
			w.WriteHeader(204)
		case "PATCH": // presence (friends sysmodule), JSON patch
			var ops []struct {
				Op, Path string
				Value    any
			}
			json.Unmarshal(body, &ops)
			state, appID, appField, groupID := "", "", "", ""
			acdIndex := -1
			for _, o := range ops {
				v, _ := o.Value.(string)
				switch o.Path {
				case "/presence/state":
					state = v
				case "/presence/extras/friends/appField":
					appField = v
				case "/presence/extras/friends/appInfo:appId":
					appID = v
				case "/presence/extras/friends/appInfo:presenceGroupId":
					groupID = v
				case "/presence/extras/friends/appInfo:acdIndex":
					// The console writes this one as a number, not a string
					// [firmware: the publish format is "appInfo:acdIndex":%d
					// beside two "%016llx" strings]. It is the catalog index
					// its friends read back, so it is stored as sent and
					// echoed as sent — nothing here needs to know what it
					// indexes.
					if n, ok := o.Value.(float64); ok {
						acdIndex = int(n)
					}
				}
			}
			if state == "" {
				baasErr(w, r, 400, "invalid_params", "Invalid Params", "no presence state in patch")
				return
			}
			client := requestClient(r)
			s.noteClientPresence(u, device, client, state, appID, appField, groupID, acdIndex)
			// This is what keeps someone counted as online: the lease the core holds is short,
			// and a client that has gone away stops renewing it.
			if state == "OFFLINE" {
				s.reportOffline(r.Context(), u)
			} else {
				s.reportOnline(r.Context(), u, client)
			}
			log.Printf("[nx-baas] presence user=%s pid=%d device=%s client=%q %s app=%s field=%q", u.ID, u.PID, device, client, state, appID, appField)
			writeJSON(w, 200, s.userObj(u, s.identity(u), ""))
		default:
			dump(r, body, "!! UNHANDLED device_accounts")
			baasErr(w, r, 405, "method_not_allowed", "Method Not Allowed", "Method Not Allowed")
		}
		return

	// >= 2, not >= 3: POST /2.0.0/friend_requests is two segments, so sending a
	// friend request fell straight through to the catch-all 404 and the console
	// said "please try again later" (2121-2031).
	case len(seg) >= 2 && seg[0] == "2.0.0":
		s.friends2(w, r, seg[1:], body)
		return

	case p == "/1.0.0/users" && r.Method == "GET":
		// Friend-code / id lookup from the friends sysmodule. Protected: a
		// live token first (discovery is a social operation, not a public
		// directory), then the console's filter expression, captured from
		// hardware on 2026-09-08:
		//
		//   GET /1.0.0/users?filter.links.friendCode.id.$in=1000-0000-0002
		//
		// The keys here used to be guesses ("friendCode", "id"), so every
		// lookup missed and the console said it could not find the user. The
		// value carries no SW- prefix and $in may list several.
		if s.validBearer(r) == nil {
			baasErr(w, r, 401, "invalid_token", "Invalid token", "a current access token is required")
			return
		}
		q := r.URL.Query()
		now := time.Now().Unix()
		// $.items[*].extras.*.playLog is whichever group the caller may see
		// [friends-contract-22.5.0 §A.7]; friendship decides the friends
		// groups.
		viewer := s.bearerUser(r)
		friendOf := map[string]bool{}
		if id := s.identity(viewer); viewer != nil && id != nil {
			for _, f := range id.Friends {
				friendOf[f.BaasUserID] = true
			}
		}
		found := func(f Friend) any {
			obj := s.searchUserObj(f, now)
			group, pl := s.visiblePlayLog(viewer, s.store.User(f.BaasUserID), friendOf[f.BaasUserID])
			setPlayLog(obj, group, pl)
			return obj
		}
		users := []any{}
		for _, code := range queryList(q, "filter.links.friendCode.id.$in", "friendCode") {
			if f, err := s.acct.Resolve(url.Values{"code": {normaliseFriendCode(code)}}); err == nil && f != nil {
				users = append(users, found(*f))
			}
		}
		for _, id := range queryList(q, "filter.id.$in", "id") {
			if f, err := s.acct.Resolve(url.Values{"baas": {id}}); err == nil && f != nil {
				users = append(users, found(*f))
			}
		}
		// {"items": [...]} -- not {"count": n, "users": [...]}. Probed against a
		// working server on 2026-09-08 with a throwaway device account: the
		// console reads "items" and nothing else, so a search that found
		// somebody was reported to the person as "unable to find user" while
		// our own log said count:1.
		writeJSON(w, 200, map[string]any{"items": users})
		return

	case p == "/1.0.0/devices/snapshot":
		var in struct {
			UserIDs []string `json:"userIds"`
		}
		json.Unmarshal(body, &in)
		persistent, deleted := []string{}, []string{}
		for _, uid := range in.UserIDs {
			if s.store.User(uid) != nil {
				persistent = append(persistent, uid)
			} else {
				deleted = append(deleted, uid)
			}
		}
		writeJSON(w, 200, map[string]any{"deletedUserIds": deleted, "persistentUserIds": persistent})
		return

	case strings.HasPrefix(p, "/1.0.0/push_channels/"):
		// VPS parity: echo the channel back as a full object (the console fails the link on {}).
		var in map[string]any
		json.Unmarshal(body, &in)
		parts := strings.Split(strings.TrimPrefix(p, "/1.0.0/push_channels/"), "/")
		userID, devID := parts[0], ""
		if len(parts) > 1 {
			devID = parts[1]
		}
		now := time.Now().Unix()
		// B workstream (NTF-01): keep the association this echo used to drop.
		s.notifStore().RecordPushChannel(userID, devID, str(in, "service"), str(in, "deviceToken"), time.Unix(now, 0))
		writeJSON(w, 200, map[string]any{
			"createdAt": now, "deviceAccountId": devID, "deviceAttributes": map[string]any{}, "deviceToken": str(in, "deviceToken"),
			"service": str(in, "service"), "updatedAt": now, "userAttributes": map[string]any{}, "userId": userID,
		})
		return
	case p == "/1.0.0/devices/me/delete":
		// A device deleting itself is a departure (PRE-02): its presence claim
		// ends here, not when a lease happens to lapse. The request names the
		// device; where it names a user too, end it on that user's record.
		if dev := bodyField(body, form, "deviceId", "deviceAccountId", "device"); dev != "" {
			if uid := bodyField(body, form, "userId", "user"); uid != "" {
				if u := s.store.User(uid); u != nil {
					s.expireDevicePresence(u, dev)
				}
			}
			s.expireDeviceEverywhere(dev, "")
		} else {
			log.Printf("[nx-baas] devices/me/delete without a device id; nothing to expire")
		}
		writeJSON(w, 200, map[string]any{})
		return
	}

	dump(r, body, "!! UNHANDLED")
	baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
}

// link binds a BAAS user to the OpenPak account behind a Nintendo-Account id_token we issued.
func (s *server) link(u *User, idTok string) (*User, error) {
	claims, err := parseJWT(idTok, &s.key.PublicKey)
	if err != nil {
		return nil, err
	}
	naID := str(claims, "sub")
	pid := s.store.PIDForNA(naID)
	if pid == 0 {
		return nil, fmt.Errorf("unknown Nintendo-Account sub %q", naID)
	}
	if lock := s.pidLock(pid); lock != "" {
		return nil, fmt.Errorf("link pid %d: %w (%s)", pid, errAccountLocked, lock)
	}
	id, err := s.acct.Identity(pid)
	if err != nil {
		return nil, err
	}
	nu := s.store.Link(u, pid, id.BaasUserID, id.NaID)
	log.Printf("[nx-baas] linked user %s -> pid %d (%s)", nu.ID, pid, id.Nickname)
	return nu, nil
}

// /1.0.0/users/<id>/{friends,friend_requests,relationships}: older-firmware spellings, same data.
func (s *server) friends(w http.ResponseWriter, r *http.Request, u *User, rest []string, body []byte) {
	s.friends2(w, r, append([]string{"users", u.ID}, rest...), body)
}

// /2.0.0 friends surface: see the function comment on friends2.
func (s *server) friends2(w http.ResponseWriter, r *http.Request, seg []string, body []byte) {
	now := time.Now().Unix()
	var in map[string]any
	json.Unmarshal(body, &in)
	form, _ := url.ParseQuery(string(body))
	field := func(k string) string {
		if v := str(in, k); v != "" {
			return v
		}
		return form.Get(k)
	}
	// me: the authenticated caller. The legacy path-based identity is gone:
	// trusting /users/<id> to choose whose social state is accessed is what
	// let one account read another's list.
	me := s.bearerUser(r)
	if me == nil {
		baasErr(w, r, 401, "invalid_token", "Invalid token", "a current access token is required")
		return
	}
	// The caller's identity as the core sees it, for rendering "me" objects.
	myID := s.identity(me)

	switch {
	case len(seg) == 3 && seg[0] == "users" && seg[2] == "friends" && r.Method == "GET":
		if s.requireCaller(w, r, seg[1]) == nil {
			return
		}
		list := []any{}
		if myID != nil {
			for _, f := range myID.Friends {
				// One relationship entry per core friend, in the shape the
				// 22.5.0 parser counts: friendId + friend{nickname,
				// thumbnailUrl} + the viewer's own relationship state.
				list = append(list, s.relationshipObj(me, f, now))
			}
			if len(list) > maxListEntries {
				// The parser caps at 300 itself; sending more would be
				// dropped silently at the far end. No native cursor exists
				// to paginate with, so the bound is the contract.
				list = list[:maxListEntries]
			}
		}
		writeJSON(w, 200, listEnvelopeWith(list, `""`, 100))
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "friends" && r.Method == "PATCH":
		// Relationship preferences (SOC-02): /isFavorite (what 22.5.0 sends),
		// /extras/self/isConfirmed (the new-friend acknowledgement) and
		// /extras/self/isOnlineNotification (the online-alert preference).
		// The older isFavoriteFriend spelling maps to the same persisted
		// state: one relationship, one favourite flag.
		if s.requireCaller(w, r, seg[1]) == nil {
			return
		}
		var ops []struct {
			Op, Path string
			Value    any
		}
		_ = json.Unmarshal(body, &ops)
		changed := false
		s.store.Update(me, func(u *User) {
			for _, o := range ops {
				p := u.pref(seg[3])
				switch {
				case strings.HasSuffix(o.Path, "isFavorite") || strings.HasSuffix(o.Path, "isFavoriteFriend"):
					if b, ok := o.Value.(bool); ok {
						p.Favorite = b
						p.UpdatedAt = now
						changed = true
					}
				case strings.HasSuffix(o.Path, "isConfirmed"):
					if b, ok := o.Value.(bool); ok {
						p.Confirmed = b
						p.UpdatedAt = now
						changed = true
					}
				case strings.HasSuffix(o.Path, "isOnlineNotification"):
					if b, ok := o.Value.(bool); ok {
						p.OnlineNotification = &b
						p.UpdatedAt = now
						changed = true
					}
				case strings.HasSuffix(o.Path, "friendNote"):
					// 30130 ChangeFriendNote: replace /friendNote, at most
					// 20 characters. Longer is invalid_params, which the
					// console tolerates by dropping the pending note
					// [friends-contract-22.5.0 §A.2].
					if note, ok := o.Value.(string); ok && len([]rune(note)) <= 20 {
						p.Note = note
						p.UpdatedAt = now
						changed = true
					}
				}
			}
		})
		if !changed {
			baasErr(w, r, 400, "invalid_params", "Invalid Params", "no known relationship field in patch")
			return
		}
		// Answer with the single-friend shape the firmware's single-entry
		// parser reads: $.friendId, $.friend.nickname, $.isFavorite.
		target := s.resolveFriend(seg[3])
		if target == nil && myID != nil {
			// The console *replaces* its cached entry with this reply, and a
			// reply without friendId, friend.nickname and friend.thumbnailUrl
			// fails the call with 2121-2411 [friends-contract-22.5.0 §A.2].
			// A lookup can be unavailable; the friendship this server is
			// already holding still names the person, so the reply stays a
			// full relationship object.
			for _, f := range myID.Friends {
				if f.BaasUserID == seg[3] {
					target = &f
					break
				}
			}
		}
		if target == nil {
			// The person may be unresolvable right now; the preference change
			// is still committed (losing a star the person just set is worse
			// than a plainer reply), so render what we know.
			target = &Friend{BaasUserID: seg[3]}
		}
		writeJSON(w, 200, s.relationshipObj(me, *target, now))
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "friends" && r.Method == "DELETE":
		// Removing a friend commits through the core (SOC-03). The old reply
		// logged "not applied" and answered 204, which was a success statement
		// about an operation that never happened.
		if s.requireCaller(w, r, seg[1]) == nil {
			return
		}
		target := s.resolveFriend(seg[3])
		if target == nil {
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if err := s.removeFriend(me, target); err != nil {
			log.Printf("[nx-baas] friend-remove failed user=%s other=%s: %v", me.ID, seg[3], err)
			status, code, title, detail := baasFailure(err)
			baasErr(w, r, status, code, title, detail)
			return
		}
		w.WriteHeader(204)
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "friend_requests":
		// The request boxes. Entries name their durable request id, so the
		// console's PATCH/DELETE later means the same request whoever answers
		// (SOC-03). The core's lists are the state of record; the ids are the
		// adapter's mapping, persisted across restarts.
		if s.requireCaller(w, r, seg[1]) == nil {
			return
		}
		if myID == nil {
			baasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "not linked")
			return
		}
		list := []map[string]any{}
		incoming := seg[3] != "outbox"
		requests := myID.FriendRequests
		if !incoming {
			requests = myID.SentRequests
		}
		// The console asks for PENDING only and trusts the filter
		// [friends-contract-22.5.0 §A.4.2]. Every request the core lists is
		// pending, so any other state is an empty box.
		q := r.URL.Query()
		if st := q.Get("filter.state.$eq"); st != "" && requestState(st) != "PENDING" {
			requests = nil
		}
		meObj := s.userObj(me, myID, "")
		for _, f := range requests {
			var reqID string
			if incoming {
				reqID, _ = s.store.EnsureRequest(f.PID, me.PID)
			} else {
				reqID, _ = s.store.EnsureRequest(me.PID, f.PID)
			}
			record := s.store.RequestByID(reqID)
			createdAt, updatedAt := now, now
			if record != nil {
				createdAt, updatedAt = record.CreatedAt, record.UpdatedAt
			}
			other := s.friendObj(f, now)
			entry := map[string]any{
				"id": reqID, "state": "PENDING",
				"createdAt": createdAt, "updatedAt": updatedAt,
				"channels": requestChannels(record),
			}
			// The route, from the side each box reads it: the inbox from
			// senderAndReceiver, the outbox from sender (and
			// senderAndReceiver for the game) [§A.4.2]. extras.sender is the
			// sender's own; it never reaches the receiver.
			ex := map[string]any{}
			if record != nil && record.SenderAndReceiver != nil {
				ex["senderAndReceiver"] = record.SenderAndReceiver
			}
			if record != nil && record.Sender != nil && !incoming {
				ex["sender"] = record.Sender
			}
			// Who sent it is the whole point of an inbox: the same object
			// in both slots said nothing, and the console had nothing to
			// show.
			if incoming {
				entry["sender"], entry["senderId"] = other, f.BaasUserID
				entry["receiver"], entry["receiverId"] = meObj, me.ID
				// The badge is the inbox items without read:true, so a
				// request 30205 marked read has to say so here or the badge
				// never clears [§A.4.3].
				ex["receiver"] = map[string]any{"read": record != nil && record.Read}
			} else {
				entry["sender"], entry["senderId"] = meObj, me.ID
				entry["receiver"], entry["receiverId"] = other, f.BaasUserID
			}
			if len(ex) > 0 {
				entry["extras"] = ex
			}
			list = append(list, entry)
		}
		// sort=createdAt:desc, then the console's page: offset from the IPC
		// call, count from its buffer. Items past count are dropped at the far
		// end and a repeated page is a duplicate, so the page is cut here
		// [§A.4.2].
		sort.SliceStable(list, func(i, j int) bool {
			return list[i]["createdAt"].(int64) > list[j]["createdAt"].(int64)
		})
		if off, err := strconv.Atoi(q.Get("offset")); err == nil && off > 0 {
			list = list[min(off, len(list)):]
		}
		if n, err := strconv.Atoi(q.Get("count")); err == nil && n >= 0 && n < len(list) {
			list = list[:n]
		}
		items := make([]any, len(list))
		for i, e := range list {
			items[i] = e
		}
		writeJSON(w, 200, listEnvelope(items))
		return

	case len(seg) == 1 && seg[0] == "friend_requests" && r.Method == "POST":
		if myID == nil {
			baasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "not linked")
			return
		}
		var target *Friend
		var err error
		if c := field("friendCode"); c != "" {
			target, err = s.acct.Resolve(url.Values{"code": {normaliseFriendCode(c)}})
		} else if t := field("receiverId"); t != "" {
			target, err = s.acct.Resolve(url.Values{"baas": {t}})
		} else if t := field("userId"); t != "" {
			target, err = s.acct.Resolve(url.Values{"baas": {t}})
		} else {
			dump(r, body, "friend_requests: unknown body")
		}
		if err != nil || target == nil {
			baasErr(w, r, 400, "invalid_friend_code_format", "Invalid friend code", "no such user")
			return
		}
		// 30811 ChangeFriendRequestReception: a receiver who turned requests
		// off refuses new ones [friends-contract-22.5.0 §A.6, C10]. A crossed
		// send is not new: the receiver already asked, and answering completes
		// the friendship they initiated.
		if receiver := s.store.User(target.BaasUserID); !acceptsFriendRequests(receiver) &&
			!s.store.OpenRequest(target.PID, me.PID) {
			baasErr(w, r, 400, "could_not_send_request", "Could Not Send Request", "not accepting friend requests")
			return
		}
		created, authorized, reqID, err := s.commitFriendRequest(me, target)
		if err != nil {
			// The request did not commit, so this is an error, never a
			// success with a timestamp (the old code logged the failure and
			// answered 201 anyway).
			log.Printf("[nx-baas] friend-request failed user=%s target=%s: %v", me.ID, target.BaasUserID, err)
			status, code, title, detail := baasFailure(err)
			baasErr(w, r, status, code, title, detail)
			return
		}
		if created {
			s.noteRequestRoute(reqID, body)
		}
		s.friendGraphChanged(me, target.BaasUserID)
		// The request gets its own durable id. It used to be handed back the
		// receiver's user id, which is a different thing entirely: the console
		// PATCHes /2.0.0/friend_requests/<id> to cancel, and an id that is
		// really somebody's user id is not a request it can act on.
		code := 200
		if created {
			code = 201
		}
		reply := s.friendRequestReply(me, myID, target, reqID, false, body, now)
		if authorized {
			// Sender mode still: the caller asked, the target is the
			// receiver, and the answer is that they are now friends.
			reply["state"] = "AUTHORIZED"
		}
		writeJSON(w, code, reply)
		return

	case len(seg) == 2 && seg[0] == "friend_requests" && (r.Method == "PATCH" || r.Method == "DELETE"):
		if myID == nil {
			baasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "not linked")
			return
		}
		state := patchedState(body)
		if r.Method == "DELETE" {
			state = "CANCELED"
		}
		record, other := s.friendRequestByRef(seg[1])
		if state == "" {
			// Marked read, not answered: the request stays open.
			var target *Friend
			incoming := true
			switch {
			case record != nil:
				incoming = record.ToPID == me.PID
				otherPID := record.FromPID
				if !incoming {
					otherPID = record.ToPID
				}
				target = s.friendByPID(otherPID)
			case other != nil:
				target = other
			}
			if target == nil {
				baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
				return
			}
			// 30205 ReadFriendRequest: [{"op":"add","path":"/extras/receiver/read",
			// "value":true}]. Kept on the request, because the inbox is where
			// the console counts it [friends-contract-22.5.0 §A.4.3]; only the
			// receiver's own flag is the receiver's to set.
			read := false
			if record != nil {
				read = record.Read
			}
			var ops []struct {
				Path  string
				Value any
			}
			_ = json.Unmarshal(body, &ops)
			for _, o := range ops {
				if v, ok := o.Value.(bool); ok && o.Path == "/extras/receiver/read" && record != nil && record.ToPID == me.PID {
					s.store.MarkRequestRead(record.ID, v)
					read = v
				}
			}
			reply := s.friendRequestReply(me, myID, target, seg[1], incoming, nil, now)
			if record != nil && record.State != "" {
				reply["state"] = requestState(record.State)
			}
			reply["extras"] = map[string]any{"receiver": map[string]any{"read": read}}
			writeJSON(w, 200, reply)
			return
		}
		var err error
		switch {
		case record != nil && record.State != "":
			// Already answered. The console PATCHes the same request twice —
			// once from the request box, once confirming — and a 404 on the
			// second one reads as "this invitation is no longer valid" even
			// though the friendship went through. Same answer, no second
			// commit; a different answer is genuinely gone.
			if requestState(record.State) != state {
				baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
				return
			}
		case record != nil:
			// The durable path: the record names the pair, so authorization
			// is exact — only the addressee answers, only the sender cancels.
			switch state {
			case "AUTHORIZED":
				err = s.settleRequest(me, record, true)
			case "REJECTED":
				err = s.settleRequest(me, record, false)
			case "CANCELED":
				err = s.cancelRequest(me, record)
			default:
				baasErr(w, r, 400, "invalid_params", "Invalid Params", "unknown request state")
				return
			}
			if err == nil {
				s.store.SettleRequest(record.ID, state) // a stale id must not commit twice
			}
		case other != nil:
			// A bare user id: a request box cached by an older build of this
			// server. The core enforces the direction — accepting a request
			// that does not address this caller fails there.
			if state == "CANCELED" {
				err = s.acct.RemoveFriend(me.PID, other.PID)
			} else {
				err = s.acct.FriendAccept(me.PID, other.PID, state == "AUTHORIZED")
			}
		default:
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if err != nil {
			// No commit, no success: the console is told, in its own error
			// contract, and can re-sync.
			log.Printf("[nx-baas] friend-request %s failed user=%s ref=%s: %v", state, me.ID, seg[1], err)
			status, code, title, detail := baasFailure(err)
			baasErr(w, r, status, code, title, detail)
			return
		}
		// The other side of the request, for the reply the console expects.
		var otherFriend *Friend
		if other != nil {
			otherFriend = other
		} else {
			otherPID := record.FromPID
			if otherPID == me.PID {
				otherPID = record.ToPID
			}
			otherFriend = s.friendByPID(otherPID)
		}
		if otherFriend == nil {
			otherFriend = &Friend{BaasUserID: seg[1]}
		}
		otherBaas := otherFriend.BaasUserID
		s.friendGraphChanged(me, otherBaas)
		// An acceptance completes the new-friend acknowledgement too: the
		// friendship is not news to the person who just accepted it.
		if state == "AUTHORIZED" {
			s.store.Update(me, func(u *User) {
				p := u.pref(otherBaas)
				p.Confirmed, p.UpdatedAt = true, now
			})
		}
		// The console sets the state itself -- [{"op":"replace","path":"/state",
		// "value":"AUTHORIZED"}] -- and expects that word back. We answered
		// with our own vocabulary ("ACCEPTED") and a three-field stub, and the
		// console called it a communication error even though the friendship
		// had gone through.
		otherObj := s.friendObj(*otherFriend, now)
		meObj := s.userObj(me, myID, "")
		senderObj, receiverObj := any(otherObj), any(meObj)
		senderID, receiverID := otherBaas, me.ID
		if state == "CANCELED" || (record != nil && record.FromPID == me.PID) {
			// A cancellation answers the request the caller sent.
			senderObj, receiverObj = receiverObj, senderObj
			senderID, receiverID = receiverID, senderID
		}
		createdAt := now
		if otherFriend.CreatedAt > 0 {
			createdAt = otherFriend.CreatedAt
		}
		writeJSON(w, 200, map[string]any{
			"id":       seg[1],
			"senderId": senderID, "receiverId": receiverID,
			"sender": senderObj, "receiver": receiverObj,
			"state": state, "channels": requestChannels(record),
			"createdAt": createdAt, "updatedAt": now,
		})
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "relationships":
		if s.requireCaller(w, r, seg[1]) == nil {
			return
		}
		rel := map[string]any{
			"userId": me.ID, "targetUserId": seg[3],
			"isFriend": false, "isFavoriteFriend": false, "isBlocking": false,
			"sentFriendRequestIds": []string{},
		}
		// The console renders the person, not just the verdict: it reads
		// targetUser.nickname and targetUser.thumbnailUrl off this reply
		// [firmware, friends module]. Resolving costs one core lookup.
		if f := s.resolveFriend(seg[3]); f != nil {
			rel["targetUser"] = s.friendObj(*f, now)
		}
		for _, b := range me.Blocks {
			if b == seg[3] {
				rel["isBlocking"] = true
			}
		}
		if p := s.prefOf(me, seg[3]); p != nil && p.Favorite {
			rel["isFavoriteFriend"] = true
		}
		if myID != nil {
			for _, f := range myID.Friends {
				if f.BaasUserID == seg[3] {
					rel["isFriend"] = true
				}
			}
			for _, f := range myID.SentRequests {
				if f.BaasUserID == seg[3] {
					rel["sentFriendRequestIds"] = []string{f.BaasUserID}
				}
			}
		}
		writeJSON(w, 200, rel)
		return
	}
	dump(r, body, "!! UNHANDLED 2.0.0")
	baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
}

// ---------- Nintendo Account (accounts.nintendo.com) ----------

func (s *server) na(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	form, _ := url.ParseQuery(string(body))
	switch {
	case p == "/1.0.0/certificates":
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.jwks)
		return

	case strings.HasPrefix(p, "/api/1.0.0/users/") && strings.HasSuffix(p, "/qrcode_param"):
		// Friend-QR parameter (VPS parity): a signed verify URL the console renders as a QR code.
		naID := strings.TrimSuffix(strings.TrimPrefix(p, "/api/1.0.0/users/"), "/qrcode_param")
		now := time.Now().Unix()
		exp := now + 7*86400
		param := fmt.Sprintf("https://accounts.nintendo.com/qr_verify?sig=%s&iat=%d&aud=6ffd70c434d303c8&sub=%s&exp=%d", randB64(32), now, naID, exp)
		writeJSON(w, 200, map[string]any{"exp": exp, "param": param, "userId": naID})
		return

	case p == "/connect/1.0.0/term_confirm" || p == "/1.0.0/term_confirm":
		// The console confirms the account's terms here, form-encoded with
		// id_token/idToken/userId [firmware, account module 0x181077]. There
		// are no terms to accept on a private network, and users/me already
		// reports the EULA and privacy policy as agreed — so this confirms
		// rather than 404s, which is what keeps account setup moving.
		log.Printf("[nx-baas] NA term_confirm for user=%s", form.Get("userId"))
		writeJSON(w, 200, map[string]any{"status": 200})
		return

	case strings.HasPrefix(p, "/connect/1.0.0/api/term_agreement_token") ||
		strings.HasPrefix(p, "/1.0.0/api/term_agreement_token"):
		// Asked for when the terms themselves change. The document it returns
		// is not recovered (the module reads $.challenge_src and $.errorCode
		// near this call), and a token is not a thing to invent, so the
		// request is recorded and refused.
		dump(r, body, "!! NA term_agreement_token (document shape unrecovered)")
		writeJSON(w, 404, map[string]any{"status": 404, "errorCode": "not_found",
			"detail": "no term agreement is issued on this network"})
		return

	case strings.Contains(p, "/api/transfer_na_tokens"):
		// Moving an account between consoles [account module 0x17d920]. This
		// server has no transfer flow, and half-answering one risks an account
		// that exists in two places: refuse plainly and record the attempt.
		dump(r, body, "!! NA transfer_na_tokens (account transfer is not supported)")
		writeJSON(w, 400, map[string]any{"status": 400, "errorCode": "invalid_request",
			"detail": "account transfer is not supported on this network"})
		return

	case p == "/connect/1.0.0/authorize" && r.Method == "POST" && form.Get("prompt") == "none":
		// SSO for system applets (e-license etc.): identified by our NA access token, no UI.
		cl, err := parseJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), &s.key.PublicKey)
		pid := uint64(0)
		if err == nil {
			pid = s.store.PIDForNA(str(cl, "sub"))
		}
		if pid == 0 {
			writeJSON(w, 401, map[string]any{"error": "login_required"})
			return
		}
		if s.pidLock(pid) != "" {
			log.Printf("[nx-baas] NA silent authorize refused: pid=%d is locked", pid)
			naAuthorizeLocked(w, r, form.Get("redirect_uri"), form.Get("state"))
			return
		}
		id, err := s.acct.Identity(pid)
		if err != nil {
			writeJSON(w, 401, map[string]any{"error": "login_required"})
			return
		}
		c := naCode{PID: pid, Username: id.Nickname, ClientID: form.Get("client_id"), NaID: id.NaID}
		code := randHex(16)
		s.mu.Lock()
		s.codes[code] = c
		s.mu.Unlock()
		frag := url.Values{"state": {form.Get("state")}, "session_state": {randHex(11)}, "code": {code}}
		if strings.Contains(form.Get("response_type"), "id_token") {
			frag.Set("id_token", s.naIDToken(c, ""))
		}
		dest := form.Get("redirect_uri") + "#" + frag.Encode()
		log.Printf("[nx-baas] NA silent authorize pid=%d client=%s -> %s", pid, c.ClientID, form.Get("redirect_uri"))
		http.Redirect(w, r, dest, http.StatusFound)
		return

	case p == "/connect/1.0.0/authorize":
		q := r.URL.Query()
		if r.Method == "POST" { // our own form
			for k := range form {
				if k != "email" && k != "password" {
					q[k] = form[k]
				}
			}
			pid, username, err := s.acct.LoginPID(form.Get("email"), form.Get("password"))
			lock := s.pidLock(pid)
			if errors.Is(err, errAccountLocked) && lock == "" {
				lock = lockBanned
			}
			if lock != "" {
				log.Printf("[nx-baas] NA login refused for %q: account is %s", form.Get("email"), lock)
				s.authorizePage(w, r, q, `<p class="err">`+lockedPageMessage(lock)+`</p>`)
				return
			}
			if err != nil {
				log.Printf("[nx-baas] NA login failed for %q: %v", form.Get("email"), err)
				s.authorizePage(w, r, q, `<p class="err">Wrong e-mail or password.</p>`)
				return
			}
			id, err := s.acct.Identity(pid)
			if err != nil {
				s.authorizePage(w, r, q, `<p class="err">Account lookup failed.</p>`)
				return
			}
			code := randHex(16)
			s.mu.Lock()
			s.codes[code] = naCode{PID: pid, Username: username, ClientID: q.Get("client_id"), NaID: id.NaID}
			s.mu.Unlock()
			s.store.RememberNA(id.NaID, pid)
			// ponytail: the redirect shape is inferred from the response_type the console sends;
			// both the query (code) and fragment (session_token_code / id_token) forms are covered.
			dest := s.authorizeRedirect(q, code)
			log.Printf("[nx-baas] NA authorize ok pid=%d response_type=%q -> %s", pid, q.Get("response_type"), dest)
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		dump(r, body, "NA authorize")
		s.authorizePage(w, r, q, "")
		return

	case p == "/connect/1.0.0/api/session_token" || p == "/connect/1.0.0/api/token":
		dump(r, body, "NA token")
		code := form.Get("session_token_code")
		if code == "" {
			code = form.Get("code")
		}
		if code == "" {
			code = form.Get("session_token")
		}
		s.mu.Lock()
		c, ok := s.codes[code]
		s.mu.Unlock()
		if !ok && form.Get("refresh_token") != "" {
			// Later boots: the console refreshes with the token we issued (a signed JWT whose sub
			// is the NA id); the NA id -> PID map is persisted, so this survives restarts.
			if cl, err := parseJWT(form.Get("refresh_token"), &s.key.PublicKey); err == nil && str(cl, "typ") == "refresh" {
				if pid := s.store.PIDForNA(str(cl, "sub")); pid != 0 {
					if id, err := s.acct.Identity(pid); err == nil {
						c, ok = naCode{PID: pid, Username: id.Nickname, ClientID: form.Get("client_id"), NaID: id.NaID}, true
						s.bindNotificationChannel(form.Get("device_authentication_token"), id.BaasUserID)
					}
				}
			}
		}
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "unknown code"})
			return
		}
		// Codes and refresh tokens minted before a ban stop here: no token for a banned
		// account, whichever grant it arrives on.
		if lock := s.pidLock(c.PID); lock != "" {
			log.Printf("[nx-baas] NA token refused: pid=%d is %s", c.PID, lock)
			naTokenLocked(w, lock)
			return
		}
		if p == "/connect/1.0.0/api/session_token" {
			writeJSON(w, 200, map[string]any{"session_token": code, "code": code})
			return
		}
		if id, err := s.acct.Identity(c.PID); err == nil {
			s.bindNotificationChannel(form.Get("device_authentication_token"), id.BaasUserID)
		}
		at := s.naAccessToken(c)
		writeJSON(w, 200, map[string]any{
			"access_token": at, "expires_in": 900, "id_token": s.naIDToken(c, at), "refresh_token": s.naRefreshToken(c),
			"scope":         strings.Fields(strings.ReplaceAll(form.Get("scope"), "+", " ")),
			"session_token": randHex(24), "token_type": "Bearer",
		})
		return

	case p == "/2.0.0/agreements": // ToS probe before authorize
		if r.Method == "POST" {
			w.WriteHeader(204)
			return
		}
		writeJSON(w, 200, map[string]any{"agreements": []any{}})
		return

	case p == "/2.0.0/users/me":
		c, err := parseJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), &s.key.PublicKey)
		if err != nil {
			writeJSON(w, 401, map[string]any{"error": "invalid_token"})
			return
		}
		pid := s.store.PIDForNA(str(c, "sub"))
		if lock := s.pidLock(pid); lock != "" {
			naTokenLocked(w, lock)
			return
		}
		id, err := s.acct.Identity(pid)
		if err != nil {
			writeJSON(w, 404, map[string]any{"error": "not_found"})
			return
		}
		// Console rules (Fix_Experimental relay, A/B on hardware): id == access token sub, 16 lowercase
		// hex; nickname non-empty, <= 32 bytes. No null-valued fields: keep the object minimal.
		nick := id.Nickname
		for len(nick) > 32 {
			nick = nick[:len(nick)-1]
		}
		// The object the VPS serves (captured 2026-09-06), with our identity substituted.
		now := time.Now().Unix()
		perm := func(ok bool) map[string]any {
			return map[string]any{"editable": map[string]any{"admin": false, "self": true}, "permitted": ok, "updatedAt": int64(1524557701), "userConfirmed": true}
		}
		// The account's own country and birthday, not the captured sample's. The console links a
		// Nintendo Account to a BAAS user in one flow and reads both objects: leaving this half
		// hardcoded told it the person lives in GB and was born in 2000 while the other half said
		// the account holds neither. Where the account has nothing, the sample's values remain —
		// a Nintendo Account always carries both, so there is no "absent" to serve here.
		country, birthday := naProfile(id)
		me := map[string]any{
			"agreedTerms": map[string]any{
				"EULA":          map[string]any{"agreedAt": int64(1524557701), "country": country, "version": 2},
				"privacyPolicy": map[string]any{"agreedAt": int64(1524557701), "country": country, "version": 2},
			},
			"analyticsOptedIn": false, "analyticsOptedInUpdatedAt": int64(1524557701),
			"analyticsPermissions": map[string]any{"dataCollection": perm(false), "internalAnalysis": perm(true), "targetMarketing": perm(false)},
			// nn.account reads $.summary.nintendo.hasMembership here
			// [firmware, account module 0x18000a]; capi answers the same
			// question on /memberships and must not disagree with it.
			"summary":  map[string]any{"nintendo": map[string]any{"hasMembership": true}},
			"birthday": birthday, "clientFriendsOptedIn": true, "clientFriendsOptedInUpdatedAt": int64(1524557701),
			"country": country, "createdAt": int64(1524557701),
			"eachEmailOptedIn": map[string]any{"deals": map[string]any{"optedIn": false, "updatedAt": int64(1524557701)}, "survey": map[string]any{"optedIn": false, "updatedAt": int64(1524557701)}},
			"email":            "legacy@example.com", "emailOptedIn": false, "emailOptedInUpdatedAt": int64(1524557701), "emailVerified": true,
			"gender": "unknown", "iconUri": avatarURL(id.PID, id.Avatar, id.ImageUpdatedAt), "id": strings.ToLower(id.NaID), "isChild": false, "language": "en-GB",
			"links": map[string]any{}, "loginId": nil, "nickname": nick, "phoneNumberEnabled": false, "region": nil,
			"screenName": "ne•••@e••••", "termsAgreementRequired": false,
			"timezone":  map[string]any{"id": "Europe/London", "name": "Europe/London", "utcOffset": "+01:00", "utcOffsetSeconds": 3600},
			"updatedAt": now,
		}
		log.Printf("[nx-baas] users/me -> id=%s nickname=%q", me["id"], nick)
		writeJSON(w, 200, me)
		return
	}
	dump(r, body, "!! UNHANDLED NA")
	w.WriteHeader(404)
}

// authorizeRedirect builds the destination the console expects for the response_type it asked
// for. Shared by the password form and the QR flow so both finish identically.
// ponytail: the redirect shape is inferred from the response_type the console sends; both the
// query (code) and fragment (session_token_code / id_token) forms are covered.
func (s *server) authorizeRedirect(q url.Values, code string) string {
	rt := q.Get("response_type")
	dest := q.Get("redirect_uri")
	params := url.Values{"state": {q.Get("state")}}
	sep := "?"
	if strings.Contains(dest, "?") {
		sep = "&"
	}
	switch {
	case strings.Contains(rt, "session_token_code"):
		// What the console sends (Settings > Users > Link Nintendo Account); it wants the code
		// back as query parameters on its nintendo:// redirect, then trades it at
		// /connect/1.0.0/api/session_token (with the PKCE verifier) and /api/token.
		params.Set("session_token_code", code)
		return dest + sep + params.Encode()
	case strings.Contains(rt, "id_token"):
		s.mu.Lock()
		c := s.codes[code]
		s.mu.Unlock()
		params.Set("id_token", s.naIDToken(c, ""))
		if strings.Contains(rt, "code") {
			params.Set("code", code)
		}
		return dest + "#" + params.Encode()
	default:
		params.Set("code", code)
		return dest + sep + params.Encode()
	}
}

// authorizePage is what the console browser shows. Typing an e-mail and password with a
// The console page describes a phone path only when a phone has somewhere to go; see linkBaseURL.
func phoneIntro(ok bool) string {
	if ok {
		return "Scan the code with your phone, sign in there, then approve it here."
	}
	return "Sign in below to link this console."
}

func qrPanel(ok bool, linkURL string) string {
	if !ok {
		return ""
	}
	return `<div class="qr"><img src="` + qrDataURI(linkURL) + `" alt="QR code"></div>`
}

func phoneSteps(ok bool) string {
	if ok {
		return `<li>Scan the square with your phone&rsquo;s camera.</li>
      <li>Sign in to OpenPak on the phone.</li>
      <li>Check this code matches, then approve below.</li>`
	}
	return `<li>Sign in below.</li>
      <li>Check this code matches, then approve.</li>`
}

func phoneAddress(ok bool, base string) string {
	if !ok {
		return ""
	}
	return `<p style="margin:10px 0 0;font-size:0.9rem">or open <strong>` +
		html.EscapeString(strings.TrimPrefix(base, "http://")) + `/link</strong> on your phone</p>`
}

// controller is miserable, so the QR path leads: a code and an image to scan, the page polls
// for a phone to claim it, and the person at the console approves. The password form is still
// there, one fold down, for anyone without a phone to hand.
func (s *server) authorizePage(w http.ResponseWriter, r *http.Request, q url.Values, msg string) {
	var hidden strings.Builder
	for k, v := range q {
		fmt.Fprintf(&hidden, `<input type="hidden" name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(v[0]))
	}
	code, pair := s.links.new(q)
	// The QR identifies this console session; it carries neither the code nor any authority.
	// phoneOK is false when nothing here is reachable by a phone, in which case no square is
	// drawn at all — one built on the hostname the console arrived by would send the pairing id
	// to Nintendo, since that is who owns that name everywhere except on this console.
	linkBase, phoneOK := s.linkBaseURL(r)
	linkURL := linkBase + "/link?p=" + pair
	var e string
	if msg != "" {
		e = msg
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeadFor("Link this console", "console")+`
<h1>Link this console</h1>
<p>`+phoneIntro(phoneOK)+`</p>
<div class="card"><div class="split">
  `+qrPanel(phoneOK, linkURL)+`
  <div>
    <ol class="steps">
      `+phoneSteps(phoneOK)+`
    </ol>
    <div id="codebox" hidden>
      <p style="margin:16px 0 0">Type this on your phone:</p>
      <p style="margin:8px 0 0"><span class="code">`+groupCode(code)+`</span></p>
    </div>
    `+phoneAddress(phoneOK, linkBase)+`
    <p id="status" style="margin:14px 0 0">Waiting for you to sign in on your phone&hellip;</p>
    <div id="confirm" hidden>
      <button id="approve" type="button">Approve</button>
      <button id="deny" class="ghost" type="button">Not me</button>
    </div>
  </div>
</div></div>

<details><summary>No phone? Sign in here instead</summary>
<div class="card" style="margin-top:14px">`+e+`<form method="post">
<label for="email">E-mail</label><input id="email" name="email" type="email" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
`+hidden.String()+`<button type="submit">Sign in</button></form></div></details>
<script>
(function () {
  var code = `+"\""+code+"\""+`, status = document.getElementById("status"),
      confirm = document.getElementById("confirm"), done = false;
  function poll() {
    if (done) return;
    var x = new XMLHttpRequest();
    x.open("GET", "/connect/1.0.0/qr/state?c=" + code, true);
    x.onreadystatechange = function () {
      if (x.readyState !== 4) return;
      var d = {};
      try { d = JSON.parse(x.responseText); } catch (e) { return; }
      if (d.state === "signed_in") {
        document.getElementById("codebox").hidden = false;
        status.innerHTML = "Signed in as <strong>" + d.account + "</strong>. Now type the code above.";
      } else if (d.state === "claimed") {
        status.innerHTML = "Signed in on your phone as <strong>" + d.account + "</strong>. Approve to finish.";
        confirm.hidden = false;
      } else if (d.state === "expired") {
        status.textContent = "This code expired. Reload the page for a new one.";
        done = true;
      }
    };
    x.send();
  }
  setInterval(poll, `+pollEvery+`);
  poll();
  document.getElementById("approve").onclick = function () {
    done = true;
    status.textContent = "Linking\u2026";
    var x = new XMLHttpRequest();
    x.open("POST", "/connect/1.0.0/qr/approve?c=" + code, true);
    x.onreadystatechange = function () {
      if (x.readyState !== 4) return;
      var d = {};
      try { d = JSON.parse(x.responseText); } catch (e) {}
      if (d.redirect) { window.location = d.redirect; }
      else { status.textContent = "That did not work. Reload and try again."; }
    };
    x.send();
  };
  document.getElementById("deny").onclick = function () {
    var x = new XMLHttpRequest();
    x.open("POST", "/connect/1.0.0/qr/deny?c=" + code, true);
    x.send();
    window.location.reload();
  };
})();
</script></main></body></html>`)
}

// ---------- plumbing ----------

type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (rec *recorder) WriteHeader(c int) { rec.status = c; rec.ResponseWriter.WriteHeader(c) }
func (rec *recorder) Write(b []byte) (int, error) {
	if rec.buf.Len() < 8192 {
		rec.buf.Write(b)
	}
	return rec.ResponseWriter.Write(b)
}

// Flush forwards to the wrapped writer when it can stream. Without this the
// debug wrapper hid http.Flusher from handlers: the Penne frontline (and any
// other held-open response) silently fell back to a buffered, non-streaming
// answer whenever NX_DEBUG was set. B workstream fix (NTF-03).
func (rec *recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards likewise: the NPNS frontline takes the raw connection for
// its bidirectional frame stream, so the debug wrapper must not hide
// http.Hijacker either. B workstream fix (NTF-03).
func (rec *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rec.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("recorder: wrapped writer is not a Hijacker")
}

var debug = os.Getenv("NX_DEBUG") != ""
var minimal = os.Getenv("NX_MINIMAL") != "" // bisecting 2124-0292: only the NA link on top of the POST /users shape

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r)
	log.Printf("[nx-baas] %s %s%s ua=%q", r.Method, host, r.URL.RequestURI(), r.UserAgent())
	// The friends module fetches its app catalog and art from a configured
	// host, so this matches on the path before host routing claims it
	// (eshop_unserved.go). It declines anything that is not /v1/apps/<id>/.
	if s.friendsAppCatalog(w, r) {
		return
	}
	// migration.<env>.scsi.srv.nintendo.net is not save data: it is the
	// console-to-console user transfer (`/api/nx/v1/account_migrations/gen_key`
	// and `get_key`, with transfer.hac.<env>.banco.srv.nintendo.net alongside)
	// [firmware, migration module]. It shares the scsi domain, so without this
	// it was being forwarded into the saves service, which can only 404 it.
	// OpenPak does not implement transfer; say so in the log rather than hide
	// it inside somebody else's 404.
	if strings.HasPrefix(host, "migration.") || strings.HasPrefix(host, "transfer.") {
		log.Printf("[nx-baas] user transfer is not implemented: %s %s%s", r.Method, host, r.URL.Path)
		http.Error(w, "user transfer is not implemented by OpenPak", 501)
		return
	}
	if strings.Contains(host, ".er.srv.nintendo.net") {
		// eupld's error reports, before the shared 1 MiB body read (errorreport.go).
		s.errorReport(w, r)
		return
	}
	if s.saves != nil && strings.Contains(host, "scsi.srv.nintendo.net") {
		// Before the body is read: a save can be hundreds of MB and streams through.
		s.savesProxy(w, r)
		return
	}
	// B workstream (NTF-02): the Penne frontline POST is bidirectional -- the
	// request body carries the client's frames, so it must reach the handler
	// unread. Everything else keeps the buffered path it has always had.
	var body []byte
	if isPenneFrontline(host) {
		body = nil
	} else {
		body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	if debug && !strings.HasPrefix(r.URL.Path, "/avatar/") {
		dump(r, passwordRe.ReplaceAll(body, []byte("password=***")), "DBG >>>")
		rec := &recorder{ResponseWriter: w, status: 200}
		w = rec
		defer func() {
			log.Printf("[nx-baas] DBG <<< %d %s %s%s body(%d)=%s", rec.status, r.Method, host, r.URL.Path, rec.buf.Len(), rec.buf.Bytes())
		}()
	}
	switch {
	// Liveness, for anything checking from outside. Deliberately answered
	// before host routing: the console-facing names all resolve here, and a
	// health check should not have to pick one of them.
	case r.URL.Path == "/healthz":
		writeJSON(w, 200, map[string]any{"status": "ok", "service": "nx-baas"})
	case strings.HasPrefix(r.URL.Path, "/connect/1.0.0/qr/") || strings.HasPrefix(r.URL.Path, "/link"):
		if !s.qrRoutes(w, r, body) {
			http.NotFound(w, r)
		}
	case strings.Contains(host, "accounts.nintendo.com"):
		s.na(w, r, body)
	// Store workstream (native OpenPak store, prds/native-switch-store-prd.md): the shop
	// applet host, the content host and the rights family. These sit before the dauth case
	// because its prefix list claims the dragons hosts; dauth keeps its setup-critical
	// dragons answers (console link, 2124-3121) and this only takes the store rights
	// routes. Beach moved from penne's `{}` placeholder to a real handler; the extraction
	// keeps penne's own cases untouched.
	case strings.HasPrefix(host, "pearljam."):
		// The eShop host NIM names beside dragons and tigers; /civil and /sugar
		// answer a checked, recorded success (eshop_unserved.go).
		s.pearljam(w, r, body)
	case strings.HasPrefix(host, "idbe-hac."):
		// NIM's icon data: Nintendo's 3DS / Wii U files relayed (eshop_idbe.go).
		s.idbe(w, r, body)
	case strings.HasPrefix(host, "bvc-hac-"):
		// NIM's firmware-version check against the operator blocklist (eshop_unserved.go).
		s.bvc(w, r)
	case strings.HasSuffix(host, ".znc.srv.nintendo.net"):
		// The voice-chat lobby page systemWeb opens (nso.go).
		s.zncLobby(w, r, body)
	case strings.HasPrefix(host, "bugyo."):
		s.shopHandler(w, r, body)
	case strings.HasSuffix(host, ".savanna.srv.nintendo.net"):
		// Where 22.5.0's systemWeb opens the shop (shop.go).
		s.savanna(w, r, body)
	case strings.HasPrefix(host, "pushmo."):
		s.pushmo(w, r, body)
	case strings.HasPrefix(host, "tagaya."):
		s.tagaya(w, r, body)
	case strings.HasPrefix(host, "veer."):
		s.veer(w, r, body)
	// NIM's other d4c hosts: system-update metadata (sun, aqua), the version
	// lookup (superfly) and atumn. They share the content domain, so they
	// must be claimed before the atum case below, which only knows content
	// routes and 404'd every one of them.
	case isNimMetaHost(host):
		if !s.nimUnserved(w, r, body) {
			dump(r, body, "!! UNHANDLED nim metadata host")
			writeJSON(w, 404, map[string]any{"status": 404, "title": "not found"})
		}
	case strings.Contains(host, ".d4c.nintendo.net"):
		s.atum(w, r, body)
	case strings.HasPrefix(host, "dragonst.") || strings.HasPrefix(host, "tigers."):
		s.dragons(w, r, body)
	case strings.HasPrefix(host, "dragons.") && shopRightsRoute(r.URL.Path):
		s.dragons(w, r, body)
	case strings.HasPrefix(host, "beach."):
		s.beach(w, r, body)
	case strings.HasPrefix(host, "dauth") || strings.HasPrefix(host, "dcert") ||
		strings.HasPrefix(host, "acert") || strings.HasPrefix(host, "aauth") ||
		strings.HasPrefix(host, "dragons"):
		// dragons hosts that are not store rights routes keep the dauth handler's
		// setup-critical answers (elicense archives, exercise, migration state, penne id).
		s.dauth(w, r, body)
	case strings.Contains(host, "penne.") || strings.Contains(host, "vermillion."):
		s.penne(w, r, body)
	case strings.HasSuffix(host, ".five.nintendo.net"):
		// Native online-play invitations (the friends sysmodule's invite UI).
		s.five(w, r, body)
	case strings.HasPrefix(host, "capi.") && strings.HasSuffix(r.URL.Path, "/membership"):
		// The per-title check, beside the list below: nn.account asks
		// `/v1/users/<id>/membership?application_id=<tid>` and reads
		// `$.membership.active` [firmware, account strings]. Answering only the
		// plural left this one on the catch-all 404.
		writeJSON(w, 200, map[string]any{"membership": map[string]any{
			"active": true, "expires_at": time.Now().Unix() + 365*86400,
		}})
	case strings.HasPrefix(host, "capi.") && strings.HasSuffix(r.URL.Path, "/memberships"):
		// NSO membership check: every account has an active membership in both
		// contexts. "default" is the base plan and "ex" the Expansion Pack
		// [firmware, account module: the parser binds .user_id, .context and
		// .membership.active]. OpenPak sells no tiers, so there is nothing an
		// account could lack; answering ex inactive sent every Expansion Pack
		// title to a paywall prompt for a purchase that does not exist.
		seg := strings.Split(r.URL.Path, "/")
		naID := seg[len(seg)-2]
		expires := time.Now().Unix() + 365*86400
		writeJSON(w, 200, map[string]any{"count": 2, "items": []any{
			map[string]any{"context": "ex", "membership": map[string]any{"active": true, "expires_at": expires}, "user_id": naID},
			map[string]any{"context": "default", "membership": map[string]any{"active": true, "expires_at": expires}, "user_id": naID},
		}, "total": 2})
	case strings.HasSuffix(host, ".nso.nintendo.net"):
		// The HOME Menu's Nintendo Switch Online button (Lhub) and its red-dot
		// feed (nso.go).
		s.nso(w, r, body)
	case strings.Contains(host, "frs.srv.nintendo.net"):
		s.frs(w, r, body)
	case strings.HasPrefix(host, "bcat-"):
		// BCAT and the News channel: msgpack, two routes (bcat.go).
		s.bcat(w, r, body)
	case strings.Contains(host, ".acbaa.srv.nintendo.net"):
		// Animal Crossing web API (acbaa.go): island registration. Before
		// this it fell into the catch-all 404 and ACNH errored (2219-xxxx)
		// before ever reaching NEX.
		s.acbaa(w, r, body)
	case strings.HasSuffix(host, ".dg.srv.nintendo.net"):
		// prepo's play reports (netdiag.go); eupld's error reports are routed above.
		s.telemetry(w, r, body)
	case strings.HasPrefix(host, "ctest") || strings.Contains(host, ".ctest.srv.nintendo.net"):
		// The Internet connection test in System Settings (netdiag.go).
		s.netdiag(w, r)
	case strings.Contains(host, "scsi.srv.nintendo.net"):
		s.olsc(w, r, body)
	case strings.Contains(host, "pctl.srv.nintendo.net") || strings.HasPrefix(host, "app.lp1.srv"):
		s.serviceStatus(w, r, body)
	// Answered by path rather than host, and only after every host-specific
	// handler above has declined: the NIM surfaces that had no handler
	// (eshop_unserved.go). It returns false when the path is not one of them.
	case s.nimUnserved(w, r, body):
	case !strings.Contains(host, "baas.nintendo.com"):
		dump(r, body, "!! UNHANDLED host (catch-all)")
		writeJSON(w, 404, map[string]any{})
	default:
		s.baas(w, r, body)
	}
}

// clientCertFor asks for a client certificate on the device-auth hosts only, where consoles do
// present one and it is the sole way to tell them apart. Everything else — the browser above
// all — is served without a CertificateRequest.
func clientCertFor(h *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error) {
	if !strings.HasPrefix(h.ServerName, "dauth") && !strings.HasPrefix(h.ServerName, "dcert") &&
		!strings.HasPrefix(h.ServerName, "aauth") {
		return nil, nil
	}
	c := base.Clone()
	c.ClientAuth = tls.RequestClientCert
	c.GetConfigForClient = nil
	return c, nil
}

func selfSigned(hosts []string, caDir string) tls.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := x509.Certificate{
		SerialNumber: func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)); return n }(), Subject: pkix.Name{CommonName: hosts[0], Organization: []string{"OpenPak"}},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: hosts,
	}
	if caPEM, err := os.ReadFile(caDir + "/ca.pem"); err == nil {
		if keyPEM, err := os.ReadFile(caDir + "/ca.key"); err == nil {
			if pair, err := tls.X509KeyPair(caPEM, keyPEM); err == nil {
				if ca, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
					if der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca, &key.PublicKey, pair.PrivateKey); err == nil {
						log.Printf("[nx-baas] server cert signed by the OpenPak CA")
						return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
					}
				}
			}
		}
	}
	log.Printf("[nx-baas] server cert self-signed (relies on disable_ca_verification)")
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newBackend selects the identity source: the historical OpenPak HTTP
// client (default, keeps the proven deployment running) or the OpenPak
// account core (ACCOUNT_BACKEND=openpak).
func newBackend() accountBackend {
	if os.Getenv("ACCOUNT_BACKEND") == "openpak" {
		b, err := newOpenpakBackend(context.Background(), getenv("NX_DATA", "/data"))
		if err != nil {
			log.Fatalf("[nx-baas] openpak backend: %v", err)
		}
		log.Printf("[nx-baas] identity backend: openpak account core (%s)", getenv("ACCOUNT_GRPC_ADDR", "127.0.0.1:7000"))
		return b
	}
	return &accountClient{
		base: strings.TrimRight(getenv("ACCOUNT_API", "http://account:8080"), "/"), adminKey: os.Getenv("OPENPAK_ADMIN_KEY"),
		secret: []byte(os.Getenv("OPENPAK_SECRET")), http: &http.Client{Timeout: 10 * time.Second},
	}
}

func main() {
	key := loadRSAKey(getenv("BAAS_SIGNING_KEY", "/keys/baas_signing_key.pem"))
	s := &server{
		store:   loadStore(getenv("NX_DATA", "/data") + "/baas.json"),
		key:     key,
		idKid:   getenv("BAAS_KID", "openpak-baas-key-1"),
		accKid:  getenv("BAAS_ACCESS_KID", "00000000-0000-0000-0000-000000000003"),
		naKid:   getenv("BAAS_NA_KID", "00000000-0000-0000-0000-000000000001"),
		codes:   map[string]naCode{},
		device:  map[string]string{},
		links:   newLinkStore(),
		guesses: newGuesses(),
		phones:  newPhoneStore(),
		acct:    newBackend(),
		shop:    newShopState(getenv("NX_DATA", "/data") + "/shop"),
	}
	s.acbaaPath = getenv("NX_DATA", "/data") + "/acbaa.json"
	s.acbaaLoad()
	if b, ok := s.acct.(*openpakBackend); ok {
		go s.followCoreEvents(b)
		// One presence reconciler beside the one core-event poller: leases,
		// heartbeats and expiries on the adapter's clock (PRE-02).
		go s.reconcilePresenceLoop()
	}
	// B workstream: the penne state file lives beside the BAAS store; the
	// sweeper drives delivery retries, expiry and retention (NTF-05).
	s.penneState = newPenneStore(getenv("NX_DATA", "/data") + "/penne.json")
	s.penneHub = newPenneHub()
	s.registerDefaultPennePolicies()
	// Integration wiring: C's committed-invitation seam delivers through B
	// (notify_wiring.go). Registered here so the REST surface keeps working
	// unchanged when the notification side is absent.
	s.wireInvitationNotifications()
	go s.penneSweep()
	// Console error reports: kept raw, forwarded to the website, retried (errorreport.go).
	go s.errorReports().run()
	if u := os.Getenv("SAVES_URL"); u != "" {
		s.saves, s.savesKey = newSavesProxy(u), os.Getenv("SAVES_INTERNAL_KEY")
		log.Printf("[nx-baas] save-data cloud: forwarding scsi hosts to %s", u)
	}
	if u := os.Getenv("NEWS_INTERNAL_URL"); u != "" {
		f, err := newNewsForwarder(u, os.Getenv("NEWS_INTERNAL_CA"), os.Getenv("NEWS_INTERNAL_SERVER_NAME"))
		if err != nil {
			log.Fatalf("[nx-baas] NEWS_INTERNAL_URL: %v", err)
		}
		s.news = f
		log.Printf("[nx-baas] news: forwarding openpak_* lists and title topics to %s", u)
	}
	s.jwks = jwksFor(&key.PublicKey, s.idKid, getenv("BAAS_ID_KID", "00000000-0000-0000-0000-000000000002"), s.accKid, s.naKid)
	cert := selfSigned([]string{baasHost, "m-lp1.baas.nintendo.com", "cdn-image-e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com",
		"accounts.nintendo.com", "api.accounts.nintendo.com", "cdn.accounts.nintendo.com",
		"god.hac.lp1.penne.srv.nintendo.net", "val.hac.penne.srv.nintendo.net", "val.hac.lp1.penne.srv.nintendo.net",
		"app.lp1.five.nintendo.net",
		"fro-3.hac.lp1.penne.srv.nintendo.net", "gw.hac.lp1.vermillion.srv.nintendo.net", "beach.hac.lp1.eshop.nintendo.net", "capi.lp1.op2.nintendo.net",
		// Store workstream: shop applet host, content host and the tigers eticket host.
		// dragons/dragonst are already above. The ashigaru page may reference further eshop
		// names (samurai/sun) — unrouted SNIs still get on-demand certs below.
		"bugyo.hac.lp1.eshop.nintendo.net", "atum.hac.lp1.d4c.nintendo.net", "tigers.hac.lp1.dragons.nintendo.net",
		// NIM names this one too; without it on the fixed cert the console
		// gets an on-demand cert for a host it may authenticate strictly.
		"pearljam.hac.lp1.eshop.nintendo.net",
		// Device auth: these must be on the fixed cert, not minted on demand — the console
		// rejects an on-demand cert on the names it authenticates against (2123-0013).
		"dauth-lp1.ndas.srv.nintendo.net", "dcert-lp1.ndas.srv.nintendo.net", "acert-lp1.ndas.srv.nintendo.net",
		"aauth-lp1.ndas.srv.nintendo.net", "aauth.hac.lp1.ndas.srv.nintendo.net",
		"dragons.hac.lp1.dragons.nintendo.net", "dragonst.hac.lp1.dragons.nintendo.net",
		// BCAT/News, prepo and the connection test (bcat.go, netdiag.go). The
		// ctest-dl/ctest-ul probes are plain HTTP and need no name here.
		"bcat-list-lp1.cdn.nintendo.net", "bcat-topics-lp1.cdn.nintendo.net",
		"api.hac.lp1.ctest.srv.nintendo.net", "fw-api.lp1.nso.nintendo.net",
		"receive-lp1.dg.srv.nintendo.net", "realtime-receive-lp1.dg.srv.nintendo.net",
		"receive.hac.lp1.er.srv.nintendo.net"}, getenv("NX_CA_DIR", "/data/ca"))
	var handler http.Handler = s
	if up := os.Getenv("NX_UPSTREAM"); up != "" {
		log.Printf("[nx-baas] CAPTURE MODE: forwarding everything to %s and logging bodies", up)
		handler = newCaptureProxy(up)
	}
	// ponytail: Traefik sends every unrouted *nintendo.* SNI here; sign a cert per name on
	// demand so the console gets past TLS and its request lands in the log as !! UNHANDLED.
	var onDemand sync.Map
	fixedNames := map[string]bool{}
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		for _, n := range leaf.DNSNames {
			fixedNames[n] = true
		}
	}
	getCert := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// The console rejects on-demand certs for the BAAS/NA names (2123-0013); those must
		// keep the fixed multi-SAN cert. On-demand is only for unrouted *.nintendo.* probes.
		if h.ServerName == "" || fixedNames[h.ServerName] {
			return &cert, nil
		}
		if c, ok := onDemand.Load(h.ServerName); ok {
			return c.(*tls.Certificate), nil
		}
		log.Printf("[nx-baas] on-demand cert for unrouted SNI %s", h.ServerName)
		c := selfSigned([]string{h.ServerName}, getenv("NX_CA_DIR", "/data/ca"))
		onDemand.Store(h.ServerName, &c)
		return &c, nil
	}
	// Ask for the console's client certificate but never require it: dauth uses it to tell
	// consoles apart, while every browser and emulator that talks to this service has none and
	// must still connect. RequestClientCert accepts whatever is offered without verifying it
	// against a CA we do not have.
	// The console's web applet is an old engine and offers only legacy TLS 1.2 suites, which
	// modern Go refuses by default: the handshake died immediately after the ClientHello, which
	// looked exactly like a certificate the browser did not trust. Offer everything Go can
	// still speak, including the suites it considers insecure, since this is a private network
	// talking to consoles that cannot be updated.
	suites := make([]uint16, 0, 32)
	for _, c := range tls.CipherSuites() {
		suites = append(suites, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		suites = append(suites, c.ID)
	}
	tlsConf := &tls.Config{
		GetCertificate: getCert,
		// Never ask the general listener for a client certificate. dauth wants one to tell
		// consoles apart, but the console's browser has none, and its TLS stack simply stops
		// when handed a CertificateRequest it cannot answer — the link page then hangs with no
		// error anywhere. The dauth hosts opt in below instead.
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS10,
		CipherSuites: suites,
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
		},
	}
	if os.Getenv("NX_DEBUG") != "" {
		// Diagnostic: every TLS handshake by SNI, so a connection that never speaks HTTP (the Penne
		// persistent frontline) is still visible in the log.
		tlsConf.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("[nx-baas] TLS hello sni=%s from=%s alpn=%v", h.ServerName, h.Conn.RemoteAddr(), h.SupportedProtos)
			return clientCertFor(h, tlsConf)
		}
	}
	if os.Getenv("NX_UPSTREAM") != "" {
		// ponytail: capture mode replicates the original capture, which used the fixed multi-SAN
		// cert. On-demand per-SNI certs disturbed the console's silent NA session and forced a
		// re-auth; the fixed cert keeps the session silent so both accounts refresh without prompting.
		tlsConf.GetCertificate = nil
		tlsConf.Certificates = []tls.Certificate{cert}
	}
	srv := &http.Server{
		Addr: getenv("NX_ADDR", ":443"), Handler: handler,
		TLSConfig: tlsConf,
	}
	// The game-facing API (Photon room presence, invitations) is plain HTTP on an internal
	// port -- consoles never reach it, only the Photon server, the emulator and rig tooling.
	go func() {
		addr := getenv("NX_API_ADDR", ":20070")
		if getenv("NX_INTERNAL_KEY", getenv("OPENPAK_INTERNAL_KEY", "")) == "" {
			log.Printf("[nx-baas] WARNING: game API on %s has no NX_INTERNAL_KEY; keep the port off any untrusted network", addr)
		}
		log.Printf("[nx-baas] game API listening %s (photon-room, invitations, mint-token)", addr)
		log.Fatal(http.ListenAndServe(addr, s.gameAPI()))
	}()
	log.Printf("[nx-baas] listening %s (BAAS + Nintendo Account); account backend %s; users=%d devices=%d", srv.Addr, getenv("ACCOUNT_BACKEND", "legacy"), len(s.store.Users), len(s.store.Devices))
	// The console's web applet enforces certificate checking unless Atmosphère patches it, so
	// the link page is also served over plain HTTP. Nothing secret crosses it: the console
	// shows a short-lived code, the password is typed on the phone against the public site,
	// and the link is approved on the console itself.
	if addr := getenv("NX_HTTP_ADDR", ""); addr != "" {
		go func() {
			log.Printf("[nx-baas] plain HTTP on %s (link page without TLS)", addr)
			if err := http.ListenAndServe(addr, handler); err != nil {
				log.Printf("[nx-baas] plain HTTP listener stopped: %v", err)
			}
		}()
	}

	if tlsConf.GetConfigForClient == nil {
		tlsConf.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			return clientCertFor(h, tlsConf)
		}
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// naProfile is the country and birthday the Nintendo Account object carries. A real Nintendo
// Account always has both, so unlike the BAAS user object there is no "absent" to serve and a
// fallback is unavoidable — but it must not be a captured stranger's when the account has its
// own. The two objects are read in the same link, and disagreeing about where someone lives is
// not something to leave to a constant.
func naProfile(id *Identity) (country, birthday string) {
	country, birthday = id.Country, id.Birthday
	if country == "" {
		country = getenv("NA_FALLBACK_COUNTRY", "GB")
		log.Printf("[nx-baas] users/me: account %s has no country of its own; serving %s", id.NaID, country)
	}
	if birthday == "" || birthday == "0000-00-00" {
		birthday = getenv("NA_FALLBACK_BIRTHDAY", "2000-01-01")
	}
	return country, birthday
}
