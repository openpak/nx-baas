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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
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

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type server struct {
	store  *Store
	acct   accountBackend
	key    *rsa.PrivateKey
	idKid  string // kid of id_tokens (openpak-baas-key-1: what Photon/NPLN/S2 already trust)
	accKid string // kid of BAAS access tokens (/1.0.0/internal_certificates)
	naKid  string // kid of Nintendo-Account tokens: the console binds kid<->issuer and rejects a kid shared with BAAS (2124-3121)
	jwks   []byte
	mu     sync.Mutex
	codes  map[string]naCode // NA authorization codes / session tokens -> who logged in
	device map[string]string // device id -> serial, from the dauth assertion
	links  *linkStore        // pending QR console links, by code
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
		claims["nintendo"] = map[string]any{"di": di, "dt": "NX Prod 1", "ist": false, "pc": "HAC", "sn": sn, "x5t#S256": "lkYHqHf2uXjNZ2UeDnW83GT_wa3-dH1KtPLVgxao3Rs"}
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

func extras() map[string]any {
	return map[string]any{"self": map[string]any{}, "favoriteFriends": map[string]any{}, "friends": map[string]any{}, "foaf": map[string]any{}, "everyone": map[string]any{}}
}

func presenceObj(p Presence) map[string]any {
	ex := extras()
	if p.AppID != "" {
		ex["friends"] = map[string]any{"appField": p.AppField, "appInfo:appId": p.AppID, "appInfo:presenceGroupId": p.PresenceGroupID}
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
	nx := u.NxAccount
	if nx == "" && id != nil {
		// Restore User needs a profile blob to import; the console accepts this constant
		// (proven 2026-09-07, identical across every VPS account) and then PATCHes its own.
		nx = os.Getenv("NX_DEFAULT_NXACCOUNT")
	}
	if nx != "" {
		self["isMediaUploaded"] = true
		self["nxAccount"] = nx
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
			links["friendCode"] = map[string]any{"id": friendCodeID(id.FriendCode), "createdAt": u.CreatedAt, "updatedAt": u.CreatedAt, "regenerableAt": u.CreatedAt + 30*86400, "regenerable": true}
			if pl, ok := id.PlayLog.(string); ok && pl != "" && pl != "null" {
				friendsEx["playLog"], everyone["playLog"] = pl, pl
			}
			if id.Avatar != "" {
				thumbAt = id.ImageUpdatedAt
				thumb1, thumb2 = cdnHost+"/1/"+u.ID, cdnHost+"/2/"+u.ID
			}
		}
	}
	return map[string]any{
		"birthday": u.Birthday, "blocksUpdatedAt": u.CreatedAt, "country": country, "createdAt": u.CreatedAt, "deleted": false,
		"deviceAccounts": devs, "etag": fmt.Sprintf("\"%s\"", etag),
		"extras":           map[string]any{"everyone": everyone, "favoriteFriends": map[string]any{"playLog": ""}, "foaf": map[string]any{"playLog": ""}, "friends": friendsEx, "self": self},
		"friendsUpdatedAt": u.UpdatedAt, "id": u.ID, "links": links, "nickname": nickname, "nicknameUpdatedAt": u.UpdatedAt,
		"permissions": map[string]any{
			"friendRequestReception": true, "friends": "EVERYONE", "personalAnalytics": true, "personalAnalyticsUpdatedAt": u.CreatedAt,
			"personalNotification": true, "personalNotificationUpdatedAt": u.CreatedAt, "presence": "FRIENDS", "presenceUpdatedAt": u.CreatedAt,
		},
		"thumbnail2Url": thumb2, "thumbnailUploadedAt": thumbAt, "thumbnailUrl": thumb1, "updatedAt": u.UpdatedAt,
	}
}

// friendObj: a friend as seen from another user. The other console's live presence (if it is
// logged in here) beats the account server's coarse status.
func (s *server) friendObj(f Friend, now int64) map[string]any {
	p := Presence{State: "OFFLINE", UpdatedAt: now}
	if fu := s.store.UserByPID(f.PID); fu != nil {
		p = fu.Presence
	} else if f.PresenceStatus > 0 {
		p = Presence{State: "ONLINE", AppField: f.PresenceAppField, AppID: f.PresenceAppID, PresenceGroupID: f.PresenceAppID, UpdatedAt: now}
		if f.PresenceStatus == 2 {
			p.State = "PLAYING"
		}
	}
	return map[string]any{
		"id": f.BaasUserID, "nickname": f.Nickname, "country": "", "thumbnailUrl": avatarURL(f.PID, f.Avatar, f.CreatedAt), "thumbnail2Url": avatarURL(f.PID, f.Avatar, f.CreatedAt),
		"links":  map[string]any{"friendCode": map[string]any{"id": friendCodeID(f.FriendCode), "createdAt": f.CreatedAt, "updatedAt": f.CreatedAt}},
		"extras": extras(), "presence": presenceObj(p), "isFavoriteFriend": false, "isNewFriend": false,
		"createdAt": f.CreatedAt, "updatedAt": now,
	}
}

// ---------- BAAS handlers ----------

func (s *server) baas(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	form, _ := url.ParseQuery(string(body))
	seg := strings.Split(strings.Trim(p, "/"), "/")

	switch {
	case strings.HasPrefix(p, "/1/") || strings.HasPrefix(p, "/2/") || strings.HasPrefix(p, "/avatar/"):
		var pid uint64
		if strings.HasPrefix(p, "/1/default") || strings.HasPrefix(p, "/2/default") {
			if img, err := os.ReadFile(getenv("NX_DATA", "/data") + "/default.jpg"); err == nil {
				w.Header().Set("Content-Type", "image/jpeg")
				w.Header().Set("Cache-Control", "public, max-age=3600")
				w.Write(img)
				return
			}
			w.WriteHeader(404)
			return
		}
		if strings.HasPrefix(p, "/avatar/") {
			pid, _ = strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(p, "/avatar/"), ".jpg"), 10, 64)
		} else if u := s.store.User(p[3:]); u != nil {
			pid = u.PID
		}
		id, err := s.acct.Identity(pid)
		if err != nil || id.Avatar == "" {
			w.WriteHeader(404)
			return
		}
		img, err := base64.StdEncoding.DecodeString(id.Avatar)
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
				log.Printf("[nx-baas] federation failed: %v", err)
				baasErr(w, r, 400, "invalid_idp_account", "Invalid IdP Account", "IdP account is invalid")
				return
			}
		}
		app, _ := parseJWT(form.Get("appAuthNToken"), nil)
		id := s.identity(u)
		username := u.Nickname
		if id != nil {
			username = id.Nickname
		}
		s.store.Update(u, func(u *User) { u.Presence.State = "ONLINE"; u.Presence.UpdatedAt = time.Now().Unix() })
		res := map[string]any{
			"expiresIn": 10800, "user": s.userObj(u, id, ""), "idToken": s.idToken(u, id, username, app),
			"accessToken": s.accessToken(u.ID, 2, func() string {
				if id != nil {
					return id.BsDid
				}
				return randHex(8)
			}(), di, sn), "tokenType": "Bearer",
		}
		if form.Get("appAuthNToken") != "" {
			res["summary"] = map[string]any{"nintendo": map[string]any{"hasMembership": true}}
		}
		log.Printf("[nx-baas] %s user=%s pid=%d ua=%s", seg[1], u.ID, u.PID, r.UserAgent())
		writeJSON(w, 200, res)
		return

	case len(seg) == 3 && seg[0] == "1.0.0" && seg[1] == "users":
		u := s.store.User(seg[2])
		if u == nil {
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
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
			// Friend codes belong to the OpenPak account; there is nothing to regenerate.
			writeJSON(w, 200, s.userObj(u, s.identity(u), ""))
		case "blocks":
			writeJSON(w, 200, map[string]any{"count": 0, "blocks": []any{}}) // ponytail: no block list
		case "friends", "friend_requests", "relationships":
			s.friends(w, r, u, seg[3:], body)
		default:
			dump(r, body, "!! UNHANDLED user sub-resource")
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
		}
		return

	case len(seg) == 5 && seg[0] == "1.0.0" && seg[1] == "users" && seg[3] == "device_accounts":
		u := s.store.User(seg[2])
		if u == nil {
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		switch r.Method {
		case "DELETE":
			w.WriteHeader(204)
		case "PATCH": // presence (friends sysmodule), JSON patch
			var ops []struct {
				Op, Path string
				Value    any
			}
			json.Unmarshal(body, &ops)
			s.store.Update(u, func(u *User) {
				for _, o := range ops {
					v, _ := o.Value.(string)
					switch o.Path {
					case "/presence/state":
						u.Presence.State = v
					case "/presence/extras/friends/appField":
						u.Presence.AppField = v
					case "/presence/extras/friends/appInfo:appId":
						u.Presence.AppID = v
					case "/presence/extras/friends/appInfo:presenceGroupId":
						u.Presence.PresenceGroupID = v
					}
				}
				u.Presence.UpdatedAt = time.Now().Unix()
				if u.Presence.State == "OFFLINE" {
					u.Presence.LogoutAt = u.Presence.UpdatedAt
				}
			})
			log.Printf("[nx-baas] presence user=%s pid=%d %s app=%s field=%q", u.ID, u.PID, u.Presence.State, u.Presence.AppID, u.Presence.AppField)
			writeJSON(w, 200, s.userObj(u, s.identity(u), ""))
		default:
			dump(r, body, "!! UNHANDLED device_accounts")
			baasErr(w, r, 405, "method_not_allowed", "Method Not Allowed", "Method Not Allowed")
		}
		return

	case len(seg) >= 3 && seg[0] == "2.0.0":
		s.friends2(w, r, seg[1:], body)
		return

	case p == "/1.0.0/users" && r.Method == "GET":
		// Friend-code / id lookup from the friends sysmodule. ponytail: query keys guessed
		// (friendCode / id); the catch-all dump tells us the real ones.
		q := r.URL.Query()
		var f *Friend
		var err error
		if c := q.Get("friendCode"); c != "" {
			f, err = s.acct.Resolve(url.Values{"code": {c}})
		} else if id := q.Get("id"); id != "" {
			f, err = s.acct.Resolve(url.Values{"baas": {id}})
		}
		if err != nil || f == nil {
			writeJSON(w, 200, map[string]any{"count": 0, "users": []any{}})
			return
		}
		writeJSON(w, 200, map[string]any{"count": 1, "users": []any{s.friendObj(*f, time.Now().Unix())}})
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
		writeJSON(w, 200, map[string]any{
			"createdAt": now, "deviceAccountId": devID, "deviceAttributes": map[string]any{}, "deviceToken": str(in, "deviceToken"),
			"service": str(in, "service"), "updatedAt": now, "userAttributes": map[string]any{}, "userId": userID,
		})
		return
	case p == "/1.0.0/devices/me/delete":
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

// /2.0.0/... friends API (friends sysmodule).
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
	me := func() (*User, *Identity) {
		if len(seg) >= 2 && seg[0] == "users" {
			u := s.store.User(seg[1])
			return u, s.identity(u)
		}
		if c := s.bearer(r); c != nil {
			u := s.store.User(str(c, "sub"))
			return u, s.identity(u)
		}
		return nil, nil
	}

	switch {
	case len(seg) == 3 && seg[0] == "users" && seg[2] == "friends" && r.Method == "GET":
		_, id := me()
		list := []any{}
		if id != nil {
			for _, f := range id.Friends {
				list = append(list, s.friendObj(f, now))
			}
		}
		// ponytail: {count, friends} envelope is a guess; a bare array is the alternative.
		writeJSON(w, 200, map[string]any{"count": len(list), "friends": list})
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "friends" && r.Method == "DELETE":
		dump(r, body, "friend-delete (not applied)")
		w.WriteHeader(204)
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "friend_requests":
		_, id := me()
		list := []any{}
		if id != nil {
			src := id.FriendRequests
			if seg[3] == "outbox" {
				src = id.SentRequests
			}
			for _, f := range src {
				o := s.friendObj(f, now)
				list = append(list, map[string]any{"id": f.BaasUserID, "sender": o, "receiver": o, "state": "PENDING", "createdAt": f.CreatedAt, "updatedAt": now})
			}
		}
		writeJSON(w, 200, map[string]any{"count": len(list), "friendRequests": list})
		return

	case len(seg) == 1 && seg[0] == "friend_requests" && r.Method == "POST":
		u, id := me()
		if id == nil {
			baasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "not linked")
			return
		}
		var target *Friend
		var err error
		if c := field("friendCode"); c != "" {
			target, err = s.acct.Resolve(url.Values{"code": {c}})
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
		logErr("friend-request", s.acct.FriendRequest(u.PID, target.PID))
		o := s.friendObj(*target, now)
		writeJSON(w, 201, map[string]any{"id": target.BaasUserID, "sender": s.userObj(u, id, ""), "receiver": o, "state": "PENDING", "createdAt": now, "updatedAt": now})
		return

	case len(seg) == 2 && seg[0] == "friend_requests" && (r.Method == "PATCH" || r.Method == "DELETE"):
		u, id := me()
		if id == nil {
			baasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "not linked")
			return
		}
		from, err := s.acct.Resolve(url.Values{"baas": {seg[1]}})
		if err != nil {
			baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		accept := r.Method == "PATCH" && !strings.Contains(strings.ToUpper(string(body)), "REJECT")
		logErr("friend-accept", s.acct.FriendAccept(u.PID, from.PID, accept))
		writeJSON(w, 200, map[string]any{"id": seg[1], "state": map[bool]string{true: "ACCEPTED", false: "REJECTED"}[accept], "updatedAt": now})
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "relationships":
		_, id := me()
		rel := "NONE"
		if id != nil {
			for _, f := range id.Friends {
				if f.BaasUserID == seg[3] {
					rel = "FRIEND"
				}
			}
		}
		writeJSON(w, 200, map[string]any{"id": seg[3], "relationship": rel})
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
					}
				}
			}
		}
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "unknown code"})
			return
		}
		if p == "/connect/1.0.0/api/session_token" {
			writeJSON(w, 200, map[string]any{"session_token": code, "code": code})
			return
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
		me := map[string]any{
			"agreedTerms": map[string]any{
				"EULA":          map[string]any{"agreedAt": int64(1524557701), "country": "GB", "version": 2},
				"privacyPolicy": map[string]any{"agreedAt": int64(1524557701), "country": "GB", "version": 2},
			},
			"analyticsOptedIn": false, "analyticsOptedInUpdatedAt": int64(1524557701),
			"analyticsPermissions": map[string]any{"dataCollection": perm(false), "internalAnalysis": perm(true), "targetMarketing": perm(false)},
			"birthday":             "2000-01-01", "clientFriendsOptedIn": true, "clientFriendsOptedInUpdatedAt": int64(1524557701),
			"country": "GB", "createdAt": int64(1524557701),
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
// controller is miserable, so the QR path leads: a code and an image to scan, the page polls
// for a phone to claim it, and the person at the console approves. The password form is still
// there, one fold down, for anyone without a phone to hand.
func (s *server) authorizePage(w http.ResponseWriter, r *http.Request, q url.Values, msg string) {
	var hidden strings.Builder
	for k, v := range q {
		fmt.Fprintf(&hidden, `<input type="hidden" name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(v[0]))
	}
	code := s.links.new(q)
	linkURL := s.linkBaseURL(r) + "/link?c=" + code
	var e string
	if msg != "" {
		e = msg
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHead("Link this console")+`
<h1>Link this console</h1>
<p>Scan the code with your phone, sign in there, then approve it here.</p>
<div class="card"><div class="split">
  <div class="qr"><img src="`+qrDataURI(linkURL)+`" alt="QR code"></div>
  <div>
    <ol class="steps">
      <li>Scan the square with your phone&rsquo;s camera.</li>
      <li>Sign in to OpenPak on the phone.</li>
      <li>Check this code matches, then approve below.</li>
    </ol>
    <p style="margin:16px 0 0"><span class="code">`+code+`</span></p>
    <p style="margin:10px 0 0;font-size:0.9rem">or open <strong>`+html.EscapeString(strings.TrimPrefix(s.linkBaseURL(r), "http://"))+`/link</strong> on your phone</p>
    <p id="status" style="margin:14px 0 0">Waiting for your phone&hellip;</p>
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
  var code = ` + "\"" + code + "\"" + `, status = document.getElementById("status"),
      confirm = document.getElementById("confirm"), done = false;
  function poll() {
    if (done) return;
    var x = new XMLHttpRequest();
    x.open("GET", "/connect/1.0.0/qr/state?c=" + code, true);
    x.onreadystatechange = function () {
      if (x.readyState !== 4) return;
      var d = {};
      try { d = JSON.parse(x.responseText); } catch (e) { return; }
      if (d.state === "claimed") {
        status.innerHTML = "Signed in on your phone as <strong>" + d.account + "</strong>. Approve to finish.";
        confirm.hidden = false;
      } else if (d.state === "expired") {
        status.textContent = "This code expired. Reload the page for a new one.";
        done = true;
      }
    };
    x.send();
  }
  setInterval(poll, ` + pollEvery + `);
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

var debug = os.Getenv("NX_DEBUG") != ""
var minimal = os.Getenv("NX_MINIMAL") != "" // bisecting 2124-0292: only the NA link on top of the POST /users shape

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	host := hostOf(r)
	log.Printf("[nx-baas] %s %s%s ua=%q", r.Method, host, r.URL.RequestURI(), r.UserAgent())
	if debug && !strings.HasPrefix(r.URL.Path, "/avatar/") {
		dump(r, passwordRe.ReplaceAll(body, []byte("password=***")), "DBG >>>")
		rec := &recorder{ResponseWriter: w, status: 200}
		w = rec
		defer func() {
			log.Printf("[nx-baas] DBG <<< %d %s %s%s body(%d)=%s", rec.status, r.Method, host, r.URL.Path, rec.buf.Len(), rec.buf.Bytes())
		}()
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/connect/1.0.0/qr/") || r.URL.Path == "/link":
		if !s.qrRoutes(w, r, body) {
			http.NotFound(w, r)
		}
	case strings.Contains(host, "accounts.nintendo.com"):
		s.na(w, r, body)
	case strings.HasPrefix(host, "dauth") || strings.HasPrefix(host, "dcert") || strings.HasPrefix(host, "aauth"):
		s.dauth(w, r, body)
	case strings.Contains(host, "penne.") || strings.Contains(host, "vermillion.") || strings.HasPrefix(host, "beach."):
		s.penne(w, r, body)
	case strings.HasPrefix(host, "capi.") && strings.HasSuffix(r.URL.Path, "/memberships"):
		// NSO membership check (VPS parity): every account has an active "default" membership.
		seg := strings.Split(r.URL.Path, "/")
		naID := seg[len(seg)-2]
		writeJSON(w, 200, map[string]any{"count": 2, "items": []any{
			map[string]any{"context": "ex", "membership": map[string]any{"active": false}, "user_id": naID},
			map[string]any{"context": "default", "membership": map[string]any{"active": true, "expires_at": time.Now().Unix() + 365*86400}, "user_id": naID},
		}, "total": 2})
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
		store:  loadStore(getenv("NX_DATA", "/data") + "/baas.json"),
		key:    key,
		idKid:  getenv("BAAS_KID", "openpak-baas-key-1"),
		accKid: getenv("BAAS_ACCESS_KID", "00000000-0000-0000-0000-000000000003"),
		naKid:  getenv("BAAS_NA_KID", "00000000-0000-0000-0000-000000000001"),
		codes:  map[string]naCode{},
		device: map[string]string{},
		links:  newLinkStore(),
		acct:   newBackend(),
	}
	s.jwks = jwksFor(&key.PublicKey, s.idKid, getenv("BAAS_ID_KID", "00000000-0000-0000-0000-000000000002"), s.accKid, s.naKid)
	cert := selfSigned([]string{baasHost, "m-lp1.baas.nintendo.com", "cdn-image-e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com",
		"accounts.nintendo.com", "api.accounts.nintendo.com", "cdn.accounts.nintendo.com",
		"god.hac.lp1.penne.srv.nintendo.net", "val.hac.penne.srv.nintendo.net", "val.hac.lp1.penne.srv.nintendo.net",
		"fro-3.hac.lp1.penne.srv.nintendo.net", "gw.hac.lp1.vermillion.srv.nintendo.net", "beach.hac.lp1.eshop.nintendo.net", "capi.lp1.op2.nintendo.net"}, getenv("NX_CA_DIR", "/data/ca"))
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
		ClientAuth: tls.NoClientCert,
		MinVersion: tls.VersionTLS10,
		CipherSuites:   suites,
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
