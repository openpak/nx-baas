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
	acct   *accountClient
	key    *rsa.PrivateKey
	idKid  string // kid of id_tokens (openpak-baas-key-1: what Photon/NPLN/S2 already trust)
	accKid string // kid of BAAS access tokens (/1.0.0/internal_certificates)
	naKid  string // kid of Nintendo-Account tokens: the console binds kid<->issuer and rejects a kid shared with BAAS (2124-3121)
	jwks   []byte
	mu     sync.Mutex
	codes  map[string]naCode // NA authorization codes / session tokens -> who logged in
	device map[string]string // device id -> serial, from the dauth assertion
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

func (s *server) idToken(u *User, id *Identity, username, di, sn string) string {
	now := time.Now().Unix()
	claims := map[string]any{
		"aud": baasAudience, "bs:did": randHex(8), "exp": now + 10800, "iat": now, "iss": baasIssuer, "jti": uuid4(),
		"nintendo": map[string]any{"di": di, "dt": "NX Prod 1", "ist": false, "pc": "HAC", "sn": sn},
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
	nx := u.NxAccount // the console uploads its own profile blob (PATCH /extras/self/nxAccount) after linking; a foreign blob makes it drop the profile to local-only
	if nx != "" {
		self["isMediaUploaded"] = true
		self["nxAccount"] = nx
	}
	friendsEx := map[string]any{"isChatActivated": true, "isChatInvitable": true, "playLog": ""}
	everyone := map[string]any{"playLog": ""}
	thumb1, thumb2, thumbAt := "", "", int64(0)
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
		id := s.identity(u)
		username := u.Nickname
		if id != nil {
			username = id.Nickname
		}
		s.store.Update(u, func(u *User) { u.Presence.State = "ONLINE"; u.Presence.UpdatedAt = time.Now().Unix() })
		res := map[string]any{
			"expiresIn": 10800, "user": s.userObj(u, id, ""), "idToken": s.idToken(u, id, username, di, sn),
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

	case strings.HasPrefix(p, "/1.0.0/push_channels/") || p == "/1.0.0/devices/me/delete":
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

const loginPage = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenPak Network</title><style>body{font-family:sans-serif;background:#111;color:#eee;display:flex;justify-content:center;padding:40px}
form{background:#222;padding:32px;border-radius:12px;width:360px}input{width:100%%;padding:12px;margin:8px 0 16px;font-size:18px;box-sizing:border-box}
button{width:100%%;padding:14px;font-size:18px;background:#e60012;color:#fff;border:0;border-radius:8px}.err{color:#f66}</style></head>
<body><form method="post"><h2>Link your OpenPak account</h2>%s<label>E-mail</label><input name="email" type="email" autofocus>
<label>Password</label><input name="password" type="password">%s<button>Sign in</button></form></body></html>`

func (s *server) na(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	form, _ := url.ParseQuery(string(body))
	switch {
	case p == "/1.0.0/certificates":
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.jwks)
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
				s.authorizePage(w, q, "<p class=err>Wrong e-mail or password.</p>")
				return
			}
			id, err := s.acct.Identity(pid)
			if err != nil {
				s.authorizePage(w, q, "<p class=err>Account lookup failed.</p>")
				return
			}
			code := randHex(16)
			s.mu.Lock()
			s.codes[code] = naCode{PID: pid, Username: username, ClientID: q.Get("client_id"), NaID: id.NaID}
			s.mu.Unlock()
			s.store.RememberNA(id.NaID, pid)
			// ponytail: the redirect shape is inferred from the response_type the console sends;
			// both the query (code) and fragment (session_token_code / id_token) forms are covered.
			rt := q.Get("response_type")
			dest := q.Get("redirect_uri")
			params := url.Values{"state": {q.Get("state")}}
			sep := "?"
			if strings.Contains(dest, "?") {
				sep = "&"
			}
			switch {
			case strings.Contains(rt, "session_token_code"):
				// What the console sends (Settings > Users > Link Nintendo Account); it wants the
				// code back as query parameters on its nintendo:// redirect, then trades it at
				// /connect/1.0.0/api/session_token (with the PKCE verifier) and /api/token.
				params.Set("session_token_code", code)
				dest += sep + params.Encode()
			case strings.Contains(rt, "id_token"):
				params.Set("id_token", s.naIDToken(s.codes[code], ""))
				if strings.Contains(rt, "code") {
					params.Set("code", code)
				}
				dest += "#" + params.Encode()
			default:
				params.Set("code", code)
				dest += sep + params.Encode()
			}
			log.Printf("[nx-baas] NA authorize ok pid=%d response_type=%q -> %s", pid, rt, dest)
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		dump(r, body, "NA authorize")
		s.authorizePage(w, q, "")
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

func (s *server) authorizePage(w http.ResponseWriter, q url.Values, msg string) {
	var hidden strings.Builder
	for k, v := range q {
		fmt.Fprintf(&hidden, `<input type="hidden" name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(v[0]))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, loginPage, msg, hidden.String())
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
	case strings.Contains(host, "accounts.nintendo.com"):
		s.na(w, r, body)
	case strings.Contains(host, "penne.") || strings.Contains(host, "vermillion.") || strings.HasPrefix(host, "beach."):
		s.penne(w, r, body)
	case !strings.Contains(host, "baas.nintendo.com"):
		dump(r, body, "!! UNHANDLED host (catch-all)")
		writeJSON(w, 404, map[string]any{})
	default:
		s.baas(w, r, body)
	}
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
		acct: &accountClient{
			base: strings.TrimRight(getenv("ACCOUNT_API", "http://account:8080"), "/"), adminKey: os.Getenv("OPENPAK_ADMIN_KEY"),
			secret: []byte(os.Getenv("OPENPAK_SECRET")), http: &http.Client{Timeout: 10 * time.Second},
		},
	}
	s.jwks = jwksFor(&key.PublicKey, s.idKid, getenv("BAAS_ID_KID", "00000000-0000-0000-0000-000000000002"), s.accKid, s.naKid)
	cert := selfSigned([]string{baasHost, "m-lp1.baas.nintendo.com", "cdn-image-e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com",
		"accounts.nintendo.com", "api.accounts.nintendo.com", "cdn.accounts.nintendo.com",
		"god.hac.lp1.penne.srv.nintendo.net", "val.hac.penne.srv.nintendo.net", "val.hac.lp1.penne.srv.nintendo.net",
		"fro-3.hac.lp1.penne.srv.nintendo.net", "gw.hac.lp1.vermillion.srv.nintendo.net", "beach.hac.lp1.eshop.nintendo.net"}, getenv("NX_CA_DIR", "/data/ca"))
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
	tlsConf := &tls.Config{GetCertificate: getCert, ClientAuth: tls.NoClientCert, MinVersion: tls.VersionTLS12}
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
	log.Printf("[nx-baas] listening %s (BAAS + Nintendo Account); account api %s; users=%d devices=%d", srv.Addr, s.acct.base, len(s.store.Users), len(s.store.Devices))
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
