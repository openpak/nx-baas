package main

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"nx-baas/internal/bans"
	"nx-baas/internal/core"
	"nx-baas/internal/dauth"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/presence"
	"nx-baas/internal/store"
	"nx-baas/internal/token"
	"nx-baas/redact"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed assets/default.jpg
var defaultAvatar []byte

// accessToken/idToken: claim for claim what a real console accepted from the VPS
// (capture 2026-09-06, /1.0.0/login). Anonymous (grant 1) tokens carry the device block;
// user tokens (grant 2) do not.
func (s *server) accessToken(sub string, grant int, bsDid, di, sn string) string {
	now := time.Now().Unix()
	claims := map[string]any{
		"aud": core.BaasAudience, "bs:did": bsDid, "bs:grt": grant, "exp": now + 10800, "iat": now,
		"iss": core.BaasIssuer, "jti": token.UUID4(), "sub": sub, "typ": "token",
	}
	if grant == 1 {
		claims["bs:pid"] = "pz" + token.RandHex(15)
		claims["bs:sts"] = []int64{1188950301625811329}
		claims["nintendo"] = map[string]any{"di": di, "dt": "NX Prod 1", "ist": false, "pc": "HAC", "sn": sn, "x5t#S256": dauth.DeviceThumbprint}
	} else {
		claims["bs:sts"] = []int64{10415858080830506, 272640, 9, 0, 0, 19316357715722240, 16}
	}
	return token.SignJWT(map[string]any{"alg": "RS256", "jku": core.BaasJku + "/1.0.0/internal_certificates", "kid": s.AccKid, "typ": "JWT"}, claims, s.Key)
}

func (s *server) idToken(u *store.User, id *identity.Identity, username string, app map[string]any) string {
	now := time.Now().Unix()
	// VPS parity: the id_token carries an APPLICATION block (ai/at/av/edi/tbh/tbn), taken from
	// the appAuthNToken when the console sends one, else the VPS defaults.
	ai, av := "0100f8f0000a2000", "0033"
	if n, ok := app["nintendo"].(map[string]any); ok {
		if v := httpx.Str(n, "ai"); v != "" {
			ai = v
		}
		if v := httpx.Str(n, "av"); v != "" {
			av = v
		}
	}
	claims := map[string]any{
		"aud": core.BaasAudience, "bs:did": u.ID, "exp": now + 10800, "iat": now, "iss": core.BaasIssuer, "jti": token.UUID4(),
		"nintendo": map[string]any{"ai": ai, "at": now, "av": av, "edi": token.RandB64(60), "tbh": token.RandB64(32), "tbn": token.RandB64(16)},
		"sub":      u.ID, "typ": "id_token",
	}
	if id != nil {
		claims["bs:did"] = id.BsDid
		if t := s.Acct.NexToken(id.PID, username); t != "" {
			claims["openpak"] = t
		}
	}
	return token.SignJWT(map[string]any{"alg": "RS256", "jku": core.BaasJku + "/1.0.0/certificates", "kid": s.IDKid, "typ": "JWT"}, claims, s.Key)
}

func (s *server) identity(u *store.User) *identity.Identity {
	if u == nil || u.PID == 0 {
		return nil
	}
	id, err := s.Acct.Identity(u.PID)
	identity.LogErr("identity", err)
	// Remember the account's bs:did: it is what a console's id_token carries and what the
	// Photon server reports back on /internal/photon-room, which has no PID of its own.
	if id != nil && id.BsDid != "" && u.BsDid != id.BsDid {
		s.Store.Update(u, func(u *store.User) { u.BsDid = id.BsDid })
	}
	return id
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

func presenceObj(p store.Presence) map[string]any {
	ex := extras()
	if p.AppID == "" && p.AppField != "" && p.AppField != "{}" {
		// No title, but words: a friend on another platform (presenceFromCore).
		// Never a foreign title id in appInfo; the description carries it.
		ex["friends"] = map[string]any{"appField": p.AppField}
	}
	if p.AppID != "" {
		friends := map[string]any{"appField": presence.AppFieldOrEmpty(p.AppField), "appInfo:appId": p.AppID, "appInfo:presenceGroupId": p.PresenceGroupID}
		if p.ACDIndex >= 0 {
			// Read back by the friend list's numeric parser
			// [firmware, $.items[*].friend.presence.extras.friends.appInfo:acdIndex].
			friends["appInfo:acdIndex"] = p.ACDIndex
		}
		ex["friends"] = friends
	}
	out := map[string]any{"state": p.State, "extras": ex, "updatedAt": p.UpdatedAt, "logoutAt": p.LogoutAt}
	if pf, ok := presence.ProbePF(p.Client); ok {
		out["pf"] = pf
	}
	return out
}

func (s *server) userObj(u *store.User, id *identity.Identity, devicePassword string) map[string]any {
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
	thumb1, thumb2, thumbAt := core.CdnHost+"/1/default", core.CdnHost+"/2/default", int64(0) // VPS parity for unlinked users
	etag := token.RandHex(8)
	if id != nil {
		etag = id.BsDid // VPS parity: user.etag == the token bs:did for a linked user
		nickname = id.Nickname
		if u.NxAccount != "" && u.Nickname != "" {
			// Once the console has PATCHed its profile (/nickname and
			// /extras/self/nxAccount always travel together) its nickname is
			// the one served back: the PATCH reply must repeat what was sent
			// or the sysmodule fails it with 2124-3121 (23.0.1 0xe8a5c), and
			// every later sync compares this field with the local profile.
			nickname = u.Nickname
		}
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
				thumb1, thumb2 = core.CdnHost+"/1/"+u.ID, core.CdnHost+"/2/"+u.ID
			} else if u.Avatar != "" {
				// The console's own upload. Without this the reply to an
				// upload still points at /1/default with an uploaded-at of
				// zero, which is the service telling the console that the
				// picture it just sent does not exist.
				thumbAt = u.UpdatedAt
				thumb1, thumb2 = core.CdnHost+"/1/"+u.ID, core.CdnHost+"/2/"+u.ID
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
		country = httpx.Getenv("NA_FALLBACK_COUNTRY", "GB")
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
func (s *server) friendObj(f identity.Friend, now int64) map[string]any {
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
	local := s.Store.User(f.BaasUserID)
	if local != nil {
		if local.Country != "" {
			country = local.Country
		}
		if local.UpdatedAt > updatedAt {
			updatedAt = local.UpdatedAt
		}
		// One, as a real search result carries. Eleven of them is this
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
	if f.PictureAt > 0 && !picKnown {
		picAt, picKnown = f.PictureAt, true // versioned, so a console drops the default it cached
	}
	thumbURL, thumb2URL := core.CdnHost+"/1/"+f.BaasUserID, core.CdnHost+"/2/"+f.BaasUserID
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
		// Exactly the groups a real reply carries about somebody else:
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
	group, pl := s.visiblePlayLog(nil, s.Store.User(f.BaasUserID), false)
	setPlayLog(obj, group, pl)
	return obj
}

// searchUserObj is a user, not a friend. The friend-list keys — friendId,
// presence, the viewer's own extras — belong to the relationship renderer,
// and a stranger you have just looked up is not one. The console refused a
// search result that carried them, the same way it refused a login reply
// that carried an extra "summary"; the exact-match test
// TestSearchReplyMatchesTheAcceptedShape keeps it that way.
func (s *server) searchUserObj(f identity.Friend, now int64) map[string]any {
	return s.friendObj(f, now)
}

// reportOnline tells the core that this account is signed in, which is a
// different claim from playing something and is counted separately. Only the
// OpenPak backend has a core to tell; the OpenPak one keeps presence to
// itself, so this is a type assertion rather than another interface method
// that one of the two would have to no-op.
//
// client is what the request said it came from (X-OpenPak-Client). When it
// said nothing, the client of the account's live claim is used, so a real
// console's title-less session says "switch" once Penne has told us so.
// clientOS travels with client and is taken from the same claim when client is.
func (s *server) reportOnline(ctx context.Context, u *store.User, client, clientOS string) {
	if u == nil || u.PID == 0 {
		return
	}
	if client == "" {
		agg := presence.Aggregate(u, time.Now().Unix(), presence.Lease())
		client, clientOS = agg.Client, agg.OS
	}
	if b, ok := s.Acct.(*identity.OpenpakBackend); ok {
		b.Online(ctx, u.PID, client, clientOS)
	}
}

// reportOffline ends the session immediately when someone says they are going,
// rather than leaving them online until the lease runs out.
func (s *server) reportOffline(ctx context.Context, u *store.User) {
	if u == nil || u.PID == 0 {
		return
	}
	if b, ok := s.Acct.(*identity.OpenpakBackend); ok {
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
		if c := s.ValidBearer(r); c != nil {
			if lock := s.locks().UserLock(s.Store.User(httpx.Str(c, "sub"))); lock != "" {
				bans.BaasLocked(w, r, lock)
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
			img, err := os.ReadFile(httpx.Getenv("NX_DATA", "/data") + "/default.jpg")
			if err != nil {
				img = defaultAvatar
			}
			writeAvatarJPEG(w, r, img, "public, max-age=3600")
			return
		}
		if strings.HasPrefix(p, "/avatar/") {
			pid, _ = strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(p, "/avatar/"), ".jpg"), 10, 64)
		} else if u := s.Store.User(p[3:]); u != nil {
			pid = u.PID
		} else if f := s.resolveFriend(p[3:]); f != nil {
			pid = f.PID // an account that has never been on a console
		}
		id, err := s.Acct.Identity(pid)
		avatar := ""
		if err == nil {
			avatar = id.Avatar
		}
		if avatar == "" && !strings.HasPrefix(p, "/avatar/") {
			// What the console uploaded -- but only while it is the newer of
			// the two. Serving it unconditionally meant a picture changed on
			// the website could never reach a console that had ever set one
			// of its own.
			if u := s.Store.User(p[3:]); u != nil {
				if err != nil || id.ImageUpdatedAt <= newerPicture(u, nil) {
					avatar = u.Avatar
				}
			}
		}
		if avatar == "" && err == nil && id.AvatarURL != "" {
			// Fetched here and nowhere else: a login must not wait on the
			// website, but a console asking for a thumbnail can.
			if img, ferr := fetchAvatar(id.AvatarURL); ferr == nil {
				writeAvatarJPEG(w, r, img, "public, max-age=300")
				return
			} else {
				log.Printf("[nx-baas] avatar fetch %s: %v", redact.Link(id.AvatarURL), redact.Err(ferr))
			}
		}
		if avatar == "" {
			if strings.HasPrefix(p, "/1/") || strings.HasPrefix(p, "/2/") {
				// The URL came out of a reply this server wrote, so a 404 here
				// is our own left hand failing our own right: the console shows
				// a friend with a broken picture. The default avatar is what an
				// account without a picture means (SOC-01: a reachable avatar).
				img, derr := os.ReadFile(httpx.Getenv("NX_DATA", "/data") + "/default.jpg")
				if derr != nil {
					img = defaultAvatar
				}
				writeAvatarJPEG(w, r, img, "public, max-age=300")
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
		writeAvatarJPEG(w, r, img, "public, max-age=3600")
		return

	case p == "/1.0.0/certificates" || p == "/1.0.0/internal_certificates":
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.JWKS)
		return

	case p == "/1.0.0/application/token" && r.Method == "POST":
		// The assertion is nx-dauth's device token; we trust it as-is (dauth already gated).
		claims, _ := token.ParseJWT(form.Get("assertion"), nil)
		di := httpx.Str(claims, "sub")
		sn := ""
		if n, ok := claims["nintendo"].(map[string]any); ok {
			sn = httpx.Str(n, "sn")
		}
		if di == "" {
			httpx.BaasErr(w, r, 400, "invalid_params", "Invalid Params", "assertion is not a device token")
			return
		}
		s.mu.Lock()
		s.device[di] = sn
		s.mu.Unlock()
		httpx.WriteJSON(w, 200, map[string]any{"accessToken": s.accessToken(di, 1, token.RandHex(8), di, sn), "tokenType": "Bearer", "expiresIn": 10800})
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
		tok := s.ValidBearer(r)
		if uid := httpx.Str(tok, "sub"); uid != "" && img.RawContent != "" {
			if raw, err := base64.StdEncoding.DecodeString(img.RawContent); err != nil {
				log.Printf("[nx-baas] image_upload: not base64 (%d bytes): %v", len(img.RawContent), redact.Err(err))
			} else if u := s.Store.User(uid); u != nil {
				s.Store.Update(u, func(u *store.User) { u.Avatar, u.AvatarAt = img.RawContent, time.Now().Unix() })
				log.Printf("[nx-baas] image_upload: stored %d bytes for %s", len(raw), redact.Tag(uid))
				// And on to the account, so the picture a person set on their
				// console is the one the website and the app show.
				s.shareAvatar(u.ID, img.RawContent)
			}
		}
		// The reply is an image, not a user. The account sysmodule reads
		// exactly two things from it, $.content.url (under 256 bytes) and
		// $.content.format, which must be "jpg"; without both it ends the
		// profile sync with 2124-3121 before its PATCH (account 22.5.0
		// .text 0xeac38, 23.0.1 0xed978). Both `{}` and the user object we
		// used to answer carry neither, which is why every sync failed here.
		//
		// The console keeps the url and later compares its last path segment
		// with thumbnailUrl's, so it is the same address the user object
		// serves from now on.
		if uid := httpx.Str(s.Bearer(r), "sub"); uid != "" {
			if u := s.Store.User(uid); u != nil {
				url := s.userObj(u, s.identity(u), "")["thumbnailUrl"]
				httpx.WriteJSON(w, 200, map[string]any{"content": map[string]any{"url": url, "format": "jpg"}})
				return
			}
		}
		httpx.BaasErr(w, r, 401, "invalid_token", "Invalid token", "no user for this token")
		return

	case p == "/1.0.0/users" && r.Method == "POST":
		u, d := s.Store.NewUser()
		log.Printf("[nx-baas] new device account %s for user %s", redact.Tag(d.ID), redact.Tag(u.ID))
		w.Header().Set("Location", "/1.0.0/users/"+u.ID)
		httpx.WriteJSON(w, 201, s.userObj(u, nil, d.Password))
		return

	case (p == "/1.0.0/login" || p == "/1.0.0/federation") && r.Method == "POST":
		u := s.Store.Login(form.Get("id"), form.Get("password"))
		if u == nil {
			httpx.BaasErr(w, r, 400, "invalid_device_account", "Invalid Device Account", "Device Account's id or password is invalid")
			return
		}
		tok := s.Bearer(r)
		di, sn := httpx.Str(tok, "sub"), ""
		if n, ok := tok["nintendo"].(map[string]any); ok {
			sn = httpx.Str(n, "sn")
		}
		if !s.Harbor.BindDeviceAccount(s.Store, form.Get("id"), di) {
			// A device account another enrolled console signed in with first.
			log.Printf("[nx-baas] %s refused: the device account belongs to another console", seg[1])
			httpx.BaasErr(w, r, 400, "invalid_device_account", "Invalid Device Account", "Device Account's id or password is invalid")
			return
		}
		if p == "/1.0.0/federation" {
			var err error
			if u, err = s.link(u, form.Get("idToken")); err != nil {
				if errors.Is(err, identity.ErrAccountLocked) {
					bans.BaasLocked(w, r, s.locks().NALockOfToken(form.Get("idToken")))
					return
				}
				log.Printf("[nx-baas] federation failed: %v", redact.Err(err))
				httpx.BaasErr(w, r, 400, "invalid_idp_account", "Invalid IdP Account", "IdP account is invalid")
				return
			}
		}
		// A console whose device account is linked to a banned account signs in to nothing:
		// no token, no presence, no notification binding.
		if lock := s.locks().UserLock(u); lock != "" {
			log.Printf("[nx-baas] %s refused: user=%s pid=%s is %s", seg[1], redact.Tag(u.ID), redact.Tag(u.PID), lock)
			bans.BaasLocked(w, r, lock)
			return
		}
		app, _ := token.ParseJWT(form.Get("appAuthNToken"), nil)
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
		s.Penne.BindConsole(di, u.ID)
		s.presenceSvc().ExpireDeviceEverywhere(form.Get("id"), u.ID)
		// A console re-logs in every hour while it plays; the login knows no
		// title, so it must not overwrite the one the device already published
		// (2026-09-22: a game dropping off the friend list at each login).
		//
		// The claim is INACTIVE, signed in with no game, which is all a login
		// knows. The console never publishes ONLINE without a running title
		// (friends 22.5.0 0x194a00: ONLINE only while an application runs),
		// and an ONLINE here reached friends as "online" at HOME, then the
		// device's own INACTIVE landed in the same second and the console,
		// which applies only a later createdAt, kept the ONLINE: the
		// friend-online pop-up for the game started next never came
		// (2026-10-10, Harbor to a Switch). INACTIVE still holds the core
		// session open (stateRank 1).
		client, clientOS := presence.RequestClient(r), presence.RequestClientOS(r)
		if !s.presenceSvc().DeviceClaimLive(u, form.Get("id")) {
			s.presenceSvc().NoteClientPresence(u, form.Get("id"), client, clientOS, "INACTIVE", "", "", "", -1)
		}
		s.reportOnline(r.Context(), u, client, clientOS)
		res := map[string]any{
			"expiresIn": 10800, "user": s.userObj(u, id, ""), "idToken": s.idToken(u, id, username, app),
			"accessToken": s.accessToken(u.ID, 2, func() string {
				if id != nil {
					return id.BsDid
				}
				return token.RandHex(8)
			}(), di, sn), "tokenType": "Bearer",
		}
		// No "summary": the login reply a console accepted carries exactly
		// accessToken, expiresIn, idToken, tokenType and user. Membership is
		// answered on capi's memberships endpoint, which is where the console
		// actually asks.
		log.Printf("[nx-baas] %s user=%s pid=%s ua=%s", seg[1], redact.Tag(u.ID), redact.Tag(u.PID), redact.IDs(r.UserAgent()))
		httpx.WriteJSON(w, 200, res)
		return

	case len(seg) == 3 && seg[0] == "1.0.0" && seg[1] == "users":
		u := s.Store.User(seg[2])
		if u == nil {
			httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		// Reading or writing a user object binds to the authenticated user:
		// a profile is not a public page (the friend list carries what
		// friends may see about a person).
		if s.RequireCaller(w, r, seg[2]) == nil {
			return
		}
		switch r.Method {
		case "GET":
			httpx.WriteJSON(w, 200, s.userObj(u, s.identity(u), ""))
		case "PATCH":
			var ops []struct {
				Op, Path string
				Value    any
			}
			json.Unmarshal(body, &ops)
			renamed := ""
			s.Store.Update(u, func(u *store.User) {
				for _, o := range ops {
					v, _ := o.Value.(string)
					switch o.Path {
					case "/nickname":
						u.Nickname = v
						renamed = v
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
			// A name is an account fact like the picture: it goes to the core so the website and
			// every friend's console show it. Before the reply is built, so the reply carries it.
			// A refusal (a name the core's 1-32 rule rejects) leaves the console's own copy alone.
			// ponytail: Mii changes are not pushed back (/internal/profile-sync) yet.
			if renamed != "" && u.PID != 0 {
				if n, ok := s.Acct.(interface{ SetNickname(uint64, string) error }); ok {
					if err := n.SetNickname(u.PID, renamed); err != nil {
						log.Printf("[nx-baas] nickname: not shared with the account: %v", redact.Err(err))
					} else {
						log.Printf("[nx-baas] nickname shared with the account for %s", redact.Tag(u.ID))
					}
				}
			}
			httpx.WriteJSON(w, 200, s.userObj(u, s.identity(u), ""))
		default:
			httpx.BaasErr(w, r, 405, "method_not_allowed", "Method Not Allowed", "Method Not Allowed")
		}
		return

	case len(seg) == 4 && seg[0] == "1.0.0" && seg[1] == "users":
		u := s.Store.User(seg[2])
		if u == nil {
			httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		switch seg[3] {
		case "link":
			nu, err := s.link(u, form.Get("idToken"))
			if err != nil {
				log.Printf("[nx-baas] link failed: %v", redact.Err(err))
				httpx.BaasErr(w, r, 400, "invalid_idp_account", "Invalid IdP Account", "IdP account is invalid")
				return
			}
			httpx.WriteJSON(w, 200, s.userObj(nu, s.identity(nu), ""))
		case "unlink":
			s.Store.Update(u, func(u *store.User) { u.PID, u.NaID = 0, "" })
			httpx.WriteJSON(w, 200, s.userObj(u, nil, ""))
		case "generate_code":
			if s.RequireCaller(w, r, seg[2]) == nil {
				return
			}
			// The wiki is explicit: a new code, and no new one for 24 hours.
			// This used to answer "there is nothing to regenerate" and hand
			// back the same code, which is a lie a console cannot see through.
			if u.CodeGeneratedAt > 0 && time.Now().Unix()-u.CodeGeneratedAt < 24*3600 {
				httpx.BaasErr(w, r, 422, "friend_code_unregenerable_state", "Friend Code Unregenerable State", "")
				return
			}
			if err := s.Acct.RegenerateFriendCode(u.PID); err != nil {
				log.Printf("[nx-baas] generate_code: %v", redact.Err(err))
				httpx.BaasErr(w, r, 500, "internal_server_error", "Internal Server Error", "Internal Server Error")
				return
			}
			s.Store.Update(u, func(u *store.User) { u.CodeGeneratedAt = time.Now().Unix() })
			httpx.WriteJSON(w, 200, s.userObj(u, s.identity(u), ""))
		case "device_histories":
			if s.RequireCaller(w, r, seg[2]) == nil {
				return
			}
			// Every console this user has signed in on. We keep no history, and
			// an empty list is a true answer; a 404 here is not.
			httpx.WriteJSON(w, 200, map[string]any{"count": 0, "deviceHistories": []any{}})
		case "blocks":
			switch r.Method {
			case "POST":
				// {"targetUserId":"%016llx","extras":{"self":{"reason":…}}}
				// is what the console sends [friends-contract-22.5.0 §A.8];
				// userId and id are what this server read before, kept.
				target := bodyField(body, form, "targetUserId", "userId", "id")
				if target == "" {
					httpx.BaasErr(w, r, 400, "invalid_params", "Invalid Params", "invalid params")
					return
				}
				if s.RequireCaller(w, r, seg[2]) == nil {
					return
				}
				other := s.resolveFriend(target)
				if other == nil {
					httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
					return
				}
				// Blocks commit in the core, which owns enforcement for every
				// adapter (SOC-03); the local mirror only feeds this server's
				// own reads.
				if err := s.setBlock(u, other, true); err != nil {
					log.Printf("[nx-baas] block failed user=%s target=%s: %v", redact.Tag(u.ID), redact.Tag(target), redact.Err(err))
					status, code, title, detail := baasFailure(err)
					httpx.BaasErr(w, r, status, code, title, detail)
					return
				}
				var in struct {
					Extras struct {
						Self map[string]any `json:"self"`
					} `json:"extras"`
				}
				_ = json.Unmarshal(body, &in)
				now := time.Now().Unix()
				s.Store.Update(u, func(u *store.User) {
					if u.BlockDetails == nil {
						u.BlockDetails = map[string]*store.BlockDetail{}
					}
					u.BlockDetails[other.BaasUserID] = &store.BlockDetail{CreatedAt: now, Self: in.Extras.Self}
				})
				// The console ignores this body; it re-syncs the list.
				httpx.WriteJSON(w, 200, s.blockObj(u, other.BaasUserID, now))
			default:
				if s.RequireCaller(w, r, seg[2]) == nil {
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
				httpx.WriteJSON(w, 200, listEnvelope(list))
			}
		case "friends", "friend_requests", "relationships":
			s.friends(w, r, u, seg[3:], body)
		default:
			httpx.Dump(r, body, "!! UNHANDLED user sub-resource")
			httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
		}
		return

	case len(seg) == 5 && seg[0] == "1.0.0" && seg[1] == "users" && seg[3] == "blocks" && r.Method == "DELETE":
		u := s.Store.User(seg[2])
		if u == nil {
			httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if s.RequireCaller(w, r, seg[2]) == nil {
			return
		}
		other := s.resolveFriend(seg[4])
		if other == nil {
			httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if err := s.setBlock(u, other, false); err != nil {
			log.Printf("[nx-baas] unblock failed user=%s target=%s: %v", redact.Tag(u.ID), redact.Tag(seg[4]), redact.Err(err))
			status, code, title, detail := baasFailure(err)
			httpx.BaasErr(w, r, status, code, title, detail)
			return
		}
		w.WriteHeader(204)
		return

	case len(seg) == 5 && seg[0] == "1.0.0" && seg[1] == "users" && seg[3] == "device_accounts":
		u := s.Store.User(seg[2])
		if u == nil {
			httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if s.RequireCaller(w, r, seg[2]) == nil {
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
			s.presenceSvc().ExpireDevicePresence(u, device)
			s.presenceSvc().ExpireDeviceEverywhere(device, u.ID)
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
				httpx.BaasErr(w, r, 400, "invalid_params", "Invalid Params", "no presence state in patch")
				return
			}
			client, clientOS := presence.RequestClient(r), presence.RequestClientOS(r)
			s.presenceSvc().NoteClientPresence(u, device, client, clientOS, state, appID, appField, groupID, acdIndex)
			// This is what keeps someone counted as online: the lease the core holds is short,
			// and a client that has gone away stops renewing it.
			if state == "OFFLINE" {
				s.reportOffline(r.Context(), u)
			} else {
				s.reportOnline(r.Context(), u, client, clientOS)
			}
			log.Printf("[nx-baas] presence user=%s pid=%s device=%s client=%q os=%q %s app=%s field(%d)", redact.Tag(u.ID), redact.Tag(u.PID), redact.Tag(device), client, clientOS, state, appID, len(appField))
			httpx.WriteJSON(w, 200, s.userObj(u, s.identity(u), ""))
		default:
			httpx.Dump(r, body, "!! UNHANDLED device_accounts")
			httpx.BaasErr(w, r, 405, "method_not_allowed", "Method Not Allowed", "Method Not Allowed")
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
		if s.ValidBearer(r) == nil {
			httpx.BaasErr(w, r, 401, "invalid_token", "Invalid token", "a current access token is required")
			return
		}
		q := r.URL.Query()
		now := time.Now().Unix()
		// $.items[*].extras.*.playLog is whichever group the caller may see
		// [friends-contract-22.5.0 §A.7]; friendship decides the friends
		// groups.
		viewer := s.BearerUser(r)
		friendOf := map[string]bool{}
		if id := s.identity(viewer); viewer != nil && id != nil {
			for _, f := range id.Friends {
				friendOf[f.BaasUserID] = true
			}
		}
		found := func(f identity.Friend) any {
			obj := s.searchUserObj(f, now)
			group, pl := s.visiblePlayLog(viewer, s.Store.User(f.BaasUserID), friendOf[f.BaasUserID])
			setPlayLog(obj, group, pl)
			return obj
		}
		users := []any{}
		for _, code := range queryList(q, "filter.links.friendCode.id.$in", "friendCode") {
			if f, err := s.Acct.Resolve(url.Values{"code": {identity.NormaliseFriendCode(code)}}); err == nil && f != nil {
				users = append(users, found(*f))
			}
		}
		for _, id := range queryList(q, "filter.id.$in", "id") {
			if f, err := s.Acct.Resolve(url.Values{"baas": {id}}); err == nil && f != nil {
				users = append(users, found(*f))
			}
		}
		// {"items": [...]} -- not {"count": n, "users": [...]}. Probed against a
		// working server on 2026-09-08 with a throwaway device account: the
		// console reads "items" and nothing else, so a search that found
		// somebody was reported to the person as "unable to find user" while
		// our own log said count:1.
		httpx.WriteJSON(w, 200, map[string]any{"items": users})
		return

	case p == "/1.0.0/devices/snapshot":
		var in struct {
			UserIDs []string `json:"userIds"`
		}
		json.Unmarshal(body, &in)
		persistent, deleted := []string{}, []string{}
		for _, uid := range in.UserIDs {
			if s.Store.User(uid) != nil {
				persistent = append(persistent, uid)
			} else {
				deleted = append(deleted, uid)
			}
		}
		httpx.WriteJSON(w, 200, map[string]any{"deletedUserIds": deleted, "persistentUserIds": persistent})
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
		s.Penne.RecordPushChannel(userID, devID, httpx.Str(in, "service"), httpx.Str(in, "deviceToken"))
		httpx.WriteJSON(w, 200, map[string]any{
			"createdAt": now, "deviceAccountId": devID, "deviceAttributes": map[string]any{}, "deviceToken": httpx.Str(in, "deviceToken"),
			"service": httpx.Str(in, "service"), "updatedAt": now, "userAttributes": map[string]any{}, "userId": userID,
		})
		return
	case p == "/1.0.0/devices/me/delete":
		// A device deleting itself is a departure (PRE-02): its presence claim
		// ends here, not when a lease happens to lapse. The request names the
		// device; where it names a user too, end it on that user's record.
		if dev := bodyField(body, form, "deviceId", "deviceAccountId", "device"); dev != "" {
			if uid := bodyField(body, form, "userId", "user"); uid != "" {
				if u := s.Store.User(uid); u != nil {
					s.presenceSvc().ExpireDevicePresence(u, dev)
				}
			}
			s.presenceSvc().ExpireDeviceEverywhere(dev, "")
		} else {
			log.Printf("[nx-baas] devices/me/delete without a device id; nothing to expire")
		}
		httpx.WriteJSON(w, 200, map[string]any{})
		return
	}

	httpx.Dump(r, body, "!! UNHANDLED")
	httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
}

// link binds a BAAS user to the OpenPak account behind a Nintendo-Account id_token we issued.
func (s *server) link(u *store.User, idTok string) (*store.User, error) {
	claims, err := token.ParseJWT(idTok, &s.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	naID := httpx.Str(claims, "sub")
	pid := s.Store.PIDForNA(naID)
	if pid == 0 {
		return nil, fmt.Errorf("unknown Nintendo-Account sub %q", naID)
	}
	if lock := s.locks().PIDLock(pid); lock != "" {
		return nil, fmt.Errorf("link pid %d: %w (%s)", pid, identity.ErrAccountLocked, lock)
	}
	id, err := s.Acct.Identity(pid)
	if err != nil {
		return nil, err
	}
	nu := s.Store.Link(u, pid, id.BaasUserID, id.NaID)
	log.Printf("[nx-baas] linked user %s -> pid %s", redact.Tag(nu.ID), redact.Tag(pid))
	return nu, nil
}

var minimal = os.Getenv("NX_MINIMAL") != "" // bisecting 2124-0292: only the NA link on top of the POST /users shape
