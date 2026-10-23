// Package baas is the BAAS surface (baas.nintendo.com): the application token, device-account
// login, users, federation with a Nintendo Account, the key sets and the avatar host. The
// friends routes on the same host are internal/friends'.
package baas

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
	"nx-baas/internal/friends"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/presence"
	"nx-baas/internal/store"
	"nx-baas/internal/token"
	"nx-baas/redact"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed assets/default.jpg
var defaultAvatar []byte

// accessToken/idToken: claim for claim what a real console accepted from the VPS
// (capture 2026-09-06, /1.0.0/login). Anonymous (grant 1) tokens carry the device block;
// user tokens (grant 2) do not.
func (s *Service) AccessToken(sub string, grant int, bsDid, di, sn string) string {
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

func (s *Service) IDToken(u *store.User, id *identity.Identity, username string, app map[string]any) string {
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
func (s *Service) reportOnline(ctx context.Context, u *store.User, client, clientOS string) {
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
func (s *Service) reportOffline(ctx context.Context, u *store.User) {
	if u == nil || u.PID == 0 {
		return
	}
	if b, ok := s.Acct.(*identity.OpenpakBackend); ok {
		b.Offline(ctx, u.PID)
	}
}

func (s *Service) Handle(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	form, _ := url.ParseQuery(string(body))
	seg := strings.Split(strings.Trim(p, "/"), "/")

	// A banned account's live access token stops working at once: every user-scoped call
	// (profile, presence, friends) answers banned_user, which the console shows as
	// 2124-5110 (bans.go). Pictures and key sets stay public.
	if strings.HasPrefix(p, "/1.0.0/users/") || strings.HasPrefix(p, "/2.0.0/") {
		if c := s.ValidBearer(r); c != nil {
			if lock := s.Locks.UserLock(s.Store.User(httpx.Str(c, "sub"))); lock != "" {
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
		} else if f := s.Friends.ResolveFriend(p[3:]); f != nil {
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
				if err != nil || id.ImageUpdatedAt <= friends.NewerPicture(u, nil) {
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
		httpx.WriteJSON(w, 200, map[string]any{"accessToken": s.AccessToken(di, 1, token.RandHex(8), di, sn), "tokenType": "Bearer", "expiresIn": 10800})
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
				url := s.Friends.UserObj(u, s.Friends.Identity(u), "")["thumbnailUrl"]
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
		httpx.WriteJSON(w, 201, s.Friends.UserObj(u, nil, d.Password))
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
					bans.BaasLocked(w, r, s.Locks.NALockOfToken(form.Get("idToken")))
					return
				}
				log.Printf("[nx-baas] federation failed: %v", redact.Err(err))
				httpx.BaasErr(w, r, 400, "invalid_idp_account", "Invalid IdP Account", "IdP account is invalid")
				return
			}
		}
		// A console whose device account is linked to a banned account signs in to nothing:
		// no token, no presence, no notification binding.
		if lock := s.Locks.UserLock(u); lock != "" {
			log.Printf("[nx-baas] %s refused: user=%s pid=%s is %s", seg[1], redact.Tag(u.ID), redact.Tag(u.PID), lock)
			bans.BaasLocked(w, r, lock)
			return
		}
		app, _ := token.ParseJWT(form.Get("appAuthNToken"), nil)
		id := s.Friends.Identity(u)
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
		s.Presence.ExpireDeviceEverywhere(form.Get("id"), u.ID)
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
		if !s.Presence.DeviceClaimLive(u, form.Get("id")) {
			s.Presence.NoteClientPresence(u, form.Get("id"), client, clientOS, "INACTIVE", "", "", "", -1)
		}
		s.reportOnline(r.Context(), u, client, clientOS)
		res := map[string]any{
			"expiresIn": 10800, "user": s.Friends.UserObj(u, id, ""), "idToken": s.IDToken(u, id, username, app),
			"accessToken": s.AccessToken(u.ID, 2, func() string {
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
			httpx.WriteJSON(w, 200, s.Friends.UserObj(u, s.Friends.Identity(u), ""))
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
						u.Permissions["presence"] = friends.NormalizePresencePermission(o.Value)
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
			httpx.WriteJSON(w, 200, s.Friends.UserObj(u, s.Friends.Identity(u), ""))
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
			httpx.WriteJSON(w, 200, s.Friends.UserObj(nu, s.Friends.Identity(nu), ""))
		case "unlink":
			s.Store.Update(u, func(u *store.User) { u.PID, u.NaID = 0, "" })
			httpx.WriteJSON(w, 200, s.Friends.UserObj(u, nil, ""))
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
			httpx.WriteJSON(w, 200, s.Friends.UserObj(u, s.Friends.Identity(u), ""))
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
				target := friends.BodyField(body, form, "targetUserId", "userId", "id")
				if target == "" {
					httpx.BaasErr(w, r, 400, "invalid_params", "Invalid Params", "invalid params")
					return
				}
				if s.RequireCaller(w, r, seg[2]) == nil {
					return
				}
				other := s.Friends.ResolveFriend(target)
				if other == nil {
					httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
					return
				}
				// Blocks commit in the core, which owns enforcement for every
				// adapter (SOC-03); the local mirror only feeds this server's
				// own reads.
				if err := s.Friends.SetBlock(u, other, true); err != nil {
					log.Printf("[nx-baas] block failed user=%s target=%s: %v", redact.Tag(u.ID), redact.Tag(target), redact.Err(err))
					status, code, title, detail := friends.BaasFailure(err)
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
				httpx.WriteJSON(w, 200, s.Friends.BlockObj(u, other.BaasUserID, now))
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
					if len(list) == friends.MaxBlockEntries {
						break
					}
					list = append(list, s.Friends.BlockObj(u, b, now))
				}
				httpx.WriteJSON(w, 200, friends.ListEnvelope(list))
			}
		case "friends", "friend_requests", "relationships":
			s.Friends.HandleV1(w, r, u, seg[3:], body)
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
		other := s.Friends.ResolveFriend(seg[4])
		if other == nil {
			httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if err := s.Friends.SetBlock(u, other, false); err != nil {
			log.Printf("[nx-baas] unblock failed user=%s target=%s: %v", redact.Tag(u.ID), redact.Tag(seg[4]), redact.Err(err))
			status, code, title, detail := friends.BaasFailure(err)
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
			s.Presence.ExpireDevicePresence(u, device)
			s.Presence.ExpireDeviceEverywhere(device, u.ID)
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
			s.Presence.NoteClientPresence(u, device, client, clientOS, state, appID, appField, groupID, acdIndex)
			// This is what keeps someone counted as online: the lease the core holds is short,
			// and a client that has gone away stops renewing it.
			if state == "OFFLINE" {
				s.reportOffline(r.Context(), u)
			} else {
				s.reportOnline(r.Context(), u, client, clientOS)
			}
			log.Printf("[nx-baas] presence user=%s pid=%s device=%s client=%q os=%q %s app=%s field(%d)", redact.Tag(u.ID), redact.Tag(u.PID), redact.Tag(device), client, clientOS, state, appID, len(appField))
			httpx.WriteJSON(w, 200, s.Friends.UserObj(u, s.Friends.Identity(u), ""))
		default:
			httpx.Dump(r, body, "!! UNHANDLED device_accounts")
			httpx.BaasErr(w, r, 405, "method_not_allowed", "Method Not Allowed", "Method Not Allowed")
		}
		return

	// >= 2, not >= 3: POST /2.0.0/friend_requests is two segments, so sending a
	// friend request fell straight through to the catch-all 404 and the console
	// said "please try again later" (2121-2031).
	case len(seg) >= 2 && seg[0] == "2.0.0":
		s.Friends.HandleV2(w, r, seg[1:], body)
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
		if id := s.Friends.Identity(viewer); viewer != nil && id != nil {
			for _, f := range id.Friends {
				friendOf[f.BaasUserID] = true
			}
		}
		found := func(f identity.Friend) any {
			obj := s.Friends.SearchUserObj(f, now)
			group, pl := s.Friends.VisiblePlayLog(viewer, s.Store.User(f.BaasUserID), friendOf[f.BaasUserID])
			friends.SetPlayLog(obj, group, pl)
			return obj
		}
		users := []any{}
		for _, code := range friends.QueryList(q, "filter.links.friendCode.id.$in", "friendCode") {
			if f, err := s.Acct.Resolve(url.Values{"code": {identity.NormaliseFriendCode(code)}}); err == nil && f != nil {
				users = append(users, found(*f))
			}
		}
		for _, id := range friends.QueryList(q, "filter.id.$in", "id") {
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
		if dev := friends.BodyField(body, form, "deviceId", "deviceAccountId", "device"); dev != "" {
			if uid := friends.BodyField(body, form, "userId", "user"); uid != "" {
				if u := s.Store.User(uid); u != nil {
					s.Presence.ExpireDevicePresence(u, dev)
				}
			}
			s.Presence.ExpireDeviceEverywhere(dev, "")
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
func (s *Service) link(u *store.User, idTok string) (*store.User, error) {
	claims, err := token.ParseJWT(idTok, &s.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	naID := httpx.Str(claims, "sub")
	pid := s.Store.PIDForNA(naID)
	if pid == 0 {
		return nil, fmt.Errorf("unknown Nintendo-Account sub %q", naID)
	}
	if lock := s.Locks.PIDLock(pid); lock != "" {
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

// bisecting 2124-0292: only the NA link on top of the POST /users shape

// Service is the BAAS surface (application token, login, users, federation, certificates and
// the avatar host) over the shared state.
type Service struct {
	*core.Core
	Locks    *bans.Checker
	Presence *presence.Service
	Friends  *friends.Service

	mu     sync.Mutex
	device map[string]string // device id -> serial, from the dauth assertion
}

// New is the BAAS surface with an empty device map.
func New(c *core.Core, locks *bans.Checker, p *presence.Service, f *friends.Service) *Service {
	return &Service{Core: c, Locks: locks, Presence: p, Friends: f, device: map[string]string{}}
}
