package friends

import (
	"fmt"
	"nx-baas/internal/core"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/presence"
	"nx-baas/internal/store"
	"nx-baas/internal/token"
	"os"
	"strconv"
	"strings"
	"time"
)

func (s *Service) Identity(u *store.User) *identity.Identity {
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
func FriendCodeID(fc string) string { return strings.TrimPrefix(fc, "SW-") }

// codeRegen reports the friend-code regeneration state the console shows:
// regenerableAt is the "next issuable" time and regenerable whether a new
// code may be issued now. A new code is allowed once a day from the last
// issue — generate_code enforces the same 24 h — so advertising +30 d showed
// a date the enforcement never kept [friends-contract-22.5.0 §A.6, C11].
// A code that was never issued is issuable now.
func CodeRegen(codeGeneratedAt, fallback int64) (regenerableAt int64, regenerable bool) {
	if codeGeneratedAt <= 0 {
		return fallback, true
	}
	at := codeGeneratedAt + 24*3600
	return at, time.Now().Unix() >= at
}

func Extras() map[string]any {
	return map[string]any{"self": map[string]any{}, "favoriteFriends": map[string]any{}, "friends": map[string]any{}, "foaf": map[string]any{}, "everyone": map[string]any{}}
}

func PresenceObj(p store.Presence) map[string]any {
	ex := Extras()
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

func (s *Service) UserObj(u *store.User, id *identity.Identity, devicePassword string) map[string]any {
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
			regenAt, regen := CodeRegen(u.CodeGeneratedAt, u.CreatedAt)
			links["friendCode"] = map[string]any{"id": FriendCodeID(id.FriendCode), "createdAt": u.CreatedAt, "updatedAt": u.CreatedAt, "regenerableAt": regenAt, "regenerable": regen}
			if pl, ok := id.PlayLog.(string); ok && pl != "" && pl != "null" && u.PlayLog == nil {
				friendsEx["playLog"], everyone["playLog"] = pl, pl
			}
			if at := NewerPicture(u, id); at > 0 {
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
		"friendsUpdatedAt": FriendsUpdatedAt(u), "id": u.ID, "links": links, "nickname": nickname, "nicknameUpdatedAt": u.UpdatedAt,
		"permissions":   PermissionsOf(u),
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
func (s *Service) FriendObj(f identity.Friend, now int64) map[string]any {
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
	regenAt, regen := CodeRegen(codeGen, created)
	// Their picture's version, when this server holds their record: the
	// console caches images by URL, so a new picture must come with a new
	// URL or friends keep the old one [friends-contract-22.5.0 §A.11, C21].
	picAt, picKnown := created, false
	if local != nil {
		if at := NewerPicture(local, nil); at > 0 {
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
				"id": FriendCodeID(f.FriendCode), "createdAt": created, "updatedAt": created,
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
	group, pl := s.VisiblePlayLog(nil, s.Store.User(f.BaasUserID), false)
	SetPlayLog(obj, group, pl)
	return obj
}

// searchUserObj is a user, not a friend. The friend-list keys — friendId,
// presence, the viewer's own extras — belong to the relationship renderer,
// and a stranger you have just looked up is not one. The console refused a
// search result that carried them, the same way it refused a login reply
// that carried an extra "summary"; the exact-match test
// TestSearchReplyMatchesTheAcceptedShape keeps it that way.
func (s *Service) SearchUserObj(f identity.Friend, now int64) map[string]any {
	return s.FriendObj(f, now)
}

// NewerPicture answers "does this user have a picture, and when did it last
// change" across the two places one can be set: the console's own upload and
// the account's avatar on the website. Zero means neither, which is the only
// case where a console should be sent to /1/default.
func NewerPicture(u *store.User, id *identity.Identity) int64 {
	at := u.AvatarAt
	if u.Avatar != "" && at == 0 {
		at = u.UpdatedAt // uploaded before this field existed
	}
	if u.Avatar == "" {
		at = 0
	}
	if id != nil && id.ImageUpdatedAt > at {
		return id.ImageUpdatedAt
	}
	return at
}

var minimal = os.Getenv("NX_MINIMAL") != "" // bisecting 2124-0292: only the NA link on top of the POST /users shape
