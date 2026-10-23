package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"nx-baas/internal/store"
	"strings"
	"time"
)

// queryList reads a console filter parameter, which may repeat and whose $in
// form is comma-separated. The fallbacks are the older, simpler spellings.
func queryList(q url.Values, keys ...string) []string {
	var out []string
	for _, k := range keys {
		for _, v := range q[k] {
			for _, part := range strings.Split(v, ",") {
				if part = strings.TrimSpace(part); part != "" {
					out = append(out, part)
				}
			}
		}
	}
	return out
}

// bodyField reads a parameter from either encoding: this server takes form or
// JSON depending on the method, and the console picks. Documented on kinnay's
// BAAS page; observed both ways on hardware.
func bodyField(body []byte, form url.Values, keys ...string) string {
	var j map[string]any
	_ = json.Unmarshal(body, &j)
	for _, k := range keys {
		if v, ok := j[k].(string); ok && v != "" {
			return v
		}
		if v := form.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// permissionsOf serves the user's privacy switches: the documented defaults,
// overridden by anything they changed on the console. Values are the console's
// own (friends EVERYONE|FRIENDS|SELF, presence FRIENDS|FAVORITE_FRIENDS|SELF).
func permissionsOf(u *store.User) map[string]any {
	p := map[string]any{
		"friendRequestReception": true, "friends": "EVERYONE",
		"personalAnalytics": true, "personalAnalyticsUpdatedAt": u.CreatedAt,
		"personalNotification": true, "personalNotificationUpdatedAt": u.CreatedAt,
		"presence": "FRIENDS", "presenceUpdatedAt": u.CreatedAt,
	}
	for k, v := range u.Permissions {
		p[k] = v
	}
	return p
}

// Friend requests this server issued, by their own durable id (SOC-03). The
// records live in the store, so a request the console is showing survives a
// restart and still names the pair it named when it was created. The old
// process-global map lost every request on restart, which turned a cancel
// into a gamble on which server instance answered.

func (s *server) rememberRequest(receiverBaasID string) string  { return "" }        // removed: see store.EnsureRequest
func (s *server) requestTarget(requestID string) (string, bool) { return "", false } // removed: see store.RequestByID

// channelsOf echoes back the channels the console said it used, defaulting to
// the one it uses when adding by code.
func channelsOf(body []byte) []string {
	var in struct {
		Channels []string `json:"channels"`
	}
	if err := json.Unmarshal(body, &in); err == nil && len(in.Channels) > 0 {
		return in.Channels
	}
	return []string{"FRIEND_CODE"}
}

// listEnvelope is how this server returns a list, captured from one a console
// accepts: {"count":n,"etag":"","items":[...],"itemsPerPage":100}. Ours used
// to name the array after its contents -- "friends", "friendRequests", "users"
// -- and a console reading "items" found nothing every time, which is what an
// empty friend list and an empty inbox looked like from the sofa.
func listEnvelope(items []any) map[string]any {
	return listEnvelopeWith(items, "", 100)
}

// listEnvelopeWith exists because the two captures differ and this parser has
// not forgiven a difference yet: the friend list carries a quoted empty etag
// and itemsPerPage 100, the request boxes a bare empty etag. The inbox reply
// with a bare etag is the one a console has demonstrably read, so it keeps it.
func listEnvelopeWith(items []any, etag string, perPage int) map[string]any {
	if items == nil {
		items = []any{}
	}
	// An empty etag is what a real server sends for an empty list, which
	// is the only list we have ever captured. A list with people in it plainly
	// has a version; ours said "" regardless, so it gets one derived from the
	// contents -- same list, same etag, and it moves when the list does.
	if etag == `""` && len(items) > 0 {
		sum := sha256.Sum256([]byte(fmt.Sprint(items)))
		etag = fmt.Sprintf("%q", hex.EncodeToString(sum[:8]))
	}
	return map[string]any{"count": len(items), "etag": etag, "items": items, "itemsPerPage": perPage}
}

// requestState spells a request state the console's way. Its state table is
// PENDING, CANCELED, AUTHORIZED, REJECTED, EXPIRED, and 30202 cancels with
// "CANCELED", one L [friends-contract-22.5.0 §A.4.4]. The double-L spelling
// this server used to insist on is still read, and still stored in records
// settled before this, so both mean the same answer.
func requestState(v string) string {
	v = strings.ToUpper(v)
	if v == "CANCELLED" {
		return "CANCELED"
	}
	return v
}

// patchedState reads the state a console set on a friend request. Its own
// words: AUTHORIZED to become friends, REJECTED to refuse, CANCELED to
// withdraw. Answering with a different word for the same thing is how a
// working accept reported itself as a communication error.
func patchedState(body []byte) string {
	var ops []struct {
		Op, Path string
		Value    any
	}
	if err := json.Unmarshal(body, &ops); err == nil {
		for _, o := range ops {
			if strings.HasSuffix(o.Path, "/state") {
				if v, ok := o.Value.(string); ok && v != "" {
					return requestState(v)
				}
			}
		}
	}
	if strings.Contains(strings.ToUpper(string(body)), "REJECT") {
		return "REJECTED"
	}
	// No answer in it. Opening the request box PATCHes
	// [{"op":"add","path":"/extras/receiver/read","value":true}], and reading
	// that as AUTHORIZED befriended everyone the moment they looked.
	return ""
}

// friendListFormatEpoch is when the 22.5.0 friend-list shape shipped. Consoles
// that cached an empty list from the old shape only refetch when the version
// moves past the one they stored, so every account's version floors here once.
const friendListFormatEpoch = 1789159700 // 2026-09-11T20:48:20Z, when this shipped

// friendsUpdatedAt is the version a console watches to decide whether its
// cached friend list is stale. It used to be the user's UpdatedAt, which moves
// for a picture or a nickname and not for a friendship, so a console that had
// just become friends with somebody never asked for the list again.
func friendsUpdatedAt(u *store.User) int64 {
	v := u.UpdatedAt
	if u.FriendsUpdatedAt > 0 {
		v = u.FriendsUpdatedAt
	}
	if v < friendListFormatEpoch {
		return friendListFormatEpoch
	}
	return v
}

// friendGraphChanged marks both sides, because a friendship changes two lists
// and only one of the two consoles is holding the controller. The bump is
// strictly monotonic (see bumpFriendsUpdated): two changes inside one second
// must not collapse into one, or a console that refetched between them keeps
// the stale list.
func (s *server) friendGraphChanged(u *store.User, otherBaasID string) {
	now := time.Now().Unix()
	s.store.Update(u, func(u *store.User) { store.BumpFriendsUpdated(u, now) })
	if other := s.store.User(otherBaasID); other != nil {
		s.store.Update(other, func(o *store.User) { store.BumpFriendsUpdated(o, now) })
	}
}
