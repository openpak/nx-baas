package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OpenPak account server (openpak-account) client: the source of truth for identity, friend
// codes and the friend graph. Its /internal/* endpoints are guarded by source network
// (internal_net.conf), so this service must run on the same compose network.
type accountClient struct {
	base     string
	adminKey string
	secret   []byte
	http     *http.Client
}

type Friend struct {
	PID              uint64 `json:"pid"`
	Country          string `json:"country"`
	BaasUserID       string `json:"baasUserID"`
	NaID             string `json:"naID"`
	Nickname         string `json:"nickname"`
	FriendCode       string `json:"friendCode"`
	Avatar           string `json:"avatar"`
	CreatedAt        int64  `json:"createdAt"`
	PresenceStatus   int    `json:"presenceStatus"`
	PresenceAppField string `json:"presenceAppField"`
	PresenceAppID    string `json:"presenceAppId"`
}

type Identity struct {
	PID        uint64 `json:"pid"`
	NaID       string `json:"naID"`
	BaasUserID string `json:"baasUserID"`
	BsDid      string `json:"bsDid"`
	Nickname   string `json:"nickname"`
	FriendCode string `json:"friendCode"`
	// The console's user object carries both and rejects it when either is malformed.
	Country  string `json:"country"`
	Birthday string `json:"birthday"`
	Avatar   string `json:"avatar"`
	// AvatarURL is where the account's own picture lives when the adapter does
	// not hold the bytes: the website's media store. Fetched only when a
	// console actually asks for the thumbnail, never on the login path.
	AvatarURL      string   `json:"avatarURL"`
	ImageUpdatedAt int64    `json:"imageUpdatedAt"`
	PlayLog        any      `json:"playLog"`
	Friends        []Friend `json:"friends"`
	FriendRequests []Friend `json:"friendRequests"`
	SentRequests   []Friend `json:"sentRequests"`
}

func (a *accountClient) get(path string, out any) error {
	req, _ := http.NewRequest("GET", a.base+path, nil)
	if a.adminKey != "" {
		req.Header.Set("X-Internal-Key", a.adminKey)
	}
	res, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s -> %d %s", path, res.StatusCode, bytes.TrimSpace(b))
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func (a *accountClient) postJSON(path string, in any, out any) error {
	body, _ := json.Marshal(in)
	req, _ := http.NewRequest("POST", a.base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if a.adminKey != "" {
		req.Header.Set("X-Internal-Key", a.adminKey)
		req.Header.Set("X-Admin-Key", a.adminKey) // exempts /api/login from Turnstile
	}
	res, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s -> %d %s", path, res.StatusCode, bytes.TrimSpace(b))
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

func (a *accountClient) Identity(pid uint64) (*Identity, error) {
	var id Identity
	if err := a.get(fmt.Sprintf("/internal/identity?pid=%d", pid), &id); err != nil {
		return nil, err
	}
	return &id, nil
}

// Resolve looks up any account by friend code or BAAS user id (16 hex).
func (a *accountClient) Resolve(q url.Values) (*Friend, error) {
	var out struct {
		Friend
		Found *bool `json:"found"`
	}
	if err := a.get("/internal/resolve?"+q.Encode(), &out); err != nil {
		return nil, err
	}
	if out.Found != nil && !*out.Found {
		return nil, fmt.Errorf("not found")
	}
	return &out.Friend, nil
}

// LoginPID checks a OpenPak e-mail + password (the "Link Nintendo Account" web page).
func (a *accountClient) LoginPID(email, password string) (uint64, string, error) {
	var out struct {
		Account struct {
			PID      uint64 `json:"pid"`
			Username string `json:"username"`
		} `json:"account"`
	}
	if err := a.postJSON("/api/login", map[string]string{"Login": email, "Password": password}, &out); err != nil {
		return 0, "", err
	}
	return out.Account.PID, out.Account.Username, nil
}

func (a *accountClient) FriendRequest(from, to uint64) error {
	return a.postJSON("/internal/friend-request", map[string]uint64{"from": from, "to": to}, nil)
}

func (a *accountClient) FriendAccept(pid, from uint64, accept bool) error {
	return a.postJSON("/internal/friend-accept", map[string]any{"pid": pid, "from": from, "accept": accept}, nil)
}

// RemoveFriend on the legacy stack: its only lever is friend-accept with
// accept=false, which ends a pending request and is best-effort for an
// accepted friendship. The core contract request for a real removal there is
// in the ledger; until it lands, a removal that could not commit comes back
// as an error, never as a success.
func (a *accountClient) RemoveFriend(pid, other uint64) error {
	return a.FriendAccept(pid, other, false)
}

// Block/Unblock on the legacy stack: that core has no block contract, so the
// adapter's local mirror is the enforcement surface there. The openpak core —
// the target backend — owns the durable block; this is a documented
// limitation of the fallback backend, not a model to copy.
func (a *accountClient) Block(uint64, uint64) error   { return nil }
func (a *accountClient) Unblock(uint64, uint64) error { return nil }

// nexToken is openpak-account's signNexToken, byte for byte: the "openpak" claim the game servers
// (Photon, NPLN) use to bind a login to a PID. Shared OPENPAK_SECRET.
func (a *accountClient) nexToken(pid uint64, username string) string {
	if len(a.secret) == 0 {
		return ""
	}
	payload := fmt.Sprintf("%d.%s.%d", pid, username, time.Now().Add(30*24*time.Hour).Unix())
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte("nex:" + payload))
	return "nx2." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *accountClient) nexSigningKey() []byte { return a.secret }

// The legacy backend keeps no account-id projection: friend codes come from
// the account server there, and nothing asks this path for one.
func (a *accountClient) friendCodeForAccount(string) (string, bool) { return "", false }
func (a *accountClient) accountForFriendCode(string) (string, bool) { return "", false }

// Codes belong to the account server on this backend, which offers no way to
// regenerate one. Saying so beats pretending it worked.
func (a *accountClient) RegenerateFriendCode(uint64) error {
	return errors.New("friend codes are the account server's on this backend")
}

func logErr(what string, err error) {
	if err != nil {
		log.Printf("[nx-baas] account: %s: %v", what, err)
	}
}

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

// normaliseFriendCode accepts what a console sends (1234-5678-9012), what a
// person types (SW-1234-5678-9012, any case, spaces) and what we store.
func normaliseFriendCode(code string) string {
	c := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	c = strings.TrimPrefix(c, "SW-")
	return "SW-" + c
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
func permissionsOf(u *User) map[string]any {
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
	// An empty etag is what a reference server sends for an empty list, which
	// is the only list we have ever captured. A list with people in it plainly
	// has a version; ours said "" regardless, so it gets one derived from the
	// contents -- same list, same etag, and it moves when the list does.
	if etag == `""` && len(items) > 0 {
		sum := sha256.Sum256([]byte(fmt.Sprint(items)))
		etag = fmt.Sprintf("%q", hex.EncodeToString(sum[:8]))
	}
	return map[string]any{"count": len(items), "etag": etag, "items": items, "itemsPerPage": perPage}
}

// patchedState reads the state a console set on a friend request. Its own
// words: AUTHORIZED to become friends, REJECTED to refuse. Answering with a
// different word for the same thing is how a working accept reported itself
// as a communication error.
func patchedState(body []byte) string {
	var ops []struct {
		Op, Path string
		Value    any
	}
	if err := json.Unmarshal(body, &ops); err == nil {
		for _, o := range ops {
			if strings.HasSuffix(o.Path, "/state") {
				if v, ok := o.Value.(string); ok && v != "" {
					return strings.ToUpper(v)
				}
			}
		}
	}
	if strings.Contains(strings.ToUpper(string(body)), "REJECT") {
		return "REJECTED"
	}
	return "AUTHORIZED"
}

// friendListFormatEpoch is when the 22.5.0 friend-list shape shipped. Consoles
// that cached an empty list from the old shape only refetch when the version
// moves past the one they stored, so every account's version floors here once.
const friendListFormatEpoch = 1789159700 // 2026-09-11T20:48:20Z, when this shipped

// friendsUpdatedAt is the version a console watches to decide whether its
// cached friend list is stale. It used to be the user's UpdatedAt, which moves
// for a picture or a nickname and not for a friendship, so a console that had
// just become friends with somebody never asked for the list again.
func friendsUpdatedAt(u *User) int64 {
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
func (s *server) friendGraphChanged(u *User, otherBaasID string) {
	now := time.Now().Unix()
	s.store.Update(u, func(u *User) { bumpFriendsUpdated(u, now) })
	if other := s.store.User(otherBaasID); other != nil {
		s.store.Update(other, func(o *User) { bumpFriendsUpdated(o, now) })
	}
}
