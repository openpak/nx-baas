// Social: the friends surface the native friends sysmodule talks to
// (SOC-01..05). Three renderers, kept separate because the firmware parses
// them separately:
//
//   - friendObj (main.go): a *user* about somebody else — what a search
//     result carries, and the nested `friend` value inside a relationship.
//   - relationshipObj (here): one entry of the friend list — `friendId` plus
//     the nested user plus the viewer's own relationship state.
//   - the request-box entries: a request is not a user and not a friendship.
//
// The 22.5.0 list parser (firmware findings, parser callback table) counts an
// entry only when `$.items[*].friendId`, `$.items[*].friend.nickname` and
// `$.items[*].friend.thumbnailUrl` all parse; everything else in the entry is
// read best-effort around those. The old flat shape parsed zero entries,
// which is why the native list was empty while the envelope said count:1.

package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// maxListEntries is the bound the console itself applies (the parser caps the
// list at 300), and the count the native list request asks for. There is no
// native cursor: the request is count=300, the answer is up to 300 items, and
// an account with more friends than that needs a core-side page contract
// first (see the ledger's contract requests) — not an invented one here.
const maxListEntries = 300

// relationshipEntryGaps returns the required-field paths a 22.5.0 parser
// would fail this entry on: friendId, friend.nickname, friend.thumbnailUrl.
// It exists so the parser contract is checked against rendered entries — and
// against the old flat shape, which must fail — in tests, not by construction.
func relationshipEntryGaps(entry map[string]any) []string {
	var missing []string
	if v, _ := entry["friendId"].(string); v == "" {
		missing = append(missing, "friendId")
	}
	friend, _ := entry["friend"].(map[string]any)
	if friend == nil {
		return append(missing, "friend", "friend.nickname", "friend.thumbnailUrl")
	}
	if v, _ := friend["nickname"].(string); v == "" {
		missing = append(missing, "friend.nickname")
	}
	if v, _ := friend["thumbnailUrl"].(string); v == "" {
		missing = append(missing, "friend.thumbnailUrl")
	}
	return missing
}

// onlineNotificationOf: the per-relationship online-alert preference. The
// native default is on, so an unset preference means enabled — and a set
// false must stay false (SOC-02). This preference gates the *alert* (PRE-04);
// it never gates the state: a friend list stays current with alerts off.
func onlineNotificationOf(p *FriendPreference) bool {
	return p == nil || p.OnlineNotification == nil || *p.OnlineNotification
}

// relationshipObj renders one friend-list entry for viewer: the nested user,
// the viewer's own relationship state, and the presence the viewer may see.
// Every timestamp is state-derived, so rendering an unchanged list twice
// produces identical entries — a stable etag (SOC-05).
func (s *server) relationshipObj(viewer *User, f Friend, now int64) map[string]any {
	user := s.friendObj(f, now)
	user["presence"] = s.visiblePresence(viewer, f, now)
	// The friend's play log, under the group that carries it when this
	// viewer may see it: what "recently played" and the same-app filters
	// read, from $.items[*].friend.extras.*.playLog [§A.1].
	group, pl := s.visiblePlayLog(viewer, s.store.User(f.BaasUserID), true)
	setPlayLog(user, group, pl)
	created := f.CreatedAt
	if created == 0 {
		created = now
	}
	pref := s.prefOf(viewer, f.BaasUserID)
	updatedAt := created
	if pref != nil && pref.UpdatedAt > updatedAt {
		updatedAt = pref.UpdatedAt
	}
	note := ""
	if pref != nil {
		note = pref.Note
	}
	return map[string]any{
		"friendId":   f.BaasUserID,
		"friend":     user,
		"isFavorite": pref != nil && pref.Favorite,
		"createdAt":  created,
		"updatedAt":  updatedAt,
		// The list parser reads a note per entry [firmware,
		// $.items[*].friendNote]; unset is the empty string, not an absent key.
		"friendNote": note,
		"extras": map[string]any{
			"self": map[string]any{
				"isConfirmed":          pref != nil && pref.Confirmed,
				"isOnlineNotification": onlineNotificationOf(pref),
			},
		},
	}
}

// playLogGroups are the extras groups a play log can sit in, in the order the
// console reads its own permission from them (self 1, favoriteFriends 2,
// friends 3, everyone 5; first match wins) [friends-contract-22.5.0 §A.6].
var playLogGroups = []string{"self", "favoriteFriends", "friends", "everyone"}

// playLogGroup is the group carrying u's play log, which is u's play-log
// permission, and the log. A value counts only as the console's parser takes
// it: a string that starts with [ and ends with ] [§A.1]. Called with the
// store lock held.
func playLogGroup(u *User) (group, pl string) {
	for _, g := range playLogGroups {
		if v := u.PlayLog[g]; strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
			return g, v
		}
	}
	return "", ""
}

// visiblePlayLog is subject's play log as viewer may see it, and the group it
// is served under: the one that carries it. everyone is anyone's (viewer nil
// is anyone), friends a friend's, favoriteFriends only a friend the subject
// marked favourite, self nobody else's. A block either way hides it.
func (s *server) visiblePlayLog(viewer, subject *User, areFriends bool) (group, pl string) {
	if subject == nil {
		return "", ""
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	group, pl = playLogGroup(subject)
	if viewer != nil && viewer.ID == subject.ID {
		return group, pl
	}
	if viewer != nil && blocksEither(viewer, subject) {
		return "", ""
	}
	switch group {
	case "everyone":
		return group, pl
	case "friends":
		if viewer != nil && areFriends {
			return group, pl
		}
	case "favoriteFriends":
		if viewer != nil && areFriends && subject.FriendPrefs[viewer.ID] != nil && subject.FriendPrefs[viewer.ID].Favorite {
			return group, pl
		}
	}
	return "", ""
}

// setPlayLog writes a play log into a rendered user's extras group.
func setPlayLog(user map[string]any, group, pl string) {
	if group == "" {
		return
	}
	ex, _ := user["extras"].(map[string]any)
	if ex == nil {
		return
	}
	g, _ := ex[group].(map[string]any)
	if g == nil {
		g = map[string]any{}
		ex[group] = g
	}
	g["playLog"] = pl
}

// normalizePresencePermission is the firmware's own reading of a presence
// permission value: SELF, FAVORITE_FRIENDS or FRIENDS, and anything else —
// including EVERYONE — becomes SELF [friends-contract-22.5.0 §A.6]. Stored
// normalized, the server and the console always agree on what was set [C10].
func normalizePresencePermission(v any) string {
	switch v {
	case "SELF", "FAVORITE_FRIENDS", "FRIENDS":
		return v.(string)
	default:
		return "SELF"
	}
}

// acceptsFriendRequests reports the receiver's 30811 switch: unset is the
// documented default (on), and only an explicit false refuses. Anything that
// is not a bool is a stored-raw relic, not a switch position [C10].
func acceptsFriendRequests(u *User) bool {
	if u == nil {
		return true
	}
	if v, ok := u.Permissions["friendRequestReception"]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return true
}

// prefOf reads the viewer's preference record for one friend. Empty records
// are never created by a read: a preference that was never set stays unset.
func (s *server) prefOf(viewer *User, friendBaasID string) *FriendPreference {
	if viewer == nil {
		return nil
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if viewer.FriendPrefs == nil {
		return nil
	}
	p := viewer.FriendPrefs[friendBaasID]
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

// visiblePresence renders one friend's presence for this viewer: the fresh
// aggregate of their devices, flattened to a plain OFFLINE when the viewer
// may not see it (PRE-03). It never invents recency: timestamps come from the
// state changes that produced the entry, not from this render.
func (s *server) visiblePresence(viewer *User, f Friend, now int64) map[string]any {
	lease := presenceLease()
	subject := s.store.User(f.BaasUserID)
	if subject == nil {
		// No local record: fall back to what the lookup carried, timestamped
		// by what we know about the relationship rather than by this render.
		p := Presence{State: "OFFLINE", UpdatedAt: f.CreatedAt}
		if f.PresenceStatus > 0 {
			p = Presence{State: "ONLINE", AppField: f.PresenceAppField, AppID: f.PresenceAppID,
				PresenceGroupID: f.PresenceAppID, UpdatedAt: f.CreatedAt}
			if f.PresenceStatus == 2 {
				p.State = "PLAYING"
			}
		}
		return presenceObj(p)
	}
	// The caller renders the core's friend list, so friendship is established;
	// presenceVisible answers the privacy half.
	if !presenceVisible(viewer, subject, true) {
		return presenceObj(Presence{State: "OFFLINE", UpdatedAt: now})
	}
	agg := aggregatePresence(subject, now, lease)
	if agg.State == "OFFLINE" {
		// Nothing of theirs is live on a Switch. The core knows where else
		// they are, and a friend playing on another console is still somebody
		// to say hello to.
		if b, ok := s.acct.(*openpakBackend); ok {
			if elsewhere, live := s.presenceFromCore(b.accountFor(f.PID), b.namespace, now); live {
				elsewhere.LogoutAt = agg.LogoutAt
				return presenceObj(elsewhere)
			}
		}
	}
	return presenceObj(homeAsOnline(agg))
}

// ---------- core mutations (SOC-03) ----------

// errReversePending is the adapter's rendering of the core's one-request-per-
// pair rule: the person we are asking has already asked us. The handler turns
// it into a truthful description of the request that already exists, so the
// console shows the pending incoming request instead of an error.
var errReversePending = errors.New("a request from them is already pending")

// errForbiddenMutation marks an authenticated caller acting on a request that
// is not theirs to act on (cross-account denial).
var errForbiddenMutation = errors.New("not this user's request to answer")

// baasFailure maps a core mutation failure onto the BAAS error contract.
// Only established error codes are used; the console reacts to codes it knows
// and shows a communication error for anything else, so inventing precise
// ones buys nothing. What the PRD requires — never return success for an
// uncommitted operation — is what these statuses guarantee.
func baasFailure(err error) (int, string, string, string) {
	switch {
	case err == nil:
		// unreachable except by misuse; fail closed
	case errors.Is(err, errCoreInvalid):
		return 400, "invalid_params", "Invalid Params", "the request was rejected"
	case errors.Is(err, errCoreNotFound):
		return 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found"
	case errors.Is(err, errStateConflict):
		// Blocked, not-pending, reverse-pending: the relationship is not in
		// the state the console believes. A 404 sends it back to re-sync its
		// boxes, which is the recovery the state needs.
		return 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found"
	case errors.Is(err, errCoreUnavailable):
		return 503, "internal_server_error", "Internal Server Error", "the account service is unavailable"
	case errors.Is(err, errForbiddenMutation):
		return 403, "insufficient_scope", "Token is insufficient", "not your request to answer"
	}
	return 500, "internal_server_error", "Internal Server Error", "internal error"
}

// commitFriendRequest commits a request through the core and resolves the
// durable id of the request that exists afterwards. Duplicate posts and
// retries are idempotent (the core keeps one pending row per pair/direction).
// Crossed requests — the person we are asking has already asked us — are the
// two of them agreeing: the pending request is accepted, and authorized says
// so. The console expects exactly that: a send answered with state
// AUTHORIZED is the case "the receiver had already asked the sender", and it
// syncs its friend list at once [friends-contract-22.5.0 §A.4.1, C4].
func (s *server) commitFriendRequest(me *User, target *Friend) (created, authorized bool, reqID string, err error) {
	if err := s.acct.FriendRequest(me.PID, target.PID); err != nil {
		if errors.Is(err, errReversePending) {
			id, _ := s.store.EnsureRequest(target.PID, me.PID)
			if err := s.acct.FriendAccept(me.PID, target.PID, true); err != nil {
				return false, false, "", err
			}
			s.store.SettleRequest(id, "AUTHORIZED")
			return false, true, id, nil
		}
		return false, false, "", err
	}
	id, created := s.store.EnsureRequest(me.PID, target.PID)
	return created, false, id, nil
}

// friendRequestReply renders the request the console should believe in, after
// the core call has committed or matched it. When incoming, sender/receiver
// are the truth of the existing request, not what the caller asked for.
func (s *server) friendRequestReply(me *User, id *Identity, target *Friend, reqID string, incoming bool, body []byte, now int64) map[string]any {
	record := s.store.RequestByID(reqID)
	createdAt, updatedAt := now, now
	if record != nil {
		createdAt, updatedAt = record.CreatedAt, record.UpdatedAt
	}
	senderObj, receiverObj := any(s.userObj(me, id, "")), any(s.friendObj(*target, now))
	senderID, receiverID := me.ID, target.BaasUserID
	if incoming {
		senderObj, receiverObj = receiverObj, senderObj
		senderID, receiverID = target.BaasUserID, me.ID
	}
	channels := channelsOf(body)
	if record != nil && record.Channel != "" {
		channels = requestChannels(record)
	}
	return map[string]any{
		"id": reqID, "senderId": senderID, "receiverId": receiverID,
		"sender": senderObj, "receiver": receiverObj,
		"state": "PENDING", "channels": channels,
		"createdAt": createdAt, "updatedAt": updatedAt,
	}
}

// requestChannels is the channel a request was sent with, as the one-element
// array the console reads channels[0] from. Requests that predate the record
// keeping it, or that came from the core rather than a console, say
// FRIEND_CODE as they always did.
func requestChannels(record *FriendRequestRecord) []string {
	if record == nil || record.Channel == "" {
		return []string{"FRIEND_CODE"}
	}
	return []string{record.Channel}
}

// noteRequestRoute keeps the channel and route extras of the POST that
// created a request, so both boxes can show which game, name or catalog it
// came from [friends-contract-22.5.0 §A.4.1].
func (s *server) noteRequestRoute(reqID string, body []byte) {
	var in struct {
		Channels []string `json:"channels"`
		Extras   struct {
			Sender            map[string]any `json:"sender"`
			SenderAndReceiver map[string]any `json:"senderAndReceiver"`
		} `json:"extras"`
	}
	if json.Unmarshal(body, &in) != nil {
		return
	}
	channel := ""
	if len(in.Channels) > 0 {
		channel = in.Channels[0]
	}
	if channel == "" && in.Extras.Sender == nil && in.Extras.SenderAndReceiver == nil {
		return
	}
	s.store.SetRequestRoute(reqID, channel, in.Extras.Sender, in.Extras.SenderAndReceiver)
}

// settleRequest accepts or rejects the request addressed to me. The durable
// record names the pair; the core owns the state. Reject, like cancel and
// remove, ends the pending relationship, which is why all three map to the
// backend's RemoveFriend.
func (s *server) settleRequest(me *User, record *FriendRequestRecord, accept bool) error {
	if me.PID != record.ToPID {
		return errForbiddenMutation
	}
	return s.acct.FriendAccept(me.PID, record.FromPID, accept)
}

// cancelRequest withdraws a request I sent.
func (s *server) cancelRequest(me *User, record *FriendRequestRecord) error {
	if me.PID != record.FromPID {
		return errForbiddenMutation
	}
	return s.acct.RemoveFriend(me.PID, record.ToPID)
}

// removeFriend commits a removal through the core and marks both lists.
// Never a silent no-op: the console's remove button must either commit or
// say so.
func (s *server) removeFriend(me *User, other *Friend) error {
	if err := s.acct.RemoveFriend(me.PID, other.PID); err != nil {
		return err
	}
	s.friendGraphChanged(me, other.BaasUserID)
	return nil
}

// setBlock commits a block or unblock through the core (which owns
// enforcement) and mirrors it locally for the surfaces that read this store's
// block list.
func (s *server) setBlock(me *User, other *Friend, block bool) error {
	var err error
	if block {
		err = s.acct.Block(me.PID, other.PID)
	} else {
		err = s.acct.Unblock(me.PID, other.PID)
	}
	if err != nil {
		return err
	}
	s.store.Update(me, func(u *User) {
		kept := u.Blocks[:0]
		for _, b := range u.Blocks {
			if b != other.BaasUserID {
				kept = append(kept, b)
			}
		}
		u.Blocks = kept
		if block {
			u.Blocks = append(u.Blocks, other.BaasUserID)
		} else {
			delete(u.BlockDetails, other.BaasUserID)
		}
	})
	return nil
}

// maxBlockEntries is the block list's bound in the console: it asks for
// count=100 and a 101st item fails the whole parse [friends-contract-22.5.0
// §A.8].
const maxBlockEntries = 100

// blockObj renders one block-list item as the console parses it:
// targetUserId and targetUser.nickname are required, and an item without
// them fails the whole list, so a target this network cannot resolve still
// gets a nickname (empty) and the default picture [friends-contract-22.5.0
// §A.8].
func (s *server) blockObj(u *User, target string, now int64) map[string]any {
	user := map[string]any{"nickname": "", "thumbnailUrl": cdnHost + "/1/default"}
	if f := s.resolveFriend(target); f != nil {
		user = s.friendObj(*f, now)
	}
	item := map[string]any{"targetUserId": target, "targetUser": user}
	s.store.mu.Lock()
	d := u.BlockDetails[target]
	s.store.mu.Unlock()
	if d != nil {
		item["createdAt"] = d.CreatedAt
		if d.Self != nil {
			item["extras"] = map[string]any{"self": d.Self}
		}
	}
	return item
}

// resolveFriend looks a target up by BAAS user id, for the mutation handlers
// that receive one.
func (s *server) resolveFriend(baasID string) *Friend {
	f, err := s.acct.Resolve(url.Values{"baas": {baasID}})
	if err != nil || f == nil {
		return nil
	}
	return f
}

// friendByPID renders what this network knows about a PID, for the replies
// that name the other side of a mutation by id (an accepted request naming
// its sender, for example). nil when the account has no readable identity.
func (s *server) friendByPID(pid uint64) *Friend {
	id, err := s.acct.Identity(pid)
	if err != nil || id == nil {
		return nil
	}
	return &Friend{PID: pid, BaasUserID: id.BaasUserID, NaID: id.NaID, FriendCode: id.FriendCode,
		Nickname: id.Nickname, Country: id.Country}
}

// friendRequestByRef maps an incoming console reference — a durable request
// id from this server, or a bare user id from an inbox rendered by an older
// build — onto its record and the friend it is about. Exactly one of the two
// results is non-nil.
func (s *server) friendRequestByRef(ref string) (*FriendRequestRecord, *Friend) {
	if record := s.store.RequestByID(ref); record != nil {
		return record, nil
	}
	return nil, s.resolveFriend(ref)
}
