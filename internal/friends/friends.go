package friends

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"nx-baas/internal/core"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/presence"
	"nx-baas/internal/store"
	"nx-baas/redact"
	"sort"
	"strconv"
	"strings"
	"time"
)

// /1.0.0/users/<id>/{friends,friend_requests,relationships}: older-firmware spellings, same data.
func (s *Service) HandleV1(w http.ResponseWriter, r *http.Request, u *store.User, rest []string, body []byte) {
	s.HandleV2(w, r, append([]string{"users", u.ID}, rest...), body)
}

// /2.0.0 friends surface: see the function comment on friends2.
func (s *Service) HandleV2(w http.ResponseWriter, r *http.Request, seg []string, body []byte) {
	now := time.Now().Unix()
	var in map[string]any
	json.Unmarshal(body, &in)
	form, _ := url.ParseQuery(string(body))
	field := func(k string) string {
		if v := httpx.Str(in, k); v != "" {
			return v
		}
		return form.Get(k)
	}
	// me: the authenticated caller. The path-based identity is gone:
	// trusting /users/<id> to choose whose social state is accessed is what
	// let one account read another's list.
	me := s.BearerUser(r)
	if me == nil {
		httpx.BaasErr(w, r, 401, "invalid_token", "Invalid token", "a current access token is required")
		return
	}
	// The caller's identity as the core sees it, for rendering "me" objects.
	myID := s.Identity(me)

	switch {
	case len(seg) == 3 && seg[0] == "users" && seg[2] == "friends" && r.Method == "GET":
		if s.RequireCaller(w, r, seg[1]) == nil {
			return
		}
		list := []any{}
		if myID != nil {
			for _, f := range myID.Friends {
				// One relationship entry per core friend, in the shape the
				// 22.5.0 parser counts: friendId + friend{nickname,
				// thumbnailUrl} + the viewer's own relationship state.
				list = append(list, s.RelationshipObj(me, f, now))
			}
			if len(list) > MaxListEntries {
				// The parser caps at 300 itself; sending more would be
				// dropped silently at the far end. No native cursor exists
				// to paginate with, so the bound is the contract.
				list = list[:MaxListEntries]
			}
		}
		httpx.WriteJSON(w, 200, ListEnvelopeWith(list, `""`, 100))
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "friends" && r.Method == "PATCH":
		// Relationship preferences (SOC-02): /isFavorite (what 22.5.0 sends),
		// /extras/self/isConfirmed (the new-friend acknowledgement) and
		// /extras/self/isOnlineNotification (the online-alert preference).
		// The older isFavoriteFriend spelling maps to the same persisted
		// state: one relationship, one favourite flag.
		if s.RequireCaller(w, r, seg[1]) == nil {
			return
		}
		var ops []struct {
			Op, Path string
			Value    any
		}
		_ = json.Unmarshal(body, &ops)
		changed := false
		s.Store.Update(me, func(u *store.User) {
			for _, o := range ops {
				p := u.Pref(seg[3])
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
			httpx.BaasErr(w, r, 400, "invalid_params", "Invalid Params", "no known relationship field in patch")
			return
		}
		// Answer with the single-friend shape the firmware's single-entry
		// parser reads: $.friendId, $.friend.nickname, $.isFavorite.
		target := s.ResolveFriend(seg[3])
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
			target = &identity.Friend{BaasUserID: seg[3]}
		}
		httpx.WriteJSON(w, 200, s.RelationshipObj(me, *target, now))
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "friends" && r.Method == "DELETE":
		// Removing a friend commits through the core (SOC-03). The old reply
		// logged "not applied" and answered 204, which was a success statement
		// about an operation that never happened.
		if s.RequireCaller(w, r, seg[1]) == nil {
			return
		}
		target := s.ResolveFriend(seg[3])
		if target == nil {
			httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if err := s.removeFriend(me, target); err != nil {
			log.Printf("[nx-baas] friend-remove failed user=%s other=%s: %v", redact.Tag(me.ID), redact.Tag(seg[3]), redact.Err(err))
			status, code, title, detail := BaasFailure(err)
			httpx.BaasErr(w, r, status, code, title, detail)
			return
		}
		w.WriteHeader(204)
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "friend_requests":
		// The request boxes. Entries name their durable request id, so the
		// console's PATCH/DELETE later means the same request whoever answers
		// (SOC-03). The core's lists are the state of record; the ids are the
		// adapter's mapping, persisted across restarts.
		if s.RequireCaller(w, r, seg[1]) == nil {
			return
		}
		if myID == nil {
			httpx.BaasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "not linked")
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
		meObj := s.UserObj(me, myID, "")
		for _, f := range requests {
			var reqID string
			if incoming {
				reqID, _ = s.Store.EnsureRequest(f.PID, me.PID)
			} else {
				reqID, _ = s.Store.EnsureRequest(me.PID, f.PID)
			}
			record := s.Store.RequestByID(reqID)
			createdAt, updatedAt := now, now
			if record != nil {
				createdAt, updatedAt = record.CreatedAt, record.UpdatedAt
			}
			other := s.FriendObj(f, now)
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
		httpx.WriteJSON(w, 200, ListEnvelope(items))
		return

	case len(seg) == 1 && seg[0] == "friend_requests" && r.Method == "POST":
		if myID == nil {
			httpx.BaasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "not linked")
			return
		}
		var target *identity.Friend
		var err error
		if c := field("friendCode"); c != "" {
			target, err = s.Acct.Resolve(url.Values{"code": {identity.NormaliseFriendCode(c)}})
		} else if t := field("receiverId"); t != "" {
			target, err = s.Acct.Resolve(url.Values{"baas": {t}})
		} else if t := field("userId"); t != "" {
			target, err = s.Acct.Resolve(url.Values{"baas": {t}})
		} else {
			httpx.Dump(r, body, "friend_requests: unknown body")
		}
		if err != nil || target == nil {
			httpx.BaasErr(w, r, 400, "invalid_friend_code_format", "Invalid friend code", "no such user")
			return
		}
		// 30811 ChangeFriendRequestReception: a receiver who turned requests
		// off refuses new ones [friends-contract-22.5.0 §A.6, C10]. A crossed
		// send is not new: the receiver already asked, and answering completes
		// the friendship they initiated.
		if receiver := s.Store.User(target.BaasUserID); !acceptsFriendRequests(receiver) &&
			!s.Store.OpenRequest(target.PID, me.PID) {
			httpx.BaasErr(w, r, 400, "could_not_send_request", "Could Not Send Request", "not accepting friend requests")
			return
		}
		created, authorized, reqID, err := s.commitFriendRequest(me, target)
		if err != nil {
			// The request did not commit, so this is an error, never a
			// success with a timestamp (the old code logged the failure and
			// answered 201 anyway).
			log.Printf("[nx-baas] friend-request failed user=%s target=%s: %v", redact.Tag(me.ID), redact.Tag(target.BaasUserID), redact.Err(err))
			status, code, title, detail := BaasFailure(err)
			httpx.BaasErr(w, r, status, code, title, detail)
			return
		}
		if created {
			s.NoteRequestRoute(reqID, body)
		}
		s.FriendGraphChanged(me, target.BaasUserID)
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
		httpx.WriteJSON(w, code, reply)
		return

	case len(seg) == 2 && seg[0] == "friend_requests" && (r.Method == "PATCH" || r.Method == "DELETE"):
		if myID == nil {
			httpx.BaasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "not linked")
			return
		}
		state := patchedState(body)
		if r.Method == "DELETE" {
			state = "CANCELED"
		}
		record, other := s.friendRequestByRef(seg[1])
		if state == "" {
			// Marked read, not answered: the request stays open.
			var target *identity.Friend
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
				httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
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
					s.Store.MarkRequestRead(record.ID, v)
					read = v
				}
			}
			reply := s.friendRequestReply(me, myID, target, seg[1], incoming, nil, now)
			if record != nil && record.State != "" {
				reply["state"] = requestState(record.State)
			}
			reply["extras"] = map[string]any{"receiver": map[string]any{"read": read}}
			httpx.WriteJSON(w, 200, reply)
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
				httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
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
				httpx.BaasErr(w, r, 400, "invalid_params", "Invalid Params", "unknown request state")
				return
			}
			if err == nil {
				s.Store.SettleRequest(record.ID, state) // a stale id must not commit twice
			}
		case other != nil:
			// A bare user id: a request box cached by an older build of this
			// server. The core enforces the direction — accepting a request
			// that does not address this caller fails there.
			if state == "CANCELED" {
				err = s.Acct.RemoveFriend(me.PID, other.PID)
			} else {
				err = s.Acct.FriendAccept(me.PID, other.PID, state == "AUTHORIZED")
			}
		default:
			httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
			return
		}
		if err != nil {
			// No commit, no success: the console is told, in its own error
			// contract, and can re-sync.
			log.Printf("[nx-baas] friend-request %s failed user=%s ref=%s: %v", state, redact.Tag(me.ID), redact.Tag(seg[1]), redact.Err(err))
			status, code, title, detail := BaasFailure(err)
			httpx.BaasErr(w, r, status, code, title, detail)
			return
		}
		// The other side of the request, for the reply the console expects.
		var otherFriend *identity.Friend
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
			otherFriend = &identity.Friend{BaasUserID: seg[1]}
		}
		otherBaas := otherFriend.BaasUserID
		s.FriendGraphChanged(me, otherBaas)
		// An acceptance completes the new-friend acknowledgement too: the
		// friendship is not news to the person who just accepted it.
		if state == "AUTHORIZED" {
			s.Store.Update(me, func(u *store.User) {
				p := u.Pref(otherBaas)
				p.Confirmed, p.UpdatedAt = true, now
			})
		}
		// The console sets the state itself -- [{"op":"replace","path":"/state",
		// "value":"AUTHORIZED"}] -- and expects that word back. We answered
		// with our own vocabulary ("ACCEPTED") and a three-field stub, and the
		// console called it a communication error even though the friendship
		// had gone through.
		otherObj := s.FriendObj(*otherFriend, now)
		meObj := s.UserObj(me, myID, "")
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
		httpx.WriteJSON(w, 200, map[string]any{
			"id":       seg[1],
			"senderId": senderID, "receiverId": receiverID,
			"sender": senderObj, "receiver": receiverObj,
			"state": state, "channels": requestChannels(record),
			"createdAt": createdAt, "updatedAt": now,
		})
		return

	case len(seg) == 4 && seg[0] == "users" && seg[2] == "relationships":
		if s.RequireCaller(w, r, seg[1]) == nil {
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
		if f := s.ResolveFriend(seg[3]); f != nil {
			rel["targetUser"] = s.FriendObj(*f, now)
		}
		for _, b := range me.Blocks {
			if b == seg[3] {
				rel["isBlocking"] = true
			}
		}
		if p := s.PrefOf(me, seg[3]); p != nil && p.Favorite {
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
		httpx.WriteJSON(w, 200, rel)
		return
	}
	httpx.Dump(r, body, "!! UNHANDLED 2.0.0")
	httpx.BaasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
}

// Service is the friends surface (friends, friend requests, relationships, blocks) and the
// BAAS user and friend objects it renders, over the shared state.
type Service struct {
	*core.Core
	Presence *presence.Service
}
