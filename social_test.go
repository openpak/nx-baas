package main

// Social mutation tests (SOC-03/04/05) and the authentication rules that
// guard the surface: durable request identity, cross-account denial,
// duplicate/reverse request behaviour, block/unblock and removal committing
// through the core (or failing loudly), and the emulator friend-code lookup.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// socialServer wires the OpenPak backend (over the fake core) to a real
// server and store, with two linked users: users[0] and users[1], each with
// a projection, a friend code, and a mutual friendship. The store user is
// keyed by the projection's BAAS id, exactly as a console link re-keys it.
func socialServer(t *testing.T) (*server, *fakeCore, []*User) {
	t.Helper()
	b, f := newTestBackend(t)
	s := dauthServer(t)
	s.store = loadStore(t.TempDir() + "/baas.json")
	s.acct = b

	users := []*User{}
	for _, acc := range []struct{ id, name, pw string }{
		{"acc-a@example.com", "PlayerA", "pw-a-aaaaaaaaaaa"},
		{"acc-b@example.com", "PlayerB", "pw-b-bbbbbbbbbbb"},
	} {
		f.addAccount(acc.id, acc.name, acc.pw)
		pid, _, err := b.LoginPID(acc.id, acc.pw)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := s.store.NewUser()
		baas := b.proj.ByAccount[acc.id].BaasUserID
		s.store.mu.Lock()
		delete(s.store.Users, u.ID)
		u.ID = baas
		s.store.Users[baas] = u
		for _, d := range s.store.Devices { // the device account follows the user
			if d.UserID == u.ID || d.UserID == "" {
				d.UserID = baas
			}
		}
		s.store.mu.Unlock()
		s.store.Update(u, func(u *User) { u.PID, u.Nickname = pid, acc.name })
		users = append(users, s.store.User(baas))
	}
	f.befriend("acc-a@example.com", "acc-b@example.com")
	return s, f, users
}

// authed builds a request with the caller's own live access token.
func authed(method, path, body string, u *User, s *server) *http.Request {
	r := httptest.NewRequest(method, "https://"+baasHost+path, strings.NewReader(body))
	r.Host = baasHost
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	return r
}

// postRequest drives POST /2.0.0/friend_requests and decodes the reply.
func postRequest(t *testing.T, s *server, from *User, body string) (int, map[string]any) {
	t.Helper()
	r := authed("POST", "/2.0.0/friend_requests", body, from, s)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// answerRequest drives PATCH/DELETE /2.0.0/friend_requests/<id>.
func answerRequest(t *testing.T, s *server, by *User, method, id, body string) (int, map[string]any) {
	t.Helper()
	r := authed(method, "/2.0.0/friend_requests/"+id, body, by, s)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A request has its own durable id, and that id means the same request to
// create, inbox, outbox, accept and cancel — including across a restart
// (SOC-03: the old in-process map lost all of it).
func TestDurableRequestIdentitySurvivesRestart(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]
	f.friends, f.incoming, f.outgoing = map[string][]string{}, map[string][]string{}, map[string][]string{}

	code, reply := postRequest(t, s, a, `{"friendCode":"`+codeOf(s, b)+`"}`)
	if code != http.StatusCreated || reply["state"] != "PENDING" {
		t.Fatalf("create: %d %v", code, reply)
	}
	reqID, _ := reply["id"].(string)
	if reqID == "" || reqID == b.ID {
		t.Fatalf("request id %v is not its own", reply["id"])
	}

	// The inbox names the same request by the same id.
	r := authed("GET", "/2.0.0/users/"+b.ID+"/friend_requests/inbox", "", b, s)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var inbox struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &inbox)
	if len(inbox.Items) != 1 || inbox.Items[0]["id"] != reqID {
		t.Fatalf("inbox: %v", inbox.Items)
	}

	// Restart: the id still resolves and still authorizes the addressee.
	s.store = loadStore(s.store.path)
	code, reply = answerRequest(t, s, b, "PATCH", reqID, `[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`)
	if code != http.StatusOK || reply["state"] != "AUTHORIZED" {
		t.Fatalf("accept after restart: %d %v", code, reply)
	}

	// And the friendship exists in the core for both.
	idA, _ := s.acct.Identity(a.PID)
	if len(idA.Friends) != 1 || idA.Friends[0].BaasUserID != b.ID {
		t.Fatalf("friends after accept: %+v", idA.Friends)
	}
}

// Opening the request box marks the request read. That is not an answer: the
// request stays open, the inbox still shows it, and nobody became friends
// (2026-09-12: every request was "accepted" the moment Leia looked at it).
func TestMarkingARequestReadDoesNotAcceptIt(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]
	f.friends, f.incoming, f.outgoing = map[string][]string{}, map[string][]string{}, map[string][]string{}

	_, reply := postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	reqID, _ := reply["id"].(string)
	code, read := answerRequest(t, s, b, "PATCH", reqID, `[{"op":"add","path":"/extras/receiver/read","value":true}]`)
	if code != http.StatusOK || read["state"] != "PENDING" {
		t.Fatalf("mark read: %d %v", code, read)
	}
	if id, _ := s.acct.Identity(a.PID); len(id.Friends) != 0 {
		t.Fatalf("marking read befriended: %+v", id.Friends)
	}
	// Still answerable afterwards.
	if code, reply := answerRequest(t, s, b, "PATCH", reqID,
		`[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`); code != http.StatusOK || reply["state"] != "AUTHORIZED" {
		t.Fatalf("accept after read: %d %v", code, reply)
	}
}

// Both sides of an acceptance (J1): A requests, B accepts, both lists show
// the relationship. Also: duplicates are idempotent, and crossed requests are
// an acceptance: B asking A while A's request is pending answers AUTHORIZED,
// which is what makes B's console sync its list at once
// [friends-contract-22.5.0 §A.4.1, C4].
func TestRequestAcceptAndTheReverseCase(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]
	f.friends, f.incoming, f.outgoing = map[string][]string{}, map[string][]string{}, map[string][]string{}

	code1, r1 := postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	code2, r2 := postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	if code1 != http.StatusCreated || code2 != http.StatusOK {
		t.Fatalf("duplicate creates: %d/%d", code1, code2)
	}
	if r1["id"] != r2["id"] {
		t.Errorf("duplicate requests got ids %v and %v; a retry must not mint a second request", r1["id"], r2["id"])
	}
	// Crossed: B asks A while A's request is pending. They both want it, so
	// it is accepted, and the reply is still read in sender mode: A is the
	// receiver B asked.
	code3, r3 := postRequest(t, s, b, `{"receiverId":"`+a.ID+`"}`)
	if code3 != http.StatusOK {
		t.Fatalf("reverse request: %d %v", code3, r3)
	}
	if r3["state"] != "AUTHORIZED" || r3["id"] != r1["id"] {
		t.Errorf("crossed request did not answer the accepted request: %v", r3)
	}
	if gaps := requestReplyGaps(r3, a, true); gaps != nil {
		t.Errorf("crossed reply lacks %v", gaps)
	}

	// The console may still answer the request it saw in its inbox; the
	// repeat replies the same and commits nothing.
	if code, reply := answerRequest(t, s, b, "PATCH", r3["id"].(string),
		`[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`); code != http.StatusOK || reply["state"] != "AUTHORIZED" {
		t.Fatalf("accept: %d %v", code, reply)
	}
	// Both lists are current with one mutual friend, and neither box holds
	// the request any more.
	for i, u := range []*User{a, b} {
		id, err := s.acct.Identity(u.PID)
		if err != nil || len(id.Friends) != 1 || len(id.FriendRequests)+len(id.SentRequests) != 0 {
			t.Fatalf("user %d after the crossed request: %+v %v", i, id, err)
		}
	}
}

// Reject and cancel end a pending request; remove ends a friendship; none of
// them can return success for an uncommitted operation.
func TestRejectCancelRemoveCommitOrError(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]
	friends0 := func() int {
		id, _ := s.acct.Identity(a.PID)
		return len(id.Friends)
	}

	// Reject: the request is gone and no friendship exists.
	_, req := postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	if code, reply := answerRequest(t, s, b, "PATCH", req["id"].(string),
		`[{"op":"replace","path":"/state","value":"REJECTED"}]`); code != http.StatusOK || reply["state"] != "REJECTED" {
		t.Fatalf("reject: %d %v", code, reply)
	}
	if id, _ := s.acct.Identity(a.PID); len(id.FriendRequests)+len(id.Friends)+len(id.SentRequests) != 0 {
		t.Errorf("rejected request left state: %+v", id)
	}

	// Cancel by the requester.
	_, req = postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	if code, _ := answerRequest(t, s, a, "DELETE", req["id"].(string), ""); code != http.StatusOK {
		t.Fatalf("cancel: %d", code)
	}
	if id, _ := s.acct.Identity(a.PID); len(id.SentRequests) != 0 {
		t.Errorf("cancelled request still in the outbox: %+v", id.SentRequests)
	}

	// Remove an actual friendship.
	f.befriend("acc-a@example.com", "acc-b@example.com")
	if friends0() != 1 {
		t.Fatal("fixture: expected one friendship")
	}
	r := authed("DELETE", "/2.0.0/users/"+a.ID+"/friends/"+b.ID, "", a, s)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", w.Code, w.Body.String())
	}
	if friends0() != 0 {
		t.Error("remove answered 204 but the friendship survived in the core")
	}

	// An uncommitted operation never reads as success: accepting a request
	// that does not exist fails in the core and must fail here.
	r = authed("PATCH", "/2.0.0/friend_requests/"+b.ID,
		`[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`, b, s)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code < 400 {
		t.Errorf("accepting a nonexistent request returned %d", w.Code)
	}
}

// requestReplyGaps returns the fields the 22.5.0 request parser requires and
// this reply lacks, in the mode the console reads it: sender mode (send,
// cancel) wants receiverId and receiver.*, receiver mode (accept, reject)
// wants senderId and sender.* [friends-contract-22.5.0 §A.4.1, §A.4.4].
func requestReplyGaps(reply map[string]any, other *User, senderMode bool) []string {
	var gaps []string
	if v, _ := reply["id"].(string); v == "" {
		gaps = append(gaps, "id")
	}
	if ch, _ := reply["channels"].([]any); len(ch) == 0 {
		gaps = append(gaps, "channels[0]")
	} else if v, _ := ch[0].(string); v == "" {
		gaps = append(gaps, "channels[0]")
	}
	if v, _ := reply["state"].(string); v == "" {
		gaps = append(gaps, "state")
	}
	party := "sender"
	if senderMode {
		party = "receiver"
	}
	if reply[party+"Id"] != other.ID {
		gaps = append(gaps, party+"Id")
	}
	obj, _ := reply[party].(map[string]any)
	if _, ok := obj["nickname"].(string); !ok {
		gaps = append(gaps, party+".nickname")
	}
	if v, _ := obj["thumbnailUrl"].(string); v == "" {
		gaps = append(gaps, party+".thumbnailUrl")
	}
	return gaps
}

// 30202 cancels with "CANCELED", one L. The server only knew "CANCELLED", so
// every console cancel was 400 invalid_params (2121-2001) and a sender could
// never withdraw a request [friends-contract-22.5.0 §A.4.4, C1]. The reply is
// read in sender mode; accept and reject are read in receiver mode.
func TestCancelUsesTheConsolesSpellingAndEveryReplyIsTheFullRequest(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]
	f.friends, f.incoming, f.outgoing = map[string][]string{}, map[string][]string{}, map[string][]string{}

	code, sent := postRequest(t, s, a, `{"channels":["FRIEND_CODE"],"senderId":"`+a.ID+`","receiverId":"`+b.ID+`","extras":{"sender":{"route:sender":"me"}}}`)
	if code >= 300 {
		t.Fatalf("send: %d %v", code, sent)
	}
	if gaps := requestReplyGaps(sent, b, true); gaps != nil {
		t.Errorf("send reply lacks %v: %v", gaps, sent)
	}
	code, canceled := answerRequest(t, s, a, "PATCH", sent["id"].(string), `[{"op":"replace","path":"/state","value":"CANCELED"}]`)
	if code != http.StatusOK || canceled["state"] != "CANCELED" {
		t.Fatalf("cancel: %d %v", code, canceled)
	}
	if gaps := requestReplyGaps(canceled, b, true); gaps != nil {
		t.Errorf("cancel reply lacks %v: %v", gaps, canceled)
	}
	if id, _ := s.acct.Identity(a.PID); len(id.SentRequests) != 0 {
		t.Errorf("canceled request still in the outbox: %+v", id.SentRequests)
	}
	// The console repeats a PATCH; the repeat answers the same.
	if code, again := answerRequest(t, s, a, "PATCH", sent["id"].(string), `[{"op":"replace","path":"/state","value":"CANCELED"}]`); code != http.StatusOK || again["state"] != "CANCELED" {
		t.Errorf("repeat cancel: %d %v", code, again)
	}

	// The old spelling still cancels.
	_, sent = postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	if code, _ := answerRequest(t, s, a, "PATCH", sent["id"].(string), `[{"op":"replace","path":"/state","value":"CANCELLED"}]`); code != http.StatusOK {
		t.Errorf("CANCELLED no longer cancels: %d", code)
	}

	// Reject and accept are read in receiver mode.
	_, sent = postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	code, rejected := answerRequest(t, s, b, "PATCH", sent["id"].(string), `[{"op":"replace","path":"/state","value":"REJECTED"}]`)
	if code != http.StatusOK {
		t.Fatalf("reject: %d %v", code, rejected)
	}
	if gaps := requestReplyGaps(rejected, a, false); gaps != nil {
		t.Errorf("reject reply lacks %v: %v", gaps, rejected)
	}
	_, sent = postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	code, accepted := answerRequest(t, s, b, "PATCH", sent["id"].(string), `[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`)
	if code != http.StatusOK {
		t.Fatalf("accept: %d %v", code, accepted)
	}
	if gaps := requestReplyGaps(accepted, a, false); gaps != nil {
		t.Errorf("accept reply lacks %v: %v", gaps, accepted)
	}
}

// requestBox drives GET /2.0.0/users/<id>/friend_requests/<box><query>.
func requestBox(t *testing.T, s *server, u *User, box, query string) []map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, authed("GET", "/2.0.0/users/"+u.ID+"/friend_requests/"+box+query, "", u, s))
	if w.Code != http.StatusOK {
		t.Fatalf("%s%s: %d %s", box, query, w.Code, w.Body.String())
	}
	var out struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out.Items
}

// The request badge is the inbox items without extras.receiver.read:true.
// 30205 marked a request read and we echoed it, but the inbox never carried
// the flag, so the badge never cleared. The console also pages the boxes and
// trusts the server to: offset from the IPC call, count from its buffer,
// newest first, PENDING only [friends-contract-22.5.0 §A.4.2, §A.4.3, C3].
func TestRequestBoxCarriesReadAndHonoursThePage(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]
	f.friends, f.incoming, f.outgoing = map[string][]string{}, map[string][]string{}, map[string][]string{}
	f.addAccount("acc-c@example.com", "PlayerC", "pw-c-ccccccccccc")
	c := newUserFor(t, s, "acc-c@example.com", "pw-c-ccccccccccc")

	_, fromA := postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	_, fromC := postRequest(t, s, c, `{"receiverId":"`+b.ID+`"}`)
	older, newer := fromA["id"].(string), fromC["id"].(string)
	s.store.mu.Lock()
	s.store.Requests[older].CreatedAt -= 60
	s.store.mu.Unlock()

	const q = "?offset=0&count=10&sort=createdAt:desc&filter.state.$eq=PENDING"
	inbox := requestBox(t, s, b, "inbox", q)
	if len(inbox) != 2 || inbox[0]["id"] != newer || inbox[1]["id"] != older {
		t.Fatalf("inbox is not newest first: %v", inbox)
	}
	read := func(item map[string]any) any {
		ex, _ := item["extras"].(map[string]any)
		rc, _ := ex["receiver"].(map[string]any)
		return rc["read"]
	}
	for _, it := range inbox {
		if read(it) != false {
			t.Errorf("unread item carries extras.receiver.read=%v", read(it))
		}
		if gaps := requestReplyGaps(it, map[string]*User{older: a, newer: c}[it["id"].(string)], false); gaps != nil {
			t.Errorf("inbox item lacks %v", gaps)
		}
	}

	// 30205 marks one read; the inbox says so from then on, and the other
	// stays unread.
	if code, _ := answerRequest(t, s, b, "PATCH", older, `[{"op":"add","path":"/extras/receiver/read","value":true}]`); code != http.StatusOK {
		t.Fatalf("mark read: %d", code)
	}
	s.store = loadStore(s.store.path) // and it survives a restart
	inbox = requestBox(t, s, b, "inbox", q)
	if read(inbox[0]) != false || read(inbox[1]) != true {
		t.Errorf("read flags after 30205: %v, %v", read(inbox[0]), read(inbox[1]))
	}
	// The sender cannot mark the receiver's flag.
	answerRequest(t, s, c, "PATCH", newer, `[{"op":"add","path":"/extras/receiver/read","value":true}]`)
	if inbox = requestBox(t, s, b, "inbox", q); read(inbox[0]) != false {
		t.Error("the sender marked the receiver's request read")
	}

	// The page: offset and count.
	if page := requestBox(t, s, b, "inbox", "?offset=1&count=1&sort=createdAt:desc&filter.state.$eq=PENDING"); len(page) != 1 || page[0]["id"] != older {
		t.Errorf("offset=1&count=1: %v", page)
	}
	if page := requestBox(t, s, b, "inbox", "?offset=0&count=1&sort=createdAt:desc&filter.state.$eq=PENDING"); len(page) != 1 || page[0]["id"] != newer {
		t.Errorf("offset=0&count=1: %v", page)
	}
	if page := requestBox(t, s, b, "inbox", "?offset=5&count=10&sort=createdAt:desc&filter.state.$eq=PENDING"); len(page) != 0 {
		t.Errorf("offset past the end: %v", page)
	}
	// Only PENDING is ever in a box.
	if page := requestBox(t, s, b, "inbox", "?offset=0&count=10&filter.state.$eq=REJECTED"); len(page) != 0 {
		t.Errorf("filter.state.$eq=REJECTED: %v", page)
	}
	// The outbox carries the receiver's six fields.
	outbox := requestBox(t, s, a, "outbox", q)
	if len(outbox) != 1 {
		t.Fatalf("outbox: %v", outbox)
	}
	if gaps := requestReplyGaps(outbox[0], b, true); gaps != nil {
		t.Errorf("outbox item lacks %v", gaps)
	}
}

// A request keeps the channel and route it was sent with. The boxes said
// FRIEND_CODE for everything and dropped the POST's extras, so an in-app
// request showed no game and no in-app name. The inbox reads the route from
// extras.senderAndReceiver, the outbox from extras.sender; extras.sender is
// the sender's own [friends-contract-22.5.0 §A.4.1, §A.4.2, C3, C4].
func TestRequestBoxesKeepTheChannelAndRoute(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]
	f.friends, f.incoming, f.outgoing = map[string][]string{}, map[string][]string{}, map[string][]string{}

	body := `{"channels":["IN_APP"],"senderId":"` + a.ID + `","receiverId":"` + b.ID + `","extras":{` +
		`"sender":{"route:sender":"me","route:name":"Bobby","route:name:language":"en-US"},` +
		`"senderAndReceiver":{"route:appInfo:appId":"0100a5a020d5e000","route:appInfo:acdIndex":0,` +
		`"route:appInfo:presenceGroupId":"0100a5a020d5e000","route:name":"Alice","route:name:language":"en-US"}}}`
	code, sent := postRequest(t, s, a, body)
	if code >= 300 {
		t.Fatalf("send: %d %v", code, sent)
	}
	if ch, _ := sent["channels"].([]any); len(ch) != 1 || ch[0] != "IN_APP" {
		t.Errorf("send reply channels: %v", sent["channels"])
	}
	extras := func(item map[string]any, group string) map[string]any {
		ex, _ := item["extras"].(map[string]any)
		g, _ := ex[group].(map[string]any)
		return g
	}

	inbox := requestBox(t, s, b, "inbox", "?offset=0&count=10")
	if len(inbox) != 1 {
		t.Fatalf("inbox: %v", inbox)
	}
	if ch, _ := inbox[0]["channels"].([]any); len(ch) != 1 || ch[0] != "IN_APP" {
		t.Errorf("inbox channels: %v", inbox[0]["channels"])
	}
	if sr := extras(inbox[0], "senderAndReceiver"); sr["route:appInfo:appId"] != "0100a5a020d5e000" || sr["route:name"] != "Alice" {
		t.Errorf("inbox senderAndReceiver: %v", sr)
	}
	if sn := extras(inbox[0], "sender"); sn != nil {
		t.Errorf("the sender's own extras reached the receiver: %v", sn)
	}

	outbox := requestBox(t, s, a, "outbox", "?offset=0&count=10")
	if len(outbox) != 1 {
		t.Fatalf("outbox: %v", outbox)
	}
	if sn := extras(outbox[0], "sender"); sn["route:name"] != "Bobby" {
		t.Errorf("outbox sender: %v", sn)
	}

	_, accepted := answerRequest(t, s, b, "PATCH", sent["id"].(string), `[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`)
	if ch, _ := accepted["channels"].([]any); len(ch) != 1 || ch[0] != "IN_APP" {
		t.Errorf("accept reply channels: %v", accepted["channels"])
	}
}

// A second answer to a settled request is refused: the record is dropped
// after its lifecycle ends, and the core refuses what the cache shows.
// The console answers the same request twice — once from the request box and
// once confirming — so the repeat has to reply like the first: 404 there reads
// as "this invitation is no longer valid" even though the friendship went
// through. It must not commit a second time, and it must not answer a
// different state.
func TestSettledRequestAnswersTheSameTwiceAndCommitsOnce(t *testing.T) {
	s, _, users := socialServer(t)
	a, b := users[0], users[1]
	_, req := postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	reqID := req["id"].(string)
	accept := `[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`
	if code, _ := answerRequest(t, s, b, "PATCH", reqID, accept); code != http.StatusOK {
		t.Fatal("first accept failed")
	}
	code, again := answerRequest(t, s, b, "PATCH", reqID, accept)
	if code != http.StatusOK {
		t.Fatalf("second accept returned %d, want 200", code)
	}
	if again["state"] != "AUTHORIZED" {
		t.Errorf("second accept state = %v, want AUTHORIZED", again["state"])
	}
	// One friendship, not two: the repeat replied without touching the core.
	id, err := s.acct.Identity(b.PID)
	if err != nil || len(id.Friends) != 1 {
		t.Errorf("friends after the repeat: %+v %v, want exactly one", id, err)
	}
	// A different answer to a settled request is genuinely gone.
	if code, _ := answerRequest(t, s, b, "PATCH", reqID,
		`[{"op":"replace","path":"/state","value":"REJECTED"}]`); code != http.StatusNotFound {
		t.Errorf("reject after accept returned %d, want 404", code)
	}
}

// Only the addressee answers a request, and only the sender cancels it:
// a valid token for the wrong user is a denial, not a success.
func TestCrossAccountDenial(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]
	// A third account, for isolation.
	f.addAccount("acc-c@example.com", "PlayerC", "pw-c-ccccccccccc")
	c := newUserFor(t, s, "acc-c@example.com", "pw-c-ccccccccccc")

	_, req := postRequest(t, s, a, `{"receiverId":"`+b.ID+`"}`)
	reqID := req["id"].(string)

	// C answers B's request: denied.
	if code, _ := answerRequest(t, s, c, "PATCH", reqID,
		`[{"op":"replace","path":"/state","value":"AUTHORIZED"}]`); code != http.StatusForbidden {
		t.Errorf("third-party accept returned %d, want 403", code)
	}
	// C cancels A's request: denied.
	if code, _ := answerRequest(t, s, c, "DELETE", reqID, ""); code != http.StatusForbidden {
		t.Errorf("third-party cancel returned %d, want 403", code)
	}
	// C reads A's friend list with C's token: denied.
	r := authed("GET", "/2.0.0/users/"+a.ID+"/friends", "", c, s)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-account list read returned %d, want 403", w.Code)
	}
	// C PATCHes A's presence device state: denied.
	r = authed("PATCH", "/1.0.0/users/"+a.ID+"/device_accounts/"+a.DeviceAccounts[0],
		`[{"op":"replace","path":"/presence/state","value":"ONLINE"}]`, c, s)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-account presence write returned %d, want 403", w.Code)
	}
}

// Blocks commit through the core and take effect on the social surface in
// both directions (J6): a blocked pair's request is refused and presence is
// hidden, and unblocking lifts it.
func TestBlockUnblockCommitAndTakeEffect(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]

	r := authed("POST", "/1.0.0/users/"+a.ID+"/blocks", `{"userId":"`+b.ID+`"}`, a, s)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("block: %d %s", w.Code, w.Body.String())
	}
	if !f.blockedEither("acc-a@example.com", "acc-b@example.com") {
		t.Error("block answered 200 but never reached the core")
	}
	// The block list the console reads shows it.
	r = authed("GET", "/1.0.0/users/"+a.ID+"/blocks", "", a, s)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), b.ID) {
		t.Errorf("block list: %s", w.Body.String())
	}
	// B's request to A is now refused, never a success.
	if code, _ := postRequest(t, s, b, `{"receiverId":"`+a.ID+`"}`); code < 400 {
		t.Errorf("blocked request returned %d", code)
	}
	// Unblock lifts it.
	r = authed("DELETE", "/1.0.0/users/"+a.ID+"/blocks/"+b.ID, "", a, s)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("unblock: %d %s", w.Code, w.Body.String())
	}
	if f.blockedEither("acc-a@example.com", "acc-b@example.com") {
		t.Error("unblock answered 204 but the core still holds the block")
	}
}

// The block list is $.items[*].targetUserId + targetUser, and the console
// blocks with {"targetUserId", "extras":{"self":{"reason"}}}. We read userId
// (400 for every console block) and answered {"blocks":[{"id"}]}, which fails
// the whole parse, so every block sync failed and the re-sync after a block
// never ran [friends-contract-22.5.0 §A.8, C14, C15].
func TestBlocksSpeakTheConsolesShape(t *testing.T) {
	s, f, users := socialServer(t)
	a, b := users[0], users[1]

	w := httptest.NewRecorder()
	s.ServeHTTP(w, authed("POST", "/1.0.0/users/"+a.ID+"/blocks",
		`{"targetUserId":"`+b.ID+`","extras":{"self":{"reason":"BAD_FRIEND"}}}`, a, s))
	if w.Code != http.StatusOK {
		t.Fatalf("block: %d %s", w.Code, w.Body.String())
	}
	if !f.blockedEither("acc-a@example.com", "acc-b@example.com") {
		t.Fatal("block answered 200 but never reached the core")
	}

	list := func() []map[string]any {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, authed("GET", "/1.0.0/users/"+a.ID+"/blocks?count=100", "", a, s))
		var out struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
			t.Fatalf("block list: %d %s", w.Code, w.Body.String())
		}
		return out.Items
	}
	items := list()
	if len(items) != 1 {
		t.Fatalf("block list items: %v", items)
	}
	it := items[0]
	user, _ := it["targetUser"].(map[string]any)
	ex, _ := it["extras"].(map[string]any)
	self, _ := ex["self"].(map[string]any)
	if it["targetUserId"] != b.ID || user["nickname"] != "PlayerB" || user["thumbnailUrl"] == "" {
		t.Errorf("block item lacks its required fields: %v", it)
	}
	if self["reason"] != "BAD_FRIEND" {
		t.Errorf("extras.self.reason: %v", it["extras"])
	}
	if _, ok := it["createdAt"].(float64); !ok {
		t.Errorf("createdAt: %v", it["createdAt"])
	}

	// Unblock empties the list, and the next block starts from its own body.
	w = httptest.NewRecorder()
	s.ServeHTTP(w, authed("DELETE", "/1.0.0/users/"+a.ID+"/blocks/"+b.ID, "", a, s))
	if w.Code != http.StatusNoContent {
		t.Fatalf("unblock: %d", w.Code)
	}
	if items := list(); len(items) != 0 {
		t.Errorf("block list after unblock: %v", items)
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, authed("POST", "/1.0.0/users/"+a.ID+"/blocks", `{"userId":"`+b.ID+`"}`, a, s))
	if w.Code != http.StatusOK {
		t.Fatalf("block by the old key: %d", w.Code)
	}
	if items := list(); len(items) != 1 || items[0]["extras"] != nil {
		t.Errorf("a re-block kept the old reason: %v", items)
	}
}

// The emulator's add-by-code path speaks the same Resolve contract as the
// console (SOC-04): "code", not a key nothing matched.
func TestEmulatorFriendCodeLookup(t *testing.T) {
	s, f, users := socialServer(t)
	_, other := users[0], users[1]
	f.addAccount("acc-d@example.com", "PlayerD", "pw-d-ddddddddddd")
	d := newUserFor(t, s, "acc-d@example.com", "pw-d-ddddddddddd")

	key := strings.Repeat("i", 32)
	t.Setenv("NX_INTERNAL_KEY", key)
	body := `{"account_id":"acc-d@example.com","action":"request","friend_code":"` + codeOf(s, other) + `"}`
	r := httptest.NewRequest("POST", "http://api/internal/switch/emulator/friend", strings.NewReader(body))
	r.Header.Set("X-Internal-Key", key)
	w := httptest.NewRecorder()
	s.gameAPI().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("emulator add-by-code: %d %s", w.Code, w.Body.String())
	}
	// The request exists in the core, addressed to the right person.
	id, _ := s.acct.Identity(other.PID)
	if len(id.FriendRequests) != 1 || id.FriendRequests[0].PID != d.PID {
		t.Errorf("request not in the addressee's inbox: %+v", id.FriendRequests)
	}
}

// Two changes inside the same wall-clock second must still be distinguishable
// (SOC-05): the friends-list version is strictly monotonic.
func TestFriendsUpdatedAtIsStrictlyMonotonic(t *testing.T) {
	s := dauthServer(t)
	s.store = loadStore(t.TempDir() + "/baas.json")
	u, _ := s.store.NewUser()
	now := time.Now().Unix()
	s.store.Update(u, func(u *User) { bumpFriendsUpdated(u, now) })
	first := s.store.User(u.ID).FriendsUpdatedAt
	for i := 0; i < 3; i++ {
		s.store.Update(u, func(u *User) { bumpFriendsUpdated(u, now) })
	}
	if got := s.store.User(u.ID).FriendsUpdatedAt; got != first+3 {
		t.Errorf("three bumps within one second moved the version %d -> %d", first, got)
	}
}

// ---------- authentication of the surface ----------

func TestExpiredAndForeignTokensAreRefused(t *testing.T) {
	s, _, users := socialServer(t)
	a := users[0]
	path := "/2.0.0/users/" + a.ID + "/friends"

	expired := s.accessToken(a.ID, 2, "did", "device", "serial")
	// Forge an expired one with the server's own key: same signature path,
	// dead exp.
	claims := map[string]any{
		"aud": baasAudience, "bs:did": "did", "bs:grt": 2, "exp": time.Now().Unix() - 10,
		"iat": time.Now().Unix() - 100, "iss": baasIssuer, "sub": a.ID, "typ": "token",
	}
	tok := signJWT(map[string]any{"alg": "RS256", "kid": "test-kid", "typ": "JWT"}, claims, s.key)

	call := func(bearer string) int {
		r := httptest.NewRequest("GET", "https://"+baasHost+path, nil)
		r.Host = baasHost
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	if code := call(""); code != http.StatusUnauthorized {
		t.Errorf("no token returned %d, want 401", code)
	}
	if code := call(expired); code != http.StatusOK {
		t.Errorf("live token returned %d", code)
	}
	if code := call(tok); code != http.StatusUnauthorized {
		t.Errorf("expired token returned %d, want 401", code)
	}
	// An id_token is a different token type, signed with the same key: it
	// must not spend as an access token.
	idTok := s.idToken(a, nil, "x", nil)
	if code := call(idTok); code != http.StatusUnauthorized {
		t.Errorf("id_token as access token returned %d, want 401", code)
	}
	// Garbage is garbage.
	if code := call("not-a-jwt"); code != http.StatusUnauthorized {
		t.Errorf("garbage token returned %d, want 401", code)
	}
}

// ---------- helpers ----------

func codeOf(s *server, u *User) string {
	id, err := s.acct.Identity(u.PID)
	if err != nil {
		return ""
	}
	return id.FriendCode
}

// newUserFor links a fresh store user to a core account's projection.
func newUserFor(t *testing.T, s *server, accountID, pw string) *User {
	t.Helper()
	b := s.acct.(*openpakBackend)
	pid, _, err := b.LoginPID(accountID, pw)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.store.NewUser()
	baas := b.proj.ByAccount[accountID].BaasUserID
	s.store.mu.Lock()
	delete(s.store.Users, u.ID)
	u.ID = baas
	s.store.Users[baas] = u
	for _, d := range s.store.Devices {
		if d.UserID == u.ID {
			d.UserID = baas
		}
	}
	s.store.mu.Unlock()
	s.store.Update(u, func(u *User) { u.PID = pid })
	return s.store.User(baas)
}
