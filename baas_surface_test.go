package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every method kinnay's BAAS page documents, answered by this server.
//
// Not a shape check: the point is that none of them is a 404 or a 405, because
// an unhandled console request is invisible from the server side and shows up
// as an error code on a television.
func TestEveryDocumentedBaasMethodIsAnswered(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID, u.Nickname = 1, "tester" })
	s.acct = fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
		FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did"}}
	other := "1111222233334444"

	for _, c := range []struct {
		method, path, body, ctype string
	}{
		{"GET", "/1.0.0/certificates", "", ""},
		{"GET", "/1.0.0/internal_certificates", "", ""},
		{"GET", "/1.0.0/users?filter.links.friendCode.id.$in=0000-0000-0000", "", ""},
		{"GET", "/1.0.0/users/" + u.ID, "", ""},
		{"PATCH", "/1.0.0/users/" + u.ID, `[{"op":"add","path":"/permissions/presence","value":"SELF"}]`, "application/json-patch+json"},
		{"POST", "/1.0.0/users/" + u.ID + "/generate_code", "type=NX", "application/x-www-form-urlencoded"},
		{"GET", "/1.0.0/users/" + u.ID + "/blocks", "", ""},
		{"POST", "/1.0.0/users/" + u.ID + "/blocks", `{"userId":"` + other + `"}`, "application/json"},
		{"DELETE", "/1.0.0/users/" + u.ID + "/blocks/" + other, "", ""},
		{"GET", "/1.0.0/users/" + u.ID + "/device_histories", "", ""},
		{"DELETE", "/1.0.0/users/" + u.ID + "/device_accounts/" + u.DeviceAccounts[0], "", ""},
		{"GET", "/2.0.0/users/" + u.ID + "/friends", "", ""},
		{"GET", "/2.0.0/users/" + u.ID + "/friend_requests/inbox", "", ""},
		{"GET", "/2.0.0/users/" + u.ID + "/friend_requests/outbox", "", ""},
		{"PATCH", "/2.0.0/users/" + u.ID + "/friends/" + other, `[{"op":"replace","path":"/isFavoriteFriend","value":true}]`, "application/json-patch+json"},
		{"DELETE", "/2.0.0/users/" + u.ID + "/friends/" + other, "", ""},
		{"GET", "/2.0.0/users/" + u.ID + "/relationships/" + other, "", ""},
	} {
		t.Run(c.method+" "+strings.SplitN(c.path, "?", 2)[0], func(t *testing.T) {
			r := httptest.NewRequest(c.method, "https://"+baasHost+c.path, strings.NewReader(c.body))
			r.Host = baasHost
			if c.ctype != "" {
				r.Header.Set("Content-Type", c.ctype)
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)

			switch w.Code {
			case http.StatusNotFound, http.StatusMethodNotAllowed:
				t.Fatalf("%d: documented and unanswered — %s", w.Code, w.Body.String())
			}
			if w.Code >= 500 {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			if w.Body.Len() > 0 && strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
				var any any
				if err := json.Unmarshal(w.Body.Bytes(), &any); err != nil {
					t.Fatalf("reply is not JSON: %v (%s)", err, w.Body.String())
				}
			}
		})
	}
}

// A second friend code within the day is refused the way the wiki documents it,
// and the code that comes back is a different one.
func TestFriendCodeRegeneratesOncePerDay(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID, u.Nickname = 1, "tester" })
	s.acct = fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
		FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did"}}

	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://"+baasHost+"/1.0.0/users/"+u.ID+"/generate_code",
			strings.NewReader("type=NX"))
		r.Host = baasHost
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}

	if w := call(); w.Code != http.StatusOK {
		t.Fatalf("first generate_code = %d: %s", w.Code, w.Body.String())
	}
	w := call()
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("second generate_code = %d, want 422", w.Code)
	}
	if !strings.Contains(w.Body.String(), "friend_code_unregenerable_state") {
		t.Fatalf("wrong error: %s", w.Body.String())
	}
}

// The other services the console reaches here. Each of these was answered with
// 404 {} tonight, which a console reports as an error rather than as "nothing
// to show" — the exact requests are from the log, hosts included.
func TestTheOtherConsoleServicesAnswer(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}

	for _, c := range []struct {
		host, method, path, body string
		wantKey                  string
	}{
		{"bcat-topics-lp1.cdn.nintendo.net", "GET",
			"/api/nx/v1/titles/0100b6001e6d6000/topics?l=en-GB&c%5b%5d=GB", "", "topics"},
		{"storage.hac.lp1.scsi.srv.nintendo.net", "GET",
			"/api/console/v3/save_data_archives?datatype=0", "", "save_data_archives"},
		{"storage.hac.lp1.scsi.srv.nintendo.net", "POST",
			"/api/console/v3/network_service_accounts/aaaaaaaaaaaa0001/notification_tokens",
			`{"notification_token":"efc21df7bbbe1d87da1c23521cdbc5dc6e6a"}`, "notification_token"},
	} {
		t.Run(c.host+c.path[:20], func(t *testing.T) {
			r := httptest.NewRequest(c.method, "https://"+c.host+c.path, strings.NewReader(c.body))
			r.Host = c.host
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			var got map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("not JSON: %v", err)
			}
			if _, ok := got[c.wantKey]; !ok {
				t.Fatalf("no %q in %s", c.wantKey, w.Body.String())
			}
		})
	}
}

// POST /2.0.0/friend_requests is two segments. The 2.0.0 dispatch required
// three, so sending a friend request fell through to the catch-all 404 and the
// console said "please try again later" (2121-2031) -- with the exact body
// hardware sends, captured 2026-09-08.
func TestSendingAFriendRequestReachesTheHandler(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID, u.Nickname = 1, "tester" })
	s.acct = codeBackend{
		fakeBackend: fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
			FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did"}},
		code: "SW-1000-0000-0002",
		friend: &Friend{PID: 2, BaasUserID: "aaaaaaaaaaaa0002", NaID: "bbbbbbbbbbbb0002",
			FriendCode: "SW-1000-0000-0002", Nickname: "Leia", Country: "IE", CreatedAt: 1788896080}}

	body := `{"channels":["FRIEND_CODE"],"senderId":"` + u.ID +
		`","receiverId":"aaaaaaaaaaaa0002","extras":{"sender":{"route:sender":"me"}}}`
	r := httptest.NewRequest("POST", "https://"+baasHost+"/2.0.0/friend_requests", strings.NewReader(body))
	r.Host = baasHost
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Code == http.StatusNotFound {
		t.Fatalf("the request never reached the handler: %s", w.Body.String())
	}
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", w.Code, w.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	// The request's id is its own, not the person it was sent to: the console
	// cancels with PATCH /2.0.0/friend_requests/<id>.
	if got["id"] == "aaaaaaaaaaaa0002" {
		t.Error("the receiver's user id was handed back as the request id")
	}
	if got["receiverId"] != "aaaaaaaaaaaa0002" || got["state"] != "PENDING" {
		t.Errorf("reply does not describe the request it made: %s", w.Body.String())
	}

	// And that id resolves when the console cancels.
	cancel := httptest.NewRequest("DELETE", "https://"+baasHost+"/2.0.0/friend_requests/"+got["id"].(string), nil)
	cancel.Host = baasHost
	cancel.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	cw := httptest.NewRecorder()
	s.ServeHTTP(cw, cancel)
	if cw.Code != http.StatusOK {
		t.Fatalf("cancel = %d: %s", cw.Code, cw.Body.String())
	}
}

// Every list this server returns uses the envelope a console reads, captured
// from a working server on 2026-09-08:
//
//	{"count":0,"etag":"","items":[],"itemsPerPage":0}
//
// Ours named the array after its contents — "friends", "friendRequests",
// "users" — so a console reading "items" found nothing. That is what an empty
// friend list and an empty inbox looked like from the sofa, with the data
// sitting in the reply the whole time.
func TestListsUseTheEnvelopeAConsoleReads(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID, u.Nickname = 1, "tester" })
	s.acct = fakeBackend{id: &Identity{PID: 1, NaID: "aabbccdd11223344", Nickname: "tester",
		FriendCode: "SW-0000-0000-0000", Country: "IE", BsDid: "did",
		Friends:        []Friend{{PID: 2, BaasUserID: "aaaaaaaaaaaa0002", Nickname: "Leia", FriendCode: "SW-1000-0000-0002"}},
		FriendRequests: []Friend{{PID: 3, BaasUserID: "2222333344445555", Nickname: "Asks", FriendCode: "SW-1111-2222-3333"}},
	}}

	for _, path := range []string{
		"/2.0.0/users/" + u.ID + "/friends",
		"/2.0.0/users/" + u.ID + "/friend_requests/inbox",
		"/2.0.0/users/" + u.ID + "/friend_requests/outbox",
	} {
		r := httptest.NewRequest("GET", "https://"+baasHost+path, nil)
		r.Host = baasHost
		r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)

		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: not JSON: %v", path, err)
		}
		for _, key := range []string{"count", "etag", "items", "itemsPerPage"} {
			if _, ok := got[key]; !ok {
				t.Errorf("%s: missing %q", path, key)
			}
		}
		for _, gone := range []string{"friends", "friendRequests", "users"} {
			if _, ok := got[gone]; ok {
				t.Errorf("%s: still carries %q; a console reads items", path, gone)
			}
		}
	}

	// An incoming request has to say who sent it.
	r := httptest.NewRequest("GET", "https://"+baasHost+"/2.0.0/users/"+u.ID+"/friend_requests/inbox", nil)
	r.Host = baasHost
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var inbox struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &inbox)
	if len(inbox.Items) != 1 {
		t.Fatalf("inbox: %s", w.Body.String())
	}
	sender, _ := inbox.Items[0]["sender"].(map[string]any)
	if sender == nil || sender["id"] != "2222333344445555" {
		t.Fatalf("the sender is not the person who asked: %v", inbox.Items[0]["sender"])
	}
}

// The relationship check the console runs before it offers to add somebody.
func TestRelationshipShape(t *testing.T) {
	s := dauthServer(t)
	s.store = &Store{Devices: map[string]*DeviceAccount{}, Users: map[string]*User{}, NaToPID: map[string]uint64{}}
	u, _ := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID, u.Nickname = 1, "tester" })
	s.acct = fakeBackend{id: &Identity{PID: 1, Nickname: "tester", FriendCode: "SW-0000-0000-0000", BsDid: "did"}}

	r := httptest.NewRequest("GET", "https://"+baasHost+"/2.0.0/users/"+u.ID+"/relationships/aaaaaaaaaaaa0002", nil)
	r.Host = baasHost
	r.Header.Set("Authorization", "Bearer "+s.accessToken(u.ID, 2, "did", "device", "serial"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"userId", "targetUserId", "isFriend", "isFavoriteFriend", "isBlocking", "sentFriendRequestIds"} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing %q — captured from a reply a console accepts", key)
		}
	}
	if _, ok := got["relationship"]; ok {
		t.Error(`still answers with "relationship", which no console asked for`)
	}
}
