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
