package main

// The core's side of Penne (penne_link.go, split.go): every push goes to nx-penne, and the
// penne hosts and /internal/penne are forwarded there.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type penneCall struct {
	method, host, path string
	body               map[string]any
}

// fakeNxPenne records what reaches it and answers like nx-penne.
func fakeNxPenne(t *testing.T) (*httptest.Server, chan penneCall) {
	t.Helper()
	got := make(chan penneCall, 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		got <- penneCall{r.Method, r.Host, r.URL.Path, body}
		if strings.HasPrefix(r.URL.Path, "/internal/") && r.Header.Get("X-Internal-Key") != "test-internal-key" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/internal/penne/notifications":
			w.Write([]byte(`{"accepted":true,"duplicate":false,"outcome":"persisted","id":"` + str(body, "id") + `"}`))
		case "/internal/penne/topic-messages":
			w.Write([]byte(`{"subscribers":2,"delivered":1}`))
		case "/internal/penne/device-messages":
			w.Write([]byte(`{"penne_id":"pz-from-dauth","connections":1}`))
		case "/internal/penne/registrations/pz1":
			w.Write([]byte(`{"penne_id":"pz1","live":true,"user_id":"` + "uid-placeholder" + `","users":[]}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func expectCall(t *testing.T, got chan penneCall, path string) penneCall {
	t.Helper()
	for {
		select {
		case c := <-got:
			if c.path == path {
				return c
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("nothing reached nx-penne at %s", path)
		}
	}
}

func TestMovedPenneReceivesTheCoresCalls(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "test-internal-key")
	srv, got := fakeNxPenne(t)
	t.Setenv("NX_PENNE_URL", srv.URL)
	s := linkedServer(t)
	s.forwardersFromEnv()
	u := s.store.UserByPID(7)

	// /1.0.0/push_channels: the association goes to nx-penne, the console gets its echo.
	req := httptest.NewRequest("POST", "https://m-lp1.baas.nintendo.com/1.0.0/push_channels/"+u.ID+"/dev1",
		strings.NewReader(`{"service":"npns","deviceToken":"tok1"}`))
	req.Host = "m-lp1.baas.nintendo.com"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"deviceToken":"tok1"`) {
		t.Fatalf("push_channels = %d %s", rec.Code, rec.Body)
	}
	if c := expectCall(t, got, "/internal/penne/push-channels"); str(c.body, "user_id") != u.ID || str(c.body, "device_token") != "tok1" || str(c.body, "device_account_id") != "dev1" {
		t.Fatalf("push channel reached nx-penne as %v", c.body)
	}

	s.penneBindConsole("cert-1", u.ID)
	if c := expectCall(t, got, "/internal/penne/consoles"); str(c.body, "device_id") != "cert-1" || str(c.body, "user_id") != u.ID {
		t.Fatalf("console binding = %v", c.body)
	}

	// A notification: the core still checks kind and recipient, then hands it over.
	if res := s.SubmitNotification(PenneDelivery{UserID: "nobody", Kind: EventFriendDeleted}); res.Accepted {
		t.Fatal("a notification for an unknown user was handed over")
	}
	s.SubmitNotification(PenneDelivery{ID: "core:9", UserID: u.ID, Kind: EventFriendDeleted, Payload: map[string]any{"friendId": "x"}})
	if c := expectCall(t, got, "/internal/penne/notifications"); str(c.body, "id") != "core:9" || str(c.body, "kind") != EventFriendDeleted {
		t.Fatalf("notification = %v", c.body)
	}
	// The test route waits for nx-penne's outcome.
	rec = identityDo(t, s, "POST", "/internal/notifications/test", `{"user_id":"`+u.ID+`","kind":"friend_deleted","id":"t1"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"outcome":"persisted"`) {
		t.Fatalf("test notification = %d %s", rec.Code, rec.Body)
	}

	// News: counts come back from nx-penne.
	rec = identityDo(t, s, "POST", "/internal/news/push", `{"topic_id":"OpenPak_News","revision":3}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"delivered":1`) {
		t.Fatalf("news push = %d %s", rec.Code, rec.Body)
	}
	if c := expectCall(t, got, "/internal/penne/topic-messages"); str(c.body, "topic") != "openpak_news" || str(c.body, "receivers") != newsReceiverToken {
		t.Fatalf("topic message = %v", c.body)
	}

	s.penneCloseUser(u.ID)
	expectCall(t, got, "/internal/penne/users/"+u.ID+"/close")

	// Penne's hosts are forwarded, the frontline is refused, the gateway stays here.
	req = httptest.NewRequest("POST", "https://god.hac.lp1.penne.srv.nintendo.net/v1/penne_ids", strings.NewReader(`{}`))
	req.Host = "god.hac.lp1.penne.srv.nintendo.net"
	s.ServeHTTP(httptest.NewRecorder(), req)
	if c := expectCall(t, got, "/v1/penne_ids"); c.host != "god.hac.lp1.penne.srv.nintendo.net" {
		t.Fatalf("god reached nx-penne with Host %q", c.host)
	}
	req = httptest.NewRequest("POST", "https://fro-3.hac.lp1.penne.srv.nintendo.net/", nil)
	req.Host = "fro-3.hac.lp1.penne.srv.nintendo.net"
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("frontline on the core = %d, want 421", rec.Code)
	}
	req = httptest.NewRequest("GET", "https://gw.hac.lp1.vermillion.srv.nintendo.net/v1/accounts/config", nil)
	req.Host = "gw.hac.lp1.vermillion.srv.nintendo.net"
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "payload") {
		t.Fatalf("vermillion gateway = %d %s; it stays here", rec.Code, rec.Body)
	}

	// Another service pointed at the core still reaches Penne.
	rec = identityDo(t, s, "GET", "/internal/penne/registrations/pz1", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"live":true`) {
		t.Fatalf("forwarded registration = %d %s", rec.Code, rec.Body)
	}
}

// A restart of nx-penne loses nothing the core queued: the worker retries, in order, until
// it is back.
func TestQueuedPushesSurviveAnNxPenneRestart(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "test-internal-key")
	var up atomic.Bool
	got := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		got <- str(body, "device_id")
		w.WriteHeader(204)
	}))
	defer srv.Close()
	p := newPenneRemote(srv.URL)
	s := &server{penneRemote: p}
	s.penneBindConsole("first", "u")
	s.penneBindConsole("second", "u")
	time.Sleep(300 * time.Millisecond)
	up.Store(true)
	for _, want := range []string{"first", "second"} {
		select {
		case d := <-got:
			if d != want {
				t.Fatalf("delivered %q, want %q (order kept)", d, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s never arrived after nx-penne came back", want)
		}
	}
}

// A dead nx-penne costs the queue one shared outage, not a minute per job, and a
// deployment fault (501, or nx-penne without an internal key) is never retried.
func TestQueueSharesOneOutageAndGivesUpOnDeploymentFaults(t *testing.T) {
	oldFor, oldProbe := penneRetryFor, pennePauseProbe
	penneRetryFor, pennePauseProbe = 300*time.Millisecond, time.Hour
	t.Cleanup(func() { penneRetryFor, pennePauseProbe = oldFor, oldProbe })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	p := newPenneRemote(srv.URL)
	var ran atomic.Int32
	for i := 0; i < 20; i++ {
		p.later("job", func() error {
			ran.Add(1)
			return p.call("POST", "/internal/penne/consoles", map[string]any{}, nil)
		})
	}
	// Past the budget the rest are dropped without running, so the queue drains at once.
	for deadline := time.Now().Add(3 * time.Second); len(p.queue) > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("twenty jobs against a dead nx-penne held the queue past one outage budget")
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := ran.Load(); n > 2 {
		t.Fatalf("%d jobs ran against a dead nx-penne; after the first outage the rest are dropped", n)
	}
	if n := calls.Load(); n > 8 {
		t.Fatalf("%d attempts: jobs after the budget were retried instead of dropped", n)
	}

	for _, c := range []struct {
		status int
		body   string
	}{{http.StatusServiceUnavailable, `{"error":"internal_key_not_configured"}`}, {http.StatusNotImplemented, `{}`}} {
		var n atomic.Int32
		fault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.Add(1)
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		}))
		err := newPenneRemote(fault.URL).call("POST", "/internal/penne/consoles", map[string]any{}, nil)
		fault.Close()
		var again retryable
		if err == nil || errors.As(err, &again) {
			t.Fatalf("%d %s: err %v, want a final error", c.status, c.body, err)
		}
	}
}
