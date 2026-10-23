package main

// Switch Online (Lhub page, the badge feed, capi contexts) and the News halves of this
// adapter (forwarding to the news service, the topic push).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The HOME Menu's NSO button opens <env>.nso.nintendo.net/<any path>: every path, the
// paywall launch included, gets the landing page with a way out.
func TestLhubPageServesAnyPath(t *testing.T) {
	s := linkedServer(t)
	for _, path := range []string{"/", "/lhub?src_app_id=0100000000001000", "/launch?from=paywall&type=lex&app_id=0100000000010000&location=x"} {
		rec := hostReq(s, "lp1.nso.nintendo.net", "GET", path, "", "")
		body := rec.Body.String()
		if rec.Code != 200 || !strings.Contains(body, "Everything is included") || !strings.Contains(body, "setAssign") || !strings.Contains(body, "endApplet") {
			t.Errorf("lhub %s = %d", path, rec.Code)
		}
	}
	// The page learns whose membership it shows.
	rec := hostReq(s, "lp1.nso.nintendo.net", "GET", "/_openpak/membership", naIDTokenFor(s), "")
	d := decodeBody(t, rec)
	if d["membership"] != "active" || d["signed_in"] != true {
		t.Errorf("membership = %s", rec.Body.String())
	}
}

// The voice-chat lobby: /lobby/ with the shim's query renders the page that sends the player to
// the app and leaves through the Lobby callback URL; the rest of the znc host is a recorded 404.
func TestZncLobbyPageLeavesThroughTheCallback(t *testing.T) {
	s := linkedServer(t)
	for _, path := range []string{"/lobby/", "/lobby/?app_id=0100000000010000&param=abc", "/lobby"} {
		rec := hostReq(s, "web-lp1.znc.srv.nintendo.net", "GET", path, "", "")
		body := rec.Body.String()
		if rec.Code != 200 || !strings.Contains(body, "Voice chat is on your phone") ||
			!strings.Contains(body, "/_openpak/voice") || !strings.Contains(body, "https://localhost/lobby/") {
			t.Errorf("lobby %s = %d", path, rec.Code)
		}
	}
	if rec := hostReq(s, "web-lp1.znc.srv.nintendo.net", "GET", "/other", "", ""); rec.Code != 404 {
		t.Errorf("znc /other = %d, want 404", rec.Code)
	}
}

// The lobby's room lookup names the console's core account to the website and passes its
// answer through; a console it can't name gets 401.
func TestZncLobbyVoiceAsksTheWebsiteForTheRoom(t *testing.T) {
	s := linkedServer(t)
	s.banSource = &fakeBans{}
	var asked string
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(401)
			return
		}
		asked = r.URL.RawQuery
		w.Write([]byte(`{"code":"KX7P2Q","in_voice":2}`))
	}))
	defer web.Close()
	t.Setenv("WEBSITE_INTERNAL_URL", web.URL)
	t.Setenv("WEBSITE_INTERNAL_KEY", "k")

	if rec := hostReq(s, "web-lp1.znc.srv.nintendo.net", "GET", "/_openpak/voice?app_id=01003BC0000A0000", "", ""); rec.Code != 401 {
		t.Errorf("no token = %d, want 401", rec.Code)
	}
	rec := hostReq(s, "web-lp1.znc.srv.nintendo.net", "GET", "/_openpak/voice?app_id=01003BC0000A0000", naIDTokenFor(s), "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "KX7P2Q") {
		t.Fatalf("voice = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(asked, "account_id=acc-") || !strings.Contains(asked, "app_id=01003BC0000A0000") {
		t.Errorf("website asked %q", asked)
	}
}

// The Switch Online pages' feature icons are served from the binary.
func TestLhubIconsAreServed(t *testing.T) {
	s := linkedServer(t)
	for _, n := range []string{"online", "cloud", "app", "consoles", "faq", "help"} {
		rec := hostReq(s, "lp1.nso.nintendo.net", "GET", "/_openpak/icon/"+n+".png", "", "")
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" {
			t.Errorf("icon %s = %d", n, rec.Code)
		}
	}
	if rec := hostReq(s, "lp1.nso.nintendo.net", "GET", "/_openpak/icon/../../main.go", "", ""); rec.Code != 404 {
		t.Errorf("path escape = %d, want 404", rec.Code)
	}
}

// The badge feed answers an empty collection rather than the catch-all 404.
func TestNsoEventsFeedAnswersEmpty(t *testing.T) {
	s := linkedServer(t)
	rec := hostReq(s, "fw-api.lp1.nso.nintendo.net", "POST", "/v1/events", "", `{"country_codes":["GB"]}`)
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("events = %d %s", rec.Code, rec.Body.String())
	}
}

// OpenPak sells no tiers: the Expansion Pack context is active like the base plan.
func TestCapiMembershipsAnswerExpansionPackActive(t *testing.T) {
	s := dauthServer(t)
	rec := hostReq(s, "capi.lp1.op2.nintendo.net", "GET", "/v1/users/0123456789abcdef/memberships", "", "")
	var got struct {
		Items []struct {
			Context    string `json:"context"`
			Membership struct {
				Active bool `json:"active"`
			} `json:"membership"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Items) != 2 {
		t.Fatalf("memberships = %s", rec.Body.String())
	}
	for _, it := range got.Items {
		if !it.Membership.Active {
			t.Errorf("context %q is inactive", it.Context)
		}
	}
}

// ---------- news ----------

// The push is an internal route: without the key it is refused; with it, the message goes
// to the live connection of a console subscribed to the topic, and nowhere else.
func TestNewsPushNeedsTheKeyAndReachesSubscribers(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k-0123456789")
	s := testServer(t)
	store := s.notifStore()
	store.AddSubscription("aaaa", "dev-a", "openpak_news", time.Now())
	store.AddSubscription("aaaa", "dev-a", "nx_data_0100000000010000", time.Now())
	store.AddSubscription("bbbb", "dev-b", "other_topic", time.Now())
	subscribed := &penneSession{user: "aaaa", device: "dev-a", send: make(chan penneOutbound, 4)}
	other := &penneSession{user: "bbbb", device: "dev-b", send: make(chan penneOutbound, 4)}
	s.notifHub().attach(subscribed)
	s.notifHub().attach(other)

	body := `{"topic_id":"openpak_news","revision":7}`
	if w := do(t, s, "POST", "/internal/news/push", "", body); w.Code != http.StatusUnauthorized {
		t.Fatalf("push without the key = %d, want 401", w.Code)
	}
	r := httptest.NewRequest("POST", "/internal/news/push", strings.NewReader(body))
	r.Header.Set("X-Internal-Key", "k-0123456789")
	w := httptest.NewRecorder()
	s.gameAPI().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("push = %d %s", w.Code, w.Body.String())
	}
	if d := decodeBody(t, w); d["subscribers"] != float64(1) || d["delivered"] != float64(1) {
		t.Errorf("push reply = %s", w.Body.String())
	}
	select {
	case out := <-subscribed.send:
		if !bytes.Contains(out.frame, []byte(`"type":"news"`)) || !bytes.Contains(out.frame, []byte(`"topic_id":"openpak_news"`)) ||
			!bytes.Contains(out.frame, []byte(`"revision":"7"`)) {
			t.Errorf("frame does not carry the news message: %q", out.frame)
		}
	default:
		t.Fatal("the subscribed console got nothing")
	}
	select {
	case <-other.send:
		t.Error("a console not subscribed to the topic got the push")
	default:
	}
	// Both of the device's topics are still held: subscribing one does not drop another.
	if n := len(store.TopicSubscribers("nx_data_0100000000010000")); n != 1 {
		t.Errorf("earlier subscription lost: %d", n)
	}
}
