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
	s := shopServerFor(t)
	for _, path := range []string{"/", "/lhub?src_app_id=0100000000001000", "/launch?from=paywall&type=lex&app_id=0100000000010000&location=x"} {
		rec := hostReq(s, "lp1.nso.nintendo.net", "GET", path, "", "")
		body := rec.Body.String()
		if rec.Code != 200 || !strings.Contains(body, "included with OpenPak") || !strings.Contains(body, "lhclose") {
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

// The badge feed answers an empty collection rather than the catch-all 404.
func TestNsoEventsFeedAnswersEmpty(t *testing.T) {
	s := shopServerFor(t)
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

// The OpenPak topics and title topic lookups reach the news service verbatim — path,
// query, conditional and range headers in; status, headers and body out. Other bcat
// paths keep this adapter's own answers.
func TestBcatForwardsNewsRoutesVerbatim(t *testing.T) {
	var got *http.Request
	news := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.Header().Set("ETag", `"v7"`)
		w.Header().Set("Content-Range", "bytes 0-3/10")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte{0x81, 0xa1, 'x', 0x01})
	}))
	defer news.Close()
	f, err := newNewsForwarder(news.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{news: f}

	req := httptest.NewRequest("GET", "https://bcat-list-lp1.cdn.nintendo.net/api/nx/v1/list/openpak_news?l=en-US&c[]=GB", nil)
	req.Host = "bcat-list-lp1.cdn.nintendo.net"
	req.Header.Set("If-None-Match", `"v6"`)
	req.Header.Set("Range", "bytes=0-3")
	req.Header.Set("If-Range", `"v6"`)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), []byte{0x81, 0xa1, 'x', 0x01}) ||
		w.Header().Get("ETag") != `"v7"` || w.Header().Get("Content-Range") != "bytes 0-3/10" {
		t.Errorf("reply not verbatim: %d %v %x", w.Code, w.Header(), w.Body.Bytes())
	}
	if got == nil || got.URL.Path != "/api/nx/v1/list/openpak_news" || got.URL.RawQuery != "l=en-US&c[]=GB" ||
		got.Header.Get("If-None-Match") != `"v6"` || got.Header.Get("Range") != "bytes=0-3" || got.Header.Get("If-Range") != `"v6"` {
		t.Fatalf("request not forwarded verbatim: %+v", got)
	}

	got = nil
	req = httptest.NewRequest("GET", "https://bcat-topics-lp1.cdn.nintendo.net/api/nx/v1/titles/0100000000010000/topics?c[]=GB", nil)
	req.Host = "bcat-topics-lp1.cdn.nintendo.net"
	s.ServeHTTP(httptest.NewRecorder(), req)
	if got == nil || got.URL.Path != "/api/nx/v1/titles/0100000000010000/topics" {
		t.Errorf("title topics not forwarded")
	}

	// A title's own BCAT list is not News: it keeps the local answer.
	got = nil
	req = httptest.NewRequest("GET", "https://bcat-list-lp1.cdn.nintendo.net/api/nx/v1/list/nx_data_0100000000010000", nil)
	req.Host = "bcat-list-lp1.cdn.nintendo.net"
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if got != nil || w.Code != 200 {
		t.Errorf("nx_data list was forwarded or failed: %d", w.Code)
	}
}

// Without NEWS_INTERNAL_URL nothing changes: the News list keeps bcat.go's answer.
func TestBcatNewsListUnforwardedWithoutTheService(t *testing.T) {
	s := &server{}
	req := httptest.NewRequest("GET", "https://bcat-list-lp1.cdn.nintendo.net/api/nx/v1/list/openpak_news", nil)
	req.Host = "bcat-list-lp1.cdn.nintendo.net"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-msgpack" {
		t.Errorf("local answer changed: %d %v", w.Code, w.Header())
	}
}

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
			!bytes.Contains(out.frame, []byte(`"revision":7`)) {
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
