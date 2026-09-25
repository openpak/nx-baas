package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
)

// The one way this spike can go badly wrong is proxying to ourselves: the console's name is
// redirected to this box, so a Director that keeps the request pointed at the listener would
// loop. It must target the same name over public TLS, which only resolves to Team17 because
// the box is not redirected.
func TestT17DirectorTargetsTheRealService(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/get-token", nil)
	r.Host = "directory.t17service.com"
	t17Proxy().(*httputil.ReverseProxy).Director(r)
	if r.URL.Scheme != "https" || r.URL.Host != "directory.t17service.com" {
		t.Fatalf("director sent the request to %s://%s", r.URL.Scheme, r.URL.Host)
	}
}

// The directory is the only address the game is given, so getting its shape wrong costs a whole
// test run. This is the reply Team17's own service sends, with our hosts in place of the empty
// `game.url` it actually returns.
func TestT17DirectoryHandsBackOurOwnHosts(t *testing.T) {
	t.Setenv("T17_SELF_HOST", "t17service.com")
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "directory.t17service.com"
	w := httptest.NewRecorder()
	if !t17Directory(w, r) {
		t.Fatal("the directory root was not answered")
	}
	var got struct {
		Game       struct{ URL string }
		XPlayURL   string `json:"xplayurl"`
		AllowXPlay string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unparseable: %v (%s)", err, w.Body)
	}
	if got.Game.URL != "https://game.t17service.com/" || got.XPlayURL != "https://xplay.t17service.com/prod/" ||
		got.AllowXPlay != "1" {
		t.Fatalf("wrong addressing: %s", w.Body)
	}
	// Anything but the root is still the capture path, or the game backend would never be read.
	if t17Directory(httptest.NewRecorder(), httptest.NewRequest("GET", "/something", nil)) {
		t.Fatal("a non-root path was answered as the directory")
	}
}
