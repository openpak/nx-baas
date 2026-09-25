package main

import (
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
