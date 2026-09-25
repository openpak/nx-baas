package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
)

// Team17's backend (T17BE) is what Moving Out 2 asks for before it ever reaches Photon
// Fusion: `directory.t17service.com` hands out an auth token and a `websocketUrl`, and the
// game then talks JSON over that socket (/sessions/*, /friends/*, /storage/*, /live/*).
// OpenPak answers none of it yet, so the redirect exists only to read the protocol: log the
// request, pass it to the real service, log the reply.
//
// ponytail: a capture spike, not a service. It lives here because Traefik already sends
// unrouted SNI to nx-baas and the on-demand cert already covers the name; it moves to
// servers/t17 the moment OpenPak answers for itself. `T17_PASSTHROUGH=0` stops the
// forwarding and answers 404, which still records what the game asked for.
func (s *server) t17(w http.ResponseWriter, r *http.Request, body []byte) {
	dump(r, body, ">>> t17")
	if os.Getenv("T17_PASSTHROUGH") == "0" {
		writeJSON(w, 404, map[string]any{})
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	t17Proxy().ServeHTTP(w, r)
}

// The real service, reached by the box's own resolver — only consoles are redirected — and
// verified against the public roots like any other client of Team17's.
var t17Proxy = sync.OnceValue(func() http.Handler {
	return &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme, r.URL.Host = "https", hostOf(r)
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		ModifyResponse: func(res *http.Response) error {
			b, _ := io.ReadAll(res.Body)
			res.Body = io.NopCloser(bytes.NewReader(b))
			log.Printf("[t17] <<< %d %s %s body(%d)=%s", res.StatusCode, res.Request.Host, res.Request.URL.RequestURI(), len(b), b)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[t17] !! upstream %s%s: %v", hostOf(r), r.URL.Path, err)
			writeJSON(w, 502, map[string]any{})
		},
	}
})
