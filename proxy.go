package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"nx-baas/internal/httpx"
	"nx-baas/redact"
	"regexp"
	"strings"
)

var passwordRe = regexp.MustCompile(`password=[^&]*`)

// Capture mode (NX_UPSTREAM=<ip>): forward every request to the real OpenPak deployment, same
// Host/SNI, and log request + response bodies. Used once to record what a console accepts;
// never a production path.
func newCaptureProxy(upstream string) http.Handler {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "https"
			r.URL.Host = r.Host
		},
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				return net.Dial(network, net.JoinHostPort(upstream, port))
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		ModifyResponse: func(res *http.Response) error {
			b, _ := io.ReadAll(res.Body)
			res.Body = io.NopCloser(bytes.NewReader(b))
			var hdr strings.Builder
			for k, v := range res.Header {
				hdr.WriteString(" " + k + ": " + strings.Join(v, ",") + ";")
			}
			if !redact.Bodies {
				log.Printf("[capture] <<< %d %s %s%s body(%d)", res.StatusCode, res.Request.Method, res.Request.Host, redact.Path(res.Request.URL.Path), len(b))
				return nil
			}
			log.Printf("[capture] <<< %d %s %s%s hdr{%s} body(%d)=%s", res.StatusCode, res.Request.Method, res.Request.Host, res.Request.URL.RequestURI(), hdr.String(), len(b), b)
			return nil
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		httpx.Dump(r, passwordRe.ReplaceAll(body, []byte("password=***")), ">>> capture")
		rp.ServeHTTP(w, r)
	})
}
