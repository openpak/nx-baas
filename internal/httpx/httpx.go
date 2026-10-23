// Package httpx holds the HTTP plumbing every nx-baas surface shares: JSON and error
// replies, the request log helpers, the forwarders to split-out services and the
// internal-key checks.
package httpx

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"nx-baas/redact"
	"os"
	"sort"
	"strings"
)

func Getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func BaasErr(w http.ResponseWriter, r *http.Request, status int, code, title, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"status": status, "errorCode": code, "title": title, "detail": detail,
		"instance": r.URL.Path, "type": fmt.Sprintf("https://baas.nintendo.com/errors/1.0.0/%d/%s", status, code),
	})
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// Captured from a real reply, which sends both beside the no-cache
	// this already had.
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Vary", "Accept-Encoding,Origin")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func HostOf(r *http.Request) string {
	h := r.Host
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

// Dump logs a request the server does not (fully) understand. By default it
// names the route, the header names and the body's size: header values, query
// values and bodies carry tokens, ids and names. NXBAAS_TRACE_BODIES=1 (never in
// production) adds the full headers and body.
func Dump(r *http.Request, body []byte, tag string) {
	if !redact.Bodies {
		names := make([]string, 0, len(r.Header))
		for k := range r.Header {
			names = append(names, k)
		}
		sort.Strings(names)
		log.Printf("[nx-baas] %s %s %s%s hdr{%s} body(%d) ct=%q", tag, r.Method, HostOf(r), redact.URL(r.URL),
			strings.Join(names, ","), len(body), r.Header.Get("Content-Type"))
		return
	}
	var hdr strings.Builder
	for k, v := range r.Header {
		if k == "Authorization" && len(v) > 0 && len(v[0]) > 40 {
			fmt.Fprintf(&hdr, " %s: %s...;", k, v[0][:40])
			continue
		}
		fmt.Fprintf(&hdr, " %s: %s;", k, strings.Join(v, ","))
	}
	log.Printf("[nx-baas] %s %s %s%s?%s hdr{%s} body(%d)=%q", tag, r.Method, HostOf(r), r.URL.Path, r.URL.RawQuery, hdr.String(), len(body), body)
	if len(body) > 0 && !json.Valid(body) && !strings.Contains(r.Header.Get("Content-Type"), "form") {
		log.Printf("[nx-baas] %s body hex: %s", tag, hex.EncodeToString(body))
	}
}

func APIErr(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]any{"error": msg})
}

// InternalOK guards the /internal endpoints. The API port is internal (compose network or
// loopback) and the key is the second lock. Fail closed: with no key configured there is
// nothing to compare, so every /internal route refuses. Isolated development opts out
// explicitly (and loudly) with NX_INTERNAL_INSECURE=1, which production must never set.
func InternalOK(r *http.Request) bool {
	k := Getenv("NX_INTERNAL_KEY", Getenv("OPENPAK_INTERNAL_KEY", ""))
	if k == "" {
		return os.Getenv("NX_INTERNAL_INSECURE") == "1"
	}
	return hmac.Equal([]byte(k), []byte(r.Header.Get("X-Internal-Key")))
}

// NewForwarder is a streaming reverse proxy that keeps the request's Host.
func NewForwarder(name, base string) *httputil.ReverseProxy {
	target, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || target.Host == "" {
		log.Fatalf("[nx-baas] %s forward URL %q: %v", name, base, redact.Err(err))
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // the service routes on the console's hostname
		},
		// Streamed both ways: store uploads are gigabytes, content downloads too.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[nx-baas] forward to %s failed: %s %s%s: %v", name, r.Method, HostOf(r), redact.Path(r.URL.Path), redact.Err(err))
			WriteJSON(w, http.StatusBadGateway, map[string]any{"status": 502, "title": name + " unreachable"})
		},
	}
}

// ForwardRead forwards a request whose body this process already read.
func ForwardRead(fwd *httputil.ReverseProxy, w http.ResponseWriter, r *http.Request, body []byte) {
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(body))
	r2.ContentLength = int64(len(body))
	fwd.ServeHTTP(w, r2)
}

// AdminError is the strict internal routes' error: {"error": code, "message": msg}. The
// store admin API introduced it; the identity API answers in the same shape.
type AdminError struct {
	status    int
	code, msg string
}

func (e *AdminError) Error() string { return e.code + ": " + e.msg }

func AdminErr(status int, code, format string, a ...any) *AdminError {
	return &AdminError{status: status, code: code, msg: fmt.Sprintf(format, a...)}
}

func WriteAdminErr(w http.ResponseWriter, err error) {
	var ae *AdminError
	if !errors.As(err, &ae) {
		log.Printf("[store-admin] internal: %v", redact.Err(err))
		ae = AdminErr(500, "internal", "%v", err)
	}
	WriteJSON(w, ae.status, map[string]any{"error": ae.code, "message": ae.msg})
}

// RequireInternalKey is InternalOK made strict: same header, same key, but no key configured
// means nobody gets in.
func RequireInternalKey(r *http.Request) error {
	k := Getenv("NX_INTERNAL_KEY", Getenv("OPENPAK_INTERNAL_KEY", ""))
	if k == "" {
		return AdminErr(503, "internal_key_not_configured", "set NX_INTERNAL_KEY to use the store admin API")
	}
	if !hmac.Equal([]byte(k), []byte(r.Header.Get("X-Internal-Key"))) {
		return AdminErr(401, "unauthorized", "X-Internal-Key missing or wrong")
	}
	return nil
}

func Str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}
