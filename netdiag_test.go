package main

// The connection test is a measurement, so the only things worth asserting are
// the ones a wrong answer would corrupt: the byte count, the range arithmetic
// and which address gets reported back.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"nx-baas/internal/core"
	"nx-baas/internal/msgpack"
	"nx-baas/internal/services"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDownloadProbeServesExactlyItsAdvertisedSize(t *testing.T) {
	s := &server{Core: &core.Core{}}
	r := httptest.NewRequest("GET", "http://ctest-dl-lp1.cdn.nintendo.net/30m", nil)
	r.Host = "ctest-dl-lp1.cdn.nintendo.net"
	w := httptest.NewRecorder()
	s.consoleSvc().Netdiag(w, r)

	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if got := w.Header().Get("Content-Length"); got != strconv.Itoa(services.CtestPayload) {
		t.Fatalf("Content-Length %q, want %d", got, services.CtestPayload)
	}
	if got := w.Body.Len(); got != services.CtestPayload {
		t.Fatalf("wrote %d bytes, want %d -- a short body measures as a slow link", got, services.CtestPayload)
	}
}

func TestDownloadProbeResumes(t *testing.T) {
	s := &server{Core: &core.Core{}}
	r := httptest.NewRequest("GET", "http://ctest-dl-lp1.cdn.nintendo.net/30m", nil)
	r.Host = "ctest-dl-lp1.cdn.nintendo.net"
	r.Header.Set("Range", "bytes=1000-1999")
	w := httptest.NewRecorder()
	s.consoleSvc().Netdiag(w, r)

	if w.Code != 206 {
		t.Fatalf("status %d, want 206", w.Code)
	}
	if got := w.Body.Len(); got != 1000 {
		t.Fatalf("range served %d bytes, want 1000", got)
	}
	want := "bytes 1000-1999/" + strconv.Itoa(services.CtestPayload)
	if got := w.Header().Get("Content-Range"); got != want {
		t.Fatalf("Content-Range %q, want %q", got, want)
	}
}

func TestUploadProbeAcceptsTheBody(t *testing.T) {
	s := &server{Core: &core.Core{}}
	r := httptest.NewRequest("POST", "http://ctest-ul-lp1.cdn.nintendo.net/1m", zeroBody(1<<20))
	r.Host = "ctest-ul-lp1.cdn.nintendo.net"
	w := httptest.NewRecorder()
	s.consoleSvc().Netdiag(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
}

// The console is behind Traefik here, so RemoteAddr is the proxy: reporting it
// would tell every console its own network's address is the proxy's.
func TestGlobalIPProbeReportsTheForwardedAddress(t *testing.T) {
	s := &server{Core: &core.Core{}}
	r := httptest.NewRequest("GET", "https://api.hac.lp1.ctest.srv.nintendo.net/v1/ip", nil)
	r.Host = "api.hac.lp1.ctest.srv.nintendo.net"
	r.RemoteAddr = "10.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "10.89.2.12, 203.0.113.7")
	w := httptest.NewRecorder()
	s.consoleSvc().Netdiag(w, r)

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if got["global_ip"] != "203.0.113.7" {
		t.Fatalf("global_ip = %v, want the console's address under the key qlaunch reads", got["global_ip"])
	}
	if _, extra := got["ip"]; extra || len(got) != 1 {
		t.Fatalf("body = %v, want global_ip alone: qlaunch's handler rejects any other key", got)
	}
}

// When every hop is private the console's address is genuinely not visible.
// Report what we can see rather than inventing a plausible public address.
func TestGlobalIPProbeDoesNotInventAnAddress(t *testing.T) {
	ip, public := services.ClientIP(&http.Request{
		RemoteAddr: "10.89.2.12:40000",
		Header:     http.Header{"X-Forwarded-For": []string{"10.89.2.247"}},
	})
	if public {
		t.Fatal("a chain of private hops was reported as a public address")
	}
	if ip != "10.89.2.12" {
		t.Fatalf("ip = %q, want the address actually seen", ip)
	}
}

// NIM (23.0.x) parses the body as one JSON object with the single key "unixtime" whose
// value is a string of at most 19 digits, Unix milliseconds. A bare number, a numeric
// value or an extra key is rejected and the console retries every 5 s.
func TestNetworkClockIsAUnixtimeStringObject(t *testing.T) {
	s := &server{Core: &core.Core{}}
	r := httptest.NewRequest("GET", "https://api.hac.lp1.ctest.srv.nintendo.net/v1/time", nil)
	r.Host = "api.hac.lp1.ctest.srv.nintendo.net"
	w := httptest.NewRecorder()
	s.consoleSvc().Netdiag(w, r)

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not a JSON object: %v", w.Body.String(), err)
	}
	if len(body) != 1 {
		t.Fatalf("body %q must have exactly one key", w.Body.String())
	}
	str, ok := body["unixtime"].(string)
	if !ok {
		t.Fatalf("unixtime must be a string, got %T", body["unixtime"])
	}
	if len(str) == 0 || len(str) > 19 {
		t.Fatalf("unixtime %q must be 1..19 digits", str)
	}
	ms, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		t.Fatalf("unixtime %q is not decimal: %v", str, err)
	}
	if delta := ms/1000 - time.Now().Unix(); delta > 5 || delta < -5 {
		t.Fatalf("clock is %ds off -- the value must be milliseconds, not seconds", delta)
	}
	if w.Body.Len() > 63 {
		t.Fatalf("body is %d bytes; NIM reads at most 63", w.Body.Len())
	}
}

// nifm decides "connected" from one header. A 200 without it reads as a captive
// portal, which is the "check your connection" screen.
func TestReachabilityProbeCarriesTheOrganizationHeader(t *testing.T) {
	s := &server{Core: &core.Core{}}
	r := httptest.NewRequest("GET", "http://ctest.cdn.nintendo.net/", nil)
	r.Host = "ctest.cdn.nintendo.net"
	w := httptest.NewRecorder()
	s.consoleSvc().Netdiag(w, r)

	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if got := w.Header().Get("X-Organization"); got != "Nintendo" {
		t.Fatalf("X-Organization = %q, want Nintendo", got)
	}
}

func TestTelemetryAcceptsAReportAndRefusesAnUnmappedRoute(t *testing.T) {
	s := &server{Core: &core.Core{}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://receive-lp1.dg.srv.nintendo.net/post", nil)
	r.Host = "receive-lp1.dg.srv.nintendo.net"
	s.consoleSvc().Telemetry(w, r, []byte{0x80})
	if w.Code != 200 {
		t.Fatalf("a play report was refused (%d); the console will keep retrying it", w.Code)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "https://receive-lp1.dg.srv.nintendo.net/elsewhere", nil)
	r.Host = "receive-lp1.dg.srv.nintendo.net"
	s.consoleSvc().Telemetry(w, r, nil)
	if w.Code != 404 {
		t.Fatalf("unmapped prepo route answered %d, want 404", w.Code)
	}
}

func zeroBody(n int) *zeroLimit { return &zeroLimit{n: n} }

type zeroLimit struct{ n int }

func (z *zeroLimit) Read(p []byte) (int, error) {
	if z.n == 0 {
		return 0, io.EOF
	}
	if len(p) > z.n {
		p = p[:z.n]
	}
	for i := range p {
		p[i] = 0
	}
	z.n -= len(p)
	return len(p), nil
}

// eupld posts a crash report to the root of its own host. It shares nothing
// with prepo's routes, so it is routed on its own (errorreport.go) and accepted.
func TestErrorReportUploadIsAccepted(t *testing.T) {
	s := &server{Core: &core.Core{}}
	s.consoleSvc().Reports = services.NewReportSpool(t.TempDir())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://receive.hac.lp1.er.srv.nintendo.net/", strings.NewReader("--boundary"))
	r.Host = "receive.hac.lp1.er.srv.nintendo.net"
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("a crash report was refused (%d); erpt will keep retrying it", w.Code)
	}
}

// A play report names its events and application, and nothing else is read.
func TestReportEvents(t *testing.T) {
	body := msgpack.Ordered("application_id", "0100c2500fc20000", "event_id", "online_error", "data", msgpack.Ordered("user", "secret"))
	got := services.ReportEvents(body)
	if got != " [application_id=0100c2500fc20000 event_id=online_error]" {
		t.Fatalf("got %q", got)
	}
	if services.ReportEvents([]byte("\xc1 not msgpack")) != " [not msgpack: first byte 0xc1]" {
		t.Fatal("non-msgpack body named events")
	}
}
