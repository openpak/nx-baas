package main

// Two surfaces the 22.5.0 modules name that nothing here answered: the Internet
// connection test (qlaunch's `nn::netdiag`) and prepo, the play-report uploader
// (the `bcat` binary carries it). Both are in
// docs/firmware-22.5.0-followup-2026-09-12.md §21f and §21g.
//
// Neither needs anything invented. The connection test measures this network,
// so serving it truthfully is the whole implementation; prepo uploads telemetry
// that OpenPak does not collect, and the honest answer to that is to accept the
// report and drop it, which is what stops the console spooling retries forever.

import (
	"io"
	"log"
	"net"
	"net/http"
	"nx-baas/redact"
	"strconv"
	"strings"
	"time"
)

// ctestPayload is the download probe's size. The console asks for
// `http://ctest-dl-<env>.cdn.nintendo.net/30m`, so 30 MiB is the name's own
// promise; the upload probe posts 1 MiB the other way.
const ctestPayload = 30 << 20

// netdiag serves the connection test, the network clock and nifm's reachability
// check. `/v1/ip` tells the console the address this server sees it from -- the
// one measurement only the server can make -- the two cdn hosts are the
// throughput probes, and `/v1/time` is where NIM corrects the system clock.
func (s *server) netdiag(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r)
	switch {
	// nifm's reachability probe, and the reason a console says "connected"
	// rather than "check your connection". It reads one header off the reply
	// and nothing else: a captive portal answering 200 has no X-Organization
	// [firmware, nifm strings, beside connection_test_timeout].
	case host == "ctest.cdn.nintendo.net":
		w.Header().Set("X-Organization", "Nintendo")
		w.WriteHeader(200)
	case strings.HasPrefix(host, "ctest-dl-"):
		// A fixed-size body the console times. Range is honored because the
		// probe may resume, and Content-Length must be exact or the measurement
		// is of a truncated transfer.
		serveZeros(w, r, ctestPayload)
	case strings.HasPrefix(host, "ctest-ul-"):
		n, _ := io.Copy(io.Discard, r.Body)
		log.Printf("[netdiag] upload probe: %d bytes", n)
		w.WriteHeader(200)
	case r.URL.Path == "/v1/time":
		// NIM reads the whole body as one JSON number and divides by 1000
		// [firmware, nim FUN_00292400 / FUN_00292560, 63-byte buffer], so this
		// is Unix milliseconds and nothing else -- no object, no wrapper.
		ms := time.Now().UnixMilli()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(strconv.FormatInt(ms, 10)))
	case r.URL.Path == "/v1/ip":
		ip, public := clientIP(r)
		if public {
			log.Printf("[netdiag] global IP probe -> %s", redact.Addr(ip))
		} else {
			// Not a defect to route around silently: no hop in front of this
			// server passes the console's address on, so this is the closest
			// true answer available. PROXY protocol on the Traefik TCP router
			// is what would carry the real one.
			log.Printf("[netdiag] global IP probe -> %s (no public address visible; the console is hidden behind TLS passthrough)", redact.Addr(ip))
		}
		// Exactly one key. qlaunch parses this with a SAX handler [firmware
		// 22.5.0, qlaunch 0x164240; handler vtable 0x1156828] whose Key()
		// returns true only for "global_ip" and whose String() copies the
		// value into a 16-byte buffer; any other key terminates the parse and
		// the test fails with 2160-6000 (0x2ee0a0, the code the caller returns
		// when nothing was extracted). A second key "ip" reproduced that on a
		// console, 2026-09-24.
		writeJSON(w, 200, map[string]any{"global_ip": ip})
	default:
		log.Printf("[netdiag] UNMAPPED %s %s%s", r.Method, host, redact.Path(r.URL.Path))
		http.Error(w, "no such netdiag route", 404)
	}
}

// telemetry accepts a play report from prepo (`receive-<env>.dg…/post`,
// `…/api/v1/realtime_reports`, msgpack) and drops it. OpenPak does not keep
// them, and a console whose upload is refused keeps the report in `prepo-sys:`
// and retries; accepting it is what actually clears the spool. eupld's crash
// reports are kept and forwarded instead (errorreport.go). The size is logged
// so an operator can see the surface is live, never the contents.
func (s *server) telemetry(w http.ResponseWriter, r *http.Request, body []byte) {
	host, p := hostOf(r), r.URL.Path
	kind := "play report"
	ok := p == "/post" || p == "/api/v1/realtime_reports"
	if !ok {
		log.Printf("[telemetry] UNMAPPED %s %s%s", r.Method, host, redact.Path(p))
		http.Error(w, "no such route", 404)
		return
	}
	log.Printf("[telemetry] %s %d bytes discarded (OpenPak collects no %ss)", redact.Path(p), len(body), kind)
	w.WriteHeader(200)
}

// serveZeros writes n bytes of nothing, with Range support.
func serveZeros(w http.ResponseWriter, r *http.Request, n int64) {
	start, end := int64(0), n-1
	if rh := r.Header.Get("Range"); rh != "" {
		var err error
		if start, end, err = parseRange(rh, n); err != nil {
			w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(n, 10))
			w.WriteHeader(416)
			return
		}
		w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+
			strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(n, 10))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	if r.Header.Get("Range") != "" {
		w.WriteHeader(206)
	}
	if r.Method == "HEAD" {
		return
	}
	io.CopyN(w, zeroReader{}, end-start+1)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// clientIP finds the console's own address, which on this topology is harder
// than it looks: Traefik splices the TLS connection through without terminating
// it, so the only address anything downstream can see is the previous hop's.
// Prefer the first PUBLIC address in the forwarded chain -- a private one is a
// proxy, never the console -- and say so plainly when the chain has none rather
// than reporting 10.x to a screen that is labelled "global IP".
func clientIP(r *http.Request) (ip string, public bool) {
	for _, hop := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if a := net.ParseIP(strings.TrimSpace(hop)); a != nil && isPublic(a) {
			return a.String(), true
		}
	}
	ip = r.RemoteAddr
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	a := net.ParseIP(ip)
	return ip, a != nil && isPublic(a)
}

func isPublic(a net.IP) bool {
	return !a.IsLoopback() && !a.IsPrivate() && !a.IsLinkLocalUnicast() && !a.IsUnspecified()
}
