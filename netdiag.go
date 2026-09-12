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
	"strconv"
	"strings"
)

// ctestPayload is the download probe's size. The console asks for
// `http://ctest-dl-<env>.cdn.nintendo.net/30m`, so 30 MiB is the name's own
// promise; the upload probe posts 1 MiB the other way.
const ctestPayload = 30 << 20

// netdiag serves the connection test. `/v1/ip` tells the console the address
// this server sees it from -- the one measurement only the server can make --
// and the two cdn hosts are the throughput probes.
func (s *server) netdiag(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r)
	switch {
	case strings.HasPrefix(host, "ctest-dl-"):
		// A fixed-size body the console times. Range is honored because the
		// probe may resume, and Content-Length must be exact or the measurement
		// is of a truncated transfer.
		serveZeros(w, r, ctestPayload)
	case strings.HasPrefix(host, "ctest-ul-"):
		n, _ := io.Copy(io.Discard, r.Body)
		log.Printf("[netdiag] upload probe: %d bytes", n)
		w.WriteHeader(200)
	case r.URL.Path == "/v1/ip":
		ip := clientIP(r)
		log.Printf("[netdiag] global IP probe -> %s", ip)
		// Key name from public research on this endpoint, not from the module:
		// `nn::netdiag::detail::ExtractIpAddress` parses the document with a
		// SAX handler whose member comparison did not fall out of the binary
		// (open question W5).
		writeJSON(w, 200, map[string]any{"ip": ip})
	default:
		log.Printf("[netdiag] UNMAPPED %s %s%s", r.Method, host, r.URL.Path)
		http.Error(w, "no such netdiag route", 404)
	}
}

// prepo accepts a play report and drops it. OpenPak keeps no telemetry, and a
// console whose upload is refused keeps the report in `prepo-sys:` and retries;
// accepting it is what actually clears the spool. The count is logged so an
// operator can see the surface is live, never the contents.
func (s *server) prepo(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	if p != "/post" && p != "/api/v1/realtime_reports" {
		log.Printf("[prepo] UNMAPPED %s %s%s", r.Method, hostOf(r), p)
		http.Error(w, "no such prepo route", 404)
		return
	}
	log.Printf("[prepo] %s %d bytes discarded (OpenPak collects no play reports)", p, len(body))
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

// clientIP prefers the proxy's X-Forwarded-For: Traefik terminates the
// connection, so RemoteAddr is the proxy on every request that came through it.
func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		if i := strings.IndexByte(f, ','); i >= 0 {
			f = f[:i]
		}
		if ip := strings.TrimSpace(f); ip != "" {
			return ip
		}
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}
