package main

// idbe: icon data for 3DS and Wii U titles, relayed from Nintendo's own CDN.
//
// NIM builds https://idbe-hac.cdn.nintendo.net/icondata/%02x/%016llX.idbe (builder
// 0x1eccc0) and .../%016llX-%hu.idbe (0x1ecc50); %02x is bits 8-15 of the id, the id is
// upper-case hex. The task (0x28c5e0, vtable 0x324830) sends a device-token header and
// Accept: application/json (the header every task of that base class sends), writes the
// body raw to a temporary file and hands it back unchanged through ns commands 5000
// (versioned) / 5001 (unversioned). It captures a quoted ETag (at most 39 characters) but
// does not send If-None-Match.
//
// The only 22.5.0 consumer is cabinet, the amiibo settings applet (0100000000001002),
// through ns 5001: it asks only for 3DS (0004…) and Wii U (0005…) title ids — the game an
// amiibo's save data belongs to — and a Switch id gets no icon. It requires the exact
// file size (0x36d2 for 3DS, 0x12082 for Wii U), byte 0 = 0 and byte 1 = key index 1-3,
// then decrypts AES-128-CBC with the per-index IDBE keys and checks the SHA-256 in front
// of the payload. That is the container idbe-ctr/idbe-wup.cdn.nintendo.net still serve
// (verified 2026-09-23 on 0004000000030800 and 0005000010101E00: 2-byte header, then
// AES-128-CBC over SHA-256 + payload; the payload is title id, version, sixteen
// UTF-16 short/long/publisher name slots and the icon). Nintendo's own idbe-hac bucket
// refuses every request (S3 AccessDenied).
//
// So OpenPak relays: a 3DS or Wii U id is fetched once from Nintendo's matching CDN
// (/icondata/10/<NAME>.idbe; the directory segment is not significant there), checked
// for size and header, cached under $NX_DATA/idbe/ and served with a quoted ETag. No
// key is held here and nothing is re-encrypted: the file is Nintendo's, byte for byte.
// A Switch id, anything else, or an upstream miss stays a logged 404. Unverified on
// hardware: that cabinet renders the relayed icon (its checks were read, not run).

import (
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// idbeSize is the exact file size cabinet accepts per platform.
var idbeSize = map[string]int{"ctr": 0x36d2, "wup": 0x12082}

// idbePlatform names the CDN for a title id: 3DS (0004…) or Wii U (0005…); "" otherwise.
func idbePlatform(tid string) string {
	switch {
	case len(tid) != 16 || !validTitleID(tid):
		return ""
	case strings.HasPrefix(tid, "0004"):
		return "ctr"
	case strings.HasPrefix(tid, "0005"):
		return "wup"
	}
	return ""
}

// validIdbe applies cabinet's own checks that need no key: size, byte 0 and key index.
func validIdbe(platform string, b []byte) error {
	if len(b) != idbeSize[platform] {
		return fmt.Errorf("size %d, want %d", len(b), idbeSize[platform])
	}
	if b[0] != 0 || b[1] < 1 || b[1] > 3 {
		return fmt.Errorf("header %02x %02x, want 00 and a key index 1-3", b[0], b[1])
	}
	return nil
}

// nintendoClass2CAG3 is the public root Nintendo's CDN certificates chain to (it is in
// the console's own trust store, ssl_TrustedCerts.bdf). Pinned so the relay trusts only
// Nintendo for these files.
const nintendoClass2CAG3 = `-----BEGIN CERTIFICATE-----
MIIErDCCA5SgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBmjELMAkGA1UEBhMCVVMx
EzARBgNVBAgTCldhc2hpbmd0b24xIjAgBgNVBAoTGU5pbnRlbmRvIG9mIEFtZXJp
Y2EsIEluYy4xCzAJBgNVBAsTAklTMSEwHwYDVQQDExhOaW50ZW5kbyBDbGFzcyAy
IENBIC0gRzMxIjAgBgkqhkiG9w0BCQEWE2NhQG5vYS5uaW50ZW5kby5jb20wHhcN
MTAwNDI5MTU1OTE4WhcNNDkxMjI4MTIwMDAwWjCBmjELMAkGA1UEBhMCVVMxEzAR
BgNVBAgTCldhc2hpbmd0b24xIjAgBgNVBAoTGU5pbnRlbmRvIG9mIEFtZXJpY2Es
IEluYy4xCzAJBgNVBAsTAklTMSEwHwYDVQQDExhOaW50ZW5kbyBDbGFzcyAyIENB
IC0gRzMxIjAgBgkqhkiG9w0BCQEWE2NhQG5vYS5uaW50ZW5kby5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDR0JlLuTabiKUVeaW1znP7dJ3m2vcu
SQk3QKAJf6inQREJIMG8LknTvdvX5Lmiwxd2P5hiSzmCzQyxMWN38zpQKzlW92es
FdwBnuUH9pXMDZBCcBEiwg2PxqNw4WdxlmRZ92R4g0Keenwh2GiETA2Ml2rasCCW
39TYNW7i8W0YQw7u1ZaMQ1GetWrvblt9UhmC7ZbI0pqJcBOZzR0tNbl79QT2WF8r
bRsSANlRi/H4LnjkMxrKrRYybLEfjDGBBfubhENKPRjUBEmp55gE2v0sVkLNLh2H
awCuSl+dpEG0D6BB/6/wZxxQdSbGVT6ahQRlHOVn0GZm4QC+Sc5yFYthAgMBAAGj
gfowgfcwHQYDVR0OBBYEFPfGCnxyfCzEvJMoQeTucPADoLu3MIHHBgNVHSMEgb8w
gbyAFPfGCnxyfCzEvJMoQeTucPADoLu3oYGgpIGdMIGaMQswCQYDVQQGEwJVUzET
MBEGA1UECBMKV2FzaGluZ3RvbjEiMCAGA1UEChMZTmludGVuZG8gb2YgQW1lcmlj
YSwgSW5jLjELMAkGA1UECxMCSVMxITAfBgNVBAMTGE5pbnRlbmRvIENsYXNzIDIg
Q0EgLSBHMzEiMCAGCSqGSIb3DQEJARYTY2FAbm9hLm5pbnRlbmRvLmNvbYIBATAM
BgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBE8V5A4HX/B3D2pbterUv8
P1hYXvF+qXXRLzEEmYSYDEC6eC/6biw1GmU1xamiuwzZC/1Llqv/9tUOsRiqbCcZ
y6PoplpfuoJpmoQltuP+hibDk6jSadEH1eK94P/6EnNpRHrgk5z4QVuXLmTi8iM6
7T5cVtqgXGhTOka6/AquzjrnJZA7q6OjH7soy+Ap4GW5iO3oNbfMcYWT25qVzhgV
cmm6niKF7yQY59H/XOaPOsL/fZlCRkp+UUxg/yj3bo+A34VSW8xlCu87HlVkKwlJ
4k5aF4MhHCbunoBTYwGhRC0hIlyvzIzG+Ky56UOimnZwztfJxA91uZzKPkWy5s43
-----END CERTIFICATE-----
`

var errIdbeMiss = errors.New("no icon data upstream")

// idbeFetch downloads one file from Nintendo's CDN; a variable so tests stand in for it.
var idbeFetch = func(platform, name string) ([]byte, time.Time, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(nintendoClass2CAG3))
	// The CDN's leaf names itself only in the legacy Common Name (*.cdn.nintendo.net, no
	// SAN), which Go's hostname check refuses. So the chain is verified against the
	// pinned root here, and the name against the Common Name.
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no certificate")
		}
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		leaf := cs.PeerCertificates[0]
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter}); err != nil {
			return err
		}
		if leaf.Subject.CommonName != "*.cdn.nintendo.net" || !strings.HasSuffix(cs.ServerName, ".cdn.nintendo.net") {
			return fmt.Errorf("certificate for %q presented for %q", leaf.Subject.CommonName, cs.ServerName)
		}
		return nil
	}
	c := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: true, // replaced by verify: pinned root + Common Name
			VerifyConnection:   verify}}}
	resp, err := c.Get("https://idbe-" + platform + ".cdn.nintendo.net/icondata/10/" + name + ".idbe")
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		// S3 answers 403 AccessDenied for a file it does not have.
		return nil, time.Time{}, fmt.Errorf("%w (HTTP %d)", errIdbeMiss, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	mod, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return b, mod, err
}

// idbeMisses remembers upstream misses for an hour so a console cannot make this server
// hammer Nintendo's CDN.
var idbeMisses = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

func idbeDir() string { return filepath.Join(getenv("NX_DATA", "/data"), "idbe") }

// idbeFile returns the cached file for a name, fetching and caching it on first use.
func idbeFile(platform, name string) ([]byte, time.Time, error) {
	path := filepath.Join(idbeDir(), platform, name+".idbe")
	if b, err := os.ReadFile(path); err == nil && validIdbe(platform, b) == nil {
		st, _ := os.Stat(path)
		return b, st.ModTime(), nil
	}
	idbeMisses.Lock()
	missed, ok := idbeMisses.at[path]
	idbeMisses.Unlock()
	if ok && time.Since(missed) < time.Hour {
		return nil, time.Time{}, fmt.Errorf("%w (cached miss)", errIdbeMiss)
	}
	b, mod, err := idbeFetch(platform, name)
	if err == nil {
		err = validIdbe(platform, b)
	}
	if err != nil {
		idbeMisses.Lock()
		idbeMisses.at[path] = time.Now()
		idbeMisses.Unlock()
		return nil, time.Time{}, err
	}
	if mod.IsZero() {
		mod = time.Now()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err == nil {
		if os.WriteFile(path+".tmp", b, 0o644) == nil && os.Rename(path+".tmp", path) == nil {
			os.Chtimes(path, mod, mod)
		}
	}
	return b, mod, nil
}

// idbe answers idbe-hac.cdn.nintendo.net.
func (s *server) idbe(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/icondata/") || !strings.HasSuffix(p, ".idbe") {
		dump(r, body, "!! UNHANDLED idbe")
		writeJSON(w, 404, map[string]any{"status": 404, "title": "no icon data"})
		return
	}
	name := strings.ToUpper(strings.TrimSuffix(p[strings.LastIndex(p, "/")+1:], ".idbe"))
	tid, version, _ := strings.Cut(name, "-")
	platform := idbePlatform(strings.ToLower(tid))
	if platform == "" {
		what := "not a 3DS or Wii U title"
		if s.shopTitleByAppID(tid) != nil {
			what = "an OpenPak store title; Switch ids have no idbe file and cabinet asks for none"
		}
		log.Printf("[shop] idbe %s %s title=%s version=%q (%s) -> 404", r.Method, p, tid, version, what)
		writeJSON(w, 404, map[string]any{"status": 404, "title": "no icon data"})
		return
	}
	b, mod, err := idbeFile(platform, name)
	if err != nil {
		log.Printf("[shop] idbe %s %s title=%s (%s) -> 404: %v", r.Method, p, tid, platform, err)
		writeJSON(w, 404, map[string]any{"status": 404, "title": "no icon data"})
		return
	}
	sum := md5.Sum(b)
	etag := `"` + hex.EncodeToString(sum[:]) + `"` // S3's ETag form: 34 characters, under NIM's 39
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Last-Modified", mod.UTC().Format(http.TimeFormat))
	h.Set("Accept-Ranges", "bytes")
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, etag) {
		log.Printf("[shop] idbe %s %s -> 304", r.Method, p)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", fmt.Sprint(len(b)))
	log.Printf("[shop] idbe %s %s title=%s -> 200: Nintendo's %s file relayed (%d bytes, key index %d; rendering unverified on hardware)",
		r.Method, p, tid, platform, len(b), b[1])
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		w.Write(b)
	}
}
