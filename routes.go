package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"nx-baas/internal/httpx"
	"nx-baas/redact"
	"os"
	"regexp"
	"strings"
	"time"
)

type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (rec *recorder) WriteHeader(c int) { rec.status = c; rec.ResponseWriter.WriteHeader(c) }

func (rec *recorder) Write(b []byte) (int, error) {
	if rec.buf.Len() < 8192 {
		rec.buf.Write(b)
	}
	return rec.ResponseWriter.Write(b)
}

// Flush forwards to the wrapped writer when it can stream. Without this the
// debug wrapper hid http.Flusher from handlers: the Penne frontline (and any
// other held-open response) silently fell back to a buffered, non-streaming
// answer whenever NX_DEBUG was set. B workstream fix (NTF-03).
func (rec *recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards likewise: the NPNS frontline takes the raw connection for
// its bidirectional frame stream, so the debug wrapper must not hide
// http.Hijacker either. B workstream fix (NTF-03).
func (rec *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rec.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("recorder: wrapped writer is not a Hijacker")
}

var debug = os.Getenv("NX_DEBUG") != ""

// pctlPinInBody finds a PIN in a body about to be logged: the console's own
// keys, and the parent side's `unlock_code`.
var pctlPinInBody = regexp.MustCompile(`("(?:synchronizedUnlockCode|unlockCode|unlock_code)"\s*:\s*")[^"]*"`)

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := httpx.HostOf(r)
	log.Printf("[nx-baas] %s %s%s ua=%q", r.Method, host, redact.URL(r.URL), redact.IDs(r.UserAgent()))
	// A family that moved to its own service is forwarded before anything here reads the
	// body (split.go); with no forward URL configured this is a no-op.
	if s.forwardMoved(w, r) {
		return
	}
	if isSpelunky(host) {
		// Before the body read: /nso carries the raw identity token (spelunky2.go).
		// Unset, this falls through to the catch-all below, which logs and 404s.
		if fwd := spelunky2Forwarder(); fwd != nil {
			fwd.ServeHTTP(w, r)
			return
		}
	}
	// The friends module fetches its app catalog and art from a configured
	// host, so this matches on the path before host routing claims it
	// (eshop_unserved.go). It declines anything that is not /v1/apps/<id>/.
	if s.friendsAppCatalog(w, r) {
		return
	}
	// migration.<env>.scsi.srv.nintendo.net is not save data: it is the
	// console-to-console user transfer (`/api/nx/v1/account_migrations/gen_key`
	// and `get_key`, with transfer.hac.<env>.banco.srv.nintendo.net alongside)
	// [firmware, migration module]. It shares the scsi domain, so without this
	// it was being forwarded into the saves service, which can only 404 it.
	// OpenPak does not implement transfer; say so in the log rather than hide
	// it inside somebody else's 404.
	if strings.HasPrefix(host, "migration.") || strings.HasPrefix(host, "transfer.") {
		log.Printf("[nx-baas] user transfer is not implemented: %s %s%s", r.Method, host, redact.Path(r.URL.Path))
		http.Error(w, "user transfer is not implemented by OpenPak", 501)
		return
	}
	if isPlayFab(host) {
		// Before the body read: login bodies carry identity tokens (playfab.go).
		if s.PlayfabFwd != nil && strings.EqualFold(host, "94845.playfabapi.com") {
			s.PlayfabFwd.ServeHTTP(w, r)
			return
		}
		playfabUnavailable(w, r)
		return
	}
	if strings.Contains(host, ".er.srv.nintendo.net") {
		// eupld's error reports, before the shared 1 MiB body read (errorreport.go).
		s.errorReport(w, r)
		return
	}
	if s.saves != nil && strings.Contains(host, "scsi.srv.nintendo.net") {
		// Before the body is read: a save can be hundreds of MB and streams through.
		s.savesProxy(w, r)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if debug && !strings.HasPrefix(r.URL.Path, "/avatar/") {
		// No PIN either: parental controls carry one in both directions.
		httpx.Dump(r, pctlPinInBody.ReplaceAll(passwordRe.ReplaceAll(body, []byte("password=***")), []byte(`${1}****"`)), "DBG >>>")
		rec := &recorder{ResponseWriter: w, status: 200}
		w = rec
		defer func() {
			if !redact.Bodies {
				log.Printf("[nx-baas] DBG <<< %d %s %s%s body(%d)", rec.status, r.Method, host, redact.Path(r.URL.Path), rec.buf.Len())
				return
			}
			log.Printf("[nx-baas] DBG <<< %d %s %s%s body(%d)=%s", rec.status, r.Method, host, r.URL.Path, rec.buf.Len(), pctlPinInBody.ReplaceAll(rec.buf.Bytes(), []byte(`${1}****"`)))
		}()
	}
	switch {
	// Liveness, for anything checking from outside. Deliberately answered
	// before host routing: the console-facing names all resolve here, and a
	// health check should not have to pick one of them.
	case r.URL.Path == "/healthz":
		httpx.WriteJSON(w, 200, map[string]any{"status": "ok", "service": "nx-baas"})
	case strings.HasPrefix(r.URL.Path, "/connect/1.0.0/qr/") || strings.HasPrefix(r.URL.Path, "/link"):
		if !s.naSvc().QRRoutes(w, r, body) {
			http.NotFound(w, r)
		}
	case strings.Contains(host, "accounts.nintendo.com"):
		s.naSvc().Handle(w, r, body)
	case strings.HasSuffix(host, ".znc.srv.nintendo.net"):
		// The voice-chat lobby page systemWeb opens (nso.go).
		s.zncLobby(w, r, body)
	// The eShop's hosts (pearljam, idbe, bvc, bugyo, savanna, pushmo, tagaya, the d4c family,
	// dragonst, tigers, beach) and the store rights routes of dragons are nx-shop's, forwarded
	// above (split.go). The dauth case below keeps dragons' setup-critical answers.
	case strings.HasPrefix(host, "dauth") || strings.HasPrefix(host, "dcert") ||
		strings.HasPrefix(host, "acert") || strings.HasPrefix(host, "aauth") ||
		strings.HasPrefix(host, "dragons"):
		// dragons hosts that are not store rights routes keep the dauth handler's
		// setup-critical answers (elicense archives, exercise, migration state, penne id).
		s.dauthSvc().Handle(w, r, body)
	case strings.Contains(host, "penne.") || strings.Contains(host, "vermillion."):
		// Penne's own hosts are nx-penne's, forwarded above; this is the vermillion gateway.
		s.vermillion(w, r, body)
	case strings.HasSuffix(host, ".five.nintendo.net"):
		// Native online-play invitations (the friends sysmodule's invite UI).
		s.invitationsSvc().Five(w, r, body)
	case strings.HasPrefix(host, "capi.") && strings.HasSuffix(r.URL.Path, "/membership"):
		// The per-title check, beside the list below: nn.account asks
		// `/v1/users/<id>/membership?application_id=<tid>` and reads
		// `$.membership.active` [firmware, account strings]. Answering only the
		// plural left this one on the catch-all 404.
		httpx.WriteJSON(w, 200, map[string]any{"membership": map[string]any{
			"active": true, "expires_at": time.Now().Unix() + 365*86400,
		}})
	case strings.HasPrefix(host, "capi.") && strings.HasSuffix(r.URL.Path, "/memberships"):
		// NSO membership check: every account has an active membership in both
		// contexts. "default" is the base plan and "ex" the Expansion Pack
		// [firmware, account module: the parser binds .user_id, .context and
		// .membership.active]. OpenPak sells no tiers, so there is nothing an
		// account could lack; answering ex inactive sent every Expansion Pack
		// title to a paywall prompt for a purchase that does not exist.
		seg := strings.Split(r.URL.Path, "/")
		naID := seg[len(seg)-2]
		expires := time.Now().Unix() + 365*86400
		httpx.WriteJSON(w, 200, map[string]any{"count": 2, "items": []any{
			map[string]any{"context": "ex", "membership": map[string]any{"active": true, "expires_at": expires}, "user_id": naID},
			map[string]any{"context": "default", "membership": map[string]any{"active": true, "expires_at": expires}, "user_id": naID},
		}, "total": 2})
	case strings.HasSuffix(host, ".nso.nintendo.net"):
		// The HOME Menu's Nintendo Switch Online button (Lhub) and its red-dot
		// feed (nso.go).
		s.nso(w, r, body)
	case strings.Contains(host, "frs.srv.nintendo.net"):
		s.frs(w, r, body)
	case isBcatHost(host):
		// BCAT and the News channel are nx-bcat's: Traefik routes these hosts there, and
		// NX_BCAT_URL forwards whatever still lands here (split.go). Without it, nothing.
		log.Printf("[nx-baas] bcat host %s%s -> 404: BCAT is served by nx-bcat (NX_BCAT_URL unset)", host, redact.Path(r.URL.Path))
		httpx.WriteJSON(w, 404, map[string]any{})
	case strings.Contains(host, ".acbaa.srv.nintendo.net"):
		// Animal Crossing web API (acbaa.go): island registration. Before
		// this it fell into the catch-all 404 and ACNH errored (2219-xxxx)
		// before ever reaching NEX.
		s.acbaaSvc().Handle(w, r, body)
	case strings.Contains(host, ".tabiji.srv.nintendo.net"):
		// Firmware 23's play-history upload (tabiji.go).
		s.tabiji(w, r, body)
	case strings.HasSuffix(host, ".dg.srv.nintendo.net"):
		// prepo's play reports (netdiag.go); eupld's error reports are routed above.
		s.telemetry(w, r, body)
	case strings.HasPrefix(host, "ctest") || strings.Contains(host, ".ctest.srv.nintendo.net"):
		// The Internet connection test in System Settings (netdiag.go).
		s.netdiag(w, r)
	case strings.Contains(host, "scsi.srv.nintendo.net"):
		s.olsc(w, r, body)
	case strings.HasPrefix(host, "app.lp1.srv"):
		s.serviceStatus(w, r, body)
	// Answered by path rather than host, and only after every host-specific
	// handler above has declined: the NIM surfaces that had no handler
	// (eshop_unserved.go). It returns false when the path is not one of them.
	case s.nimUnserved(w, r, body):
	case !strings.Contains(host, "baas.nintendo.com"):
		httpx.Dump(r, body, "!! UNHANDLED host (catch-all)")
		httpx.WriteJSON(w, 404, map[string]any{})
	default:
		s.baasSvc().Handle(w, r, body)
	}
}

// clientCertFor asks for a client certificate on the device-auth hosts only, where consoles do
// present one and it is the sole way to tell them apart. Everything else — the browser above
// all — is served without a CertificateRequest.
func clientCertFor(h *tls.ClientHelloInfo, base *tls.Config) (*tls.Config, error) {
	if !strings.HasPrefix(h.ServerName, "dauth") && !strings.HasPrefix(h.ServerName, "dcert") &&
		!strings.HasPrefix(h.ServerName, "aauth") {
		return nil, nil
	}
	c := base.Clone()
	c.ClientAuth = tls.RequestClientCert
	c.GetConfigForClient = nil
	return c, nil
}

func selfSigned(hosts []string, caDir string) tls.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := x509.Certificate{
		SerialNumber: func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)); return n }(), Subject: pkix.Name{CommonName: hosts[0], Organization: []string{"OpenPak"}},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: hosts,
	}
	if caPEM, err := os.ReadFile(caDir + "/ca.pem"); err == nil {
		if keyPEM, err := os.ReadFile(caDir + "/ca.key"); err == nil {
			if pair, err := tls.X509KeyPair(caPEM, keyPEM); err == nil {
				if ca, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
					if der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca, &key.PublicKey, pair.PrivateKey); err == nil {
						log.Printf("[nx-baas] server cert signed by the OpenPak CA")
						return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
					}
				}
			}
		}
	}
	log.Printf("[nx-baas] server cert self-signed (relies on disable_ca_verification)")
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
