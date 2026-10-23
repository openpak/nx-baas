// nx-baas: the BAAS (baas.nintendo.com) and Nintendo Account (accounts.nintendo.com) servers a
// real CFW Switch talks to, backed by the account server for identity and the friend graph.
//
// Flow the console drives (account sysmodule, then the friends sysmodule with the same device
// account):  dauth -> POST /1.0.0/application/token -> POST /1.0.0/users (first boot) ->
// POST /1.0.0/login -> [Link: browser GET /connect/1.0.0/authorize -> POST /connect/1.0.0/api/token
// -> POST /1.0.0/federation] -> GET/PATCH /1.0.0/users/<id> -> /2.0.0 friends + presence.
//
// Everything unknown is logged in full (method, host, path, headers, body): the console teaches us
// the undocumented parts (the friend-invitation endpoint above all).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"log"
	"net/http"
	"net/http/httputil"
	"nx-baas/internal/acbaa"
	"nx-baas/internal/baas"
	"nx-baas/internal/bans"
	"nx-baas/internal/core"
	"nx-baas/internal/dauth"
	"nx-baas/internal/devices"
	"nx-baas/internal/events"
	"nx-baas/internal/friends"
	"nx-baas/internal/gameapi"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/invitations"
	"nx-baas/internal/nxaccount"
	"nx-baas/internal/penne"
	"nx-baas/internal/presence"
	"nx-baas/internal/store"
	"nx-baas/internal/token"
	"nx-baas/redact"
	"os"
	"strings"
	"sync"
	"time"
)

type server struct {
	*core.Core
	mu sync.Mutex
	// saves forwards the scsi hosts (save-data cloud) to the saves service, with the
	// console's proven account attached. nil answers the empty-cloud fallback instead.
	saves    *httputil.ReverseProxy
	savesKey string
	// shopFwd forwards the eShop to nx-shop (split.go).
	shopFwd *httputil.ReverseProxy
	// penneFwd forwards the Penne hosts and /internal/penne to nx-penne (split.go).
	penneFwd *httputil.ReverseProxy
	// notifier is where checked notifications go (internal/penne): Core.Penne.
	notifier penne.Notifier
	// pctlFwd forwards parental controls to nx-pctl (split.go).
	pctlFwd *httputil.ReverseProxy
	// bcatFwd is nx-bcat once the bcat hosts have moved (NX_BCAT_URL, split.go).
	bcatFwd *httputil.ReverseProxy
	// playfabFwd serves only explicitly supported PlayFab titles (playfab.go).
	playfabFwd *httputil.ReverseProxy
	// bansChecker answers whether an account may use the network (internal/bans); locks()
	// creates it on first use so test servers built as literals work unchanged.
	bansChecker *bans.Checker
	// presenceService is presence: per-device claims, the aggregate friends see, the core's
	// sessions and other platforms (internal/presence).
	presenceService *presence.Service
	presenceOnce    sync.Once
	// invitationsService is online-play invitations, five and the mailbox (internal/invitations).
	invitationsService *invitations.Service
	invitationsOnce    sync.Once
	// naService is the Nintendo Account surface and the console link pages (internal/nxaccount).
	naService *nxaccount.Service
	naOnce    sync.Once
	// friendsService is the friends surface and the BAAS objects it renders (internal/friends).
	friendsService *friends.Service
	friendsOnce    sync.Once
	// baasService is the BAAS surface: application token, login, users, federation and the
	// avatar host (internal/baas).
	baasService *baas.Service
	baasOnce    sync.Once
	// acbaaService is Animal Crossing's web API (internal/acbaa).
	acbaaService *acbaa.Service
	acbaaOnce    sync.Once
	// dauthService is device and application authentication (internal/dauth).
	dauthService *dauth.Service
	dauthOnce    sync.Once
	bansOnce     sync.Once
	// reports is the console error-report spool (errorreport.go).
	reports *reportSpool
}

// newBackend selects the identity source: the historical OpenPak HTTP
// client (default, keeps the proven deployment running) or the OpenPak
// account core (ACCOUNT_BACKEND=openpak).
func newBackend() identity.Backend {
	if os.Getenv("ACCOUNT_BACKEND") == "openpak" {
		b, err := identity.NewOpenpakBackend(context.Background(), httpx.Getenv("NX_DATA", "/data"))
		if err != nil {
			log.Fatalf("[nx-baas] openpak backend: %v", redact.Err(err))
		}
		log.Printf("[nx-baas] identity backend: openpak account core (%s)", httpx.Getenv("ACCOUNT_GRPC_ADDR", "127.0.0.1:7000"))
		return b
	}
	log.Printf("[nx-baas] identity backend: earlier account server (no console two-factor step-up; alpha requires ACCOUNT_BACKEND=openpak)")
	return &identity.AccountClient{
		Base: strings.TrimRight(httpx.Getenv("ACCOUNT_API", "http://account:8080"), "/"), AdminKey: os.Getenv("OPENPAK_ADMIN_KEY"),
		Secret: []byte(os.Getenv("OPENPAK_SECRET")), HTTP: &http.Client{Timeout: 10 * time.Second},
	}
}

func main() {
	if env, service := missingForward(); env != "" {
		log.Fatalf("[nx-baas] %s is required: %s serves that family now and nx-baas only forwards to it (docs/service-split.md)", env, service)
	}
	key := token.LoadRSAKey(httpx.Getenv("BAAS_SIGNING_KEY", "/keys/baas_signing_key.pem"))
	s := &server{
		Core: &core.Core{
			Store:  store.Load(httpx.Getenv("NX_DATA", "/data") + "/baas.json"),
			Key:    key,
			IDKid:  httpx.Getenv("BAAS_KID", "openpak-baas-key-1"),
			AccKid: httpx.Getenv("BAAS_ACCESS_KID", "00000000-0000-0000-0000-000000000003"),
			NAKid:  httpx.Getenv("BAAS_NA_KID", "00000000-0000-0000-0000-000000000001"),
			Acct:   newBackend(),
		},
	}
	s.forwardersFromEnv()
	s.Harbor = devices.FromEnv()
	s.acbaaSvc().Open(httpx.Getenv("NX_DATA", "/data") + "/acbaa.json")
	if b, ok := s.Acct.(*identity.OpenpakBackend); ok {
		go s.eventsSvc().Follow(b)
		// One presence reconciler beside the one core-event poller: leases,
		// heartbeats and expiries on the adapter's clock (PRE-02).
		go s.presenceSvc().ReconcileLoop()
		go s.eventsSvc().ProvisionAll(b)
	}
	// Integration wiring: C's committed-invitation seam delivers through B
	// (notify_wiring.go). Registered here so the REST surface keeps working
	// unchanged when the notification side is absent.
	s.eventsSvc().WireInvitations()
	// Console error reports: kept raw, forwarded to the website, retried (errorreport.go).
	go s.errorReports().run()
	// Latest version only: outdated titles get 2124-3001 at aauth (versiongate.go).
	s.dauthSvc().Versions = dauth.NewVersionGateFromEnv()
	if s.dauthSvc().Versions.On {
		log.Printf("[version-gate] on (%d override(s))", len(s.dauthSvc().Versions.Overrides))
		go s.dauthSvc().Versions.Run()
	} else {
		log.Printf("[version-gate] off (NX_VERSION_GATE)")
	}
	if u := os.Getenv("SAVES_URL"); u != "" {
		s.saves, s.savesKey = newSavesProxy(u), os.Getenv("SAVES_INTERNAL_KEY")
		log.Printf("[nx-baas] save-data cloud: forwarding scsi hosts to %s", u)
	}
	s.JWKS = token.JWKSFor(&key.PublicKey, s.IDKid, httpx.Getenv("BAAS_ID_KID", "00000000-0000-0000-0000-000000000002"), s.AccKid, s.NAKid)
	cert := selfSigned([]string{core.BaasHost, "m-lp1.baas.nintendo.com", "cdn-image-e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com",
		"accounts.nintendo.com", "api.accounts.nintendo.com", "cdn.accounts.nintendo.com",
		"god.hac.lp1.penne.srv.nintendo.net", "val.hac.penne.srv.nintendo.net", "val.hac.lp1.penne.srv.nintendo.net",
		"app.lp1.five.nintendo.net",
		"fro-3.hac.lp1.penne.srv.nintendo.net", "gw.hac.lp1.vermillion.srv.nintendo.net", "beach.hac.lp1.eshop.nintendo.net", "capi.lp1.op2.nintendo.net",
		// Store workstream: shop applet host, content host and the tigers eticket host.
		// dragons/dragonst are already above. The ashigaru page may reference further eshop
		// names (samurai/sun) — unrouted SNIs still get on-demand certs below.
		"bugyo.hac.lp1.eshop.nintendo.net", "atum.hac.lp1.d4c.nintendo.net", "tigers.hac.lp1.dragons.nintendo.net",
		// NIM names this one too; without it on the fixed cert the console
		// gets an on-demand cert for a host it may authenticate strictly.
		"pearljam.hac.lp1.eshop.nintendo.net",
		// Device auth: these must be on the fixed cert, not minted on demand — the console
		// rejects an on-demand cert on the names it authenticates against (2123-0013).
		"dauth-lp1.ndas.srv.nintendo.net", "dcert-lp1.ndas.srv.nintendo.net", "acert-lp1.ndas.srv.nintendo.net",
		"aauth-lp1.ndas.srv.nintendo.net", "aauth.hac.lp1.ndas.srv.nintendo.net",
		"dragons.hac.lp1.dragons.nintendo.net", "dragonst.hac.lp1.dragons.nintendo.net",
		// BCAT/News (nx-bcat's now), prepo and the connection test (netdiag.go). The
		// ctest-dl/ctest-ul probes are plain HTTP and need no name here.
		"bcat-list-lp1.cdn.nintendo.net", "bcat-topics-lp1.cdn.nintendo.net", "bcat-data-lp1.cdn.nintendo.net",
		"api.hac.lp1.ctest.srv.nintendo.net", "fw-api.lp1.nso.nintendo.net",
		"receive-lp1.dg.srv.nintendo.net", "realtime-receive-lp1.dg.srv.nintendo.net",
		"receive.hac.lp1.er.srv.nintendo.net",
		// Firmware 23's play-history upload (tabiji.go), authenticated with the NSA id token.
		"api.hac.lp1.tabiji.srv.nintendo.net",
		// Friend suggestions (FRS). The friends module authenticates this name
		// strictly, exactly like the dauth names above: on 2026-09-26 05:08 the
		// on-demand cert happened to be accepted and the GET landed, and at
		// 16:23 — after a restart regenerated it — the console answered the
		// handshake with EOF and the suggestions pane failed with no request
		// ever sent. A fixed SAN is the difference between those two runs.
		"api-lp1.frs.srv.nintendo.net",
		// Parental controls (moon, nx-pctl's now). Added before the first on-console
		// pairing attempt rather than after: this name was on the on-demand
		// path too, and if pctl authenticates it the way friends does, that
		// attempt would produce a handshake EOF and no log at all — which
		// reads as "the console never tried" and would send phase 0's gate
		// hunting the wrong thing. Firmware template: api-%.pctl.srv.nintendo.net.
		"api-lp1.pctl.srv.nintendo.net"}, httpx.Getenv("NX_CA_DIR", "/data/ca"))
	var handler http.Handler = s
	if up := os.Getenv("NX_UPSTREAM"); up != "" {
		log.Printf("[nx-baas] CAPTURE MODE: forwarding everything to %s; bodies and headers are logged only with NXBAAS_TRACE_BODIES=1", up)
		handler = newCaptureProxy(up)
	}
	// ponytail: Traefik sends every unrouted *nintendo.* SNI here; sign a cert per name on
	// demand so the console gets past TLS and its request lands in the log as !! UNHANDLED.
	var onDemand sync.Map
	fixedNames := map[string]bool{}
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		for _, n := range leaf.DNSNames {
			fixedNames[n] = true
		}
	}
	getCert := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// The console rejects on-demand certs for the BAAS/NA names (2123-0013); those must
		// keep the fixed multi-SAN cert. On-demand is only for unrouted *.nintendo.* probes.
		if h.ServerName == "" || fixedNames[h.ServerName] {
			return &cert, nil
		}
		if c, ok := onDemand.Load(h.ServerName); ok {
			return c.(*tls.Certificate), nil
		}
		log.Printf("[nx-baas] on-demand cert for unrouted SNI %s", h.ServerName)
		c := selfSigned([]string{h.ServerName}, httpx.Getenv("NX_CA_DIR", "/data/ca"))
		onDemand.Store(h.ServerName, &c)
		return &c, nil
	}
	// Ask for the console's client certificate but never require it: dauth uses it to tell
	// consoles apart, while every browser and emulator that talks to this service has none and
	// must still connect. RequestClientCert accepts whatever is offered without verifying it
	// against a CA we do not have.
	// The console's web applet is an old engine and offers only legacy TLS 1.2 suites, which
	// modern Go refuses by default: the handshake died immediately after the ClientHello, which
	// looked exactly like a certificate the browser did not trust. Offer everything Go can
	// still speak, including the suites it considers insecure, since this is a private network
	// talking to consoles that cannot be updated.
	suites := make([]uint16, 0, 32)
	for _, c := range tls.CipherSuites() {
		suites = append(suites, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		suites = append(suites, c.ID)
	}
	tlsConf := &tls.Config{
		GetCertificate: getCert,
		// Never ask the general listener for a client certificate. dauth wants one to tell
		// consoles apart, but the console's browser has none, and its TLS stack simply stops
		// when handed a CertificateRequest it cannot answer — the link page then hangs with no
		// error anywhere. The dauth hosts opt in below instead.
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS10,
		CipherSuites: suites,
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
		},
	}
	if os.Getenv("NX_DEBUG") != "" {
		// Diagnostic: every TLS handshake by SNI, so a connection that never speaks HTTP (the Penne
		// persistent frontline) is still visible in the log.
		tlsConf.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("[nx-baas] TLS hello sni=%s from=%s alpn=%v", h.ServerName, redact.Addr(h.Conn.RemoteAddr()), h.SupportedProtos)
			return clientCertFor(h, tlsConf)
		}
	}
	if os.Getenv("NX_UPSTREAM") != "" {
		// ponytail: capture mode replicates the original capture, which used the fixed multi-SAN
		// cert. On-demand per-SNI certs disturbed the console's silent NA session and forced a
		// re-auth; the fixed cert keeps the session silent so both accounts refresh without prompting.
		tlsConf.GetCertificate = nil
		tlsConf.Certificates = []tls.Certificate{cert}
	}
	srv := &http.Server{
		Addr: httpx.Getenv("NX_ADDR", ":443"), Handler: handler,
		TLSConfig: tlsConf, ErrorLog: redact.ErrorLog(),
	}
	// The game-facing API (Photon room presence, invitations) is plain HTTP on an internal
	// port -- consoles never reach it, only the Photon server, the emulator and rig tooling.
	go func() {
		addr := httpx.Getenv("NX_API_ADDR", ":20070")
		if httpx.Getenv("NX_INTERNAL_KEY", httpx.Getenv("OPENPAK_INTERNAL_KEY", "")) == "" {
			if os.Getenv("NX_INTERNAL_INSECURE") == "1" {
				log.Printf("[nx-baas] WARNING: game API on %s runs with NX_INTERNAL_INSECURE=1: /internal routes accept without a key. Isolated development only.", addr)
			} else {
				log.Printf("[nx-baas] game API on %s has no NX_INTERNAL_KEY: /internal routes refuse everything until one is configured", addr)
			}
		}
		log.Printf("[nx-baas] game API listening %s (photon-room, invitations, mint-token)", addr)
		log.Fatal((&http.Server{Addr: addr, Handler: s.gameAPI(), ErrorLog: redact.ErrorLog()}).ListenAndServe())
	}()
	log.Printf("[nx-baas] listening %s (BAAS + Nintendo Account); account backend %s; users=%d devices=%d", srv.Addr, httpx.Getenv("ACCOUNT_BACKEND", "unset"), len(s.Store.Users), len(s.Store.Devices))
	// The console's web applet enforces certificate checking unless Atmosphère patches it, so
	// the link page is also served over plain HTTP. Nothing secret crosses it: the console
	// shows a short-lived code, the password is typed on the phone against the public site,
	// and the link is approved on the console itself.
	if addr := httpx.Getenv("NX_HTTP_ADDR", ""); addr != "" {
		go func() {
			log.Printf("[nx-baas] plain HTTP on %s (link page without TLS)", addr)
			if err := (&http.Server{Addr: addr, Handler: handler, ErrorLog: redact.ErrorLog()}).ListenAndServe(); err != nil {
				log.Printf("[nx-baas] plain HTTP listener stopped: %v", redact.Err(err))
			}
		}()
	}

	if tlsConf.GetConfigForClient == nil {
		tlsConf.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			return clientCertFor(h, tlsConf)
		}
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// locks is the ban check, shared by every surface.
func (s *server) locks() *bans.Checker {
	s.bansOnce.Do(func() { s.bansChecker = bans.New(s.Core) })
	return s.bansChecker
}

// dauthSvc is dauth, dcert and aauth, created on first use like locks.
func (s *server) dauthSvc() *dauth.Service {
	s.dauthOnce.Do(func() { s.dauthService = &dauth.Service{Core: s.Core} })
	return s.dauthService
}

// presenceSvc is presence, created on first use like locks.
func (s *server) presenceSvc() *presence.Service {
	s.presenceOnce.Do(func() { s.presenceService = &presence.Service{Core: s.Core, Notify: s.SubmitNotification} })
	return s.presenceService
}

// invitationsSvc is the invitations surface, created on first use like locks.
func (s *server) invitationsSvc() *invitations.Service {
	s.invitationsOnce.Do(func() { s.invitationsService = &invitations.Service{Core: s.Core, Locks: s.locks()} })
	return s.invitationsService
}

// naSvc is the Nintendo Account surface, created on first use like locks.
func (s *server) naSvc() *nxaccount.Service {
	s.naOnce.Do(func() { s.naService = nxaccount.New(s.Core, s.locks()) })
	return s.naService
}

// friendsSvc is the friends surface, created on first use like locks.
func (s *server) friendsSvc() *friends.Service {
	s.friendsOnce.Do(func() { s.friendsService = &friends.Service{Core: s.Core, Presence: s.presenceSvc()} })
	return s.friendsService
}

// baasSvc is the BAAS surface, created on first use like locks.
func (s *server) baasSvc() *baas.Service {
	s.baasOnce.Do(func() { s.baasService = baas.New(s.Core, s.locks(), s.presenceSvc(), s.friendsSvc()) })
	return s.baasService
}

// gameAPISvc is the game API over the current services and forwarders. It keeps no state, so
// it is built afresh: a test that installs a forwarder after the first call still sees it.
func (s *server) gameAPISvc() *gameapi.Service {
	return &gameapi.Service{Core: s.Core, Locks: s.locks(), Dauth: s.dauthSvc(), Invitations: s.invitationsSvc(),
		Presence: s.presenceSvc(), NA: s.naSvc(), BAAS: s.baasSvc(), Friends: s.friendsSvc(),
		Submit: s.submitNotification, ShopFwd: s.shopFwd, PctlFwd: s.pctlFwd, PenneFwd: s.penneFwd}
}

// gameAPI is the game-facing internal API's mux (NX_API_ADDR).
func (s *server) gameAPI() http.Handler { return s.gameAPISvc().Handler() }

// acbaaSvc is Animal Crossing's web API, created on first use like locks.
func (s *server) acbaaSvc() *acbaa.Service {
	s.acbaaOnce.Do(func() { s.acbaaService = &acbaa.Service{Core: s.Core} })
	return s.acbaaService
}

// eventsSvc follows the account core's events over the current services.
func (s *server) eventsSvc() *events.Follower {
	return &events.Follower{Core: s.Core, Locks: s.locks(), Friends: s.friendsSvc(), Presence: s.presenceSvc(), Notify: s.SubmitNotification}
}

// SubmitNotification is the entry point the social, presence and invitation code calls.
// Accepted means nx-penne has it (or will, through the ordered queue); the caller never
// retries a submission that returned Accepted.
func (s *server) SubmitNotification(d penne.Delivery) penne.Submission {
	return s.submitNotification(d, false)
}

// submitNotification is SubmitNotification with the choice to wait for nx-penne's outcome.
func (s *server) submitNotification(d penne.Delivery, wait bool) penne.Submission {
	return penne.Submit(s.Store, s.notifier, d, wait)
}
