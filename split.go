package main

// Forwarding to the services split out of this one (docs/service-split.md).
//
// Each moved family has a base URL: NX_SHOP_URL for the eShop (nx-shop), NX_PENNE_URL for
// Penne (nx-penne; the core's own calls into Penne are penne_link.go's), NX_PCTL_URL for
// parental controls (nx-pctl). Unset, this process serves the family itself exactly as
// before, which is the state production stays in until the cut-over. Set, it stops touching
// that family's state and forwards whatever of the family still reaches it: a console host
// Traefik does not route to the new service yet (or any more, after a router is removed), a
// path-routed request on a host this process keeps, and the family's internal admin routes
// the website calls here. So the cut-over is one restart of this process with the URL set,
// and every later step -- the Traefik routers that take this process out of the path -- can
// be added and removed without touching it.
//
// The forward is plain HTTP on the openpak network to the service's internal listener, with
// the console's Host kept: TLS ended here, and the service answers the same routes there as on
// its own TLS listener.

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// newForwarder is a streaming reverse proxy that keeps the request's Host.
func newForwarder(name, base string) *httputil.ReverseProxy {
	target, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || target.Host == "" {
		log.Fatalf("[nx-baas] %s forward URL %q: %v", name, base, err)
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // the service routes on the console's hostname
		},
		// Streamed both ways: store uploads are gigabytes, content downloads too.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[nx-baas] forward to %s failed: %s %s%s: %v", name, r.Method, hostOf(r), r.URL.Path, err)
			writeJSON(w, http.StatusBadGateway, map[string]any{"status": 502, "title": name + " unreachable"})
		},
	}
}

// forwardersFromEnv installs the forwarders whose URLs are set.
func (s *server) forwardersFromEnv() {
	if u := os.Getenv("NX_SHOP_URL"); u != "" {
		s.shopFwd = newForwarder("nx-shop", u)
		log.Printf("[nx-baas] eShop moved: forwarding its hosts and /internal/store to %s", u)
	}
	if u := os.Getenv("NX_PENNE_URL"); u != "" {
		s.penneFwd = newForwarder("nx-penne", u)
		s.penneRemote = newPenneRemote(u)
		log.Printf("[nx-baas] Penne moved: registrations, tickets, /internal/penne and every push go to %s", u)
	}
	if u := os.Getenv("NX_PCTL_URL"); u != "" {
		s.pctlFwd = newForwarder("nx-pctl", u)
		log.Printf("[nx-baas] parental controls moved: forwarding the pctl hosts and /internal/pctl to %s", u)
	}
}

// isPctlHost names the parental-controls hosts: moon's API host and the explainer movie's.
func isPctlHost(host string) bool {
	return strings.Contains(host, "pctl.srv.nintendo.net") || strings.HasPrefix(host, "parentalcontrols-movie-")
}

// isPenneHost names Penne's own hosts: god (registrations), val (login tickets) and the
// fro- frontlines. The vermillion gateway is not among them: it is the online-licence gate
// and a title's bootstrap, stateless, and stays here (penne.go keeps answering it).
func isPenneHost(host string) bool {
	return strings.Contains(host, "penne.")
}

// isShopHost names the hostnames the eShop owns outright. dragons.* is not among them: it
// carries the setup-critical licence answers every title needs (dauth.go), so only its
// store rights routes move (shopRightsRoute).
func isShopHost(host string) bool {
	for _, p := range []string{"pearljam.", "idbe-hac.", "bvc-hac-", "bugyo.", "pushmo.", "tagaya.", "veer.", "dragonst.", "tigers.", "beach."} {
		if strings.HasPrefix(host, p) {
			return true
		}
	}
	return strings.HasSuffix(host, ".savanna.srv.nintendo.net") || strings.Contains(host, ".d4c.nintendo.net")
}

// forwardMoved hands a console request to the service that owns its host, before the body
// is read so uploads and downloads stream. False when this process still serves it.
func (s *server) forwardMoved(w http.ResponseWriter, r *http.Request) bool {
	host := hostOf(r)
	if s.shopFwd != nil && (isShopHost(host) || strings.HasPrefix(host, "dragons.") && shopRightsRoute(r.URL.Path)) {
		s.shopFwd.ServeHTTP(w, r)
		return true
	}
	if s.penneFwd != nil && isPenneHost(host) {
		if isPenneFrontline(host) {
			// A full-duplex stream this process cannot proxy (penne_conn.go: net/http
			// drains the request body on the first flush). Traefik must send the
			// frontline straight to nx-penne; reaching here means its router is missing.
			log.Printf("[nx-baas] !! MISROUTED Penne frontline %s: route it to nx-penne in Traefik", host)
			writeJSON(w, http.StatusMisdirectedRequest, map[string]any{"status": 421, "title": "misdirected request"})
			return true
		}
		s.penneFwd.ServeHTTP(w, r)
		return true
	}
	if s.pctlFwd != nil && isPctlHost(host) {
		s.pctlFwd.ServeHTTP(w, r)
		return true
	}
	return false
}

// forwardRead forwards a request whose body this process already read.
func forwardRead(fwd *httputil.ReverseProxy, w http.ResponseWriter, r *http.Request, body []byte) {
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(body))
	r2.ContentLength = int64(len(body))
	fwd.ServeHTTP(w, r2)
}

// importPctlRollback takes parental controls back from nx-pctl: when $NX_DATA holds a
// pctl-rollback.json (nx-pctl's pctl.json, copied in for a rollback), its records replace the
// ones baas.json kept from before the cut-over, and the file is renamed so a later restart
// does not apply it again. Without the file this does nothing.
func (s *Store) importPctlRollback(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var in struct {
		PctlDevices map[string]*PctlDevice `json:"pctlDevices"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		log.Printf("[nx-baas] %s is not nx-pctl's state (%v); not applied", path, err)
		return
	}
	s.mu.Lock()
	s.PctlDevices = in.PctlDevices
	s.save()
	s.mu.Unlock()
	done := path + ".applied-" + time.Now().UTC().Format("20060102T150405")
	os.Rename(path, done)
	log.Printf("[nx-baas] parental controls taken back from nx-pctl: %d record(s) from %s (now %s)", len(in.PctlDevices), path, done)
}
