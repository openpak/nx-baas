package main

// Forwarding to the services split out of this one (docs/service-split.md).
//
// Each moved family has a base URL: NX_SHOP_URL for the eShop (nx-shop), NX_PENNE_URL for
// Penne (nx-penne; the core's own calls into Penne are penne_link.go's), NX_PCTL_URL for
// parental controls (nx-pctl), NX_BCAT_URL for BCAT (nx-bcat). nx-baas no longer serves any
// of them itself, so the first three are required at startup (requiredForwards). BCAT is
// optional: Traefik routes the bcat hosts straight to nx-bcat, and without the URL whatever
// still lands here gets a 404. Whatever of a family still reaches this process is forwarded:
// a console host Traefik does not route to the service, a path-routed request on a host this
// process keeps, and the family's internal admin routes the website calls here.
//
// The forward is plain HTTP on the openpak network to the service's internal listener, with
// the console's Host kept: TLS ended here, and the service answers the same routes there as on
// its own TLS listener.

import (
	"log"
	"net/http"
	"nx-baas/internal/httpx"
	"nx-baas/internal/penne"
	"nx-baas/redact"
	"os"
	"strings"
)

// requiredForwards are the families nx-baas no longer serves itself: without the URL of the
// service that owns one, its consoles would get nothing, so the process refuses to start.
// BCAT is not among them: Traefik routes the bcat hosts straight to nx-bcat, and
// NX_BCAT_URL is only the safety net.
var requiredForwards = []struct{ env, service string }{
	{"NX_SHOP_URL", "nx-shop"},
	{"NX_PENNE_URL", "nx-penne"},
	{"NX_PCTL_URL", "nx-pctl"},
}

// missingForward names the first required forward URL that is not set, or "".
func missingForward() (env, service string) {
	for _, f := range requiredForwards {
		if os.Getenv(f.env) == "" {
			return f.env, f.service
		}
	}
	return "", ""
}

// forwardersFromEnv installs the forwarders whose URLs are set.
func (s *server) forwardersFromEnv() {
	if u := os.Getenv("NX_PLAYFAB_URL"); u != "" {
		s.PlayfabFwd = httpx.NewForwarder("playfab", u)
		// Preserve the SDK error envelope even when the upstream is unavailable.
		s.PlayfabFwd.ErrorHandler = func(w http.ResponseWriter, r *http.Request, _ error) {
			playfabUnavailable(w, r)
		}
		log.Printf("[nx-baas] Core Keeper PlayFab forwarding enabled")
	}
	if u := os.Getenv("NX_SHOP_URL"); u != "" {
		s.ShopFwd = httpx.NewForwarder("nx-shop", u)
		log.Printf("[nx-baas] eShop moved: forwarding its hosts and /internal/store to %s", u)
	}
	if u := os.Getenv("NX_PENNE_URL"); u != "" {
		s.PenneFwd = httpx.NewForwarder("nx-penne", u)
		s.Penne = penne.NewRemote(u)
		s.notifier = s.Penne
		log.Printf("[nx-baas] Penne moved: registrations, tickets, /internal/penne and every push go to %s", u)
	}
	if u := os.Getenv("NX_PCTL_URL"); u != "" {
		s.PctlFwd = httpx.NewForwarder("nx-pctl", u)
		log.Printf("[nx-baas] parental controls moved: forwarding the pctl hosts and /internal/pctl to %s", u)
	}
	if u := os.Getenv("NX_BCAT_URL"); u != "" {
		s.BcatFwd = httpx.NewForwarder("nx-bcat", u)
		log.Printf("[nx-baas] BCAT moved: forwarding the bcat hosts (News lists, game data) to %s", u)
	}
}

// isBcatHost names the BCAT hosts (bcat-list, bcat-topics, bcat-data): nx-bcat's.
func isBcatHost(host string) bool { return strings.HasPrefix(host, "bcat-") }

// isPctlHost names the parental-controls hosts: moon's API host and the explainer movie's.
func isPctlHost(host string) bool {
	return strings.Contains(host, "pctl.srv.nintendo.net") || strings.HasPrefix(host, "parentalcontrols-movie-")
}

// isPenneFrontline names Penne's persistent-connection hosts (fro-).
func isPenneFrontline(host string) bool { return strings.HasPrefix(host, "fro-") }

// isPenneHost names Penne's own hosts: god (registrations), val (login tickets) and the
// fro- frontlines. The vermillion gateway is not among them: it is the online-licence gate
// and a title's bootstrap, stateless, and stays here (vermillion.go keeps answering it).
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
	host := httpx.HostOf(r)
	if strings.HasPrefix(r.URL.Path, "/internal/") && s.movedFamily(host) {
		// The services serve their admin routes on the same listener this forwards to;
		// a console host must never reach them, whatever path it asks for.
		log.Printf("[nx-baas] refused %s %s%s: /internal/ is not a console route", r.Method, host, redact.Path(r.URL.Path))
		http.NotFound(w, r)
		return true
	}
	if s.ShopFwd != nil && (isShopHost(host) || strings.HasPrefix(host, "dragons.") && shopRightsRoute(r.URL.Path)) {
		s.ShopFwd.ServeHTTP(w, r)
		return true
	}
	if s.PenneFwd != nil && isPenneHost(host) {
		if isPenneFrontline(host) {
			// A full-duplex stream this process cannot proxy (net/http drains the request
			// body on the first flush). Traefik must send the
			// frontline straight to nx-penne; reaching here means its router is missing.
			log.Printf("[nx-baas] !! MISROUTED Penne frontline %s: route it to nx-penne in Traefik", host)
			httpx.WriteJSON(w, http.StatusMisdirectedRequest, map[string]any{"status": 421, "title": "misdirected request"})
			return true
		}
		s.PenneFwd.ServeHTTP(w, r)
		return true
	}
	if s.PctlFwd != nil && isPctlHost(host) {
		s.PctlFwd.ServeHTTP(w, r)
		return true
	}
	if s.BcatFwd != nil && isBcatHost(host) {
		s.BcatFwd.ServeHTTP(w, r)
		return true
	}
	return false
}

// movedFamily reports whether host belongs to a family this process forwards.
func (s *server) movedFamily(host string) bool {
	return s.ShopFwd != nil && (isShopHost(host) || strings.HasPrefix(host, "dragons.")) ||
		s.PenneFwd != nil && isPenneHost(host) || s.PctlFwd != nil && isPctlHost(host) ||
		s.BcatFwd != nil && isBcatHost(host)
}

// shopRightsRoute: the dragons rights routes the store workstream owns. Everything else on
// the dragons host stays with the dauth handler's setup-critical answers (they keep the
// working console link alive); these are the acquisition surface (SHP-03) and the edge
// token issuer, which NIM may address on dragons. as well as dragonst.
func shopRightsRoute(p string) bool {
	p = strings.TrimPrefix(p, "/v2")
	p = strings.TrimPrefix(p, "/v1")
	return p == "/rights/publish_elicenses" || p == "/rights/available_elicenses" || p == "/elicenses/revoke" ||
		p == "/edge_token/issue" || p == "/edge_token/issuable_titles"
}
