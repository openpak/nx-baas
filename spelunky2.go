package main

import (
	"log"
	"net/http/httputil"
	"net/url"
	"nx-baas/redact"
	"os"
	"strings"
)

// Spelunky 2's own rendezvous (`x.spelunky2.net`): the lobby get/put, the
// Nintendo token check (/nso) and /64b. The family is redirected so a console
// never reaches Mossmouth, and Traefik's catch-all sends the connection here
// with an on-demand OpenPak-CA certificate. OpenPak runs a service for the
// API when NX_SPELUNKY2_URL is set (platforms/switch/games/spelunky2); without it the
// connection falls through to the catch-all below, which logs the exchange
// and 404s — today's capture behavior.
//
// Answered before the body is read and never dumped: /nso carries the
// console's raw identity token.
//
// The forwarder is built per matching request rather than installed with the
// other split-out services (split.go): this name has no fixed leaf and no
// Traefik router, so there is no cut-over to stage — the env var alone moves
// it, and unsetting it restores the catch-all with no restart semantics
// beyond the quadlet's.
func isSpelunky(host string) bool {
	return strings.EqualFold(host, "x.spelunky2.net")
}

func spelunky2Forwarder() *httputil.ReverseProxy {
	u := strings.TrimRight(os.Getenv("NX_SPELUNKY2_URL"), "/")
	if u == "" {
		return nil
	}
	target, err := url.Parse(u)
	if err != nil || target.Host == "" {
		log.Printf("[nx-baas] NX_SPELUNKY2_URL %q: %v (forwarding off)", u, redact.Err(err))
		return nil
	}
	return newForwarder("spelunky2", u)
}
