// Package core is what every nx-baas surface shares: the BAAS store, the account backend,
// the signing key with its key ids, and the checks on the bearer tokens this server mints.
package core

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"nx-baas/internal/devices"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/penne"
	"nx-baas/internal/store"
	"nx-baas/internal/token"
	"nx-baas/redact"
	"strings"
	"time"
)

// Core is the shared state. One instance backs the whole process; every service holds the
// same pointer.
type Core struct {
	Store  *store.Store
	Acct   identity.Backend
	Key    *rsa.PrivateKey
	IDKid  string // kid of id_tokens (openpak-baas-key-1: what Photon/NPLN/S2 already trust)
	AccKid string // kid of BAAS access tokens (/1.0.0/internal_certificates)
	NAKid  string // kid of Nintendo-Account tokens: the console binds kid<->issuer and rejects a kid shared with BAAS (2124-3121)
	JWKS   []byte
	// Harbor is the Harbor device enrolment; nil while no device CA is configured, which
	// leaves dauth and BaaS as they were.
	Harbor *devices.Registry
	// Penne is nx-penne, where every push the core decides on goes (internal/penne).
	Penne *penne.Remote
}

const (
	BaasHost   = "e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com"
	BaasIssuer = "https://" + BaasHost
	// jku host for BAAS tokens: the console caches key sets per URL and had the VPS's set cached
	// for the e0d67c... URLs (different RSA key) -> 2124-3121. m-lp1 is the host firmware 21+
	// talks to anyway, and a URL it has not cached, so it fetches ours.
	BaasJku      = "https://m-lp1.baas.nintendo.com"
	BaasAudience = "ed9e2f05d286f7b8" // what citron's id_token carries; the game servers accept it
	NaIssuer     = "https://accounts.nintendo.com"
)

// bearer returns the claims of our own access token on the request, or nil.
func (s *Core) Bearer(r *http.Request) map[string]any {
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, "Bearer ") {
		return nil
	}
	c, err := token.ParseJWT(strings.TrimPrefix(a, "Bearer "), &s.Key.PublicKey)
	if err != nil {
		return nil
	}
	return c
}

// validBearer returns the claims of our own *live* access token: signature,
// issuer, type and expiry all checked. bearer() above only checked the
// signature, which let an expired token — or a refresh or Nintendo-Account
// token, which we also sign with this key — spend itself as a credential.
func (s *Core) ValidBearer(r *http.Request) map[string]any {
	c := s.Bearer(r)
	if c == nil {
		return nil
	}
	if httpx.Str(c, "typ") != "token" || httpx.Str(c, "iss") != BaasIssuer {
		return nil
	}
	exp, ok := c["exp"].(float64)
	if !ok || int64(exp) <= time.Now().Unix() {
		return nil
	}
	return c
}

// bearerUser resolves the user an authenticated request acts as, or nil.
//
// Says WHY when it refuses. Every rejection here used to be the same opaque
// 401, and telling "no header" from "the wrong one of two tokens this server
// itself minted" cost a debugging round trip with a client author on
// 2026-09-12: the application token from /1.0.0/application/token and the
// access token from /1.0.0/login both carry typ "token" and the same issuer,
// but the first has the DEVICE id as its subject and the second the BAAS user
// id. Only the second can act as a user.
func (s *Core) BearerUser(r *http.Request) *store.User {
	c := s.ValidBearer(r)
	if c == nil {
		if a := r.Header.Get("Authorization"); !strings.HasPrefix(a, "Bearer ") {
			log.Printf("[nx-baas] auth: %s %s carries no bearer", r.Method, redact.Path(r.URL.Path))
		} else if raw := s.Bearer(r); raw == nil {
			log.Printf("[nx-baas] auth: %s %s bearer does not verify against this server's key", r.Method, redact.Path(r.URL.Path))
		} else if httpx.Str(raw, "typ") != "token" || httpx.Str(raw, "iss") != BaasIssuer {
			log.Printf("[nx-baas] auth: %s %s bearer is typ=%q iss=%q, want typ=token from this issuer",
				r.Method, redact.Path(r.URL.Path), httpx.Str(raw, "typ"), httpx.Str(raw, "iss"))
		} else {
			log.Printf("[nx-baas] auth: %s %s bearer has expired", r.Method, redact.Path(r.URL.Path))
		}
		return nil
	}
	sub := httpx.Str(c, "sub")
	u := s.Store.User(sub)
	if u == nil {
		// The give-away: an application token's subject is the device id.
		log.Printf("[nx-baas] auth: %s %s bearer names sub=%s, which is not a user "+
			"(an application token from /1.0.0/application/token has the DEVICE id as its subject; "+
			"a user-scoped call needs the accessToken from /1.0.0/login)", r.Method, redact.Path(r.URL.Path), redact.Tag(sub))
	}
	return u
}

// requireCaller enforces the principal binding on a user-scoped path: the
// path may only name the authenticated user. Returns false having written
// the error when it does not.
func (s *Core) RequireCaller(w http.ResponseWriter, r *http.Request, pathUserID string) *store.User {
	me := s.BearerUser(r)
	if me == nil {
		httpx.BaasErr(w, r, 401, "invalid_token", "Invalid token", "a current access token is required")
		return nil
	}
	if pathUserID != "" && pathUserID != me.ID {
		// Cross-account denial: a valid token for someone else must not read
		// or write this user's social state, ever.
		httpx.BaasErr(w, r, 403, "insufficient_scope", "Token is insufficient", "the token does not belong to this user")
		return nil
	}
	return me
}

// bearerHeader verifies one of our own JWTs from "Bearer <token>" on the named header.
func (s *Core) BearerHeader(r *http.Request, header string) map[string]any {
	v := r.Header.Get(header)
	if !strings.HasPrefix(v, "Bearer ") {
		return nil
	}
	c, err := token.ParseJWT(strings.TrimPrefix(v, "Bearer "), &s.Key.PublicKey)
	if err != nil {
		return nil
	}
	return c
}

// bindNotificationChannel records which BAAS account is signed in on the console a
// device authentication token names — the same bind the /1.0.0/login handler performs
// (BindConsole at the login case). It belongs on the NA token paths as well because an
// awake console's steady state is the refresh, not a login: sleep/wake and days-long
// play sessions reuse the Nintendo-Account session, so /1.0.0/login may not recur for
// a very long time, and an unbound console is one no notification can be addressed to.
func (s *Core) BindNotificationChannel(deviceAuthenticationToken, baasUserID string) {
	if baasUserID == "" {
		return
	}
	if dt, err := token.ParseJWT(deviceAuthenticationToken, &s.Key.PublicKey); err == nil {
		s.Penne.BindConsole(httpx.Str(dt, "sub"), baasUserID)
	}
}

const CdnHost = "https://cdn-image-e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com"

// avatarURL: the console wants an https URL, never inline data. The earlier account server hands us the
// raw base64 JPEG; we serve it at /avatar/<pid>.jpg on the cdn-image host (in our cert + route).
func AvatarURL(pid uint64, b64 string, updatedAt int64) string {
	if b64 == "" {
		return ""
	}
	return fmt.Sprintf("%s/avatar/%d.jpg?v=%d", CdnHost, pid, updatedAt)
}
