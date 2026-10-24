// Package nxaccount is the Nintendo Account surface the console links an account through
// (accounts.nintendo.com: authorize, session_token, token, users/me) and the link pages a
// phone or the console itself signs in on.
package nxaccount

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"nx-baas/internal/bans"
	"nx-baas/internal/core"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/token"
	"nx-baas/redact"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Code struct {
	PID      uint64
	Username string
	ClientID string
	NaID     string
	Nonce    string
	// Created bounds the code's life (see takeCode): a code the console
	// never spends must stop working and stop occupying the map.
	Created time.Time
	// Spent marks a code already traded at the token endpoint. The console
	// presents the same code twice by design (session_token, then token),
	// so the session_token exchange checks but does not set this; the token
	// exchange sets it, and any later presentation is a replay.
	Spent bool
}

// codeTTL caps an authorization code's life: console round-trips take
// seconds, and anything unspent after this is abandoned, not pending.
const naCodeTTL = 10 * time.Minute

// issueCode stores an authorization code for c and returns it.
func (s *Service) IssueCode(c Code) string {
	code := token.RandHex(16)
	s.mu.Lock()
	s.codes[code] = c
	s.mu.Unlock()
	return code
}

// takeCode spends an authorization code: unknown, expired or already-spent
// codes are refused, and expired rows are purged so the map cannot grow
// without end.
// SpendCode resolves a Nintendo Account authorization code the way a third-party server does:
// the code must be fresh, unspent and issued to clientID, and is spent by the answer. The
// client id is how the console's silent authorize filled it (the title id), compared without case.
func (s *Service) SpendCode(code, clientID string) (Code, bool) {
	if code == "" || clientID == "" {
		return Code{}, false
	}
	s.mu.Lock()
	c, ok := s.codes[code]
	s.mu.Unlock()
	if !ok || !strings.EqualFold(c.ClientID, clientID) {
		return Code{}, false
	}
	return s.takeCode(code, true)
}

// PIDForNAIDToken proves a Nintendo Account id_token this server signed (issuer, expiry, and a
// subject it knows) and answers with the account behind it; 0 when the token is not ours or the
// account is unknown.
func (s *Service) PIDForNAIDToken(tok string) uint64 {
	c, err := token.ParseJWT(tok, &s.Key.PublicKey)
	if err != nil || httpx.Str(c, "iss") != core.NaIssuer || httpx.Str(c, "typ") != "" {
		return 0
	}
	if exp, _ := c["exp"].(float64); int64(exp) <= time.Now().Unix() {
		return 0
	}
	return s.Store.PIDForNA(httpx.Str(c, "sub"))
}

func (s *Service) takeCode(code string, spend bool) (Code, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.codes {
		if now.Sub(v.Created) > naCodeTTL {
			delete(s.codes, k)
		}
	}
	c, ok := s.codes[code]
	if !ok || now.Sub(c.Created) > naCodeTTL || c.Spent {
		delete(s.codes, code)
		return Code{}, false
	}
	if spend {
		c.Spent = true
		s.codes[code] = c
	}
	return c, true
}

func (s *Service) naHeader() map[string]any {
	return map[string]any{"alg": "RS256", "jku": core.NaIssuer + "/1.0.0/certificates", "kid": s.NAKid, "typ": "JWT"}
}

func (s *Service) naRefreshToken(c Code) string {
	now := time.Now().Unix()
	return token.SignJWT(s.naHeader(), map[string]any{"aud": c.ClientID, "exp": now + 365*86400, "iat": now, "iss": core.NaIssuer, "jti": token.UUID4(), "sub": c.NaID, "typ": "refresh"}, s.Key)
}

func (s *Service) NAAccessToken(c Code) string {
	now := time.Now().Unix()
	return token.SignJWT(s.naHeader(), map[string]any{
		"ac:grt": 4, "ac:scp": []int{0, 1, 4, 5, 8, 9, 10, 11, 12, 13, 23, 28},
		"aud": c.ClientID, "exp": now + 900, "iat": now, "iss": core.NaIssuer, "jti": token.UUID4(), "sub": c.NaID, "typ": "token",
	}, s.Key)
}

// naLinks is the NA account's linked-account block. The account module reads
// $.links.nintendoNetwork.{id,createdAt} out of this document, alongside the
// facebook/google/twitter/nintendoAccount siblings it also knows [firmware,
// account module: path table at 0x1c2010, entries +0x128 and +0x138].
//
// We advertise a Nintendo Network link because the Add Friend applet is the
// suspected gate on the "Nintendo 3DS" and "Wii U" friend panes: over 30 days
// the console has only ever asked FRS for type=nintendo_account, never
// nintendo_3ds or nintendo_network_id, while IPC 20301 is perfectly reachable
// in the firmware. An empty links object is the only precondition we were
// visibly failing. If the panes appear after this, the gate is confirmed.
//
// ponytail: the id is the core PID as a decimal string, which is a stand-in.
// The real Wii U/3DS identity is the shadow PNID nn-account mints per core
// account, and nx-baas has no field for it (Identity carries no PNID) — wiring
// that through is the follow-up once the gate is proven, not before. The type
// matches every other links.*.id we already serve as a string and the console
// accepts.
//
// There is a second, larger NNID surface we do NOT serve: the account module
// can open a web authorize at
// "%s?response_type=id_token&claims=%s&scope=%s&client_id=%016llx&state=%.*s&id_token_hint="
// with scope "user.links user.links[].id" and claims
// {"links.nintendoNetwork.id":{"essential":true}} — the real linking flow. If
// something in System Settings starts reaching for that, this is why.
func naLinks(id *identity.Identity) map[string]any {
	if id == nil || id.PID == 0 {
		return map[string]any{}
	}
	created := int64(1524557701)
	return map[string]any{
		"nintendoNetwork": map[string]any{
			"id":        strconv.FormatUint(id.PID, 10),
			"createdAt": created,
			"updatedAt": created,
		},
	}
}

// naIDToken mints the OpenID Connect id_token for a Nintendo Account client.
//
// The console's own client tolerates a loose token, but the path a *game* uses does not:
// nn::account's GetResultWithInteractionIfRequired validates it, and Don't Starve Together
// died on exactly that (its own log: "[NX] GetResultWithInteractionIfRequired failed. (41)"
// -> "Unable to retrieve id token", which is the 2124-0041 on screen). Measured on hardware
// 2026-09-29. Three things it wants, and which the loose token got wrong:
//
//   - nonce is echoed when the request carried one. A client that sent a nonce and gets a
//     token without it must reject the token; that is the whole point of the nonce.
//   - c_hash is present whenever an authorization code is being returned alongside the token
//     (response_type "code id_token"). OIDC requires it for the hybrid flow -- it is what ties
//     this token to that code.
//   - at_hash is only present when an access token is actually being returned. It used to be
//     stamped unconditionally, so a silent authorize carried the hash of the empty string
//     (47DEQpj8HBSa-_TImW-5JA) and claimed an access token that did not exist.
//
// Both hashes are the left half of the SHA-256 of the value, per OIDC for an RS256 token.
func (s *Service) NAIDToken(c Code, accessToken, code string) string {
	now := time.Now().Unix()
	claims := map[string]any{
		"aud": c.ClientID, "exp": now + 900, "iat": now, "iss": core.NaIssuer, "jti": token.UUID4(), "sub": c.NaID,
	}
	if c.Nonce != "" {
		claims["nonce"] = c.Nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["at_hash"] = token.B64URL(sum[:16])
	}
	if code != "" {
		sum := sha256.Sum256([]byte(code))
		claims["c_hash"] = token.B64URL(sum[:16])
	}
	return token.SignJWT(s.naHeader(), claims, s.Key)
}

func (s *Service) Handle(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	form, _ := url.ParseQuery(string(body))
	switch {
	case p == "/1.0.0/certificates":
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.JWKS)
		return

	case strings.HasPrefix(p, "/api/1.0.0/users/") && strings.HasSuffix(p, "/qrcode_param"):
		// Friend-QR parameter (VPS parity): a signed verify URL the console renders as a QR code.
		naID := strings.TrimSuffix(strings.TrimPrefix(p, "/api/1.0.0/users/"), "/qrcode_param")
		now := time.Now().Unix()
		exp := now + 7*86400
		param := fmt.Sprintf("https://accounts.nintendo.com/qr_verify?sig=%s&iat=%d&aud=6ffd70c434d303c8&sub=%s&exp=%d", token.RandB64(32), now, naID, exp)
		httpx.WriteJSON(w, 200, map[string]any{"exp": exp, "param": param, "userId": naID})
		return

	case p == "/connect/1.0.0/term_confirm" || p == "/1.0.0/term_confirm":
		// The console confirms the account's terms here, form-encoded with
		// id_token/idToken/userId [firmware, account module 0x181077]. There
		// are no terms to accept on a private network, and users/me already
		// reports the EULA and privacy policy as agreed — so this confirms
		// rather than 404s, which is what keeps account setup moving.
		log.Printf("[nx-baas] NA term_confirm for user=%s", redact.Tag(form.Get("userId")))
		httpx.WriteJSON(w, 200, map[string]any{"status": 200})
		return

	case strings.HasPrefix(p, "/connect/1.0.0/api/term_agreement_token") ||
		strings.HasPrefix(p, "/1.0.0/api/term_agreement_token"):
		// Asked for when the terms themselves change. The document it returns
		// is not recovered (the module reads $.challenge_src and $.errorCode
		// near this call), and a token is not a thing to invent, so the
		// request is recorded and refused.
		httpx.Dump(r, body, "!! NA term_agreement_token (document shape unrecovered)")
		httpx.WriteJSON(w, 404, map[string]any{"status": 404, "errorCode": "not_found",
			"detail": "no term agreement is issued on this network"})
		return

	case strings.Contains(p, "/api/transfer_na_tokens"):
		// Moving an account between consoles [account module 0x17d920]. This
		// server has no transfer flow, and half-answering one risks an account
		// that exists in two places: refuse plainly and record the attempt.
		httpx.Dump(r, body, "!! NA transfer_na_tokens (account transfer is not supported)")
		httpx.WriteJSON(w, 400, map[string]any{"status": 400, "errorCode": "invalid_request",
			"detail": "account transfer is not supported on this network"})
		return

	case p == "/connect/1.0.0/authorize" && r.Method == "POST" && form.Get("prompt") == "none":
		// SSO for system applets (e-license etc.): identified by our NA access token, no UI.
		cl, err := token.ParseJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), &s.Key.PublicKey)
		pid := uint64(0)
		if err == nil {
			pid = s.Store.PIDForNA(httpx.Str(cl, "sub"))
		}
		if pid == 0 {
			// An emulator keeps no NA access token, only the BAAS id_token of its sign-in.
			pid, _ = s.PIDForIDToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		}
		if pid == 0 {
			httpx.WriteJSON(w, 401, map[string]any{"error": "login_required"})
			return
		}
		if s.Locks.PIDLock(pid) != "" {
			log.Printf("[nx-baas] NA silent authorize refused: pid=%s is locked", redact.Tag(pid))
			bans.NAAuthorizeLocked(w, r, form.Get("redirect_uri"), form.Get("state"))
			return
		}
		id, err := s.Acct.Identity(pid)
		if err != nil {
			httpx.WriteJSON(w, 401, map[string]any{"error": "login_required"})
			return
		}
		c := Code{PID: pid, Username: id.Nickname, ClientID: form.Get("client_id"), NaID: id.NaID, Nonce: form.Get("nonce"), Created: time.Now()}
		code := s.IssueCode(c)
		frag := url.Values{"state": {form.Get("state")}, "session_state": {token.RandHex(11)}, "code": {code}}
		if strings.Contains(form.Get("response_type"), "id_token") {
			frag.Set("id_token", s.NAIDToken(c, "", code))
		}
		dest := form.Get("redirect_uri") + "#" + frag.Encode()
		// The whole fragment, not just the redirect_uri: the friends module's
		// NxFriends token fetch dies between this 302 and its own GET, and the
		// account module's fragment parser is the only thing in between. It
		// accepts exactly state, error, error_detail, code, id_token,
		// access_token and expires_in, and silently ignores anything else
		// (dispatcher 0x20d840 falls through to a plain return), so what is
		// left to see is the literal text we hand it. An empty NaID would also
		// explain it: the module caches the token per NA id.
		// The inbound form matters as much as the answer: we only attach an
		// id_token when response_type mentions one, and no /api/token exchange
		// was ever seen either, so "what did it ask for" is still an
		// assumption taken from the firmware rather than from this server.
		// ponytail: a diagnostic; drop it once the NxFriends fetch is understood.
		// The redirect's fragment carries an id_token, so only its names are logged.
		log.Printf("[nx-baas] NA silent authorize pid=%s client=%s naID=%s response_type=%q scope=%q state=%s nonce=%s -> %s",
			redact.Tag(pid), c.ClientID, redact.Tag(c.NaID), form.Get("response_type"), form.Get("scope"),
			redact.Tag(form.Get("state")), redact.Tag(form.Get("nonce")), redact.Link(dest))
		http.Redirect(w, r, dest, http.StatusFound)
		return

	case p == "/connect/1.0.0/authorize":
		q := r.URL.Query()
		if r.Method == "POST" { // our own form
			for k := range form {
				if k != "email" && k != "password" {
					q[k] = form[k]
				}
			}
			// Password guesses are capped per account like link codes are.
			pwKey := "pw:" + strings.ToLower(strings.TrimSpace(form.Get("email")))
			if blocked, _ := s.guesses.blocked(pwKey); blocked {
				log.Printf("[nx-baas] NA login throttled for %s", redact.Tag(form.Get("email")))
				s.authorizePage(w, r, q, `<p class="err">Too many attempts. Wait a few minutes and try again.</p>`)
				return
			}
			res, err := s.Acct.LoginPID(form.Get("email"), form.Get("password"))
			lock := s.Locks.PIDLock(res.PID)
			if errors.Is(err, identity.ErrAccountLocked) && lock == "" {
				lock = bans.Banned
			}
			if lock != "" {
				log.Printf("[nx-baas] NA login refused for %s: account is %s", redact.Tag(form.Get("email")), lock)
				s.authorizePage(w, r, q, `<p class="err">`+bans.LockedPageMessage(lock)+`</p>`)
				return
			}
			if errors.Is(err, identity.ErrSecondFactorRequired) {
				s.authorizePage(w, r, q, `<p class="err">This account has two-factor authentication: finish signing in on the website, then link.</p>`)
				return
			}
			if err != nil {
				s.guesses.wrong(pwKey)
				log.Printf("[nx-baas] NA login failed for %s: %v", redact.Tag(form.Get("email")), redact.Err(err))
				s.authorizePage(w, r, q, `<p class="err">Wrong e-mail or password.</p>`)
				return
			}
			s.guesses.right(pwKey)
			if res.Need2FA {
				// Password proved on the television; the code is typed here
				// too — six digits, no authenticator round-trip to a phone.
				tok := s.pending2FA.new(&pending2FA{AccountID: res.AccountID, PID: res.PID, Username: res.Username, Query: q, Mode: pending2FAModeAuthorize})
				s.authorize2FAPage(w, r, tok, "")
				return
			}
			id, err := s.Acct.Identity(res.PID)
			if err != nil {
				s.authorizePage(w, r, q, `<p class="err">Account lookup failed.</p>`)
				return
			}
			code := s.IssueCode(Code{PID: res.PID, Username: res.Username, ClientID: q.Get("client_id"), NaID: id.NaID, Created: time.Now()})
			s.Store.RememberNA(id.NaID, res.PID)
			// ponytail: the redirect shape is inferred from the response_type the console sends;
			// both the query (code) and fragment (session_token_code / id_token) forms are covered.
			dest := s.authorizeRedirect(q, code)
			log.Printf("[nx-baas] NA authorize ok pid=%s response_type=%q -> %s", redact.Tag(res.PID), q.Get("response_type"), redact.Link(dest))
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		httpx.Dump(r, body, "NA authorize")
		s.authorizePage(w, r, q, "")
		return

	case p == "/connect/1.0.0/authorize/2fa" && r.Method == "POST":
		// Second step of the console authorize form: the code (or a recovery
		// code) for a password-proved login. Same single-use pending record
		// as the phone flow; the core counts failures per account on top.
		p, ok := s.pending2FA.peek(form.Get("token"))
		if !ok || p.Mode != pending2FAModeAuthorize {
			s.authorizePage(w, r, r.URL.Query(), `<p class="err">That took too long — sign in again.</p>`)
			return
		}
		if err := s.Acct.VerifySecondFactor(p.AccountID, strings.TrimSpace(form.Get("code")), strings.TrimSpace(form.Get("recovery_code"))); err != nil {
			if errors.Is(err, identity.ErrSecondFactorLocked) {
				s.authorize2FAPage(w, r, form.Get("token"), `<p class="err">Too many wrong codes. Wait a few minutes and try again.</p>`)
				return
			}
			s.authorize2FAPage(w, r, form.Get("token"), `<p class="err">That code did not work. Check your authenticator and try again.</p>`)
			return
		}
		if _, ok := s.pending2FA.take(form.Get("token")); !ok {
			s.authorizePage(w, r, r.URL.Query(), `<p class="err">That took too long — sign in again.</p>`)
			return
		}
		q := p.Query
		id, err := s.Acct.Identity(p.PID)
		if err != nil {
			s.authorizePage(w, r, q, `<p class="err">Account lookup failed.</p>`)
			return
		}
		code := s.IssueCode(Code{PID: p.PID, Username: p.Username, ClientID: q.Get("client_id"), NaID: id.NaID, Created: time.Now()})
		s.Store.RememberNA(id.NaID, p.PID)
		dest := s.authorizeRedirect(q, code)
		log.Printf("[nx-baas] NA authorize ok pid=%s (second factor) response_type=%q -> %s", redact.Tag(p.PID), q.Get("response_type"), redact.Link(dest))
		http.Redirect(w, r, dest, http.StatusFound)
		return

	case p == "/connect/1.0.0/api/session_token" || p == "/connect/1.0.0/api/token":
		httpx.Dump(r, body, "NA token")
		code := form.Get("session_token_code")
		if code == "" {
			code = form.Get("code")
		}
		if code == "" {
			code = form.Get("session_token")
		}
		// The session_token exchange checks without marking (the console
		// presents the same code again at the token endpoint); the token
		// exchange marks spent, so a replayed code is refused.
		c, ok := s.takeCode(code, p != "/connect/1.0.0/api/session_token")
		if !ok && form.Get("refresh_token") != "" {
			// Later boots: the console refreshes with the token we issued (a signed JWT whose sub
			// is the NA id); the NA id -> PID map is persisted, so this survives restarts.
			if cl, err := token.ParseJWT(form.Get("refresh_token"), &s.Key.PublicKey); err == nil && httpx.Str(cl, "typ") == "refresh" {
				if pid := s.Store.PIDForNA(httpx.Str(cl, "sub")); pid != 0 {
					if id, err := s.Acct.Identity(pid); err == nil {
						c, ok = Code{PID: pid, Username: id.Nickname, ClientID: form.Get("client_id"), NaID: id.NaID}, true
						s.BindNotificationChannel(form.Get("device_authentication_token"), id.BaasUserID)
					}
				}
			}
		}
		if !ok {
			httpx.WriteJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "unknown code"})
			return
		}
		// Codes and refresh tokens minted before a ban stop here: no token for a banned
		// account, whichever grant it arrives on.
		if lock := s.Locks.PIDLock(c.PID); lock != "" {
			log.Printf("[nx-baas] NA token refused: pid=%s is %s", redact.Tag(c.PID), lock)
			bans.NATokenLocked(w, lock)
			return
		}
		if p == "/connect/1.0.0/api/session_token" {
			httpx.WriteJSON(w, 200, map[string]any{"session_token": code, "code": code})
			return
		}
		if id, err := s.Acct.Identity(c.PID); err == nil {
			s.BindNotificationChannel(form.Get("device_authentication_token"), id.BaasUserID)
		}
		at := s.NAAccessToken(c)
		httpx.WriteJSON(w, 200, map[string]any{
			"access_token": at, "expires_in": 900, "id_token": s.NAIDToken(c, at, ""), "refresh_token": s.naRefreshToken(c),
			"scope":         strings.Fields(strings.ReplaceAll(form.Get("scope"), "+", " ")),
			"session_token": token.RandHex(24), "token_type": "Bearer",
		})
		return

	case p == "/2.0.0/agreements": // ToS probe before authorize
		if r.Method == "POST" {
			w.WriteHeader(204)
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{"agreements": []any{}})
		return

	case p == "/2.0.0/users/me":
		c, err := token.ParseJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), &s.Key.PublicKey)
		if err != nil {
			httpx.WriteJSON(w, 401, map[string]any{"error": "invalid_token"})
			return
		}
		pid := s.Store.PIDForNA(httpx.Str(c, "sub"))
		if lock := s.Locks.PIDLock(pid); lock != "" {
			bans.NATokenLocked(w, lock)
			return
		}
		id, err := s.Acct.Identity(pid)
		if err != nil {
			httpx.WriteJSON(w, 404, map[string]any{"error": "not_found"})
			return
		}
		// Console rules (Fix_Experimental relay, A/B on hardware): id == access token sub, 16 lowercase
		// hex; nickname non-empty, <= 32 bytes. No null-valued fields: keep the object minimal.
		nick := id.Nickname
		for len(nick) > 32 {
			nick = nick[:len(nick)-1]
		}
		// The object the VPS serves (captured 2026-09-06), with our identity substituted.
		now := time.Now().Unix()
		perm := func(ok bool) map[string]any {
			return map[string]any{"editable": map[string]any{"admin": false, "self": true}, "permitted": ok, "updatedAt": int64(1524557701), "userConfirmed": true}
		}
		// The account's own country and birthday, not the captured sample's. The console links a
		// Nintendo Account to a BAAS user in one flow and reads both objects: leaving this half
		// hardcoded told it the person lives in GB and was born in 2000 while the other half said
		// the account holds neither. Where the account has nothing, the sample's values remain —
		// a Nintendo Account always carries both, so there is no "absent" to serve here.
		country, birthday := NAProfile(id)
		email, screenName := naAddress(id.Email)
		me := map[string]any{
			"agreedTerms": map[string]any{
				"EULA":          map[string]any{"agreedAt": int64(1524557701), "country": country, "version": 2},
				"privacyPolicy": map[string]any{"agreedAt": int64(1524557701), "country": country, "version": 2},
			},
			"analyticsOptedIn": false, "analyticsOptedInUpdatedAt": int64(1524557701),
			"analyticsPermissions": map[string]any{"dataCollection": perm(false), "internalAnalysis": perm(true), "targetMarketing": perm(false)},
			// nn.account reads $.summary.nintendo.hasMembership here
			// [firmware, account module 0x18000a]; capi answers the same
			// question on /memberships and must not disagree with it.
			"summary":  map[string]any{"nintendo": map[string]any{"hasMembership": true}},
			"birthday": birthday, "clientFriendsOptedIn": true, "clientFriendsOptedInUpdatedAt": int64(1524557701),
			"country": country, "createdAt": int64(1524557701),
			"eachEmailOptedIn": map[string]any{"deals": map[string]any{"optedIn": false, "updatedAt": int64(1524557701)}, "survey": map[string]any{"optedIn": false, "updatedAt": int64(1524557701)}},
			"email":            email, "emailOptedIn": false, "emailOptedInUpdatedAt": int64(1524557701), "emailVerified": true,
			"gender": "unknown", "iconUri": core.AvatarURL(id.PID, id.Avatar, id.ImageUpdatedAt), "id": strings.ToLower(id.NaID), "isChild": false, "language": "en-GB",
			"links": naLinks(id), "loginId": nil, "nickname": nick, "phoneNumberEnabled": false, "region": nil,
			"screenName": screenName, "termsAgreementRequired": false,
			"timezone":  map[string]any{"id": "Europe/London", "name": "Europe/London", "utcOffset": "+01:00", "utcOffsetSeconds": 3600},
			"updatedAt": now,
		}
		log.Printf("[nx-baas] users/me -> id=%s nickname=%s", redact.Tag(me["id"]), redact.Text(nick))
		httpx.WriteJSON(w, 200, me)
		return
	}
	httpx.Dump(r, body, "!! UNHANDLED NA")
	w.WriteHeader(404)
}

// authorizeRedirect builds the destination the console expects for the response_type it asked
// for. Shared by the password form and the QR flow so both finish identically.
// ponytail: the redirect shape is inferred from the response_type the console sends; both the
// query (code) and fragment (session_token_code / id_token) forms are covered.
func (s *Service) authorizeRedirect(q url.Values, code string) string {
	rt := q.Get("response_type")
	dest := q.Get("redirect_uri")
	params := url.Values{"state": {q.Get("state")}}
	sep := "?"
	if strings.Contains(dest, "?") {
		sep = "&"
	}
	switch {
	case strings.Contains(rt, "session_token_code"):
		// What the console sends (Settings > Users > Link Nintendo Account); it wants the code
		// back as query parameters on its nintendo:// redirect, then trades it at
		// /connect/1.0.0/api/session_token (with the PKCE verifier) and /api/token.
		params.Set("session_token_code", code)
		return dest + sep + params.Encode()
	case strings.Contains(rt, "id_token"):
		s.mu.Lock()
		c := s.codes[code]
		s.mu.Unlock()
		idCode := ""
		if strings.Contains(rt, "code") {
			idCode = code
		}
		params.Set("id_token", s.NAIDToken(c, "", idCode))
		if strings.Contains(rt, "code") {
			params.Set("code", code)
		}
		return dest + "#" + params.Encode()
	default:
		params.Set("code", code)
		return dest + sep + params.Encode()
	}
}

// authorizePage is what the console browser shows. Typing an e-mail and password with a
// The console page describes a phone path only when a phone has somewhere to go; see linkBaseURL.
func phoneIntro(ok bool) string {
	if ok {
		return "Scan the code with your phone, sign in there, then approve it here."
	}
	return "Sign in below to link this console."
}

func qrPanel(ok bool, linkURL string) string {
	if !ok {
		return ""
	}
	return `<div class="qr"><img src="` + qrDataURI(linkURL) + `" alt="QR code"></div>`
}

func phoneSteps(ok bool) string {
	if ok {
		return `<li>Scan the square with your phone&rsquo;s camera.</li>
      <li>Sign in to OpenPak on the phone.</li>
      <li>Check this code matches, then approve below.</li>`
	}
	return `<li>Sign in below.</li>
      <li>Check this code matches, then approve.</li>`
}

func phoneAddress(ok bool, base string) string {
	if !ok {
		return ""
	}
	return `<p style="margin:10px 0 0;font-size:0.9rem">or open <strong>` +
		html.EscapeString(strings.TrimPrefix(base, "http://")) + `/link</strong> on your phone</p>`
}

// controller is miserable, so the QR path leads: a code and an image to scan, the page polls
// for a phone to claim it, and the person at the console approves. The password form is still
// there, one fold down, for anyone without a phone to hand.
// authorize2FAPage: the password proved on the television and the account
// wants its second factor. Same six digits (or a recovery code) as the phone
// flow, styled for the sofa.
func (s *Service) authorize2FAPage(w http.ResponseWriter, r *http.Request, token, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeadFor("Two-factor check", "console")+`
<h1>Check your authenticator</h1>
<p>This account has two-factor authentication. Enter the 6-digit code, or a recovery code.</p>
<div class="card">`+msg+`<form method="post" action="/connect/1.0.0/authorize/2fa">
<input type="hidden" name="token" value="`+html.EscapeString(token)+`">
<label for="code">6-digit code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" spellcheck="false"
       maxlength="6" minlength="6" pattern="[0-9]{6}" autofocus>
<label for="recovery_code">Or a recovery code</label>
<input id="recovery_code" name="recovery_code" autocomplete="off" spellcheck="false">
<button type="submit">Verify</button>
</form></div></main></body></html>`)
}

func (s *Service) authorizePage(w http.ResponseWriter, r *http.Request, q url.Values, msg string) {
	var hidden strings.Builder
	for k, v := range q {
		fmt.Fprintf(&hidden, `<input type="hidden" name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(v[0]))
	}
	code, pair := s.links.new(q)
	// The QR identifies this console session; it carries neither the code nor any authority.
	// phoneOK is false when nothing here is reachable by a phone, in which case no square is
	// drawn at all — one built on the hostname the console arrived by would send the pairing id
	// to Nintendo, since that is who owns that name everywhere except on this console.
	linkBase, phoneOK := s.linkBaseURL(r)
	linkURL := linkBase + "/link?p=" + pair
	var e string
	if msg != "" {
		e = msg
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHeadFor("Link this console", "console")+`
<h1>Link this console</h1>
<p>`+phoneIntro(phoneOK)+`</p>
<div class="card"><div class="split">
  `+qrPanel(phoneOK, linkURL)+`
  <div>
    <ol class="steps">
      `+phoneSteps(phoneOK)+`
    </ol>
    <div id="codebox" hidden>
      <p style="margin:16px 0 0">Type this on your phone:</p>
      <p style="margin:8px 0 0"><span class="code">`+groupCode(code)+`</span></p>
    </div>
    `+phoneAddress(phoneOK, linkBase)+`
    <p id="status" style="margin:14px 0 0">Waiting for you to sign in on your phone&hellip;</p>
    <div id="confirm" hidden>
      <button id="approve" type="button">Approve</button>
      <button id="deny" class="ghost" type="button">Not me</button>
    </div>
  </div>
</div></div>

<details><summary>No phone? Sign in here instead</summary>
<div class="card" style="margin-top:14px">`+e+`<form method="post">
<label for="email">E-mail</label><input id="email" name="email" type="email" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
`+hidden.String()+`<button type="submit">Sign in</button></form></div></details>
<script>
(function () {
  var code = `+"\""+code+"\""+`, status = document.getElementById("status"),
      confirm = document.getElementById("confirm"), done = false;
  function poll() {
    if (done) return;
    var x = new XMLHttpRequest();
    x.open("GET", "/connect/1.0.0/qr/state?c=" + code, true);
    x.onreadystatechange = function () {
      if (x.readyState !== 4) return;
      var d = {};
      try { d = JSON.parse(x.responseText); } catch (e) { return; }
      if (d.state === "signed_in") {
        document.getElementById("codebox").hidden = false;
        status.innerHTML = "Signed in as <strong>" + d.account + "</strong>. Now type the code above.";
      } else if (d.state === "claimed") {
        status.innerHTML = "Signed in on your phone as <strong>" + d.account + "</strong>. Approve to finish.";
        confirm.hidden = false;
      } else if (d.state === "expired") {
        status.textContent = "This code expired. Reload the page for a new one.";
        done = true;
      }
    };
    x.send();
  }
  setInterval(poll, `+pollEvery+`);
  poll();
  document.getElementById("approve").onclick = function () {
    done = true;
    status.textContent = "Linking\u2026";
    var x = new XMLHttpRequest();
    x.open("POST", "/connect/1.0.0/qr/approve?c=" + code, true);
    x.onreadystatechange = function () {
      if (x.readyState !== 4) return;
      var d = {};
      try { d = JSON.parse(x.responseText); } catch (e) {}
      if (d.redirect) { window.location = d.redirect; }
      else { status.textContent = "That did not work. Reload and try again."; }
    };
    x.send();
  };
  document.getElementById("deny").onclick = function () {
    var x = new XMLHttpRequest();
    x.open("POST", "/connect/1.0.0/qr/deny?c=" + code, true);
    x.send();
    window.location.reload();
  };
})();
</script></main></body></html>`)
}

// naProfile is the country and birthday the Nintendo Account object carries. A real Nintendo
// Account always has both, so unlike the BAAS user object there is no "absent" to serve and a
// fallback is unavoidable — but it must not be a captured stranger's when the account has its
// own. The two objects are read in the same link, and disagreeing about where someone lives is
// not something to leave to a constant.
// naAddress is users/me's email and screenName. A Nintendo Account's screenName is its address
// masked: the first two characters of the name, the first of the domain ("pl•••@e••••" in the
// captured sample). Without an address (the earlier account backend has none) the sample's values remain.
func naAddress(address string) (email, screenName string) {
	name, domain, ok := strings.Cut(address, "@")
	if !ok || name == "" || domain == "" {
		return "player@example.com", "pl•••@e••••"
	}
	nameRunes, domainRunes := []rune(name), []rune(domain)
	return address, string(nameRunes[:min(2, len(nameRunes))]) + "•••@" + string(domainRunes[:1]) + "••••"
}

func NAProfile(id *identity.Identity) (country, birthday string) {
	country, birthday = id.Country, id.Birthday
	if country == "" {
		country = httpx.Getenv("NA_FALLBACK_COUNTRY", "GB")
		log.Printf("[nx-baas] users/me: account %s has no country of its own; serving %s", redact.Tag(id.NaID), country)
	}
	if birthday == "" || birthday == "0000-00-00" {
		birthday = httpx.Getenv("NA_FALLBACK_BIRTHDAY", "2000-01-01")
	}
	return country, birthday
}

// Service is the Nintendo Account surface (accounts.nintendo.com) and the console link pages
// over the shared state. Locks refuses banned accounts.
type Service struct {
	*core.Core
	Locks interface{ PIDLock(pid uint64) string }

	mu         sync.Mutex
	codes      map[string]Code  // NA authorization codes / session tokens -> who logged in
	links      *linkStore       // pending QR console links, by code
	guesses    *guesses         // wrong-code/password attempts, per account
	phones     *phoneStore      // signed-in phones entering a code
	pending2FA *pending2FAStore // password-proved logins awaiting a second factor
}

// New is the Nintendo Account surface with empty link and code state.
func New(c *core.Core, locks interface{ PIDLock(pid uint64) string }) *Service {
	return &Service{Core: c, Locks: locks, codes: map[string]Code{}, links: newLinkStore(),
		guesses: newGuesses(), phones: newPhoneStore(), pending2FA: newPending2FAStore()}
}
