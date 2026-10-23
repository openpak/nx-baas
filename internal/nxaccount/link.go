package nxaccount

// Console account linking by QR code.
//
// The console opens /connect/1.0.0/authorize in its browser. Typing an e-mail and password on a
// TV with a controller is miserable, so that page also shows a short code and a QR image for
// https://<host>/link. The flow:
//
//	1. console page  GET  /connect/1.0.0/authorize   -> shows code + QR, then polls
//	2. phone         GET  /link?c=CODE               -> sign-in page (code prefilled from the QR)
//	3. phone         POST /link                      -> verifies the account, claims the code
//	4. console page  GET  /connect/1.0.0/qr/state    -> sees "claimed" and who it is
//	5. console       POST /connect/1.0.0/qr/approve  -> the person at the console confirms
//	6. console page                                   -> redirects exactly as the password form does
//
// The approval deliberately happens on the console: scanning a QR proves you have a phone, not
// that you are standing in front of that Switch.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"nx-baas/internal/bans"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/token"
	"nx-baas/redact"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Codes are read off a TV and typed on a phone: no vowels (no accidental words), no 0/O/1/I/L.
// Digits only: this is read off a television and typed on a phone, often by
// someone who cannot see the screen well from the sofa, and a numeric keypad
// beats a full keyboard for six characters. It costs entropy — 10^6 rather
// than 28^6 — which is why guesses are capped below; a code alone still cannot
// finish a link, because the console asks its owner to approve.
const codeAlphabet = "0123456789"

const (
	codeLength = 6
	codeTTL    = 10 * time.Minute
	pollEvery  = "2000" // ms, used by the console page
)

type linkState string

const (
	linkWaiting  linkState = "waiting"   // on screen, nobody has scanned it yet
	linkSignedIn linkState = "signed_in" // a phone scanned the QR and signed in; the code is now shown
	linkClaimed  linkState = "claimed"   // that phone typed the code back
	linkApproved linkState = "approved"  // the person at the console pressed Approve
	linkDenied   linkState = "denied"
)

type pendingLink struct {
	State linkState
	// Pair identifies the console session and is what the QR carries. It grants nothing on its
	// own: a phone still has to sign in, and the code is only revealed on the console once it
	// has. Photographing the screen therefore gives an onlooker neither.
	Pair     string
	PID      uint64
	Username string
	NaID     string
	Query    url.Values // the console's original authorize parameters
	Created  time.Time
}

// phoneSession is a signed-in phone, held only long enough to enter a code. Short by design:
// this is a page someone opens for a minute, not a place to stay logged in.
type phoneSession struct {
	PID      uint64
	Username string
	Expires  time.Time
}

const (
	PhoneCookie     = "openpak_link"
	phoneSessionTTL = 15 * time.Minute
)

type phoneStore struct {
	mu sync.Mutex
	by map[string]phoneSession
}

func newPhoneStore() *phoneStore { return &phoneStore{by: map[string]phoneSession{}} }

func (p *phoneStore) new(pid uint64, username string) string {
	token := token.RandHex(32)
	p.mu.Lock()
	defer p.mu.Unlock()
	for t, s := range p.by {
		if time.Now().After(s.Expires) {
			delete(p.by, t)
		}
	}
	p.by[token] = phoneSession{PID: pid, Username: username, Expires: time.Now().Add(phoneSessionTTL)}
	return token
}

func (p *phoneStore) get(token string) (phoneSession, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.by[token]
	if !ok || time.Now().After(s.Expires) {
		delete(p.by, token)
		return phoneSession{}, false
	}
	return s, true
}

func (p *phoneStore) drop(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.by, token)
}

// pending2FA holds a password-proved login whose second factor is still
// owed. It carries the account id and where to continue — never the
// password, which is not stored past the login call. Short-lived and
// single-use: dropped when the code verifies (or when it expires).
type pending2FA struct {
	AccountID string
	PID       uint64 // projection minted at password time; usable only after the code verifies
	Username  string
	Pair      string     // link flow: the console pairing ("" for authorize flow)
	Query     url.Values // authorize flow: the console's original parameters
	Mode      string     // "link" or "authorize"
	Created   time.Time
}

const pending2FAModesLink, pending2FAModeAuthorize = "link", "authorize"

const pending2FATTL = 10 * time.Minute

type pending2FAStore struct {
	mu sync.Mutex
	by map[string]*pending2FA
}

func newPending2FAStore() *pending2FAStore { return &pending2FAStore{by: map[string]*pending2FA{}} }

func (s *pending2FAStore) new(p *pending2FA) string {
	token := token.RandHex(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, q := range s.by {
		if time.Since(q.Created) > pending2FATTL {
			delete(s.by, t)
		}
	}
	p.Created = time.Now()
	s.by[token] = p
	return token
}

func (s *pending2FAStore) take(token string) (*pending2FA, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.by[token]
	if !ok || time.Since(p.Created) > pending2FATTL {
		delete(s.by, token)
		return nil, false
	}
	delete(s.by, token)
	return p, true
}

func (s *pending2FAStore) peek(token string) (*pending2FA, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.by[token]
	if !ok || time.Since(p.Created) > pending2FATTL {
		delete(s.by, token)
		return nil, false
	}
	cp := *p
	return &cp, true
}

type linkStore struct {
	mu sync.Mutex
	by map[string]*pendingLink
}

func newLinkStore() *linkStore { return &linkStore{by: map[string]*pendingLink{}} }

func (l *linkStore) new(q url.Values) (code, pair string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	code, pair = randCode(), token.RandHex(16)
	l.by[code] = &pendingLink{State: linkWaiting, Pair: pair, Query: q, Created: time.Now()}
	return code, pair
}

// byPair finds the console session a scanned QR belongs to, and the code it is holding back.
func (l *linkStore) byPair(pair string) (code string, p *pendingLink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	for c, cand := range l.by {
		if cand.Pair == pair && pair != "" {
			copy := *cand
			return c, &copy
		}
	}
	return "", nil
}

func (l *linkStore) get(code string) *pendingLink {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	if p, ok := l.by[strings.ToUpper(strings.TrimSpace(code))]; ok {
		copy := *p
		return &copy
	}
	return nil
}

func (l *linkStore) update(code string, fn func(*pendingLink)) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	p, ok := l.by[strings.ToUpper(strings.TrimSpace(code))]
	if !ok {
		return false
	}
	fn(p)
	return true
}

// expireLocked drops codes nobody completed. A stale code on a TV screen must stop working.
func (l *linkStore) expireLocked() {
	for code, p := range l.by {
		if time.Since(p.Created) > codeTTL {
			delete(l.by, code)
		}
	}
}

func randCode() string {
	raw := make([]byte, codeLength)
	if _, err := rand.Read(raw); err != nil {
		// Never hand out a guessable code: without entropy there is nothing safe to return.
		panic("link: no entropy for a link code: " + err.Error())
	}
	b := make([]byte, codeLength)
	for i := range b {
		// Rejection sampling: 256 is not a multiple of 10, so a plain modulo
		// would make 0-5 more likely than 6-9 and shrink the space further.
		for {
			if _, err := rand.Read(raw[i : i+1]); err != nil {
				panic("link: no entropy for a link code: " + err.Error())
			}
			if v := int(raw[i]); v < 250 {
				b[i] = codeAlphabet[v%len(codeAlphabet)]
				break
			}
		}
	}
	return string(b)
}

// guessLimit is how many wrong codes one signed-in phone may try before it has
// to wait. Six digits is one in a million; without a cap, a script working
// through the space would find whichever codes happen to be live, and there
// are always fewer live codes than the space is wide. Ten is far more than a
// person mistypes and far fewer than a search needs.
const (
	GuessLimit  = 10
	guessWindow = 10 * time.Minute
)

// guesses counts wrong codes per account. In memory on purpose: a link
// code lives ten minutes, so nothing here needs to outlive a restart, and a
// restart clearing the counters costs an attacker more time than it saves.
type guesses struct {
	mu sync.Mutex
	by map[string]*guessCount
}

type guessCount struct {
	n     int
	until time.Time
}

func newGuesses() *guesses { return &guesses{by: map[string]*guessCount{}} }

// blocked reports whether this phone has spent its attempts, and how long is
// left, so the page can say something truer than "wrong code".
func (g *guesses) blocked(key string) (bool, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.by[key]
	if !ok {
		return false, 0
	}
	if time.Now().After(c.until) {
		delete(g.by, key)
		return false, 0
	}
	return c.n >= GuessLimit, time.Until(c.until)
}

func (g *guesses) wrong(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.by[key]
	if !ok || time.Now().After(c.until) {
		c = &guessCount{}
		g.by[key] = c
	}
	c.n++
	c.until = time.Now().Add(guessWindow)
}

// right clears the count: someone who got there is not mid-attack.
func (g *guesses) right(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.by, key)
}

// groupCode splits the code for the screen it is read from: six digits in one
// run are easy to lose your place in across a room, three and three are not.
// Only for display — what the phone submits is trimmed of spaces anyway.
func groupCode(code string) string {
	if len(code) != codeLength {
		return code
	}
	return code[:3] + " " + code[3:]
}

// qrDataURI renders url as a PNG data URI for an <img>, so the page needs no extra request.
func qrDataURI(u string) string {
	png, err := qrcode.Encode(u, qrcode.Medium, 320)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

// linkBaseURL is what the QR points at: the phone must reach this host by name, and ok says
// whether any phone can.
//
// Falling back to the name the request arrived on is what a console reaches us by, and that name
// is Nintendo's — reached only because the console's DNS was pointed here. A phone's was not. A
// QR built on that host does not merely fail: it sends the pairing id to Nintendo, from a device
// that never opted into any of this. So without NX_LINK_BASE_URL there is no phone path at all,
// and callers show the code and the password form instead of a square that leaks.
func (s *Service) linkBaseURL(r *http.Request) (string, bool) {
	if v := httpx.Getenv("NX_LINK_BASE_URL", ""); v != "" {
		return strings.TrimRight(v, "/"), true
	}
	host := httpx.HostOf(r)
	if strings.Contains(host, "nintendo.") {
		return "", false
	}
	return "https://" + host, true
}

// qrRoutes serves the console-side polling endpoints and the phone-side page.
// Returns true when it handled the request.
func (s *Service) QRRoutes(w http.ResponseWriter, r *http.Request, body []byte) bool {
	form, _ := url.ParseQuery(string(body))
	code := r.URL.Query().Get("c")
	if code == "" {
		code = form.Get("code")
	}

	switch {
	case r.URL.Path == "/connect/1.0.0/qr/new" && r.Method == "POST":
		// The console's link screen, for a client that draws it itself. An emulator has a keyboard
		// and a window, so it shows this screen in-app rather than in a browser it cannot style —
		// and every emulator gets the same screen because every emulator gets the same three
		// things from here: the code, the page a phone should open, and the QR that points at it.
		//
		// The QR is rendered here so no client needs a QR encoder to draw the console's screen.
		code, pair := s.links.new(r.URL.Query())
		out := map[string]any{
			"code": code, "code_display": groupCode(code), "pair": pair,
			"expires_in": int(codeTTL.Seconds()),
		}
		if base, ok := s.linkBaseURL(r); ok {
			link := base + "/link?p=" + pair
			out["link_url"], out["qr"] = link, qrDataURI(link)
		} else {
			// Said plainly rather than left empty: a client showing a blank square would be a
			// worse answer than one showing none.
			out["no_phone_reason"] = "NX_LINK_BASE_URL is not set, so there is no address a phone could open"
			log.Printf("[link] no phone path offered: NX_LINK_BASE_URL is unset")
		}
		log.Printf("[link] code %s opened by an in-app client (%s)", redact.Tag(code), redact.IDs(r.UserAgent()))
		httpx.WriteJSON(w, 200, out)
		return true

	case r.URL.Path == "/connect/1.0.0/qr/state":
		p := s.links.get(code)
		if p == nil {
			httpx.WriteJSON(w, 200, map[string]any{"state": "expired"})
			return true
		}
		httpx.WriteJSON(w, 200, map[string]any{"state": string(p.State), "account": p.Username})
		return true

	case r.URL.Path == "/connect/1.0.0/qr/deny" && r.Method == "POST":
		s.links.update(code, func(p *pendingLink) { p.State = linkDenied })
		httpx.WriteJSON(w, 200, map[string]any{"state": "denied"})
		return true

	case r.URL.Path == "/connect/1.0.0/qr/approve" && r.Method == "POST":
		p := s.links.get(code)
		if p == nil || p.State != linkClaimed {
			httpx.WriteJSON(w, 409, map[string]any{"error": "not ready"})
			return true
		}
		s.links.update(code, func(p *pendingLink) { p.State = linkApproved })
		log.Printf("[link] code %s approved on the console for %s (pid %s)", redact.Tag(code), redact.Tag(p.Username), redact.Tag(p.PID))
		httpx.WriteJSON(w, 200, map[string]any{"state": "approved", "redirect": s.finishLink(p)})
		return true

	case r.URL.Path == "/link" && r.Method == "GET":
		pair := r.URL.Query().Get("p")
		if sess, ok := s.phoneSession(r); ok {
			s.markSignedIn(pair, sess)
			s.phoneConfirmPage(w, sess.Username, pair, "")
		} else {
			s.phoneLoginPage(w, pair, "")
		}
		return true

	case r.URL.Path == "/link" && r.Method == "POST":
		// Sign-in step: credentials only. No code is accepted here, so a stolen link cannot
		// approve anything on its own. Password guesses are capped per account like link
		// codes are: the television writes nothing down, but the endpoint is still HTTP.
		pair := form.Get("pair")
		pwKey := "pw:" + strings.ToLower(strings.TrimSpace(form.Get("email")))
		if blocked, _ := s.guesses.blocked(pwKey); blocked {
			s.phoneLoginPage(w, pair, "Too many attempts. Wait a few minutes and try again.")
			return true
		}
		res, err := s.Acct.LoginPID(form.Get("email"), form.Get("password"))
		lock := s.Locks.PIDLock(res.PID)
		if errors.Is(err, identity.ErrAccountLocked) && lock == "" {
			lock = bans.Banned
		}
		if lock != "" {
			s.phoneLoginPage(w, pair, bans.LockedPageMessage(lock))
			return true
		}
		if errors.Is(err, identity.ErrSecondFactorRequired) {
			s.phoneLoginPage(w, pair, "This account has two-factor authentication: finish signing in on the website, then link.")
			return true
		}
		if err != nil {
			s.guesses.wrong(pwKey)
			s.phoneLoginPage(w, pair, "Wrong e-mail or password.")
			return true
		}
		s.guesses.right(pwKey)
		if res.Need2FA {
			// Password proved, second factor owed: hold only the account id
			// and where to continue, then ask for the authenticator code (or
			// a recovery code) on the next page.
			tok := s.pending2FA.new(&pending2FA{AccountID: res.AccountID, PID: res.PID, Username: res.Username, Pair: pair, Mode: pending2FAModesLink})
			s.phone2FAPage(w, pair, tok, "")
			return true
		}
		if _, err := s.Acct.Identity(res.PID); err != nil {
			s.phoneLoginPage(w, pair, "Account lookup failed.")
			return true
		}
		s.finishPhoneSignIn(w, r, pair, res.PID, res.Username)
		return true

	case r.URL.Path == "/link/2fa" && r.Method == "POST":
		// Second step: the code (or a recovery code) for a password-proved
		// login. The pending record is consumed only by a correct code; wrong
		// ones leave it for retry inside its ten minutes, and the core counts
		// failures per account (5 per 15 minutes) on top.
		pair := form.Get("pair")
		p, ok := s.pending2FA.peek(form.Get("token"))
		if !ok || p.Mode != pending2FAModesLink {
			s.phoneLoginPage(w, pair, "That took too long — sign in again.")
			return true
		}
		if err := s.Acct.VerifySecondFactor(p.AccountID, strings.TrimSpace(form.Get("code")), strings.TrimSpace(form.Get("recovery_code"))); err != nil {
			if errors.Is(err, identity.ErrSecondFactorLocked) {
				s.phone2FAPage(w, pair, form.Get("token"), "Too many wrong codes. Wait a few minutes and try again.")
				return true
			}
			s.phone2FAPage(w, pair, form.Get("token"), "That code did not work. Check your authenticator and try again.")
			return true
		}
		if _, ok := s.pending2FA.take(form.Get("token")); !ok {
			s.phoneLoginPage(w, pair, "That took too long — sign in again.")
			return true
		}
		if _, err := s.Acct.Identity(p.PID); err != nil {
			s.phoneLoginPage(w, pair, "Account lookup failed.")
			return true
		}
		s.finishPhoneSignIn(w, r, pair, p.PID, p.Username)
		return true

	case r.URL.Path == "/link/signout" && r.Method == "GET":
		// A phone browser that prefetches the form's action lands here and used
		// to be shown "404 page not found" in the middle of the flow. Signing
		// out is not something a GET may do, so send it back to the page.
		http.Redirect(w, r, "/link", http.StatusSeeOther)
		return true

	case r.URL.Path == "/link/signout" && r.Method == "POST":
		if c, err := r.Cookie(PhoneCookie); err == nil {
			s.phones.drop(c.Value)
		}
		s.clearPhoneCookie(w, r)
		s.phoneLoginPage(w, form.Get("pair"), "")
		return true

	case r.URL.Path == "/link/code" && r.Method == "POST":
		sess, ok := s.phoneSession(r)
		if !ok {
			s.phoneLoginPage(w, form.Get("pair"), "That took too long — sign in again.")
			return true
		}
		// Keyed by the account, not by the cookie: a counter a person can reset
		// by clearing a cookie is not a limit.
		key := strconv.FormatUint(sess.PID, 10)
		if blocked, left := s.guesses.blocked(key); blocked {
			log.Printf("[link] %s is out of attempts for %s", redact.Tag(sess.Username), left.Round(time.Minute))
			s.phoneConfirmPage(w, sess.Username, form.Get("pair"),
				"Too many wrong codes. Wait a few minutes and try again.")
			return true
		}
		// People copy what they see, and what they see has a space in it.
		entered := strings.ReplaceAll(strings.TrimSpace(form.Get("code")), " ", "")
		pending := s.links.get(entered)
		if pending == nil {
			s.guesses.wrong(key)
			s.phoneConfirmPage(w, sess.Username, form.Get("pair"), "That code is wrong or has expired. Check the console.")
			return true
		}
		if pending.State != linkWaiting && pending.State != linkSignedIn {
			s.phoneConfirmPage(w, sess.Username, form.Get("pair"), "That code has already been used.")
			return true
		}
		id, err := s.Acct.Identity(sess.PID)
		if err != nil {
			s.phoneConfirmPage(w, sess.Username, form.Get("pair"), "Account lookup failed.")
			return true
		}
		s.guesses.right(key)
		s.links.update(entered, func(p *pendingLink) {
			p.State, p.PID, p.Username, p.NaID = linkClaimed, sess.PID, sess.Username, id.NaID
		})
		log.Printf("[link] code %s claimed by %s (pid %s)", redact.Tag(entered), redact.Tag(sess.Username), redact.Tag(sess.PID))
		s.phoneDonePage(w, sess.Username)
		return true
	}
	return false
}

// finishLink mints the same code the password form does and builds the console's redirect, so
// both paths end identically.
func (s *Service) finishLink(p *pendingLink) string {
	code := s.IssueCode(Code{PID: p.PID, Username: p.Username, ClientID: p.Query.Get("client_id"), NaID: p.NaID, Created: time.Now()})
	s.Store.RememberNA(p.NaID, p.PID)
	return s.authorizeRedirect(p.Query, code)
}

// ---------- pages ----------
//
// Both pages carry a trimmed copy of openpak.org's tokens rather than linking its stylesheet:
// this service must render on a console browser with no network access to the website, and a
// linked stylesheet would be one more thing to fail at exactly the wrong moment.

const LogoDataURI = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA1MTIgNTEyIiBmaWxsPSJub25lIj4gPGRlZnM+IDxsaW5lYXJHcmFkaWVudCBpZD0iYmciIHgxPSIwIiB5MT0iMCIgeDI9IjUxMiIgeTI9IjUxMiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPiA8c3RvcCBvZmZzZXQ9IjAlIiBzdG9wLWNvbG9yPSIjNjM2NmYxIi8+IDxzdG9wIG9mZnNldD0iMTAwJSIgc3RvcC1jb2xvcj0iIzQzMzhjYSIvPiA8L2xpbmVhckdyYWRpZW50PiA8L2RlZnM+IDxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSJ1cmwoI2JnKSIvPiA8Y2lyY2xlIGN4PSIyNTYiIGN5PSIyNTYiIHI9IjE4MCIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSIyMCIgZmlsbD0ibm9uZSIgb3BhY2l0eT0iMC45Ii8+IDxwYXRoIGQ9Ik0xNjAgMjU2YzAtNTMgNDMtOTYgOTYtOTZzOTYgNDMgOTYgOTYtNDMgOTYtOTYgOTYiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMjAiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgZmlsbD0ibm9uZSIgb3BhY2l0eT0iMC45Ii8+IDxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjgiIGZpbGw9IndoaXRlIiBvcGFjaXR5PSIwLjk1Ii8+IDwvc3ZnPg=="

const pageCSS = `
/* The site's tokens (website/web/src/input.css, 2026-10 "console HOME menu" redesign), so the
   page a console sends you to looks like the place it sends you to: a cool grey shell, white
   tiles, slate ink, indigo for links and primary actions, and a cyan selection cursor that
   appears only on hover, focus and the selected thing. Flat colours, no gradients. Light and
   dark follow the reader's system setting: this opens on a phone in daylight as often as on a
   television at night. Inline on purpose — a console browser may have no route to the website. */
:root{color-scheme:light dark;--paper:#e9ecf0;--paper-2:#f2f4f7;--raised:#ffffff;--sunk:#dde1e7;--ink:#20262f;--ink-2:#48505c;--muted:#6b7380;--faint:#9aa1ab;
--line:#d9dde3;--line-2:#c3c9d1;--cursor:#0094be;--cursor-2:#39c9ea;
--accent:#4f46e5;--accent-2:#6366f1;--accent-weak:#eceeff;--accent-line:#c5cafb;--on-accent:#fff;
--ok:#138a45;--ok-weak:#e3f5ea;--ok-line:#b2e0c3;--bad:#c42b2b;--bad-weak:#fde9e9;--bad-line:#f2bfbf;
--warn:#a35f00;--warn-weak:#fdf2dc;--warn-line:#efd39c;
--shadow-sm:0 1px 0 rgba(32,38,47,.06);--shadow:0 1px 0 rgba(32,38,47,.06),0 6px 16px -10px rgba(32,38,47,.25);--r:14px}
@media (prefers-color-scheme:dark){:root{--paper:#24272d;--paper-2:#2b2f36;--raised:#31353d;--sunk:#1d2025;--ink:#eef1f5;--ink-2:#c4c9d1;--muted:#949ba6;--faint:#6c737e;
--line:#3b4048;--line-2:#4a505a;--cursor:#3ad7f2;--cursor-2:#a2efff;
--accent:#9198ff;--accent-2:#a5abff;--accent-weak:#2e3156;--accent-line:#4a4f8c;--on-accent:#15172e;
--ok:#4fd486;--ok-weak:#1f3a2b;--ok-line:#2f5c42;--bad:#ff7676;--bad-weak:#432528;--bad-line:#6e3439;
--warn:#f6bd4f;--warn-weak:#3f3320;--warn-line:#6a5328;
--shadow-sm:0 1px 0 rgba(0,0,0,.25);--shadow:0 1px 0 rgba(0,0,0,.25),0 8px 18px -10px rgba(0,0,0,.6)}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
display:flex;justify-content:center;padding:24px 16px 40px}
main{width:100%;max-width:34rem}
h1{font-size:clamp(1.5rem,5vw,1.8rem);line-height:1.2;letter-spacing:-0.02em;margin:0 0 6px;font-weight:650}
p{color:var(--muted);margin:0 0 20px}
strong{color:var(--ink)}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;margin-bottom:24px;color:var(--ink)}
.brand img{width:28px;height:28px}
.card{--ring-gap:var(--raised);background:var(--raised);border:1px solid var(--line);border-radius:var(--r);padding:20px;margin-bottom:16px;box-shadow:var(--shadow-sm)}
/* The code is the whole point of the screen it appears on: as large as it can
   be without wrapping on a narrow phone. */
.code{font:600 clamp(1.8rem,9vw,2.4rem)/1 ui-monospace,SFMono-Regular,Menlo,monospace;
letter-spacing:0.16em;color:var(--accent);background:var(--accent-weak);
border:1px solid var(--accent-line);border-radius:10px;padding:16px 18px;display:inline-block}
.qr{background:#fff;padding:12px;border-radius:10px;display:inline-block;line-height:0}
.qr img{width:min(220px,60vw);height:auto;aspect-ratio:1}
.split{display:flex;gap:20px;flex-wrap:wrap;align-items:center}
label{display:block;font-size:0.92rem;color:var(--ink-2);margin:14px 0 6px}
/* 44px tall and never under 16px: a smaller field makes iOS zoom on focus and
   leaves the page scrolled sideways. */
input{width:100%;min-height:44px;padding:0.65rem 0.8rem;font:inherit;font-size:max(1rem,16px);
color:var(--ink);background:var(--paper-2);border:1px solid var(--line-2);border-radius:12px}
button{margin-top:18px;min-height:44px;padding:0.7rem 1.1rem;font:inherit;font-weight:600;
color:var(--on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:999px;
cursor:pointer;width:100%}
button.ghost{background:transparent;border-color:var(--line-2);color:var(--ink);margin-top:10px}
/* The selection cursor: a gap in the page's own colour, then the cyan ring. A D-pad moves focus,
   so :focus is what the player sees as the cursor; hover selects for a pointer. Inside a card the
   gap is the card's colour (--ring-gap). It breathes between two cyans where motion is welcome. */
a:focus,button:hover,button:focus,summary:focus,input:focus{outline:none;box-shadow:0 0 0 3px var(--ring-gap,var(--paper)),0 0 0 7px var(--cursor)}
a:focus,summary:focus{border-radius:8px}
input:focus{border-color:var(--cursor);background:var(--raised)}
@keyframes breathe{50%{box-shadow:0 0 0 3px var(--ring-gap,var(--paper)),0 0 0 7px var(--cursor-2)}}
@media (prefers-reduced-motion:no-preference){a:focus,button:hover,button:focus,summary:focus{animation:breathe 1.6s ease-in-out infinite}}
@media (prefers-color-scheme:dark){.card{border-color:transparent}}
/* One row, tinted by state, with a pill on the right — the same shape the
   status page uses, so the two read as one product. */
.row{display:flex;align-items:center;gap:0.75rem;padding:0.9rem 1rem;border-radius:12px;
border:1px solid var(--line);background:var(--raised);margin-bottom:0.6rem}
.row .name{font-weight:600;overflow-wrap:anywhere}
.row .pill{margin-left:auto;flex:none;white-space:nowrap;display:inline-flex;align-items:center;
gap:0.4rem;padding:0.3rem 0.7rem;border-radius:999px;font-size:0.85rem;font-weight:600;
background:transparent;border:1px solid var(--line-2);color:var(--muted)}
.row .pill::before{content:"";width:0.45rem;height:0.45rem;border-radius:50%;background:currentColor}
.row.ok{background:var(--ok-weak);border-color:var(--ok-line)}
.row.ok .pill{border-color:var(--ok-line);color:var(--ok)}
.row.bad{background:var(--bad-weak);border-color:var(--bad-line)}
.row.bad .pill{border-color:var(--bad-line);color:var(--bad)}
.err{color:var(--bad);margin:0 0 12px}
.ok{color:var(--ok)}
.steps{margin:0;padding-left:1.2em;color:var(--muted)}
.steps li{margin:6px 0}
hr{border:0;border-top:1px solid var(--line);margin:24px 0}
details summary{color:var(--muted);cursor:pointer;min-height:44px;display:flex;align-items:center}

/* The console browser: a television, read from a sofa, driven with a stick.
   Everything is bigger, the two halves sit side by side because a 720p screen
   is wide and short, and focus is visible because there is no pointer to tell
   you where you are. Televisions also crop their edges, so nothing important
   goes near them. */
body.console{font-size:20px;padding:40px 56px;align-items:flex-start}
.console main{max-width:66rem}
.console h1{font-size:2.5rem;margin-bottom:10px}
.console p{font-size:1.05rem}
.console .brand{font-size:1.3rem;margin-bottom:28px}
.console .brand img{width:36px;height:36px}
.console .card{padding:28px}
.console .split{flex-wrap:nowrap;gap:40px;align-items:flex-start}
.console .qr img{width:300px}
/* The code is read across a room: it is the largest thing on the screen. */
.console .code{font-size:3.2rem;letter-spacing:0.2em;padding:20px 26px}
.console .steps{font-size:1.05rem;line-height:1.7}
.console .steps li{margin:10px 0}
.console button{width:auto;min-height:60px;padding:0.85rem 1.8rem;font-size:1.05rem;margin-top:0}
.console #confirm{display:flex;gap:16px;margin-top:22px}
.console #confirm[hidden]{display:none}
.console label{font-size:1rem}
.console input{min-height:52px;font-size:1.05rem}
/* No pointer: the cursor ring above announces the focused control. */
@media (max-width:900px){
  .console .split{flex-wrap:wrap;gap:24px}
  body.console{padding:24px 20px;font-size:18px}
  .console .qr img{width:min(240px,60vw)}
}
`

func pageHead(title string) string { return pageHeadFor(title, "") }

// pageHeadFor stamps a body class so one stylesheet can serve two very
// different screens: a phone held at arm's length, and a television across a
// room driven with a controller.
func pageHeadFor(title, class string) string {
	body := "<body>"
	if class != "" {
		body = `<body class="` + class + `">`
	}
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>` + title + ` · OpenPak</title>` +
		`<style>` + pageCSS + `</style></head>` + body + `<main>` +
		`<div class="brand"><img src="` + LogoDataURI + `" alt=""> OpenPak</div>`
}

func (s *Service) phoneDonePage(w http.ResponseWriter, username string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHead("Almost there")+`
<h1>Now approve it on the console</h1>
<div class="row ok"><span class="name">`+html.EscapeString(username)+`</span><span class="pill">Signed in</span></div>
<div class="card"><p style="margin:0">Your console is showing this account. Choose <strong>Approve</strong>
there to finish linking. You can close this page.</p></div></main></body></html>`)
}

// ---------- phone session ----------

func (s *Service) phoneSession(r *http.Request) (phoneSession, bool) {
	c, err := r.Cookie(PhoneCookie)
	if err != nil {
		return phoneSession{}, false
	}
	return s.phones.get(c.Value)
}

// secure marks the cookie when the page was reached over TLS — through the tunnel it is
// https, on a LAN it may not be, and a Secure cookie there would simply never come back.
func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Service) setPhoneCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: PhoneCookie, Value: token, Path: "/link", HttpOnly: true,
		Secure: secureRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: int(phoneSessionTTL.Seconds()),
	})
}

func (s *Service) clearPhoneCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: PhoneCookie, Value: "", Path: "/link", HttpOnly: true,
		Secure: secureRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// ---------- phone pages ----------

func errBlock(msg string) string {
	if msg == "" {
		return ""
	}
	return `<p class="err">` + html.EscapeString(msg) + `</p>`
}

// phoneLoginPage: credentials only. The code is asked for afterwards, so scanning the QR by
// itself approves nothing.
func (s *Service) phoneLoginPage(w http.ResponseWriter, pair, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHead("Link a console")+`
<h1>Sign in</h1>
<p>Then type the code shown on your console.</p>
<div class="card">`+errBlock(errMsg)+`<form method="post" action="/link">
`+pairField(pair)+`<label for="email">E-mail</label>
<input id="email" name="email" type="email" autocomplete="username" autofocus required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form></div></main></body></html>`)
}

// phoneConfirmPage: signed in already — check it is the right account before taking a code,
// since a phone stays signed in and the console in front of you may not be yours.
func (s *Service) phoneConfirmPage(w http.ResponseWriter, username, pair, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHead("Link a console")+`
<h1>Link a console</h1>
<div class="row ok"><span class="name">`+html.EscapeString(username)+`</span><span class="pill">Signed in</span></div>
<div class="card">`+errBlock(errMsg)+`<form method="post" action="/link/code">
`+pairField(pair)+`<label for="code">Code shown on the console</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" spellcheck="false"
       maxlength="6" minlength="6" pattern="[0-9]{6}" required autofocus>
<button type="submit">Link this console</button>
</form></div>
<div class="card"><p style="margin:0 0 12px">Not your account?</p>
<form method="post" action="/link/signout">`+pairField(pair)+`<button class="ghost" type="submit">Sign out and use another</button></form>
</div></main></body></html>`)
}

func pairField(pair string) string {
	if pair == "" {
		return ""
	}
	return `<input type="hidden" name="pair" value="` + html.EscapeString(pair) + `">`
}

// finishPhoneSignIn runs the post-login continuation both the password step
// and the second-factor step share: cookie session, console reveal, confirm.
func (s *Service) finishPhoneSignIn(w http.ResponseWriter, r *http.Request, pair string, pid uint64, username string) {
	sess := phoneSession{PID: pid, Username: username}
	s.setPhoneCookie(w, r, s.phones.new(pid, username))
	// Only now does the console reveal its code.
	s.markSignedIn(pair, sess)
	s.phoneConfirmPage(w, username, pair, "")
}

// phone2FAPage: password proved, second factor owed. Six digits from the
// authenticator, or one of the recovery codes shown once at enrolment.
func (s *Service) phone2FAPage(w http.ResponseWriter, pair, token, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHead("Two-factor check")+`
<h1>Check your authenticator</h1>
<p>This account has two-factor authentication. Enter the 6-digit code, or a recovery code.</p>
<div class="card">`+errBlock(errMsg)+`<form method="post" action="/link/2fa">
`+pairField(pair)+`<input type="hidden" name="token" value="`+html.EscapeString(token)+`">
<label for="code">6-digit code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" spellcheck="false"
       maxlength="6" minlength="6" pattern="[0-9]{6}" autofocus>
<label for="recovery_code">Or a recovery code</label>
<input id="recovery_code" name="recovery_code" autocomplete="off" spellcheck="false">
<button type="submit">Verify</button>
</form></div></main></body></html>`)
}

// markSignedIn tells the console session that a phone has signed in, which is what makes the
// code appear on the television. Nothing is claimed yet: the code still has to be typed back.
func (s *Service) markSignedIn(pair string, sess phoneSession) {
	if pair == "" {
		return
	}
	code, p := s.links.byPair(pair)
	if p == nil || p.State != linkWaiting {
		return
	}
	s.links.update(code, func(p *pendingLink) {
		p.State, p.Username = linkSignedIn, sess.Username
	})
	log.Printf("[link] %s signed in on the phone; console may show its code", redact.Tag(sess.Username))
}
