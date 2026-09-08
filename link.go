package main

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
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Codes are read off a TV and typed on a phone: no vowels (no accidental words), no 0/O/1/I/L.
const codeAlphabet = "23456789BCDFGHJKMNPQRSTVWXYZ"

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
	phoneCookie     = "openpak_link"
	phoneSessionTTL = 15 * time.Minute
)

type phoneStore struct {
	mu sync.Mutex
	by map[string]phoneSession
}

func newPhoneStore() *phoneStore { return &phoneStore{by: map[string]phoneSession{}} }

func (p *phoneStore) new(pid uint64, username string) string {
	token := randHex(32)
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

type linkStore struct {
	mu sync.Mutex
	by map[string]*pendingLink
}

func newLinkStore() *linkStore { return &linkStore{by: map[string]*pendingLink{}} }

func (l *linkStore) new(q url.Values) (code, pair string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	code, pair = randCode(), randHex(16)
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
	for i, v := range raw {
		b[i] = codeAlphabet[int(v)%len(codeAlphabet)]
	}
	return string(b)
}

// qrDataURI renders url as a PNG data URI for an <img>, so the page needs no extra request.
func qrDataURI(u string) string {
	png, err := qrcode.Encode(u, qrcode.Medium, 320)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

// linkBaseURL is what the QR points at: the phone must reach this host by name.
func (s *server) linkBaseURL(r *http.Request) string {
	if v := getenv("NX_LINK_BASE_URL", ""); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://" + hostOf(r)
}

// qrRoutes serves the console-side polling endpoints and the phone-side page.
// Returns true when it handled the request.
func (s *server) qrRoutes(w http.ResponseWriter, r *http.Request, body []byte) bool {
	form, _ := url.ParseQuery(string(body))
	code := r.URL.Query().Get("c")
	if code == "" {
		code = form.Get("code")
	}

	switch {
	case r.URL.Path == "/connect/1.0.0/qr/state":
		p := s.links.get(code)
		if p == nil {
			writeJSON(w, 200, map[string]any{"state": "expired"})
			return true
		}
		writeJSON(w, 200, map[string]any{"state": string(p.State), "account": p.Username})
		return true

	case r.URL.Path == "/connect/1.0.0/qr/deny" && r.Method == "POST":
		s.links.update(code, func(p *pendingLink) { p.State = linkDenied })
		writeJSON(w, 200, map[string]any{"state": "denied"})
		return true

	case r.URL.Path == "/connect/1.0.0/qr/approve" && r.Method == "POST":
		p := s.links.get(code)
		if p == nil || p.State != linkClaimed {
			writeJSON(w, 409, map[string]any{"error": "not ready"})
			return true
		}
		s.links.update(code, func(p *pendingLink) { p.State = linkApproved })
		log.Printf("[link] code %s approved on the console for %s (pid %d)", code, p.Username, p.PID)
		writeJSON(w, 200, map[string]any{"state": "approved", "redirect": s.finishLink(p)})
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
		// approve anything on its own.
		pair := form.Get("pair")
		pid, username, err := s.acct.LoginPID(form.Get("email"), form.Get("password"))
		if err != nil {
			s.phoneLoginPage(w, pair, "Wrong e-mail or password.")
			return true
		}
		if _, err := s.acct.Identity(pid); err != nil {
			s.phoneLoginPage(w, pair, "Account lookup failed.")
			return true
		}
		sess := phoneSession{PID: pid, Username: username}
		s.setPhoneCookie(w, r, s.phones.new(pid, username))
		// Only now does the console reveal its code.
		s.markSignedIn(pair, sess)
		s.phoneConfirmPage(w, username, pair, "")
		return true

	case r.URL.Path == "/link/signout" && r.Method == "POST":
		if c, err := r.Cookie(phoneCookie); err == nil {
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
		entered := strings.ToUpper(strings.TrimSpace(form.Get("code")))
		pending := s.links.get(entered)
		if pending == nil {
			s.phoneConfirmPage(w, sess.Username, form.Get("pair"), "That code is wrong or has expired. Check the console.")
			return true
		}
		if pending.State != linkWaiting && pending.State != linkSignedIn {
			s.phoneConfirmPage(w, sess.Username, form.Get("pair"), "That code has already been used.")
			return true
		}
		id, err := s.acct.Identity(sess.PID)
		if err != nil {
			s.phoneConfirmPage(w, sess.Username, form.Get("pair"), "Account lookup failed.")
			return true
		}
		s.links.update(entered, func(p *pendingLink) {
			p.State, p.PID, p.Username, p.NaID = linkClaimed, sess.PID, sess.Username, id.NaID
		})
		log.Printf("[link] code %s claimed by %s (pid %d)", entered, sess.Username, sess.PID)
		s.phoneDonePage(w, sess.Username)
		return true
	}
	return false
}

// finishLink mints the same code the password form does and builds the console's redirect, so
// both paths end identically.
func (s *server) finishLink(p *pendingLink) string {
	code := randHex(16)
	s.mu.Lock()
	s.codes[code] = naCode{PID: p.PID, Username: p.Username, ClientID: p.Query.Get("client_id"), NaID: p.NaID}
	s.mu.Unlock()
	s.store.RememberNA(p.NaID, p.PID)
	return s.authorizeRedirect(p.Query, code)
}

// ---------- pages ----------
//
// Both pages carry a trimmed copy of openpak.org's tokens rather than linking its stylesheet:
// this service must render on a console browser with no network access to the website, and a
// linked stylesheet would be one more thing to fail at exactly the wrong moment.

const logoDataURI = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA1MTIgNTEyIiBmaWxsPSJub25lIj4gPGRlZnM+IDxsaW5lYXJHcmFkaWVudCBpZD0iYmciIHgxPSIwIiB5MT0iMCIgeDI9IjUxMiIgeTI9IjUxMiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPiA8c3RvcCBvZmZzZXQ9IjAlIiBzdG9wLWNvbG9yPSIjNjM2NmYxIi8+IDxzdG9wIG9mZnNldD0iMTAwJSIgc3RvcC1jb2xvcj0iIzQzMzhjYSIvPiA8L2xpbmVhckdyYWRpZW50PiA8L2RlZnM+IDxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSJ1cmwoI2JnKSIvPiA8Y2lyY2xlIGN4PSIyNTYiIGN5PSIyNTYiIHI9IjE4MCIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSIyMCIgZmlsbD0ibm9uZSIgb3BhY2l0eT0iMC45Ii8+IDxwYXRoIGQ9Ik0xNjAgMjU2YzAtNTMgNDMtOTYgOTYtOTZzOTYgNDMgOTYgOTYtNDMgOTYtOTYgOTYiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMjAiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgZmlsbD0ibm9uZSIgb3BhY2l0eT0iMC45Ii8+IDxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjgiIGZpbGw9IndoaXRlIiBvcGFjaXR5PSIwLjk1Ii8+IDwvc3ZnPg=="

const pageCSS = `
/* The site's tokens, so the page a console sends you to looks like the place
   it sends you to. Light and dark follow the reader's system setting: this
   opens on a phone in daylight as often as on a television at night.
   Inline on purpose — a console browser may have no route to the website. */
:root{color-scheme:light dark;
--paper:#ffffff;--paper-2:#f7f7f8;--raised:#ffffff;--ink:#16161a;--ink-2:#3d3f47;--muted:#6b6e79;
--line:#e4e4e8;--line-2:#c9cad1;--accent:#4f46e5;--accent-weak:#eef0ff;--accent-line:#c7ccfb;
--ok:#1a7f4b;--ok-weak:#e8f5ee;--ok-line:#bfe0cd;--bad:#b3261e;--bad-weak:#fbeceb;--bad-line:#eec4c1;--r:12px}
@media (prefers-color-scheme:dark){:root{
--paper:#101114;--paper-2:#191a1f;--raised:#1c1e24;--ink:#e9eaee;--ink-2:#b7bac2;--muted:#8a8e99;
--line:#26282e;--line-2:#3b3e47;--accent:#818cf8;--accent-weak:#1c2040;--accent-line:#343a6b;
--ok:#4ec98a;--ok-weak:#12251b;--ok-line:#2c4d3a;--bad:#ff8079;--bad-weak:#2a1615;--bad-line:#57302c}}
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
.card{background:var(--raised);border:1px solid var(--line);border-radius:var(--r);padding:20px;margin-bottom:16px}
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
color:var(--ink);background:var(--paper);border:1px solid var(--line-2);border-radius:8px}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-weak)}
button{margin-top:18px;min-height:44px;padding:0.7rem 1.1rem;font:inherit;font-weight:600;
color:#fff;background:var(--accent);border:1px solid var(--accent);border-radius:8px;
cursor:pointer;width:100%}
button.ghost{background:transparent;border-color:var(--line-2);color:var(--ink);margin-top:10px}
/* One row, tinted by state, with a pill on the right — the same shape the
   status page uses, so the two read as one product. */
.row{display:flex;align-items:center;gap:0.75rem;padding:0.9rem 1rem;border-radius:var(--r);
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
`

func pageHead(title string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>` + title + ` · OpenPak</title>` +
		`<style>` + pageCSS + `</style></head><body><main>` +
		`<div class="brand"><img src="` + logoDataURI + `" alt=""> OpenPak</div>`
}

func (s *server) phoneDonePage(w http.ResponseWriter, username string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHead("Almost there")+`
<h1>Now approve it on the console</h1>
<div class="row ok"><span class="name">`+html.EscapeString(username)+`</span><span class="pill">Signed in</span></div>
<div class="card"><p style="margin:0">Your console is showing this account. Choose <strong>Approve</strong>
there to finish linking. You can close this page.</p></div></main></body></html>`)
}

// ---------- phone session ----------

func (s *server) phoneSession(r *http.Request) (phoneSession, bool) {
	c, err := r.Cookie(phoneCookie)
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

func (s *server) setPhoneCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: phoneCookie, Value: token, Path: "/link", HttpOnly: true,
		Secure: secureRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: int(phoneSessionTTL.Seconds()),
	})
}

func (s *server) clearPhoneCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: phoneCookie, Value: "", Path: "/link", HttpOnly: true,
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
func (s *server) phoneLoginPage(w http.ResponseWriter, pair, errMsg string) {
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
func (s *server) phoneConfirmPage(w http.ResponseWriter, username, pair, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHead("Link a console")+`
<h1>Link a console</h1>
<div class="row ok"><span class="name">`+html.EscapeString(username)+`</span><span class="pill">Signed in</span></div>
<div class="card">`+errBlock(errMsg)+`<form method="post" action="/link/code">
`+pairField(pair)+`<label for="code">Code shown on the console</label>
<input id="code" name="code" autocapitalize="characters" autocomplete="off" spellcheck="false"
       maxlength="8" pattern="[A-Za-z0-9]{6}" required autofocus>
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

// markSignedIn tells the console session that a phone has signed in, which is what makes the
// code appear on the television. Nothing is claimed yet: the code still has to be typed back.
func (s *server) markSignedIn(pair string, sess phoneSession) {
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
	log.Printf("[link] %s signed in on the phone; console may show its code", sess.Username)
}
