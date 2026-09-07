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
	linkWaiting  linkState = "waiting"  // shown on the console, nobody has claimed it
	linkClaimed  linkState = "claimed"  // a phone signed in and entered the code
	linkApproved linkState = "approved" // the person at the console pressed Approve
	linkDenied   linkState = "denied"
)

type pendingLink struct {
	State    linkState
	PID      uint64
	Username string
	NaID     string
	Query    url.Values // the console's original authorize parameters
	Created  time.Time
}

type linkStore struct {
	mu sync.Mutex
	by map[string]*pendingLink
}

func newLinkStore() *linkStore { return &linkStore{by: map[string]*pendingLink{}} }

func (l *linkStore) new(q url.Values) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	code := randCode()
	l.by[code] = &pendingLink{State: linkWaiting, Query: q, Created: time.Now()}
	return code
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
		s.phonePage(w, code, "")
		return true

	case r.URL.Path == "/link" && r.Method == "POST":
		p := s.links.get(form.Get("code"))
		if p == nil {
			s.phonePage(w, form.Get("code"), "That code has expired. Start again on the console.")
			return true
		}
		pid, username, err := s.acct.LoginPID(form.Get("email"), form.Get("password"))
		if err != nil {
			s.phonePage(w, form.Get("code"), "Wrong e-mail or password.")
			return true
		}
		id, err := s.acct.Identity(pid)
		if err != nil {
			s.phonePage(w, form.Get("code"), "Account lookup failed.")
			return true
		}
		s.links.update(form.Get("code"), func(p *pendingLink) {
			p.State, p.PID, p.Username, p.NaID = linkClaimed, pid, username, id.NaID
		})
		log.Printf("[link] code %s claimed by %s (pid %d)", strings.ToUpper(form.Get("code")), username, pid)
		s.phoneDonePage(w, username)
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
:root{--paper:#101114;--raised:#1c1e24;--line:#26282e;--ink:#e9eaee;--muted:#8a8e99;
--accent:#818cf8;--accent-weak:#1c2040;--accent-line:#343a6b;--ok:#4ec98a;--r:12px}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;
display:flex;justify-content:center;padding:32px 20px}
main{width:100%;max-width:760px}
h1{font-size:1.6rem;letter-spacing:-0.02em;margin:0 0 6px}
p{color:var(--muted);margin:0 0 20px}
.card{background:var(--raised);border:1px solid var(--line);border-radius:var(--r);padding:24px;margin-bottom:16px}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;margin-bottom:22px}
.brand img{width:28px;height:28px}
.code{font:600 2.2rem/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:0.18em;
color:#fff;background:var(--accent-weak);border:1px solid var(--accent-line);border-radius:10px;
padding:16px 20px;display:inline-block}
.qr{background:#fff;padding:12px;border-radius:10px;display:inline-block;line-height:0}
.qr img{width:220px;height:220px}
.split{display:flex;gap:28px;flex-wrap:wrap;align-items:center}
label{display:block;font-size:0.88rem;color:var(--muted);margin:14px 0 6px}
input{width:100%;padding:12px 14px;font-size:1rem;color:var(--ink);background:var(--paper);
border:1px solid var(--line);border-radius:8px}
button{margin-top:18px;padding:13px 18px;font-size:1rem;font-weight:600;color:#fff;
background:var(--accent);border:0;border-radius:8px;cursor:pointer;width:100%}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--ink);margin-top:10px}
.err{color:#ff8079;margin:0 0 12px}
.ok{color:var(--ok)}
.steps{margin:0;padding-left:1.2em;color:var(--muted)}
.steps li{margin:6px 0}
hr{border:0;border-top:1px solid var(--line);margin:26px 0}
details summary{color:var(--muted);cursor:pointer}
`

func pageHead(title string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>` + title + ` · OpenPak</title>` +
		`<style>` + pageCSS + `</style></head><body><main>` +
		`<div class="brand"><img src="` + logoDataURI + `" alt=""> OpenPak</div>`
}

// phonePage is what the QR opens: sign in, confirm the code from the TV.
func (s *server) phonePage(w http.ResponseWriter, code, errMsg string) {
	var e string
	if errMsg != "" {
		e = `<p class="err">` + html.EscapeString(errMsg) + `</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHead("Link a console")+`
<h1>Link a console</h1>
<p>Sign in, check the code matches the one on your console, and this device will be linked.</p>
<div class="card">`+e+`<form method="post" action="/link">
<label for="code">Code shown on the console</label>
<input id="code" name="code" value="`+html.EscapeString(strings.ToUpper(code))+`" autocapitalize="characters" autocomplete="off" required>
<label for="email">E-mail</label>
<input id="email" name="email" type="email" autocomplete="username" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form></div></main></body></html>`)
}

func (s *server) phoneDonePage(w http.ResponseWriter, username string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, pageHead("Almost there")+`
<h1>Now approve it on the console</h1>
<p>Signed in as <strong class="ok">`+html.EscapeString(username)+`</strong>.</p>
<div class="card"><p style="margin:0">Your console is showing this account. Choose <strong>Approve</strong>
there to finish linking. You can close this page.</p></div></main></body></html>`)
}
