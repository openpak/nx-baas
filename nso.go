package main

// Nintendo Switch Online on the console's own terms: the HOME Menu button and its badge.
//
// The button is Lhub. qlaunch's launch sequence (StPrefetchEPrivacy, StPrefetchNaIdToken,
// StPsel, StLhub) ends in systemWeb, whose Lhub usage opens https://<env>.nso.nintendo.net/
// <path>?src_app_id=… with a referer and tags the session NsoApplet [firmware, systemWeb
// ShimUsageLhub::overwriteInternalArgs]. playerSelect's paywall opens the same host at
// launch?from=paywall&type=lex|basic&app_id=…&location=… [firmware, playerSelect
// StCheckPaywall]. Before this file every one of those requests hit the catch-all 404, so
// the button opened an error page.
//
// OpenPak sells nothing: every account has the base plan and the Expansion Pack (main.go's
// capi answers), so this page says that and closes. The Lhub start path is still a hardware
// question, so any path renders the page and the request is logged in full.
//
// The badge: bcat's NxLHub client POSTs fw-api.<env>.nso.nintendo.net/v1/events for the red
// dot's events [firmware, bcat]. Its body and reply are built and read without string
// literals, so neither is recovered. The reply here is an empty collection — "you have no
// events" is true — and the full request is logged so a console writes the specification.
// This is unconfirmed: if the console rejects it, the badge simply stays off.
//
// The voice-chat lobby is a third web page. systemWeb's Lobby usage opens
// https://web-<env>.znc.srv.nintendo.net/lobby/ with the calling title's app_id (and a
// "param" when the caller passed one), tags the session LobbyApplet, sets
// https://localhost/lobby/ as the callback URL and https://web-<env>.znc.srv.nintendo.net/
// as the only prefix allowed to reach it [firmware, systemWeb ShimUsageLobby::
// overwriteInternalArgs, 0x85c65c; the shop shim passes eshop:// through the same two
// setters]. So the page ends the applet by navigating to the callback URL. OpenPak has no
// voice chat, so the page says so and offers that way out.

import (
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *server) nso(w http.ResponseWriter, r *http.Request, body []byte) {
	host, p := hostOf(r), r.URL.Path
	if strings.HasPrefix(host, "fw-api.") {
		// Logged in full whatever the path: the body is the unrecovered half.
		dump(r, body, "!! NSO fw-api (events shape unrecovered; answering an empty collection)")
		if p == "/v1/events" {
			writeJSONValue(w, 200, []any{})
			return
		}
		writeJSON(w, 404, map[string]any{"status": 404, "title": "not found"})
		return
	}
	if p == "/_openpak/membership" {
		s.nsoMembership(w, r)
		return
	}
	if p == "/favicon.ico" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	log.Printf("[nso] lhub %s %s%s src_app_id=%q from=%q type=%q app_id=%q referer=%q ua=%q",
		r.Method, host, p, q.Get("src_app_id"), q.Get("from"), q.Get("type"), q.Get("app_id"),
		r.Referer(), r.UserAgent())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, lhubPage)
}

// zncLobby answers web-<env>.znc.srv.nintendo.net: the voice-chat lobby page under
// /lobby/, a recorded 404 for anything else on the host.
func (s *server) zncLobby(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	if p == "/_openpak/voice" {
		s.lobbyVoice(w, r)
		return
	}
	if p != "/lobby" && !strings.HasPrefix(p, "/lobby/") {
		dump(r, body, "!! UNHANDLED znc (only /lobby/ is known)")
		writeJSON(w, 404, map[string]any{"status": 404, "title": "not found"})
		return
	}
	q := r.URL.Query()
	log.Printf("[nso] znc lobby %s %s%s app_id=%q param=%q ua=%q -> OpenPak voice chat lobby",
		r.Method, hostOf(r), p, q.Get("app_id"), q.Get("param"), r.UserAgent())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, lobbyPage)
}

// lobbyVoice is the lobby page's room lookup: the console's account from its NA id token,
// then the website's answer for that account's game room, passed through unchanged
// (200 room, 404 in no room). 401 when the console can't be named; 503 when the website
// is not configured or unreachable.
func (s *server) lobbyVoice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, baasUser := s.shopPrincipal(r)
	account := ""
	if s.store == nil || baasUser == "" {
		// fall through to 401
	} else if u := s.store.User(baasUser); u != nil && s.banSrc() != nil {
		account = s.banSrc().accountFor(u.PID)
	}
	if account == "" {
		writeJSON(w, 401, map[string]any{"status": 401, "title": "who is this console?"})
		return
	}
	base, key := strings.TrimRight(getenv("WEBSITE_INTERNAL_URL", ""), "/"), getenv("WEBSITE_INTERNAL_KEY", "")
	if base == "" || key == "" {
		writeJSON(w, 503, map[string]any{"status": 503, "title": "voice chat is not configured"})
		return
	}
	u := base + "/internal/voice/room?" + url.Values{"account_id": {account}, "app_id": {r.URL.Query().Get("app_id")}}.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u, nil)
	if err != nil {
		writeJSON(w, 503, map[string]any{"status": 503, "title": "voice chat unavailable"})
		return
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		log.Printf("[nso] lobby voice: website unreachable: %v", err)
		writeJSON(w, 503, map[string]any{"status": 503, "title": "voice chat unavailable"})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}

// nsoMembership tells the page whose membership it is showing. The status itself is the
// same for everyone; the name is what makes the page answer "am I covered?".
func (s *server) nsoMembership(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"membership": "active", "plans": []string{"default", "ex"}}
	if account, baasUser := s.shopPrincipal(r); account != "" {
		out["signed_in"] = true
		if s.store != nil && baasUser != "" {
			if u := s.store.User(baasUser); u != nil {
				out["nickname"] = u.Nickname
			}
		}
	} else {
		out["signed_in"] = false
	}
	writeJSON(w, 200, out)
}

// writeJSONValue is writeJSON for a reply whose top level is not an object.
func writeJSONValue(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprint(w, mustJSON(v))
}

// lhubPage is the controller-first landing page, in the shop's visual language. Closing
// ends the applet through the bridge when the console offers a way to, and falls back to
// the browser's own close and back.
var lhubPage = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=device-width,initial-scale=1"><title>Nintendo Switch Online</title>` +
	`<style>` + pageCSS + shopCSS + `</style></head>` +
	`<body class="console"><main><div class="brand"><img src="` + logoDataURI + `" alt=""> OpenPak` +
	`<button class="small close" id="lhclose" type="button">Close</button></div>` +
	`<h1>Nintendo Switch Online — included with OpenPak</h1>` +
	`<div class="row ok" id="status"><span class="name">Membership: active</span><span class="pill">included</span></div>` +
	`<p id="paywall" class="note" hidden></p>` +
	`<p>Online play, cloud saves and the Expansion Pack are part of every OpenPak account. There is nothing to buy and nothing to renew.</p>` +
	`<button class="small" id="done" type="button">Back to the HOME Menu</button>` +
	`</main><script>` + shopBridgeJS + lhubJS + `</script></body></html>`

const lhubJS = `
(function(){
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function param(k){var m=location.search.match(new RegExp('[?&]'+k+'=([^&]*)'));return m?decodeURIComponent(m[1]):'';}
function leave(){
 if(nxCall('endApplet',[],null)){return;}
 try{window.close();}catch(e){}
 try{history.back();}catch(e){}
}
document.getElementById('lhclose').addEventListener('click',leave);
document.getElementById('done').addEventListener('click',leave);
document.getElementById('done').focus();
if(param('from')==='paywall'){
 var p=document.getElementById('paywall');p.hidden=false;
 p.textContent=(param('type')==='lex'?'This game uses the Expansion Pack. ':'This game uses Nintendo Switch Online. ')+
  'Your OpenPak account already includes it, so you can go back and start the game.';
}
function show(t){
 var h={};if(t){h['Authorization']='Bearer '+t;}
 fetch('/_openpak/membership',{headers:h}).then(function(r){return r.json();}).then(function(m){
  var who=m.nickname?esc(m.nickname)+': ':'';
  document.getElementById('status').innerHTML='<span class="name">'+who+'membership active (Nintendo Switch Online + Expansion Pack)</span><span class="pill">included</span>';
 }).catch(function(){});
}
var asked=false;
function take(r){var t=nxToken(r&&r.value);if(t&&!asked){asked=true;show(t);}}
if(!nxCall('requestNaIdToken',[],take)){if(!nxCall('ensureNaIdToken',[],take)){nxCall('loadCachedNaIdToken',[],take);}}
setTimeout(function(){if(!asked){asked=true;show(null);}},4000);
})();
`

// lobbyPage is the voice-chat lobby (assets/lobby.html): it sends the player to the
// OpenPak app's voice chat and shows their room from /_openpak/voice. Leaving navigates
// to the Lobby shim's callback URL, https://localhost/lobby/; endApplet and window.close are fallbacks.
//
//go:embed assets/lobby.html
var lobbyPage string
