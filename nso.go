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
	if p == "/_openpak/diag" && r.Method == http.MethodPost {
		// What the page saw (the keys L and R send, gamepad buttons): logged, nothing kept.
		log.Printf("[nso] page diag: %.400s", body)
		w.WriteHeader(http.StatusNoContent)
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

// lhubPage is the Switch Online landing page, laid out like Nintendo's: a tab bar of pages
// that L and R move between, each page one of the things an OpenPak account includes, and
// a footer with the button hints. OpenPak's purple and blue. Closing ends the applet.
var lhubPage = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=1280,initial-scale=1"><title>Nintendo Switch Online</title>` +
	`<style>` + lhubCSS + `</style></head><body>` +
	`<header><div class="logo"><img src="` + logoDataURI + `" alt="">OpenPak Online</div>` +
	`<div id="status" class="status">Membership active · included</div></header>` +
	`<div class="tabs"><span class="sh">L</span><div id="tabbar"></div><span class="sh">R</span></div>` +
	`<p id="paywall" class="paywall" hidden></p>` +
	`<main id="page"></main>` +
	`<script>` + shopBridgeJS + lhubJS + `</script></body></html>`

const lhubCSS = `
:root{--p1:#6d4aff;--p2:#3b82f6;--bg:#ececf1;--card:#fff;--ink:#1d1b26;--muted:#6b6880;--line:#dcdae6}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);overflow:hidden;
font:22px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
button{font:inherit;color:inherit;cursor:pointer}
header{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 34px;color:#fff;
background:linear-gradient(120deg,var(--p1),var(--p2))}
.logo{display:flex;align-items:center;gap:12px;font-weight:700;font-size:26px}
.logo img{width:32px;height:32px;filter:brightness(0) invert(1)}
.status{font-size:18px;background:rgba(255,255,255,.18);padding:6px 16px;border-radius:20px}
.tabs{display:flex;align-items:center;gap:12px;padding:12px 24px;background:#f7f7fa;border-bottom:1px solid var(--line)}
#tabbar{display:flex;gap:6px;flex:1;justify-content:center}
.tab{background:none;border:3px solid transparent;border-radius:24px;padding:8px 18px;font-size:19px;color:var(--muted)}
.tab.on{background:#fff;color:var(--ink);font-weight:700;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.sh{display:inline-flex;align-items:center;justify-content:center;min-width:44px;height:30px;border-radius:8px;background:#1d1b26;color:#fff;font-size:16px;font-weight:700}
.paywall{margin:14px 34px 0;padding:12px 18px;border-radius:12px;background:#e9f7ef;color:#11643a;font-size:19px}
main{position:fixed;top:128px;bottom:0;left:0;right:0;overflow-y:auto;padding:24px 34px}
h1{font-size:34px;margin:0 0 6px}
.lead{color:var(--muted);margin:0 0 22px;font-size:21px}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.cards.two{grid-template-columns:1fr 1fr}
.c{background:var(--card);border-radius:16px;padding:22px;border:3px solid transparent;text-align:left;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.c .ic{width:52px;height:52px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:28px;color:#fff;
background:linear-gradient(120deg,var(--p1),var(--p2));margin-bottom:12px}
.c h2{font-size:23px;margin:0 0 6px}
.c p{margin:0;color:#4a475c;font-size:18px}
.qa{background:var(--card);border-radius:14px;padding:18px 22px;margin-bottom:12px;border:3px solid transparent;width:100%;text-align:left}
.qa b{display:block;font-size:21px;margin-bottom:4px}
.qa span{color:#4a475c;font-size:18px}
.url{font-weight:700;color:var(--p1)}
.tab:focus,.c:focus,.qa:focus{outline:none;border-color:var(--p1);box-shadow:0 0 0 3px #fff,0 0 0 6px rgba(59,130,246,.55)}
`

const lhubJS = `
(function(){
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function param(k){var m=location.search.match(new RegExp('[?&]'+k+'=([^&]*)'));return m?decodeURIComponent(m[1]):'';}
function $(id){return document.getElementById(id);}
function card(ic,h,p){return '<div class="c" tabindex="0"><div class="ic">'+ic+'</div><h2>'+h+'</h2><p>'+p+'</p></div>';}
function qa(q,a){return '<div class="qa" tabindex="0"><b>'+q+'</b><span>'+a+'</span></div>';}
var PAGES=[
 {t:'Home',h:'<h1>Everything is included</h1><p class="lead">Your OpenPak account is your membership. There is nothing to buy and nothing to renew.</p><div class="cards">'+
  card('🌐','Online play','Play supported games online with friends and players around the world.')+
  card('☁','Save Data Cloud','Your saves are backed up and follow you to another console.')+
  card('📱','Smartphone app','Friends, messages and voice chat on your phone.')+
  card('🎮','Across consoles','Switch, Wii U, 3DS, Wii and DS share one account and one friend list.')+
  card('📰','News','OpenPak news and channels in the News tab.')+
  card('★','Expansion Pack','Games that ask for the Expansion Pack see it as active.')+'</div>'},
 {t:'Online Play',h:'<h1>Online play</h1><p class="lead">OpenPak runs its own servers for the games it supports.</p><div class="cards two">'+
  card('🌐','Matchmaking and rooms','Join random matches, make private rooms and invite friends, as the game itself offers.')+
  card('🏆','Rankings and events','Leaderboards and events work where the game has them and OpenPak serves them.')+
  card('✓','Supported games','The list of games and what works in each is on <span class="url">openpak.org/titles</span>.')+
  card('🛡','Fair play','Reports and bans apply across the whole network, on every console.')+'</div>'},
 {t:'Save Data Cloud',h:'<h1>Save Data Cloud</h1><p class="lead">Keep your progress safe on the OpenPak servers.</p><div class="cards two">'+
  card('☁','Automatic backup','Saves of supported games are uploaded to your OpenPak account.')+
  card('⇄','Restore anywhere','Download a save to another console signed in to the same account.')+
  card('📱','See them on your phone','The OpenPak app and openpak.org list your saves and when they were backed up.')+
  card('🔒','Only yours','Saves are tied to your account and are never shared.')+'</div>'},
 {t:'Smartphone App',h:'<h1>The OpenPak app</h1><p class="lead">Get it from <span class="url">openpak.org/app</span> and sign in with your OpenPak account.</p><div class="cards">'+
  card('🎙','Voice chat','Talk with the players in your game room, or with friends by room code.')+
  card('👥','Friends','Friend requests, invitations and who is playing what, on every console.')+
  card('💬','Messages','Chat with friends from your phone.')+
  card('☁','Your saves','See your cloud saves and when they were made.')+
  card('🆘','Help','Open a help ticket and read the replies.')+
  card('🔐','Your account','Sign-in, two-step verification and devices.')+'</div>'},
 {t:'Across Consoles',h:'<h1>One network, every console</h1><p class="lead">OpenPak connects Nintendo consoles old and new under one account.</p><div class="cards">'+
  card('🎮','Nintendo Switch','Online play, friends, eShop, News and Save Data Cloud.')+
  card('🎮','Wii U and 3DS','Online play, friends, Miiverse-style posts and chat.')+
  card('🎮','Wii and DS','Nintendo Wi-Fi Connection games online again.')+
  card('👥','One friend list','Friends from every console appear together, on the console and in the app.')+
  card('💬','Talk across consoles','Messages sent on one console or the app arrive on the others.')+
  card('🖥','Emulators','Supported emulators connect to the same network as real consoles.')+'</div>'},
 {t:'FAQ',h:'<h1>Questions</h1>'+
  qa('Does OpenPak cost anything?','No. Everything here is included with a free OpenPak account.')+
  qa('Is OpenPak made by Nintendo?','No. OpenPak is an independent network and is not affiliated with Nintendo.')+
  qa('Which games work online?','The supported list, with what works in each game, is on openpak.org/titles.')+
  qa('Can I use my Nintendo Account?','OpenPak uses its own accounts. Link your console to your OpenPak account to play.')+
  qa('Where do I report a player?','From the game or the console where it offers it, or on openpak.org. Reports reach the moderators for every console.')},
 {t:'Help & Guides',h:'<h1>Help and guides</h1><p class="lead">Step-by-step guides and support live on openpak.org.</p><div class="cards two">'+
  card('📖','Guides','Setting up a console, linking an account and getting online: <span class="url">openpak.org/help</span>.')+
  card('🆘','Contact support','Open a ticket at <span class="url">openpak.org/help</span> or in the app. Replies show in both.')+
  card('📊','Service status','Is something down? <span class="url">status.openpak.org</span>.')+
  card('ℹ','More information','About OpenPak, its rules and privacy: <span class="url">openpak.org</span>.')+'</div>'}
];
var cur=0;
function report(o){try{fetch('/_openpak/diag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});}catch(e){}}
function tabs(){
 var h='';for(var i=0;i<PAGES.length;i++){h+='<button class="tab'+(i===cur?' on':'')+'" data-i="'+i+'">'+PAGES[i].t+'</button>';}
 $('tabbar').innerHTML=h;
 var b=document.querySelectorAll('.tab');
 for(var j=0;j<b.length;j++){b[j].addEventListener('click',function(){go(+this.getAttribute('data-i'));});}
}
function go(i){
 cur=(i+PAGES.length)%PAGES.length; tabs(); $('page').innerHTML=PAGES[cur].h; $('page').scrollTop=0;
 var f=$('page').querySelector('[tabindex]'); if(f){f.focus();}
}
function leave(){
 if(nxCall('endApplet',[],null)){return;}
 try{window.close();}catch(e){}
 try{history.back();}catch(e){}
}
// L and R change page. Which keys the Switch browser sends for them is not known, so the
// likely ones are all taken, the gamepad buttons (standard mapping 4 and 5) are polled,
// and every key the page sees is reported once so the first console run names them.
var seen={};
document.addEventListener('keydown',function(e){
 var k=e.key||'', c=e.keyCode;
 if(!seen[k+c]){seen[k+c]=1;report({event:'key',key:k,code:e.code||'',keyCode:c});}
 if(k==='PageUp'||k==='q'||k==='Q'||k==='L'||c===33){e.preventDefault();go(cur-1);}
 else if(k==='PageDown'||k==='e'||k==='E'||k==='R'||c===34){e.preventDefault();go(cur+1);}
 else if(k==='Escape'||k==='Backspace'||c===27||c===8){e.preventDefault();leave();}
});
var held={};
function poll(){
 var pads=navigator.getGamepads?navigator.getGamepads():[];
 for(var i=0;i<pads.length;i++){var p=pads[i];if(!p){continue;}
  for(var b=4;b<=5;b++){var d=p.buttons[b]&&p.buttons[b].pressed;
   if(d&&!held[b]){go(b===4?cur-1:cur+1);report({event:'pad',button:b,id:p.id});}
   held[b]=d;}}
 window.requestAnimationFrame(poll);
}
if(window.requestAnimationFrame){window.requestAnimationFrame(poll);}
if(param('from')==='paywall'){
 var pw=$('paywall');pw.hidden=false;
 pw.textContent=(param('type')==='lex'?'This game uses the Expansion Pack. ':'This game uses Nintendo Switch Online. ')+
  'Your OpenPak account already includes it, so you can go back and start the game.';
}
function show(t){
 var h={};if(t){h['Authorization']='Bearer '+t;}
 fetch('/_openpak/membership',{headers:h}).then(function(r){return r.json();}).then(function(m){
  $('status').textContent=(m.nickname?m.nickname+' · ':'')+'Membership active · included';
 }).catch(function(){});
}
var asked=false;
function take(r){var t=nxToken(r&&r.value);if(t&&!asked){asked=true;show(t);}}
if(!nxCall('requestNaIdToken',[],take)){if(!nxCall('ensureNaIdToken',[],take)){nxCall('loadCachedNaIdToken',[],take);}}
go(0);
})();
`

// lobbyPage is the voice-chat lobby (assets/lobby.html): it sends the player to the
// OpenPak app's voice chat and shows their room from /_openpak/voice. Leaving navigates
// to the Lobby shim's callback URL, https://localhost/lobby/; endApplet and window.close are fallbacks.
//
//go:embed assets/lobby.html
var lobbyPage string
