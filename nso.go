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

// lhubPage is the Switch Online landing page, laid out like Nintendo's: an all-blue page
// with the OpenPak Online mark on the left, the page's content on the right, dots between
// L and R, and one wide button at the bottom. L and R move between the pages. The console
// draws the button hints itself (footerJS keeps them to Confirm and Back).
var lhubPage = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=1280,initial-scale=1,maximum-scale=1,user-scalable=no"><title>OpenPak Online</title>` +
	`<style>` + lhubCSS + `</style></head><body>` +
	`<button class="side l" id="prev" tabindex="-1">‹</button><button class="side r" id="next" tabindex="-1">›</button>` +
	`<div class="wrap"><div class="left"><p class="tag" id="tag">Everything is included</p>` +
	`<div class="mark"><img src="` + logoDataURI + `" alt=""><span>ONLINE</span></div>` +
	`<p class="sub">OpenPak Online</p><button class="guide" id="guide">Complete Guide</button>` +
	`<p class="who" id="status">Membership active · included</p></div>` +
	`<div class="right" id="page"></div></div>` +
	`<div class="dots"><span class="lr">‹ <b>L</b></span><span id="dots"></span><span class="lr"><b>R</b> ›</span></div>` +
	`<button class="cta" id="cta">Membership active — nothing to buy</button>` +
	`<script>` + shopBridgeJS + footerJS + lhubJS + `</script></body></html>`

const lhubCSS = `
*{box-sizing:border-box}
html,body{margin:0;height:100%;overflow:hidden;color:#fff;
background:radial-gradient(ellipse at 30% 40%,#3b6cff 0%,#2448e0 45%,#1a33b8 100%);
font:22px/1.35 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
button{font:inherit;color:inherit;cursor:pointer}
.wrap{display:flex;height:540px;padding:40px 110px 0}
.left{width:400px;display:flex;flex-direction:column;justify-content:center}
.tag{margin:0 0 6px;font-size:22px;opacity:.9}
.mark{display:flex;align-items:center;gap:14px}
.mark img{width:70px;height:70px;filter:brightness(0) invert(1)}
.mark span{font-size:72px;font-weight:800;letter-spacing:.02em;line-height:1}
.sub{margin:6px 0 22px;font-weight:700;letter-spacing:.08em;font-size:20px}
.guide{align-self:flex-start;background:#fff;color:#1f3fbf;border:4px solid transparent;border-radius:30px;padding:10px 34px;font-size:24px}
.who{margin:18px 0 0;font-size:18px;opacity:.85}
.right{flex:1;display:flex;flex-direction:column;justify-content:center;padding-left:30px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:26px 20px}
.it{background:none;border:4px solid transparent;border-radius:18px;padding:14px 8px;text-align:center}
.it .ic{font-size:64px;line-height:1.1;display:block;margin-bottom:8px}
.it .t{font-size:21px}
h1{font-size:40px;margin:0 0 14px}
.lead{margin:0 0 18px;font-size:21px;opacity:.9}
.rows{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.row{background:rgba(255,255,255,.12);border:4px solid transparent;border-radius:16px;padding:14px 18px;text-align:left}
.row b{display:block;font-size:21px;margin-bottom:2px}
.row span{font-size:17px;opacity:.9}
.rows.one{grid-template-columns:1fr}
.url{font-weight:700;text-decoration:underline}
.dots{position:absolute;left:0;right:0;top:560px;display:flex;justify-content:center;align-items:center;gap:22px;font-size:20px}
.dots b{display:inline-flex;align-items:center;justify-content:center;width:28px;height:24px;border:2px solid #fff;border-radius:5px;font-size:15px}
#dots i{display:inline-block;width:10px;height:10px;margin:0 7px;border-radius:50%;background:rgba(255,255,255,.45)}
#dots i.on{background:#fff;transform:scale(1.4)}
.cta{position:absolute;left:230px;right:230px;top:610px;height:70px;background:#fff;color:#1f3fbf;border:4px solid transparent;
border-radius:36px;font-size:26px;font-weight:700}
.side{position:absolute;top:300px;width:64px;height:64px;border-radius:50%;border:0;background:rgba(0,0,0,.18);font-size:40px;line-height:1}
.side.l{left:24px}.side.r{right:24px}
.it:focus,.row:focus,.guide:focus,.cta:focus{outline:none;border-color:#7ff0ff;box-shadow:0 0 12px rgba(127,240,255,.8)}
`

const lhubJS = `
(function(){
function param(k){var m=location.search.match(new RegExp('[?&]'+k+'=([^&]*)'));return m?decodeURIComponent(m[1]):'';}
function $(id){return document.getElementById(id);}
function it(ic,t,go){return '<button class="it" data-go="'+go+'"><span class="ic">'+ic+'</span><span class="t">'+t+'</span></button>';}
function row(h,p){return '<div class="row" tabindex="0"><b>'+h+'</b><span>'+p+'</span></div>';}
var PAGES=[
 {tag:'Everything is included',h:'<div class="grid">'+
  it('🌐','Online Play',1)+it('☁️','Save Data Cloud',2)+it('📱','Smartphone App',3)+
  it('🎮','Across Consoles',4)+it('❓','Questions',5)+it('📖','Help &amp; Guides',6)+'</div>'},
 {tag:'Play together',h:'<h1>🌐 Online Play</h1><p class="lead">OpenPak runs its own servers for the games it supports.</p><div class="rows">'+
  row('Matchmaking and rooms','Random matches, private rooms and invites, as the game offers them.')+
  row('Rankings and events','Leaderboards and events where the game has them.')+
  row('Supported games','The list and what works in each: <span class="url">openpak.org/titles</span>')+
  row('Fair play','Reports and bans apply across the whole network.')+'</div>'},
 {tag:'Never lose progress',h:'<h1>☁️ Save Data Cloud</h1><p class="lead">Your saves, kept safe on the OpenPak servers.</p><div class="rows">'+
  row('Automatic backup','Saves of supported games go to your OpenPak account.')+
  row('Restore anywhere','Download a save to another console on the same account.')+
  row('See them on your phone','The OpenPak app and openpak.org list your saves.')+
  row('Only yours','Saves belong to your account and are never shared.')+'</div>'},
 {tag:'OpenPak in your pocket',h:'<h1>📱 Smartphone App</h1><p class="lead">Get it at <span class="url">openpak.org/app</span> and sign in with your OpenPak account.</p><div class="rows">'+
  row('Voice chat','Talk with the players in your game room, or friends by room code.')+
  row('Friends','Requests, invitations and who is playing what, on every console.')+
  row('Messages','Chat with friends from your phone.')+
  row('Help','Open a ticket and read the replies.')+'</div>'},
 {tag:'One network',h:'<h1>🎮 Across Consoles</h1><p class="lead">One account and one friend list for Nintendo consoles old and new.</p><div class="rows">'+
  row('Nintendo Switch','Online play, friends, eShop, News and Save Data Cloud.')+
  row('Wii U and 3DS','Online play, friends, posts and chat.')+
  row('Wii and DS','Nintendo Wi-Fi Connection games online again.')+
  row('Emulators','Supported emulators join the same network as consoles.')+'</div>'},
 {tag:'Good to know',h:'<h1>❓ Questions</h1><div class="rows one">'+
  row('Does it cost anything?','No. Everything is included with a free OpenPak account.')+
  row('Is OpenPak made by Nintendo?','No. OpenPak is independent and not affiliated with Nintendo.')+
  row('Which games work online?','See openpak.org/titles for the list and what works in each.')+
  row('Can I use my Nintendo Account?','OpenPak uses its own accounts. Link your console to yours to play.')+'</div>'},
 {tag:'We are here to help',h:'<h1>📖 Help &amp; Guides</h1><p class="lead">Guides and support live on openpak.org.</p><div class="rows">'+
  row('Guides','Setting up a console and getting online: <span class="url">openpak.org/help</span>')+
  row('Contact support','Open a ticket at openpak.org/help or in the app.')+
  row('Service status','Is something down? <span class="url">status.openpak.org</span>')+
  row('About OpenPak','Rules and privacy: <span class="url">openpak.org</span>')+'</div>'}
];
var cur=0;
function report(o){try{fetch('/_openpak/diag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});}catch(e){}}
var last=0;
// One press can arrive twice (the footer's L/R and a key or gamepad event): the second is dropped.
function flip(d){var now=Date.now();if(now-last<250){return;}last=now;go(cur+d);}
function go(i){
 cur=(i+PAGES.length)%PAGES.length;
 $('page').innerHTML=PAGES[cur].h; $('tag').textContent=PAGES[cur].tag;
 var d='';for(var k=0;k<PAGES.length;k++){d+='<i class="'+(k===cur?'on':'')+'"></i>';} $('dots').innerHTML=d;
 var b=$('page').querySelectorAll('.it');
 for(var j=0;j<b.length;j++){b[j].addEventListener('click',function(){go(+this.getAttribute('data-go'));});}
 var f=$('page').querySelector('.it,.row'); if(f){f.focus();}
}
function leave(){
 if(nxCall('endApplet',[],null)){return;}
 try{window.close();}catch(e){}
 try{history.back();}catch(e){}
}
$('prev').addEventListener('click',function(){go(cur-1);});
$('next').addEventListener('click',function(){go(cur+1);});
$('guide').addEventListener('click',function(){go(6);});
$('cta').addEventListener('click',leave);
// L and R through the console footer when it offers them; keys and gamepad as a fallback,
// each key reported once so a console run names what arrives.
nxFooterSetup({B:function(){if(cur){go(0);}else{leave();}}, L:function(){flip(-1);}, R:function(){flip(1);}}, report);
var seen={};
document.addEventListener('keydown',function(e){
 var k=e.key||'', c=e.keyCode;
 if(!seen[k+c]){seen[k+c]=1;report({event:'key',key:k,code:e.code||'',keyCode:c});}
 if(k==='PageUp'||k==='q'||k==='Q'||c===33){e.preventDefault();flip(-1);}
 else if(k==='PageDown'||k==='e'||k==='E'||c===34){e.preventDefault();flip(1);}
 else if(k==='Escape'||k==='Backspace'||c===27||c===8){e.preventDefault();if(cur){go(0);}else{leave();}}
});
var held={};
function poll(){
 var pads=navigator.getGamepads?navigator.getGamepads():[];
 for(var i=0;i<pads.length;i++){var p=pads[i];if(!p){continue;}
  for(var b=4;b<=5;b++){var d=p.buttons[b]&&p.buttons[b].pressed;
   if(d&&!held[b]){flip(b===4?-1:1);report({event:'pad',button:b,id:p.id});}
   held[b]=d;}}
 window.requestAnimationFrame(poll);
}
if(window.requestAnimationFrame){window.requestAnimationFrame(poll);}
if(param('from')==='paywall'){
 $('cta').textContent=(param('type')==='lex'?'Expansion Pack included':'Nintendo Switch Online included')+' — back to the game';
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

// footerJS drives the console's own button bar through window.nx.footer (the web applet's
// footer API: setAssign(button, label, callback) and unsetAssign(button)). Only Confirm and
// Back are shown, as on Nintendo's pages: the browser's End (X) and zoom (R/L) assignments are
// removed, and L/R are given to the page when it wants them. Nothing here is confirmed on
// 22.5.0 hardware, so what the footer object offers and every call's outcome are reported.
const footerJS = `
function nxFooterSetup(handlers,rep){
 var f=window.nx&&window.nx.footer;
 var out={event:'footer',present:!!f,keys:[],calls:{}};
 if(!f){rep(out);return;}
 try{for(var k in f){out.keys.push(k);}}catch(e){}
 function call(name,args){try{var r=f[name].apply(f,args);out.calls[name+'('+args[0]+')']=String(r);}catch(e){out.calls[name+'('+args[0]+')']='!'+String(e);}}
 var drop=['X','Y','L','R','ZL','ZR','Plus','Minus'];
 for(var i=0;i<drop.length;i++){if(!handlers[drop[i]]&&typeof(f.unsetAssign)==='function'){call('unsetAssign',[drop[i]]);}}
 if(typeof(f.setAssign)==='function'){
  call('setAssign',['A','Confirm',function(){var e=document.activeElement;if(e&&e.click){e.click();}}]);
  for(var b in handlers){call('setAssign',[b,b==='B'?'Back':'',handlers[b]]);}
 }
 rep(out);
}
`

// lobbyPage is the voice-chat lobby (assets/lobby.html): it sends the player to the
// OpenPak app's voice chat and shows their room from /_openpak/voice. Leaving navigates
// to the Lobby shim's callback URL, https://localhost/lobby/; endApplet and window.close are fallbacks.
//
//go:embed assets/lobby.html
var lobbyPage string
