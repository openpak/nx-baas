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
	"embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"nx-baas/redact"
	"path"
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
	if strings.HasPrefix(p, "/_openpak/icon/") {
		// The feature icons of the Switch Online pages (assets/nso).
		b, err := nsoIcons.ReadFile("assets/nso/" + path.Base(p))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(b)
		return
	}
	if p == "/_openpak/membership" {
		s.nsoMembership(w, r)
		return
	}
	if p == "/_openpak/diag" && r.Method == http.MethodPost {
		// What the page saw (the keys L and R send, gamepad buttons): logged, nothing kept.
		log.Printf("[nso] page diag: %d bytes", len(body))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if p == "/favicon.ico" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	log.Printf("[nso] lhub %s %s%s src_app_id=%q from=%q type=%q app_id=%q referer=%q ua=%q",
		r.Method, host, redact.Path(p), redact.IDs(q.Get("src_app_id")), redact.IDs(q.Get("from")), redact.IDs(q.Get("type")), redact.IDs(q.Get("app_id")),
		redact.Link(r.Referer()), redact.IDs(r.UserAgent()))
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
		r.Method, hostOf(r), redact.Path(p), redact.IDs(q.Get("app_id")), redact.IDs(q.Get("param")), redact.IDs(r.UserAgent()))
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
		log.Printf("[nso] lobby voice: website unreachable: %v", redact.Err(err))
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

//go:embed assets/nso/*.png
var nsoIcons embed.FS

// lhubPage is the Switch Online landing page, laid out like Nintendo's: an all-blue page
// with the OpenPak Online mark on the left, the page's content on the right, dots between
// L and R, and one wide button at the bottom. L and R move between the pages. The console
// draws the button hints itself (footerJS keeps them to Confirm and Back).
var lhubPage = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=1280,initial-scale=1,maximum-scale=1,user-scalable=no"><title>OpenPak Online</title>` +
	`<style>` + lhubCSS + `</style></head><body>` +
	`<button class="side l" id="prev" tabindex="-1">‹</button><button class="side r" id="next" tabindex="-1">›</button>` +
	`<div class="wrap"><div class="left" id="left"><p class="tag" id="tag">Everything is included</p>` +
	`<div class="mark"><img src="` + logoDataURI + `" alt=""><span>ONLINE</span></div>` +
	`<p class="sub">OpenPak Online</p><button class="guide" id="guide">Complete Guide</button>` +
	`<p class="who" id="status">Membership active · included</p></div>` +
	`<div class="right" id="page"></div></div>` +
	`<div class="dots"><span class="lr">‹ <b>L</b></span><span id="dots"></span><span class="lr"><b>R</b> ›</span></div>` +
	`<button class="cta" id="cta">Membership active — nothing to buy</button>` +
	`<script>` + shopBridgeJS + footerJS + lhubJS + `</script></body></html>`

const lhubCSS = `
/* The website's design tokens (website/web/src/input.css, 2026-10 "console HOME menu" redesign) on
   the lhub page: cool grey shell, white tiles, slate ink, indigo for primary, a cyan selection
   cursor on hover, focus and the selected page dot. Flat colours, no gradients or glow; light and
   dark follow the reader's system setting. Units are vh: the console leaves ~650 of 720. */
:root{color-scheme:light dark;--paper:#e9ecf0;--paper-2:#f2f4f7;--raised:#ffffff;--sunk:#dde1e7;--ink:#20262f;--ink-2:#48505c;--muted:#6b7380;--faint:#9aa1ab;
--line:#d9dde3;--line-2:#c3c9d1;--cursor:#0094be;--cursor-2:#39c9ea;
--accent:#4f46e5;--accent-2:#6366f1;--accent-weak:#eceeff;--accent-line:#c5cafb;--on-accent:#fff;
--ok:#138a45;--ok-weak:#e3f5ea;--ok-line:#b2e0c3;--bad:#c42b2b;--bad-weak:#fde9e9;--bad-line:#f2bfbf;
--warn:#a35f00;--warn-weak:#fdf2dc;--warn-line:#efd39c;
--shadow-sm:0 1px 0 rgba(32,38,47,.06);--shadow:0 1px 0 rgba(32,38,47,.06),0 6px 16px -10px rgba(32,38,47,.25)}
@media (prefers-color-scheme:dark){:root{--paper:#24272d;--paper-2:#2b2f36;--raised:#31353d;--sunk:#1d2025;--ink:#eef1f5;--ink-2:#c4c9d1;--muted:#949ba6;--faint:#6c737e;
--line:#3b4048;--line-2:#4a505a;--cursor:#3ad7f2;--cursor-2:#a2efff;
--accent:#9198ff;--accent-2:#a5abff;--accent-weak:#2e3156;--accent-line:#4a4f8c;--on-accent:#15172e;
--ok:#4fd486;--ok-weak:#1f3a2b;--ok-line:#2f5c42;--bad:#ff7676;--bad-weak:#432528;--bad-line:#6e3439;
--warn:#f6bd4f;--warn-weak:#3f3320;--warn-line:#6a5328;
--shadow-sm:0 1px 0 rgba(0,0,0,.25);--shadow:0 1px 0 rgba(0,0,0,.25),0 8px 18px -10px rgba(0,0,0,.6)}}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
[hidden]{display:none!important}
html,body{margin:0;height:100%;overflow:hidden;background:var(--paper);color:var(--ink);-webkit-font-smoothing:antialiased;
font:2.9vh/1.5 "Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
body{display:flex;flex-direction:column}
button{font:inherit;color:inherit;cursor:pointer;touch-action:manipulation}
.wrap{flex:1;min-height:0;display:flex;align-items:center;padding:0 9vw}
.left{width:30vw;display:flex;flex-direction:column}
.tag{margin:0 0 1vh;font-size:2.2vh;font-weight:700;color:var(--muted)}
.mark{display:flex;align-items:center;gap:1.4vw}
.mark img{width:8vh;height:8vh;padding:1vh;border-radius:12px;background:var(--raised);box-shadow:var(--shadow)}
.mark span{font-size:9vh;font-weight:800;letter-spacing:-.035em;line-height:1;color:var(--accent)}
.sub{margin:1vh 0 3vh;font-weight:650;font-size:2.6vh;color:var(--ink-2)}
.guide{align-self:flex-start;min-height:8.4vh;padding:0 2.8vw;border-radius:999px;font-weight:650;font-size:2.9vh;color:var(--on-accent);
border:1px solid var(--accent);background:var(--accent)}
.who{display:inline-flex;align-self:flex-start;align-items:center;gap:.6vw;margin:2.4vh 0 0;padding:.4vh 1vw;border-radius:999px;font-size:2vh;font-weight:650;
background:var(--ok-weak);border:1px solid var(--ok-line);color:var(--ok)}
.who::before{content:"";width:.9vh;height:.9vh;border-radius:50%;background:currentColor}
.right{flex:1;display:flex;flex-direction:column;justify-content:center;padding-left:2vw}
.right.full{padding:0 1vw}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:2.4vh 1.6vw}
.it{display:block;width:100%;min-height:26vh;background:var(--raised);border:1px solid var(--line);border-radius:20px;padding:2.4vh .6vw 2vh;text-align:center;box-shadow:var(--shadow-sm)}
.it .ico{display:block;width:12vh;height:12vh;margin:0 auto 1.4vh}
.it .t{font-size:2.7vh;font-weight:650;letter-spacing:-.01em}
h1{font-size:5vh;font-weight:750;letter-spacing:-.03em;line-height:1.1;margin:0 0 1.2vh;display:flex;align-items:center}
h1 .ico{width:6.4vh;height:6.4vh;margin-right:1.2vw}
.lead{margin:0 0 2.6vh;font-size:2.7vh;color:var(--ink-2)}
.rows{display:grid;grid-template-columns:1fr 1fr;gap:2.2vh 1.6vw}
.rows.one{grid-template-columns:1fr}
.row{background:var(--raised);border:1px solid var(--line);border-radius:16px;padding:1.8vh 1.6vw;text-align:left;box-shadow:var(--shadow-sm)}
.row b{display:block;font-size:2.8vh;font-weight:650;letter-spacing:-.01em;margin-bottom:.3vh}
.row span{font-size:2.4vh;color:var(--ink-2)}
.back{display:inline-flex;align-items:center;align-self:flex-start;min-height:8vh;margin:0 0 2vh;padding:0 2.4vw;border-radius:999px;font-weight:650;font-size:2.8vh;
background:var(--raised);color:var(--ink);border:1px solid var(--line-2);box-shadow:var(--shadow-sm)}
.url{font-weight:650;color:var(--accent)}
.dots{flex:none;display:flex;justify-content:center;align-items:center;gap:1.6vw;font-size:2.2vh;color:var(--muted);margin:0 0 1.8vh}
.dots b{display:inline-flex;align-items:center;justify-content:center;width:3.6vh;height:3vh;border:1px solid var(--line-2);border-radius:.8vh;font-size:1.7vh;color:var(--ink);background:var(--raised)}
/* A dot is a 6vh tap target around a 1.1vh mark: touch jumps straight to a page. */
#dots .d{display:inline-flex;align-items:center;justify-content:center;width:6vh;height:6vh;padding:0;border:0;background:none}
#dots i{display:block;width:1.1vh;height:1.1vh;border-radius:50%;background:var(--line-2)}
#dots .on i{width:3vh;border-radius:999px;background:var(--cursor)}
.cta{flex:none;align-self:center;width:62vw;min-height:9.4vh;margin:0 0 3vh;border-radius:999px;font-size:2.9vh;font-weight:600;
background:var(--accent);color:var(--on-accent);border:1px solid var(--accent)}
.side{position:absolute;top:40%;width:9vh;height:9vh;border-radius:50%;border:1px solid var(--line-2);background:var(--raised);font-size:5vh;line-height:1;box-shadow:var(--shadow-sm)}
.side:active,.it:active,.guide:active,.cta:active,.back:active{background:var(--accent-weak)}
.side.l{left:2vw}.side.r{right:2vw}
/* The selection cursor: a gap in the page's own colour, then the cyan ring. The D-pad moves focus, so
   :focus is what the player sees as the cursor; hover selects for a pointer. It breathes between two
   cyans where motion is welcome, and is a static ring where the browser cannot say. */
.it:hover,.it:focus,.row:hover,.row:focus,.guide:hover,.guide:focus,.cta:hover,.cta:focus,.back:hover,.back:focus{outline:none;box-shadow:0 0 0 3px var(--paper),0 0 0 7px var(--cursor)}
@keyframes breathe{50%{box-shadow:0 0 0 3px var(--paper),0 0 0 7px var(--cursor-2)}}
@media (prefers-reduced-motion:no-preference){.it:hover,.it:focus,.row:hover,.row:focus,.guide:hover,.guide:focus,.cta:hover,.cta:focus,.back:hover,.back:focus{animation:breathe 1.6s ease-in-out infinite}}
@media (prefers-color-scheme:dark){.it,.row{border-color:transparent}}
`

const lhubJS = `
(function(){
function param(k){var m=location.search.match(new RegExp('[?&]'+k+'=([^&]*)'));return m?decodeURIComponent(m[1]):'';}
function $(id){return document.getElementById(id);}
function ic(name){return '<img class="ico" src="/_openpak/icon/'+name+'.png" alt="">';}
function it(name,t,go){return '<button class="it" data-go="'+go+'">'+ic(name)+'<span class="t">'+t+'</span></button>';}
function row(h,p){return '<div class="row" tabindex="0"><b>'+h+'</b><span>'+p+'</span></div>';}
var PAGES=[
 {tag:'Everything is included',h:'<div class="grid">'+
  it('online','Online Play',1)+it('cloud','Save Data Cloud',2)+it('app','Smartphone App',3)+
  it('consoles','Across Consoles',4)+it('faq','Questions',5)+it('help','Help &amp; Guides',6)+'</div>'},
 {tag:'Play together',h:'<h1>'+ic('online')+'Online Play</h1><p class="lead">OpenPak runs its own servers for the games it supports.</p><div class="rows">'+
  row('Matchmaking and rooms','Random matches, private rooms and invites, as the game offers them.')+
  row('Rankings and events','Leaderboards and events where the game has them.')+
  row('Supported games','The list and what works in each: <span class="url">openpak.org/titles</span>')+
  row('Fair play','Reports and bans apply across the whole network.')+'</div>'},
 {tag:'Never lose progress',h:'<h1>'+ic('cloud')+'Save Data Cloud</h1><p class="lead">Your saves, kept safe on the OpenPak servers.</p><div class="rows">'+
  row('Automatic backup','Saves of supported games go to your OpenPak account.')+
  row('Restore anywhere','Download a save to another console on the same account.')+
  row('See them on your phone','The OpenPak app and openpak.org list your saves.')+
  row('Only yours','Saves belong to your account and are never shared.')+'</div>'},
 {tag:'OpenPak in your pocket',h:'<h1>'+ic('app')+'Smartphone App</h1><p class="lead">Get it at <span class="url">openpak.org/app</span> and sign in with your OpenPak account.</p><div class="rows">'+
  row('Voice chat','Talk with the players in your game room, or friends by room code.')+
  row('Friends','Requests, invitations and who is playing what, on every console.')+
  row('Messages','Chat with friends from your phone.')+
  row('Help','Open a ticket and read the replies.')+'</div>'},
 {tag:'One network',h:'<h1>'+ic('consoles')+'Across Consoles</h1><p class="lead">One account and one friend list for Nintendo consoles old and new.</p><div class="rows">'+
  row('Nintendo Switch','Online play, friends, eShop, News and Save Data Cloud.')+
  row('Wii U and 3DS','Online play, friends, posts and chat.')+
  row('Wii and DS','Nintendo Wi-Fi Connection games online again.')+
  row('Emulators','Supported emulators join the same network as consoles.')+'</div>'},
 {tag:'Good to know',h:'<h1>'+ic('faq')+'Questions</h1><div class="rows one">'+
  row('Does it cost anything?','No. Everything is included with a free OpenPak account.')+
  row('Is OpenPak made by Nintendo?','No. OpenPak is independent and not affiliated with Nintendo.')+
  row('Which games work online?','See openpak.org/titles for the list and what works in each.')+
  row('Can I use my Nintendo Account?','OpenPak uses its own accounts. Link your console to yours to play.')+'</div>'},
 {tag:'We are here to help',h:'<h1>'+ic('help')+'Help &amp; Guides</h1><p class="lead">Guides and support live on openpak.org.</p><div class="rows">'+
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
 $('page').innerHTML=(cur?'<button class="back" id="back" type="button">‹ OpenPak Online</button>':'')+PAGES[cur].h; $('tag').textContent=PAGES[cur].tag;
 // The mark, the guide button and the wide button belong to the main page; a topic page gets the whole width.
 $('left').style.display=cur?'none':''; $('cta').style.display=cur?'none':''; $('page').className='right'+(cur?' full':'');
 var d='';for(var k=0;k<PAGES.length;k++){d+='<button class="d'+(k===cur?' on':'')+'" data-i="'+k+'" tabindex="-1" aria-label="Page '+(k+1)+'"><i></i></button>';} $('dots').innerHTML=d;
 var bk=$('back'); if(bk){bk.addEventListener('click',function(){go(0);});}
 var b=$('page').querySelectorAll('.it');
 for(var j=0;j<b.length;j++){b[j].addEventListener('click',function(){go(+this.getAttribute('data-go'));});}
 var f=$('page').querySelector('.it,.row'); if(f){f.focus();}
}
function leave(){
 if(nxCall('endApplet',[],null)){return;}
 try{window.close();}catch(e){}
 try{history.back();}catch(e){}
}
$('dots').addEventListener('click',function(e){var t=e.target;while(t&&t!==this&&!t.getAttribute('data-i')){t=t.parentNode;}if(t&&t!==this){go(+t.getAttribute('data-i'));}});
// Touch: swipe sideways to turn the page, like L and R.
var sx=0,sy=0;
document.addEventListener('touchstart',function(e){var t=e.touches[0];sx=t.clientX;sy=t.clientY;});
document.addEventListener('touchend',function(e){var t=e.changedTouches[0],dx=t.clientX-sx,dy=t.clientY-sy;
 if(Math.abs(dx)>60&&Math.abs(dx)>Math.abs(dy)*1.5){flip(dx<0?1:-1);}});
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
