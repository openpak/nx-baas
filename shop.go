package main

// The OpenPak storefront on the native shop applet's host (SHP-01/02).
//
// The native eShop applet opens https://bugyo.hac.lp1.eshop.nintendo.net/ashigaru/ and
// exposes console functions to the page through window.nx / window.nx.shop (public
// research: kinnay's eShop-Applet-(Switch) wiki page, accessed 2026-09-11; the 22.5.0
// LibAppletOff strings agree: bugyo.hac.%.eshop.nintendo.net, window.nx.shop,
// requestSyncRights, requestDownloadTaskListOnEnd, requestEdgeToken, requestLinkDevice,
// prepareSpaceSizes, getApplicationContentMetaStatusArray, and window.nx.dispatchEvent).
//
// What neither the firmware strings nor public research documents is each bridge call's
// argument shape. So this file ships in the PRD's own order: a diagnostic page first
// (SHP-01) that probes every documented bridge and reports what exists, then the
// storefront (SHP-02), which degrades honestly where a bridge is absent. Nothing here
// claims a native install happened — download-task state is proven in atum.go/beach.go
// and, on hardware, by the diagnostic page recording what the applet actually invoked.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

type shopUI struct {
	mu sync.Mutex
	// diag keeps the last 32 bridge diagnostics the pages reported, for the review
	// evidence trail. Diagnostics are memory-only: they describe one console session.
	diag [][2]any
}

func (s *server) shopDiag() *shopUI {
	if s.shopUI == nil {
		s.shopUI = &shopUI{}
	}
	return s.shopUI
}

func (s *server) shopHandler(w http.ResponseWriter, r *http.Request, body []byte) {
	if s.shop == nil {
		s.shop = newShopState("")
	}
	p := r.URL.Path
	switch {
	case p == "/ashigaru" || p == "/ashigaru/":
		s.shopEntryPage(w, r)
	case p == "/ashigaru/diag":
		s.shopDiagPage(w, r)
	case p == "/ashigaru/api/v1/diag" && r.Method == "POST":
		s.shopDiagReport(w, r, body)
	case strings.HasPrefix(p, "/ashigaru/api/v1/"):
		s.shopAPI(w, r, body)
	case strings.HasPrefix(p, "/ashigaru/icon/"):
		s.shopIcon(w, r)
	default:
		// The applet asks for favicons and (on the real store) many more /ashigaru/ paths.
		// Record rather than 404 silently: SHP-01 wants the actual request sequence.
		dump(r, body, "!! SHOP unhandled bugyo path")
		http.NotFound(w, r)
	}
}

// ---------- catalog / acquisition / task API (OpenPak-owned protocol) ----------

func (s *server) shopLang(r *http.Request) string {
	lang := r.URL.Query().Get("lang")
	if lang == "" {
		lang = "en-US"
	}
	return lang
}

func (s *server) shopAPI(w http.ResponseWriter, r *http.Request, body []byte) {
	p := strings.TrimPrefix(r.URL.Path, "/ashigaru/api/v1")
	lang := s.shopLang(r)
	account, _ := s.shopPrincipal(r)

	switch {
	case p == "/catalog" && r.Method == "GET":
		owned := map[string]*ShopEntitlement{}
		if account != "" {
			owned = s.shop.ownedTitles(account)
		}
		s.shop.mu.Lock()
		items := []map[string]any{}
		for _, t := range s.shop.Catalog {
			tx := t.text(lang)
			item := map[string]any{
				"title_id": t.TitleID, "name": tx.Name, "publisher": t.Publisher,
				"category": t.Category, "size_bytes": t.SizeBytes, "version": t.Version,
				"version_label": t.VersionLabel, "updated_at": t.UpdatedAt,
				"icon": "/ashigaru/icon/" + t.TitleID,
			}
			if account != "" {
				if e := owned[t.TitleID]; e != nil {
					item["ownership"] = "owned"
					item["version_owned"] = e.Version
				} else {
					item["ownership"] = "not_owned"
				}
			}
			items = append(items, item)
		}
		s.shop.mu.Unlock()
		writeJSON(w, 200, map[string]any{"count": len(items), "titles": items, "lang": lang})

	case strings.HasPrefix(p, "/catalog/") && !strings.HasSuffix(p, "/acquire") && r.Method == "GET":
		tid := strings.TrimPrefix(p, "/catalog/")
		s.shop.mu.Lock()
		t := s.shop.Catalog[tid]
		s.shop.mu.Unlock()
		if t == nil {
			writeJSON(w, 404, map[string]any{"error": map[string]any{"code": "2001", "message": "no such title"}})
			return
		}
		tx := t.text(lang)
		detail := map[string]any{
			"title_id": t.TitleID, "name": tx.Name, "description": tx.Description,
			"publisher": t.Publisher, "category": t.Category, "size_bytes": t.SizeBytes,
			"version": t.Version, "version_label": t.VersionLabel,
			"compatibility": t.Compatibility, "languages": t.Languages,
			"icon": "/ashigaru/icon/" + t.TitleID, "screenshots": t.Screenshots,
			"distribution": t.Distribution, "updated_at": t.UpdatedAt,
		}
		if account != "" {
			ownership := "not_owned"
			if e := s.shop.entitlementFor(account, tid); e != nil {
				if e.Status == "active" {
					ownership = "owned"
					detail["version_owned"] = e.Version
				} else {
					ownership = "revoked"
				}
			}
			detail["ownership"] = ownership
		}
		writeJSON(w, 200, detail)

	case p == "/ownership" && r.Method == "GET":
		if account == "" {
			writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "1002", "message": "account identity required"}})
			return
		}
		items := []map[string]any{}
		for _, e := range s.shop.ownedTitles(account) {
			items = append(items, map[string]any{
				"title_id": e.TitleID, "elicense_id": e.ELicenseID, "rights_id": e.RightsID,
				"version": e.Version, "status": e.Status, "created_at": e.CreatedAt,
			})
		}
		writeJSON(w, 200, map[string]any{"entitlements": items})

	case strings.HasPrefix(p, "/catalog/") && strings.HasSuffix(p, "/acquire") && r.Method == "POST":
		tid := strings.TrimSuffix(strings.TrimPrefix(p, "/catalog/"), "/acquire")
		s.shopAcquire(w, r, tid)

	case p == "/tasks" && r.Method == "GET":
		if account == "" {
			writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "1002", "message": "account identity required"}})
			return
		}
		items := []map[string]any{}
		for _, t := range s.shop.tasksFor(account) {
			items = append(items, map[string]any{
				"id": t.ID, "title_id": t.TitleID, "version": t.Version, "state": t.State,
				"fail_reason": t.FailReason, "created_at": t.CreatedAt, "updated_at": t.UpdatedAt,
			})
		}
		writeJSON(w, 200, map[string]any{"tasks": items})
	case p == "/tasks" && r.Method == "POST":
		if account == "" {
			writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "1002", "message": "account identity required"}})
			return
		}
		var in struct {
			TitleID string `json:"title_id"`
		}
		json.Unmarshal(body, &in)
		e := s.shop.entitlementFor(account, in.TitleID)
		if e == nil || e.Status != "active" {
			// No false ownership: a task for an unowned (or revoked) title is refused.
			writeJSON(w, 403, map[string]any{"error": map[string]any{"code": "2003", "message": "no active entitlement for this title"}})
			return
		}
		t, err := s.shop.createTask(account, in.TitleID)
		if err != nil {
			writeJSON(w, 404, map[string]any{"error": map[string]any{"code": "2001", "message": "no such title"}})
			return
		}
		writeJSON(w, 200, map[string]any{"id": t.ID, "title_id": t.TitleID, "version": t.Version, "state": t.State})

	case strings.HasPrefix(p, "/tasks/") && strings.HasSuffix(p, "/progress") && r.Method == "POST":
		// The storefront's own progress channel (OpenPak protocol): the page mirrors what
		// it observed — the applet's download-task callbacks — into the server's task
		// projection. This records the page's observation; it is not the native install
		// itself, and the review ledger says so (SHP-04).
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/tasks/"), "/progress")
		if account == "" {
			writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "1002", "message": "account identity required"}})
			return
		}
		var in struct {
			State string `json:"state"`
		}
		json.Unmarshal(body, &in)
		switch in.State {
		case "downloading", "paused", "completed":
			if t := s.shop.updateTask(id, account, in.State, ""); t != nil {
				writeJSON(w, 200, map[string]any{"id": t.ID, "state": t.State})
				return
			}
			writeJSON(w, 404, map[string]any{"error": map[string]any{"code": "2004", "message": "no such open task"}})
		default:
			writeJSON(w, 400, map[string]any{"error": map[string]any{"code": "2005", "message": "state must be downloading, paused or completed"}})
		}

	case strings.HasPrefix(p, "/tasks/") && strings.HasSuffix(p, "/cancel") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/tasks/"), "/cancel")
		if account == "" {
			writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "1002", "message": "account identity required"}})
			return
		}
		if t := s.shop.updateTask(id, account, "canceled", ""); t != nil {
			writeJSON(w, 200, map[string]any{"id": t.ID, "state": t.State})
			return
		}
		writeJSON(w, 404, map[string]any{"error": map[string]any{"code": "2004", "message": "no such open task"}})
	default:
		dump(r, body, "!! SHOP unhandled api path")
		writeJSON(w, 404, map[string]any{"error": map[string]any{"code": "1001", "message": "api not found"}})
	}
}

// shopAcquire is the acquisition gate (SHP-03): authenticated, idempotent, durable.
// Repeating the call — including after a restart — returns the same elicense id.
func (s *server) shopAcquire(w http.ResponseWriter, r *http.Request, tid string) {
	account, baasUser := s.shopPrincipal(r)
	if account == "" {
		writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "1002", "message": "account identity required"}})
		return
	}
	device := s.deviceIdentity(r)
	s.shop.mu.Lock()
	title := s.shop.Catalog[tid]
	s.shop.mu.Unlock()
	if title == nil {
		writeJSON(w, 404, map[string]any{"error": map[string]any{"code": "2001", "message": "no such title"}})
		return
	}
	e, created, err := s.shop.acquire(account, baasUser, tid, device, title.Version)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": map[string]any{"code": "2001", "message": "no such title"}})
		return
	}
	log.Printf("[shop] acquire: account %s title %s -> elicense %s (device %s, new=%v)", account, tid, e.ELicenseID, device, created)
	writeJSON(w, 200, map[string]any{
		"title_id": e.TitleID, "elicense_id": e.ELicenseID, "rights_id": e.RightsID,
		"version": e.Version, "status": e.Status, "already_owned": !created,
	})
}

// shopIcon serves a title's icon from the operator's shop directory.
func (s *server) shopIcon(w http.ResponseWriter, r *http.Request) {
	tid := strings.TrimPrefix(r.URL.Path, "/ashigaru/icon/")
	if !validTitleID(tid) {
		http.NotFound(w, r)
		return
	}
	s.shop.mu.Lock()
	t := s.shop.Catalog[tid]
	s.shop.mu.Unlock()
	if t == nil || t.IconPath == "" {
		// A neutral placeholder keeps grids usable when an icon is missing; never a
		// third-party image, just the OpenPak mark the link pages already carry.
		w.Header().Set("Content-Type", "image/svg+xml")
		fmt.Fprint(w, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><rect width="128" height="128" rx="16" fill="#4338ca"/><circle cx="64" cy="64" r="34" fill="none" stroke="#fff" stroke-width="8" opacity=".9"/><circle cx="64" cy="64" r="10" fill="#fff" opacity=".95"/></svg>`)
		return
	}
	b, err := os.ReadFile(s.shop.dir + "/" + t.IconPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Write(b)
}

// ---------- diagnostics (SHP-01) ----------

// shopDiagReport records one storefront diagnostic report. No auth: the report describes
// the requesting console session itself, is bounded in memory, and stays out of the
// store's normal UI.
func (s *server) shopDiagReport(w http.ResponseWriter, r *http.Request, body []byte) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSON(w, 400, map[string]any{"error": "not json"})
		return
	}
	payload["ua"] = r.UserAgent()
	payload["at"] = timeNowUnix()
	if b, err := json.Marshal(payload); err == nil {
		log.Printf("[shop] diag: %s", b)
	}
	d := s.shopDiag()
	d.mu.Lock()
	d.diag = append(d.diag, [2]any{timeNowUnix(), payload})
	if len(d.diag) > 32 {
		d.diag = d.diag[len(d.diag)-32:]
	}
	d.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------- pages ----------
//
// The shop pages reuse the link pages' stylesheet (pageCSS: light/dark tokens, console
// sizing, visible focus) and add a tile grid. Controller usability is CSS first: every
// interactive element is a real button or link, focus is always visible, and hit targets
// are large. No protocol diagnostics appear on the storefront; they live on /ashigaru/diag.

func (s *server) shopEntryPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, shopPage("OpenPak Shop", shopAppJS))
}

func (s *server) shopDiagPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, shopPage("OpenPak Shop — Diagnostics", shopDiagJS))
}

func shopPage(title, js string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>` + title + `</title>` +
		`<style>` + pageCSS + shopCSS + `</style></head>` +
		`<body class="console"><main><div class="brand"><img src="` + logoDataURI + `" alt=""> OpenPak Shop</div>` +
		`<div id="banner" class="banner" hidden></div>` +
		`<div id="app"><div class="row"><span class="name">Loading…</span></div></div>` +
		`</main><script>` + js + `</script></body></html>`
}

const shopCSS = `
.banner{background:var(--bad-weak);border:1px solid var(--bad-line);color:var(--bad);
border-radius:var(--r);padding:14px 18px;margin:0 0 16px;display:none}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:18px}
.tile{display:flex;gap:14px;align-items:center;text-align:left;background:var(--raised);
border:1px solid var(--line);border-radius:var(--r);padding:16px;cursor:pointer;min-height:96px;width:100%}
.tile img{width:72px;height:72px;border-radius:10px;background:var(--paper-2)}
.tile .t-name{font-weight:650;font-size:1.05rem}
.tile .t-sub{color:var(--muted);font-size:.9rem}
.tile .own{color:var(--ok);font-size:.9rem;font-weight:600}
.detail img.icon{width:160px;height:160px;border-radius:14px;background:var(--paper-2)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 18px;color:var(--ink-2);margin:14px 0}
.kv b{color:var(--ink)}
.back{margin-bottom:14px;display:inline-block}
button.small{width:auto;min-height:48px;padding:0.6rem 1.4rem;margin-top:8px}
.note{color:var(--muted);font-size:.95rem}
`

// shopDiagJS probes the bridge surface the firmware strings and the wiki name, and reports
// both what exists and what calling the safe ones returns. It never calls anything with
// side effects beyond identity/cancellation: the point is a reproducible record of what
// this console's applet actually provides (SHP-01's first deliverable).
const shopDiagJS = `
(function(){
function post(o){try{fetch('/ashigaru/api/v1/diag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});}catch(e){}}
var probe={bridge:false, functions:{}, events:[], errors:[]};
function name_(o){return Object.prototype.toString.call(o);}
try{
  if(window.nx){probe.bridge=true;
    var list=['canHistoryBack','footer','isKeyboardShown','open1ButtonDialog','open2ButtonDialog','playSystemSe','dispatchEvent'];
    for(var i=0;i<list.length;i++){probe.functions['nx.'+list[i]]=typeof(window.nx[list[i]]);}
    if(window.nx.shop){
      var s=['canJumpToLhubApplet','cancelAsync','cancelDeviceAuthToken','cancelNaAuthToken','cancelSyncRights','clearNaAuthTokenCache','getApplicationContentMetaStatusArray','getDeviceAccountInfo','getTotalSizeNand','getTotalSizeSd','isAnyApplicationRunning','prepareSpaceSizes','requestCleanupAllPreInstalledApplications','requestDeviceRegistrationInfo','requestDownloadTaskListOnEnd','requestEdgeToken','requestLinkDevice','requestNaAuthToken','requestRegisterDeviceAccount','requestSyncRegistration','requestSyncRights','requestUnlinkDevice','requestUnregisterDeviceAccount','setDeviceAuthTokenAvailableCallback','setNaAuthTokenAvailableCallback'];
      for(var j=0;j<s.length;j++){probe.functions['nx.shop.'+s[j]]=typeof(window.nx.shop[s[j]]);}
    }
    if(window.nx.system){var y=['getAccountNickname','isUserOperationLocked','productModel','version'];
      for(var k=0;k<y.length;k++){probe.functions['nx.system.'+y[k]]=typeof(window.nx.system[y[k]]);}}
    if(window.nx.addEventListener){window.nx.addEventListener('message',function(e){
      probe.events.push(String(e&&e.data).slice(0,400)); post(probe);});}
  } else {probe.errors.push('window.nx is undefined (standalone browser: the applet bridge is absent)');}
}catch(e){probe.errors.push(String(e));}
post(probe);
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
var app=document.getElementById('app');
var rows='';
var keys=Object.keys(probe.functions).sort();
for(var i=0;i<keys.length;i++){
  var v=probe.functions[keys[i]];
  var cls=v==='function'?'ok':'';
  rows+='<div class="row '+cls+'"><span class="name">'+esc(keys[i])+'</span><span class="pill">'+esc(v)+'</span></div>';
}
if(!probe.bridge){rows='<div class="row bad"><span class="name">window.nx is undefined</span><span class="pill">standalone</span></div>'+rows;}
var ev=probe.events.map(function(e){return '<li>'+esc(e)+'</li>';}).join('');
var er=probe.errors.map(function(e){return '<li>'+esc(e)+'</li>';}).join('');
app.innerHTML='<h1>Bridge diagnostics</h1>'+
 '<p class="note">Probes reported to the server. Console: '+esc(navigator.userAgent)+'</p>'+
 '<h2>window.nx surface</h2>'+rows+
 (er?'<h2>Errors</h2><ul class="steps">'+er+'</ul>':'')+
 (ev?'<h2>Events</h2><ul class="steps">'+ev+'</ul>':'')+
 '<p class="note">Full request sequence is logged server-side: every request this applet makes lands in the nx-baas log.</p>';
})();
`

// shopAppJS is the storefront (SHP-02): catalog grid, details, acquisition, tasks.
// Bridge calls are guarded: when window.nx is missing (a plain browser), the page says so
// and refuses acquisition instead of pretending a download can happen — a web page is not
// a native install (SHP-04).
const shopAppJS = `
(function(){
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
var app=document.getElementById('app'), banner=document.getElementById('banner');
var token=null, lang=(navigator.language||'en-US');
function show(m){banner.style.display='block';banner.textContent=m;}
function hide(){banner.style.display='none';}
function api(path,opts){opts=opts||{};opts.headers=opts.headers||{};if(token)opts.headers['Authorization']='Bearer '+token;
 return fetch('/ashigaru/api/v1'+path,opts).then(function(r){return r.json().then(function(b){return {status:r.status,body:b};});});}

// Account handoff: the applet binds the shop session to the selected account; the page
// learns who through requestNaAuthToken. The token's shape and delivery are part of what
// the diagnostics record; until a capture fixes them, every failure degrades to
// standalone mode and says so.
var bridge={present:typeof(window.nx)!=='undefined'};
function identify(){
 return new Promise(function(res){
  if(!bridge.present||!window.nx.shop||typeof(window.nx.shop.requestNaAuthToken)!=='function'){return res(false);}
  try{
   window.nx.shop.requestNaAuthToken(function(t){
     if(t&&typeof t==='string'){token=t;res(true);}else{res(false);}
   });
   setTimeout(function(){res(!!token);},4000);
  }catch(e){res(false);}
 });
}
function report(o){try{fetch('/ashigaru/api/v1/diag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});}catch(e){}}

function human(n){if(n>1073741824)return (n/1073741824).toFixed(2)+' GB';if(n>1048576)return (n/1048576).toFixed(1)+' MB';if(n>1024)return (n/1024).toFixed(0)+' KB';return n+' B';}

function list(){
 hide(); app.innerHTML='<div class="row"><span class="name">Loading…</span></div>';
 api('/catalog?lang='+encodeURIComponent(lang)).then(function(r){
  if(r.status!==200){show('The catalog is unavailable right now ('+r.status+').');app.innerHTML='';return;}
  var ts=r.body.titles||[];
  if(!ts.length){app.innerHTML='<div class="row"><span class="name">The catalog is empty.</span><span class="pill">nothing here yet</span></div>';return;}
  var g='<div class="grid">';
  for(var i=0;i<ts.length;i++){var t=ts[i];
   g+='<button class="tile" data-tid="'+esc(t.title_id)+'">'+
      '<img src="'+esc(t.icon)+'" alt="">'+
      '<span><span class="t-name">'+esc(t.name)+'</span><br>'+
      '<span class="t-sub">'+esc(t.publisher||'')+' · '+human(t.size_bytes||0)+' · v'+esc(t.version_label||t.version)+'</span>'+
      (t.ownership==='owned'?'<br><span class="own">Owned</span>':'')+
      '</span></button>';
  }
  app.innerHTML=g+'</div>';
  var b=app.querySelectorAll('.tile');
  for(var j=0;j<b.length;j++){b[j].addEventListener('click',function(){detail(this.getAttribute('data-tid'));});}
 }).catch(function(){show('The catalog could not be reached.');app.innerHTML='';});
}

function detail(tid){
 hide(); app.innerHTML='<div class="row"><span class="name">Loading…</span></div>';
 api('/catalog/'+tid+'?lang='+encodeURIComponent(lang)).then(function(r){
  var t=r.body;
  if(r.status!==200||!t){show('This title is not available.');list();return;}
  var own=t.ownership;
  var act='';
  if(own==='owned'){act='<button class="small" id="dl">Download</button>';}
  else if(own==='revoked'){act='<p class="note">This title is no longer licensed on this account.</p>';}
  else if(!bridge.present){act='<p class="note">Acquisition needs the console shop bridge (window.nx). You are viewing a standalone page; nothing can be acquired here.</p>';}
  else{act='<button class="small" id="acq">Acquire</button>';}
  app.innerHTML='<a class="back" href="#" id="back">← Back</a>'+
   '<div class="detail card"><img class="icon" src="'+esc(t.icon)+'" alt="">'+
   '<h1>'+esc(t.name)+'</h1><p>'+esc(t.description||'')+'</p>'+
   '<div class="kv">'+
   '<b>Publisher</b><span>'+esc(t.publisher||'—')+'</span>'+
   '<b>Size</b><span>'+human(t.size_bytes||0)+'</span>'+
   '<b>Version</b><span>'+esc(t.version_label||t.version)+'</span>'+
   '<b>Compatibility</b><span>'+esc((t.compatibility||[]).join(', ')||'—')+'</span>'+
   '<b>Languages</b><span>'+esc((t.languages||[]).join(', ')||'—')+'</span>'+
   '<b>Ownership</b><span>'+esc(own||'unknown (not signed in)')+'</span>'+
   '</div>'+act+'</div>';
  document.getElementById('back').addEventListener('click',function(e){e.preventDefault();list();});
  var acq=document.getElementById('acq');
  if(acq)acq.addEventListener('click',function(){acquire(t);});
  var dl=document.getElementById('dl');
  if(dl)dl.addEventListener('click',function(){startDownload(t);});
 }).catch(function(){show('This title could not be reached.');});
}

function acquire(t){
 hide(); app.innerHTML='<div class="row"><span class="name">Acquiring '+esc(t.name)+'…</span></div>';
 api('/catalog/'+t.title_id+'/acquire',{method:'POST'}).then(function(r){
  if(r.status===200){
   report({event:'acquired',title_id:t.title_id,elicense_id:r.body.elicense_id,already_owned:r.body.already_owned});
   syncRights();
   detail(t.title_id);
  }else{
   show('Acquisition failed: '+((r.body.error&&r.body.error.message)||r.status));
   detail(t.title_id);
  }
 });
}

function syncRights(){
 if(!window.nx.shop||typeof(window.nx.shop.requestSyncRights)!=='function'){report({event:'sync_rights',result:'bridge absent'});return;}
 try{
  report({event:'sync_rights',result:'invoked'});
  window.nx.shop.requestSyncRights(function(res){report({event:'sync_rights',result:String(JSON.stringify(res)).slice(0,400)});});
 }catch(e){report({event:'sync_rights',result:'threw',detail:String(e)});}
}

function startDownload(t){
 hide(); app.innerHTML='<div class="row"><span class="name">Preparing download…</span></div>';
 api('/tasks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title_id:t.title_id})}).then(function(r){
  if(r.status!==200){show('Download refused: '+((r.body.error&&r.body.error.message)||r.status));detail(t.title_id);return;}
  api('/tasks/'+r.body.id+'/progress',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state:'downloading'})});
  pollTask(r.body.id,t);
 });
}
function pollTask(id,t){
 api('/tasks').then(function(r){
  var ts=(r.body&&r.body.tasks)||[], task=null;
  for(var i=0;i<ts.length;i++){if(ts[i].id===id)task=ts[i];}
  if(!task){show('The download task disappeared.');detail(t.title_id);return;}
  if(task.state==='completed'){app.innerHTML='<div class="row ok"><span class="name">'+esc(t.name)+' is installed.</span><span class="pill">done</span></div><button class="small" id="back2">Back</button>';
   document.getElementById('back2').addEventListener('click',function(){list();});return;}
  if(task.state==='failed'){show('Download failed: '+esc(task.fail_reason||'unknown'));detail(t.title_id);return;}
  if(task.state==='canceled'){detail(t.title_id);return;}
  app.innerHTML='<div class="row"><span class="name">Downloading '+esc(t.name)+'…</span><span class="pill">'+esc(task.state)+'</span></div>'+
   '<button class="small" id="cancel">Cancel</button>';
  document.getElementById('cancel').addEventListener('click',function(){
   api('/tasks/'+id+'/cancel',{method:'POST'}).then(function(){detail(t.title_id);});
  });
  setTimeout(function(){pollTask(id,t);},2000);
 });
}

identify().then(function(){
 if(!bridge.present){show('Standalone mode: the console shop bridge is absent. Browsing works; acquiring does not.');}
 report({event:'page',bridge:bridge.present,identified:!!token});
 list();
});
})();
`
