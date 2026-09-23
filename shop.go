package main

// The OpenPak storefront on the native shop applet's hosts (SHP-01/02).
//
// On 22.5.0 the shop is not the old LibAppletOff page on bugyo: qlaunch hands LibAppletShop a
// scene query, and systemWeb (EcUsage) opens https://hac.<env>.savanna.srv.nintendo.net/<scene
// path> [firmware, systemWeb 0100000000001042: "https://hac.%.savanna.srv", the scene-to-path
// table and the eshop_hac_urls allowlist]. `ashigaru` does not occur anywhere in 22.5.0; the
// bugyo /ashigaru/ pages stay as an alias because older firmware and the public research
// (kinnay's eShop-Applet-(Switch) wiki page, accessed 2026-09-11) use them.
//
// Scene paths served on savanna: /top[?landing_page=], /detail/<id>,
// /detail/application_items/<id>/{dlc_items,ticket_item_groups,consumable_item_groups,
// manage_subscriptions}, /catalog_tickets/<id>, /search/result/conditions, /my[?tab=],
// /membership, /redeem/input and /shelf (the "list" scene). Every one renders the same
// storefront, which reads its own location to pick the view. Query parameters the applet adds
// (mode, dst_app_id, dst_nsuid, news_id, edition, pwl_reason, pwl_app_id, ...) are accepted
// and ignored unless the view can use them. Leaving the shop is a navigation to eshop://success,
// the callback URL qlaunch passes and checks.
//
// The page reaches the console through window.nx. The 22.5.0 systemWeb binary names the
// functions (requestNaIdToken, setNsaIdTokenAvailableCallback, requestSyncRights,
// requestDownloadTaskListOnEnd, ...) but not which object carries each one, nor any argument
// or callback shape. So the pages look each name up on window.nx.shop, window.nx.ec,
// window.nx.account, window.nx.lhub and window.nx in turn, the diagnostic page (SHP-01)
// reports where each one was found, and the storefront (SHP-02) degrades honestly where one
// is absent. Nothing here claims a native install happened.

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
		// The applet asks for favicons and (on the real store) many more paths.
		// Record rather than 404 silently: SHP-01 wants the actual request sequence.
		dump(r, body, "!! SHOP unhandled shop path")
		http.NotFound(w, r)
	}
}

// savanna serves hac.<env>.savanna.srv.nintendo.net, where 22.5.0's systemWeb opens the
// shop. Scene paths render the storefront; /ashigaru/* (the page's own API, icons and the
// diagnostic page) is shared with bugyo so both hosts run one implementation.
func (s *server) savanna(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/ashigaru") {
		s.shopHandler(w, r, body)
		return
	}
	if savannaScene(p) {
		// The applet's query is recorded in full once per page load: which scene and
		// parameters qlaunch sends is still a hardware question (report, eShop "Needs
		// hardware" 1).
		log.Printf("[shop] savanna scene %s query=%q ua=%q", p, r.URL.RawQuery, r.UserAgent())
		if s.shop == nil {
			s.shop = newShopState("")
		}
		s.shopEntryPage(w, r)
		return
	}
	dump(r, body, "!! SHOP unhandled savanna path")
	http.NotFound(w, r)
}

// savannaScene reports whether p is one of the scene paths systemWeb builds from a shop
// query [firmware, systemWeb ConvertEcSceneQueryToPathname].
func savannaScene(p string) bool {
	p = strings.TrimSuffix(p, "/")
	switch p {
	case "", "/top", "/search/result/conditions", "/my", "/membership", "/redeem/input", "/shelf":
		return true
	}
	for _, prefix := range []string{"/detail/", "/catalog_tickets/"} {
		if rest, ok := strings.CutPrefix(p, prefix); ok && rest != "" {
			return true
		}
	}
	return false
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
	case p == "/me/avatar" && r.Method == "GET":
		// The signed-in user's picture for the corner of the storefront: the same one
		// the console's profile shows, served on the shop's own origin.
		_, baasUser := s.shopPrincipal(r)
		if baasUser == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/1/" + baasUser
		s.baas(w, r2, nil)
		return
	case p == "/catalog" && r.Method == "GET":
		owned := map[string]*ShopEntitlement{}
		if account != "" {
			owned = s.shop.ownedTitles(account)
		}
		s.shop.mu.Lock()
		items := []map[string]any{}
		for _, t := range s.shop.Catalog {
			if t.Unpublished {
				continue
			}
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
		t := s.shop.listed(tid)
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
	title := s.shop.listed(tid)
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
	t := s.shop.listed(tid)
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
	w.Header().Set("Content-Type", http.DetectContentType(b))
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
	fmt.Fprint(w, storePage())
}

func (s *server) shopDiagPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, shopPage("OpenPak Shop — Diagnostics", shopDiagJS))
}

func shopPage(title, js string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>` + title + `</title>` +
		`<style>` + pageCSS + shopCSS + `</style></head>` +
		`<body class="console"><main><div class="brand"><img src="` + logoDataURI + `" alt=""> OpenPak Shop` +
		`<button class="small close" id="close" type="button">Close</button></div>` +
		`<div id="banner" class="banner" hidden></div>` +
		`<div id="app"><div class="row"><span class="name">Loading…</span></div></div>` +
		`</main><script>` + shopBridgeJS + js + `</script></body></html>`
}

const shopCSS = `
.brand .close{margin-left:auto;margin-top:0}
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

// shopBridgeJS is shared by every shop page. The 22.5.0 systemWeb binary names the bridge
// functions but not the object carrying each one, nor how results come back, so a call
// looks the name up across the candidate objects and accepts a callback, a promise or a
// plain return value — whichever the console uses is what the diagnostics then record.
// Leaving the shop navigates to eshop://success, the callback URL qlaunch checks.
const shopBridgeJS = `
var NX_SPACES=['shop','ec','account','lhub'];
function nxFind(name){
 var nx=window.nx; if(!nx){return null;}
 for(var i=0;i<NX_SPACES.length;i++){var o=nx[NX_SPACES[i]];
  if(o&&typeof(o[name])==='function'){return {fn:o[name],self:o,where:'nx.'+NX_SPACES[i]+'.'+name};}}
 if(typeof(nx[name])==='function'){return {fn:nx[name],self:nx,where:'nx.'+name};}
 return null;
}
function nxCall(name,args,cb){
 var f=nxFind(name);
 if(!f){if(cb){cb({absent:true,name:name});}return false;}
 function got(v){if(cb){cb({where:f.where,value:v});}}
 try{
  var r=f.fn.apply(f.self,(args||[]).concat([got]));
  if(r&&typeof(r.then)==='function'){r.then(got,function(e){got({error:String(e)});});}
  else if(r!==undefined){got(r);}
 }catch(e){got({error:String(e)});}
 return true;
}
function nxToken(v){
 if(!v){return null;}
 if(typeof(v)==='string'){return v.split('.').length===3?v:null;}
 return nxToken(v.idToken||v.id_token||v.naIdToken||v.nsaIdToken||v.token||null);
}
function brief(v){try{return String(JSON.stringify(v)).slice(0,400);}catch(e){return String(v).slice(0,400);}}
function report(o){try{fetch('/ashigaru/api/v1/diag',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});}catch(e){}}
function closeShop(){report({event:'close'});location.href='eshop://success';}
(function(){var c=document.getElementById('close');if(c){c.addEventListener('click',closeShop);}})();
`

// shopBridgeNames is what the diagnostic page probes: every bridge name the 22.5.0 systemWeb
// binary carries for the shop and its tokens (native-news-eshop-nso-gap-22.5.0 report,
// "window.nx bridge in 22.5.0"), plus the general nx helpers the same binary names. Names
// that appeared in older research but are absent from 22.5.0 (requestNaAuthToken and its
// cancel/cache/callback siblings, the device-account registration calls) are gone.
var shopBridgeNames = []string{
	// shop
	"prepareSpaceSizes", "getTotalSizeNand", "getTotalSizeSd", "getTotalSizeUsb",
	"getFreeSizeNand", "getFreeSizeSd", "getFreeSizeUsb", "requestDownloadTaskListOnEnd",
	"getApplicationContentMetaStatusArray", "requestCleanupAllPreInstalledApplications",
	"requestCleanupPreInstalledApplication", "cleanupDigitalBundles", "canJumpToLhubApplet",
	"requestUpdateNsaIdTokenCache", "getAdditionalQueryParameters", "setAdditionalQueryParameters",
	"setLanguage", "isInitialLaunchFinished", "notifyFinishInitialLaunch",
	"setInitialLaunchFinishedForCurrentAccount", "getAccountIdentificationTiming",
	"setAccountIdentificationTiming", "isPinCodeSetForAccountIdentification",
	"showIdentificationPinOnly", "showPinRegistrationForIdentificationIfNotSet",
	// rights
	"requestSyncRights", "cancelSyncRights", "requestLinkDevice", "requestUnlinkDevice",
	// tokens
	"requestNaIdToken", "ensureNaIdToken", "loadCachedNaIdToken", "requestEdgeToken",
	"setNsaIdTokenAvailableCallback", "requestNaTokenForProfile", "getNintendoAccountIdsOnDevice",
	"requestSignedDeviceIdentifierForNintendoAccount",
	// general
	"canHistoryBack", "footer", "isKeyboardShown", "open1ButtonDialog", "open2ButtonDialog",
	"playSystemSe", "dispatchEvent", "isUserOperationLocked", "lockUserOperation",
	"startCpuBoost", "cancelCpuBoost", "saveScreenshot", "sendMessage", "endApplet",
}

// shopDiagJS probes the bridge names and reports where each one lives and what the safe
// ones return. It never calls anything with side effects beyond identity: the point is a
// reproducible record of what this console's systemWeb provides (SHP-01).
var shopDiagJS = `
(function(){
var NAMES=` + mustJSON(shopBridgeNames) + `;
var probe={bridge:!!window.nx, href:String(location.href), found:{}, missing:[], namespaces:[], calls:{}, errors:[]};
try{
 if(window.nx){
  for(var k in window.nx){try{if(window.nx[k]&&typeof(window.nx[k])==='object'){probe.namespaces.push('nx.'+k);}}catch(e){}}
  for(var i=0;i<NAMES.length;i++){var f=nxFind(NAMES[i]);if(f){probe.found[NAMES[i]]=f.where;}else{probe.missing.push(NAMES[i]);}}
  if(window.nx.addEventListener){window.nx.addEventListener('message',function(e){
   probe.calls['event:message']=brief(e&&e.data);report(probe);});}
 } else {probe.errors.push('window.nx is undefined (standalone browser: the applet bridge is absent)');}
}catch(e){probe.errors.push(String(e));}
report(probe);
['requestNaIdToken','canJumpToLhubApplet','getAdditionalQueryParameters'].forEach(function(n){
 nxCall(n,[],function(r){if(r.absent){return;}
  var v=r.value;if(n==='requestNaIdToken'){v=nxToken(v)?'<token '+nxToken(v).length+' chars>':v;}
  probe.calls[n]=brief(v);report(probe);render();});
});
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function render(){
 var rows='';
 for(var i=0;i<NAMES.length;i++){var w=probe.found[NAMES[i]];
  rows+='<div class="row '+(w?'ok':'')+'"><span class="name">'+esc(NAMES[i])+'</span><span class="pill">'+esc(w||'absent')+'</span></div>';}
 if(!probe.bridge){rows='<div class="row bad"><span class="name">window.nx is undefined</span><span class="pill">standalone</span></div>'+rows;}
 var calls='';for(var c in probe.calls){calls+='<li>'+esc(c)+': '+esc(probe.calls[c])+'</li>';}
 var er=probe.errors.map(function(e){return '<li>'+esc(e)+'</li>';}).join('');
 document.getElementById('app').innerHTML='<h1>Bridge diagnostics</h1>'+
  '<p class="note">Probes reported to the server. Page: '+esc(probe.href)+'<br>Console: '+esc(navigator.userAgent)+'</p>'+
  '<p class="note">Objects on window.nx: '+esc(probe.namespaces.join(', ')||'none')+'</p>'+
  '<h2>Bridge functions</h2>'+rows+
  (calls?'<h2>Calls</h2><ul class="steps">'+calls+'</ul>':'')+
  (er?'<h2>Errors</h2><ul class="steps">'+er+'</ul>':'')+
  '<p class="note">Every request this applet makes lands in the nx-baas log.</p>';
}
render();
})();
`

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// storePage is the storefront's own shell, laid out like the console eShop: a sidebar with
// the brand block and sections, a two-column card grid, and a footer with the button hints.
// OpenPak's purple and blue replace Nintendo's red. Sized for the 1280x720 applet.
func storePage() string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=1280,initial-scale=1,maximum-scale=1,user-scalable=no"><title>OpenPak Shop</title>` +
		`<style>` + storeCSS + `</style></head><body>` +
		`<nav id="side"><div class="logo"><img src="` + logoDataURI + `" alt="">OpenPak Shop</div>` +
		`<button class="nav" data-view="highlights"><span class="ic">☆</span>Highlights</button>` +
		`<button class="nav" data-view="search"><span class="ic">⌕</span>Search</button>` +
		`<button class="nav" data-view="owned"><span class="ic">♡</span>Your Titles</button>` +
		`<div class="gap"></div>` +
		`<button class="nav sub" data-view="recent">Recent Releases</button>` +
		`<button class="nav sub" data-view="updates">Recently Updated</button>` +
		`</nav><section id="main"><div class="top"><span class="note">All titles are free</span>` +
		`<img id="who" class="who" alt="" hidden></div>` +
		`<div id="banner" class="banner"></div><div id="app"><p class="empty">Loading…</p></div></section>` +
		`<script>` + shopBridgeJS + footerJS + shopAppJS + `</script></body></html>`
}

const storeCSS = `
/* The website's design tokens (website/web/src/input.css, 2026-09 redesign), sized for the
   1280x~650 the console leaves the page: units are vh so the layout follows that height. */
:root{color-scheme:light dark;--paper:#f6f6f8;--raised:#fff;--paper-2:#f1f1f4;--ink:#0e0f14;--ink-2:#41444f;--muted:#6e717d;
--line:#e5e5ea;--line-2:#d3d4db;--accent:#4f46e5;--accent-2:#6366f1;--accent-weak:#eef0ff;--accent-line:#c7ccfb;
--ok:#15803d;--ok-weak:#e7f6ec;--ok-line:#b9e3c6;--bad:#b91c1c;--bad-weak:#fdecec;--bad-line:#f3c2c2;
--shadow-sm:0 1px 2px rgb(15 16 20/.05);--shadow:0 1px 2px rgb(15 16 20/.04),0 8px 24px -8px rgb(15 16 20/.10)}
@media (prefers-color-scheme:dark){:root{--paper:#0a0b0f;--raised:#121319;--paper-2:#181a21;--ink:#eceef3;--ink-2:#b4b8c3;--muted:#858a97;
--line:#22242d;--line-2:#2f323d;--accent:#818cf8;--accent-weak:#1a1d3a;--accent-line:#333a73;--ok:#4ade80;--ok-weak:#0f2418;--ok-line:#1f4a2f;
--bad:#f87171;--bad-weak:#2a1213;--bad-line:#572526;--shadow-sm:0 1px 2px rgb(0 0 0/.3);--shadow:0 1px 2px rgb(0 0 0/.3),0 8px 24px -8px rgb(0 0 0/.5)}}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--paper);color:var(--ink);overflow:hidden;
font:2.9vh/1.55 "Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
button{font:inherit;color:inherit;cursor:pointer}
#side{position:fixed;left:0;top:0;bottom:0;width:26vw;overflow-y:auto;padding:2.4vh 1.4vw;border-right:1px solid var(--line)}
.logo{display:flex;align-items:center;gap:1vw;font-weight:750;letter-spacing:-.02em;font-size:3.4vh;padding:0 .8vw 2.6vh}
.logo img{width:5.6vh;height:5.6vh}
.nav{display:flex;align-items:center;gap:1vw;width:100%;margin:.4vh 0;padding:1.3vh 1.3vw;background:none;
border:1px solid transparent;border-radius:999px;text-align:left;font-weight:600;font-size:3vh;color:var(--ink-2)}
.nav.sub{font-size:2.6vh;padding:1vh 1.3vw;font-weight:500}
.nav .ic{width:2.2vw;text-align:center}
.nav.on{background:var(--raised);border-color:var(--line);box-shadow:var(--shadow-sm);color:var(--ink)}
.gap{height:1.2vh;border-bottom:1px solid var(--line);margin:0 1vw 1.2vh}
#main{position:fixed;left:26vw;right:0;top:0;bottom:0;overflow-y:auto;padding:0 3vw 4vh}
.top{display:flex;align-items:center;justify-content:space-between;height:11vh}
.note{color:var(--muted);font-size:2.2vh;font-weight:700;letter-spacing:.09em;text-transform:uppercase}
.who{width:8vh;height:8vh;border-radius:50%;border:2px solid var(--raised);box-shadow:0 0 0 1px var(--line-2),var(--shadow);object-fit:cover;background:var(--raised)}
.banner{display:none;background:var(--bad-weak);border:1px solid var(--bad-line);color:var(--bad);border-radius:16px;padding:1.6vh 1.6vw;margin-bottom:2vh;font-size:2.4vh}
h1{font-size:5vh;font-weight:750;letter-spacing:-.03em;line-height:1.1;margin:0 0 2.4vh}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:2.8vh 1.6vw}
.card{position:relative;display:block;width:100%;padding:0;background:var(--raised);border:1px solid var(--line);border-radius:20px;
overflow:hidden;text-align:left;box-shadow:var(--shadow-sm)}
.strip{position:absolute;z-index:1;top:1.6vh;left:1.2vw;display:inline-flex;align-items:center;gap:.5vw;padding:.3vh .9vw;border-radius:999px;
font-size:1.9vh;font-weight:650;background:rgb(255 255 255/.85);color:var(--accent);border:1px solid var(--accent-line)}
.art{position:relative;height:30vh;overflow:hidden;
background:radial-gradient(circle at 30% 30%,#818cf8,transparent 55%),radial-gradient(circle at 80% 80%,#ec4899,transparent 50%),linear-gradient(135deg,#312e81,#4f46e5)}
.art .blur{position:absolute;inset:-4vh;background-size:cover;background-position:center;filter:blur(3vh) saturate(1.2);opacity:.35}
.art img{position:relative;display:block;height:20vh;width:20vh;margin:5vh auto;border-radius:22%;box-shadow:0 24px 48px -16px rgb(15 16 20/.45)}
.cap{display:flex;align-items:center;justify-content:space-between;gap:1vw;padding:1.8vh 1.4vw;font-size:2.9vh;font-weight:650;letter-spacing:-.01em}
.cap .n{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.badge{flex:none;display:inline-flex;align-items:center;gap:.4vw;padding:.3vh .9vw;border-radius:999px;font-size:1.9vh;font-weight:650;
background:var(--accent-weak);border:1px solid var(--accent-line);color:var(--accent)}
.badge::before{content:"";width:.9vh;height:.9vh;border-radius:50%;background:currentColor}
.badge.own{background:var(--ok-weak);border-color:var(--ok-line);color:var(--ok)}
.detail{display:grid;grid-template-columns:40vh 1fr;gap:2.6vw;background:var(--raised);border:1px solid var(--line);border-radius:20px;padding:3vh 2vw;box-shadow:var(--shadow-sm)}
.detail .art{height:40vh;border-radius:16px}
.detail .art img{width:26vh;height:26vh;margin:7vh auto}
.detail h1{margin:0 0 .6vh}
.pub{color:var(--muted);margin:0 0 2vh}
.desc{margin:0 0 2.4vh;font-size:2.6vh;color:var(--ink-2)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.6vh 1.6vw;font-size:2.4vh;margin-bottom:3vh}
.kv b{color:var(--muted);font-weight:500}
.act{display:inline-flex;align-items:center;justify-content:center;min-height:7vh;padding:0 2.4vw;border-radius:999px;font-weight:600;font-size:2.8vh;
color:#fff;border:1px solid #4338ca;background:linear-gradient(180deg,#6366f1,#4338ca);
box-shadow:0 1px 0 rgb(255 255 255/.2) inset,0 6px 16px -6px rgb(79 70 229/.6)}
.act.plain{background:var(--raised);color:var(--ink);border-color:var(--line-2);box-shadow:var(--shadow-sm)}
.msg{color:var(--ink-2);font-size:2.6vh}
.empty{color:var(--muted);font-size:2.8vh;padding:4vh 0}
.search{width:100%;font:inherit;font-size:3vh;min-height:7vh;padding:0 1.6vw;border:1px solid var(--line-2);border-radius:12px;margin-bottom:2.6vh;
background:var(--raised);color:var(--ink)}
.nav:focus,.card:focus,.act:focus,.search:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 .6vh var(--accent-weak),0 0 0 .9vh var(--accent-line)}
.card:focus{transform:translateY(-2px)}
`

// shopAppJS is the storefront (SHP-02): sections, catalog cards, details, acquisition,
// downloads, and the scene views systemWeb opens on savanna. The catalog renders at once;
// the account is asked for in the background and the view refreshes when it arrives, so a
// slow or unanswered bridge never holds the shop closed. Bridge calls are guarded: without
// window.nx (a plain browser) acquisition is refused rather than faked (SHP-04).
const shopAppJS = `
(function(){
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function $(id){return document.getElementById(id);}
var app=$('app'), banner=$('banner');
var token=null, lang=(navigator.language||'en-US'), catalog=null, view=null, back=null;
function show(m){banner.style.display='block';banner.textContent=m;}
function hide(){banner.style.display='none';}
function api(path,opts){opts=opts||{};opts.headers=opts.headers||{};if(token)opts.headers['Authorization']='Bearer '+token;
 return fetch('/ashigaru/api/v1'+path,opts).then(function(r){return r.json().then(function(b){return {status:r.status,body:b};});});}
function query(){var o={},s=location.search.replace(/^\?/,'').split('&');
 for(var i=0;i<s.length;i++){if(!s[i])continue;var kv=s[i].split('=');o[decodeURIComponent(kv[0])]=decodeURIComponent((kv[1]||'').replace(/\+/g,' '));}
 return o;}
var Q=query();
var bridge={present:typeof(window.nx)!=='undefined'};

// Account handoff. On 22.5.0 the console carries nx.shop.requestNaIdToken, and calling it
// with only a callback throws "Not enough arguments" (hardware, 2026-09-23). Its parameters
// are not recovered, so the likely shapes are tried in turn; the first that does not throw,
// the function's declared length and what came back are reported, so the next console run
// names the real signature. The shop does not wait for any of it.
function identify(done){
 if(!bridge.present){return;}
 function take(r){
  var t=nxToken(r&&r.value);
  report({event:'identify',where:r&&r.where,absent:!!(r&&r.absent),token:!!t,shape:t?'':brief(r&&r.value)});
  if(t&&!token){token=t;done();}
 }
 nxCall('setNsaIdTokenAvailableCallback',[],take);
 var f=nxFind('requestNaIdToken')||nxFind('ensureNaIdToken');
 if(!f){return;}
 var CB={};
 var tries=[[CB],[false,CB],[true,CB],[CB,CB],['',CB],[{},CB]];
 for(var i=0;i<tries.length;i++){
  var args=tries[i].map(function(a){return a===CB?function(v){take({where:f.where,value:v});}:a;});
  try{
   var r=f.fn.apply(f.self,args);
   report({event:'identify_call',where:f.where,declared:f.fn.length,tried:i,returned:brief(r)});
   if(r&&typeof(r.then)==='function'){r.then(function(v){take({where:f.where,value:v});},function(e){take({where:f.where,value:{error:String(e)}});});}
   else if(r!==undefined){take({where:f.where,value:r});}
   return;
  }catch(e){report({event:'identify_call',where:f.where,declared:f.fn.length,tried:i,error:String(e)});}
 }
}

// The user's own picture, top right, once the account is known.
function avatar(){
 fetch('/ashigaru/api/v1/me/avatar',{headers:{'Authorization':'Bearer '+token}}).then(function(r){return r.ok?r.blob():null;}).then(function(b){
  if(!b){return;}var i=$('who');i.src=URL.createObjectURL(b);i.hidden=false;}).catch(function(){});
}
function human(n){if(n>1073741824)return (n/1073741824).toFixed(2)+' GB';if(n>1048576)return (n/1048576).toFixed(1)+' MB';if(n>1024)return (n/1024).toFixed(0)+' KB';return n+' B';}
var DAY=86400;
function isNew(t){return t.updated_at&&(Date.now()/1000-t.updated_at)<30*DAY;}
function load(){
 if(catalog){return Promise.resolve(catalog);}
 return api('/catalog?lang='+encodeURIComponent(lang)).then(function(r){
  if(r.status!==200){throw new Error(String(r.status));}
  catalog=r.body.titles||[];return catalog;});
}
function select(v){
 var b=document.querySelectorAll('.nav');
 for(var i=0;i<b.length;i++){b[i].className=b[i].className.replace(/ on/g,'')+(b[i].getAttribute('data-view')===v?' on':'');}
}
function art(t){return '<div class="art"><div class="blur" style="background-image:url('+esc(t.icon)+')"></div><img src="'+esc(t.icon)+'" alt=""></div>';}
function card(t){
 var badge=t.ownership==='owned'?'<span class="badge own">OWNED</span>':(isNew(t)?'<span class="badge">NEW</span>':'');
 return '<button class="card" data-tid="'+esc(t.title_id)+'"><div class="strip">'+esc(t.category||'Homebrew')+'</div>'+
  art(t)+'<div class="cap"><span class="n">'+esc(t.name)+'</span>'+badge+'</div></button>';
}
function wire(){
 var b=app.querySelectorAll('.card');
 for(var j=0;j<b.length;j++){b[j].addEventListener('click',function(){detail(this.getAttribute('data-tid'));});}
}
function grid(ts,title,empty){
 app.innerHTML=(title?'<h1>'+title+'</h1>':'')+(ts.length?'<div class="grid">'+ts.map(card).join('')+'</div>':'<p class="empty">'+empty+'</p>');
 wire();
}
function section(v,focusFirst){
 view=function(){section(v,false);}; back=null; select(v); hide();
 if(v==='nso'){return info('Nintendo Switch Online','Memberships are not sold on OpenPak: online play and every other Nintendo Switch Online feature are already included with your OpenPak account.');}
 if(v==='redeem'){return info('Redeem Code','Codes are not needed on OpenPak: every title in this shop is free to get.');}
 if(v==='search'){return search();}
 load().then(function(ts){
  ts=ts.slice();
  if(v==='owned'){
   if(!token){return info('Your Titles','Sign-in has not reached the shop yet, so it cannot tell which titles are yours.');}
   return grid(ts.filter(function(t){return t.ownership==='owned';}),'Your Titles','You have no titles from this shop yet.');
  }
  if(v==='recent'||v==='updates'){ts.sort(function(a,b){return (b.updated_at||0)-(a.updated_at||0);});
   return grid(ts,v==='recent'?'Recent Releases':'Recently Updated','Nothing here yet.');}
  grid(ts,'','The shop is empty for now.');
  if(focusFirst){var c=app.querySelector('.card');if(c){c.focus();}}
 }).catch(function(e){show('The shop could not be reached ('+e.message+').');app.innerHTML='';});
}
function search(){
 app.innerHTML='<input class="search" id="q" placeholder="Search the OpenPak Shop" autocomplete="off"><div id="res"></div>';
 var q=$('q');
 function run(){load().then(function(ts){var s=q.value.trim().toLowerCase();
  var hit=s?ts.filter(function(t){return (t.name+' '+(t.publisher||'')).toLowerCase().indexOf(s)>=0;}):[];
  $('res').innerHTML=s?(hit.length?'<div class="grid">'+hit.map(card).join('')+'</div>':'<p class="empty">No titles match “'+esc(q.value)+'”.</p>'):'';
  wire();});}
 q.addEventListener('input',run);q.addEventListener('change',run);q.focus();
}
function info(h,body){
 app.innerHTML='<h1>'+esc(h)+'</h1><p class="msg">'+esc(body)+'</p>';
}
function detail(tid){
 var from=view; hide();
 view=function(){detail(tid);}; back=function(){from();};
 app.innerHTML='<p class="empty">Loading…</p>';
 api('/catalog/'+encodeURIComponent(tid)+'?lang='+encodeURIComponent(lang)).then(function(r){
  var t=r.body;
  if(r.status!==200||!t){show('This title is not in the OpenPak shop.');return section('highlights',true);}
  var own=t.ownership, act='';
  if(own==='owned'){act='<button class="act" id="dl">Download</button>';}
  else if(own==='revoked'){act='<p class="msg">This title is no longer licensed on this account.</p>';}
  else if(!bridge.present){act='<p class="msg">Getting titles needs the console. This page is open in a plain browser.</p>';}
  else{act='<button class="act" id="acq">Free Download</button>';}
  app.innerHTML='<div class="detail">'+art(t)+'<div><h1>'+esc(t.name)+'</h1><p class="pub">'+esc(t.publisher||'')+'</p>'+
   (t.description?'<p class="desc">'+esc(t.description)+'</p>':'')+
   '<div class="kv"><b>Size</b><span>'+human(t.size_bytes||0)+'</span>'+
   '<b>Version</b><span>'+esc(t.version_label||t.version)+'</span>'+
   '<b>Play modes</b><span>'+esc((t.compatibility||[]).join(', ')||'—')+'</span>'+
   '<b>Languages</b><span>'+esc((t.languages||[]).join(', ')||'—')+'</span></div>'+act+'</div></div>';
  var a=$('acq')||$('dl');
  if($('acq')){$('acq').addEventListener('click',function(){acquire(t);});}
  if($('dl')){$('dl').addEventListener('click',function(){startDownload(t);});}
  if(a){a.focus();}
 }).catch(function(){show('This title could not be reached.');});
}

function acquire(t){
 hide(); app.innerHTML='<p class="empty">Getting '+esc(t.name)+'…</p>';
 api('/catalog/'+t.title_id+'/acquire',{method:'POST'}).then(function(r){
  if(r.status===200){
   report({event:'acquired',title_id:t.title_id,elicense_id:r.body.elicense_id,already_owned:r.body.already_owned});
   catalog=null; startDownload(t);
  }else{
   show('Could not get it: '+((r.body.error&&r.body.error.message)||r.status));
   detail(t.title_id);
  }
 });
}

// The native chain after an acquisition: requestSyncRights makes NIM fetch the account's
// rights from dragons, then requestDownloadTaskListOnEnd makes it fetch its download list
// from pushmo, which lists the task created here. The page only hands over; the download
// itself is NIM's.
function syncRights(next){
 var moved=false; function go(){if(!moved){moved=true;next();}}
 if(!nxCall('requestSyncRights',[],function(r){report({event:'sync_rights',where:r.where,absent:!!r.absent,result:brief(r.value)});go();})){go();return;}
 setTimeout(go,8000);
}
function handOff(t){
 if(!nxCall('requestDownloadTaskListOnEnd',[],function(r){report({event:'download_task_list',where:r.where,absent:!!r.absent,result:brief(r.value)});})){
  report({event:'download_task_list',absent:true});
 }
}
function startDownload(t){
 hide(); app.innerHTML='<p class="empty">Preparing download…</p>';
 api('/tasks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title_id:t.title_id})}).then(function(r){
  if(r.status!==200){show('Download refused: '+((r.body.error&&r.body.error.message)||r.status));detail(t.title_id);return;}
  var id=r.body.id;
  syncRights(function(){
   handOff(t);
   app.innerHTML='<div class="detail">'+art(t)+'<div><h1>'+esc(t.name)+'</h1>'+
    '<p class="msg">The download has started. Progress shows on the HOME Menu, and you can close the shop.</p>'+
    '<button class="act" id="done">Close the shop</button> <button class="act plain" id="cancel">Cancel download</button></div></div>';
   $('done').addEventListener('click',closeShop);
   $('cancel').addEventListener('click',function(){api('/tasks/'+id+'/cancel',{method:'POST'}).then(function(){handOff(t);detail(t.title_id);});});
   $('done').focus();
  });
 });
}

// The controller: B goes back one step, and from a section it leaves the shop.
document.addEventListener('keydown',function(e){
 var k=e.key||e.keyCode;
 if(e.target&&e.target.id==='q'&&(k==='Backspace'||k===8)){return;}
 if(k==='Escape'||k==='Backspace'||k===27||k===8){e.preventDefault();if(back){back();}else{closeShop();}}
});
nxFooterSetup({B:function(){if(back){back();}else{closeShop();}}},report);
var navs=document.querySelectorAll('.nav');
for(var i=0;i<navs.length;i++){navs[i].addEventListener('click',function(){section(this.getAttribute('data-view'),true);});}

// The scene systemWeb opened, from the savanna path (bugyo's /ashigaru/ lands on the top).
// OpenPak's shop carries homebrew and its updates only: add-on content, tickets,
// subscriptions, memberships and codes are Nintendo's commerce, and their scenes say so.
function route(){
 var p=location.pathname.replace(/\/$/,''), m;
 if(/^\/detail\/application_items\//.test(p)||/^\/catalog_tickets\//.test(p)){section('highlights');return info('Not available on OpenPak','This part of the Nintendo eShop is not available on OpenPak. The OpenPak shop carries free homebrew and its updates.');}
 if((m=p.match(/^\/detail\/([^\/]+)/))){section('highlights');return detail(decodeURIComponent(m[1]).toLowerCase());}
 if(Q.dst_app_id){section('highlights');return detail(Q.dst_app_id.toLowerCase());}
 if(p==='/my'||p==='/shelf'){return section('owned',true);}
 if(p==='/membership'||Q.landing_page==='nso'){return section('nso');}
 if(p==='/redeem/input'){return section('redeem');}
 section('highlights');
 var h=document.querySelector('.nav');if(h){h.focus();}
}

if(!bridge.present){show('This is the console shop opened in a plain browser: browsing works, getting titles does not.');}
report({event:'page',path:location.pathname,query:location.search,bridge:bridge.present});
route();
identify(function(){catalog=null;avatar();report({event:'identified'});if(view){view();}});
})();
`
