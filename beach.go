package main

// Beach, dragons, dragonst and tigers: the rights side of the native store journey.
//
// The native chain an acquisition drives (public research: kinnay's Beach-Server,
// Dragons-Servers and Atum-Server wiki pages, accessed 2026-09-11; the 22.5.0 NIM strings
// in the private scan agree route for route):
//
//	shop page  -> window.nx.shop.requestLinkDevice   -> NIM -> beach  /v1/my/devices/hac/link
//	            -> window.nx.shop.requestSyncRights  -> NIM -> dragons rights/publish_elicenses,
//	                                                           tigers /v1/etickets/publish
//	            -> download                          -> NIM -> dragonst edge_token/issue,
//	                                                           atum content (atum.go)
//
// Shapes marked "wiki" below come from that public research. Shapes marked hypothesis are
// our own minimal answers where the research is silent; each one is a named open question
// in docs/native-shop.md, to be settled by a hardware capture before native acceptance.
// The one thing this file will not do is fake a native install: /v1/etickets/publish needs
// Nintendo-trusted ticket signatures that cannot be minted here, so it records and answers
// with a documented error until the packaging/trust spike concludes (SHP-04).
//
// This file also owns the beach host, extracted from penne.go's placeholder (which answered
// every beach request with `{}`) — the extraction agreed with A/B: penne.go keeps its other
// cases untouched.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// beachDeviceLink is the durable beach registration: which device is linked to which
// account, and the penne/notification identifiers NIM registered through it. Persisted so
// a restart does not unlink a console (the audit's echo-without-saving finding, for the
// beach share of that surface; penne's own registrations belong to B and read this table).
type beachDeviceLink struct {
	DeviceID          string `json:"device_id"`
	AccountID         string `json:"account_id"` // Nintendo Account id
	BaasUserID        string `json:"baas_user_id"`
	PenneID           string `json:"penne_id,omitempty"`
	NotificationToken string `json:"notification_token,omitempty"`
	LinkedAt          int64  `json:"linked_at"`
	UpdatedAt         int64  `json:"updated_at"`
}

// deviceLinks lives on the server struct's shop state document so it persists with the
// store. (Held in shopState to keep one persistence path for the whole store workstream.)
type deviceLinkTable struct {
	Links []*beachDeviceLink `json:"device_links"`
}

func (s *shopState) linkDevice(deviceID, accountID, baasUserID string) *beachDeviceLink {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for _, l := range s.Links.Links {
		if l.DeviceID == deviceID && l.AccountID == accountID {
			l.UpdatedAt = now
			if l.BaasUserID == "" {
				l.BaasUserID = baasUserID
			}
			s.save()
			return l
		}
	}
	l := &beachDeviceLink{DeviceID: deviceID, AccountID: accountID, BaasUserID: baasUserID, LinkedAt: now, UpdatedAt: now}
	s.Links.Links = append(s.Links.Links, l)
	s.save()
	return l
}

func (s *shopState) linkFor(deviceID, accountID string) *beachDeviceLink {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.Links.Links {
		if l.DeviceID == deviceID && (accountID == "" || l.AccountID == accountID) {
			return l
		}
	}
	return nil
}

func (s *shopState) linksForAccount(accountID string) []*beachDeviceLink {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*beachDeviceLink
	for _, l := range s.Links.Links {
		if l.AccountID == accountID {
			out = append(out, l)
		}
	}
	return out
}

func (s *shopState) setLinkRegistration(deviceID, accountID, field, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.Links.Links {
		if l.DeviceID != deviceID || (accountID != "" && l.AccountID != accountID) {
			continue
		}
		switch field {
		case "penne":
			l.PenneID = value
		case "notification_token":
			l.NotificationToken = value
		}
		l.UpdatedAt = time.Now().Unix()
	}
	s.save()
}

// beachErr answers in the error shape the Beach wiki documents: {"error":{code,message}}.
func beachErr(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

// beach serves beach.hac.lp1.eshop.nintendo.net. Wiki: beach requires a device certificate
// and a device token. Our consoles' certificates are not Nintendo-signed, so authentication
// here is the adapter's device identity (the dauth device token, DeviceAuthorization) and,
// where the method is account-scoped, the Nintendo-Account-Id header bound to a verified NA
// id token when one is presented. A capture of the real header set on hardware supersedes
// this; the routes and state effects below are the part that must not drift.
func (s *server) beach(w http.ResponseWriter, r *http.Request, body []byte) {
	if s.shop == nil {
		s.shop = newShopState("")
	}
	device := s.deviceIdentity(r)
	p := r.URL.Path
	log.Printf("[shop] beach %s %s device=%s", r.Method, p, device)

	// Device-scoped registrations. wiki: /v1/devices/<id>/notification_token/register;
	// NIM strings add /v1/devices/<id>/penne_id/register.
	if strings.HasPrefix(p, "/v1/devices/") && (strings.HasSuffix(p, "/notification_token/register") || strings.HasSuffix(p, "/penne_id/register")) {
		var in map[string]any
		json.Unmarshal(body, &in)
		field, value := "", str(in, "penne_id")
		if strings.HasSuffix(p, "/penne_id/register") {
			field = "penne"
		} else {
			field, value = "notification_token", str(in, "notification_token")
		}
		if value == "" {
			beachErr(w, 400, "1000", "missing value")
			return
		}
		// Persist for the named device across its linked accounts (the request carries no
		// account of its own).
		s.shop.setLinkRegistration(seg(p, 2), "", field, value)
		w.WriteHeader(200)
		return
	}

	// Account-scoped surface: needs a Nintendo account id to act on.
	account, baasUser := s.shopPrincipal(r)
	switch {
	case p == "/v1/my/devices" && r.Method == "GET":
		links := []*beachDeviceLink{}
		if account != "" {
			links = s.shop.linksForAccount(account)
		}
		// wiki lists the method but not the response; devices is the minimal self-evident
		// container. Hypothesis to settle on hardware.
		writeJSON(w, 200, map[string]any{"devices": linkObjs(links)})
	case p == "/v1/my/devices/hac/link" && r.Method == "POST":
		if account == "" || device == "" {
			beachErr(w, 401, "1002", "device and account identity required")
			return
		}
		l := s.shop.linkDevice(device, account, baasUser)
		log.Printf("[shop] beach: linked device %s to account %s (at %d)", l.DeviceID, l.AccountID, l.LinkedAt)
		writeJSON(w, 200, map[string]any{"device": linkObj(l)})
	case p == "/v1/my/devices/hac/unlink_all" && r.Method == "POST":
		if account == "" {
			beachErr(w, 401, "1002", "account identity required")
			return
		}
		for _, l := range s.shop.linksForAccount(account) {
			s.shop.setLinkRegistration(l.DeviceID, l.AccountID, "penne", "")
		}
		s.shop.mu.Lock()
		kept := s.shop.Links.Links[:0]
		for _, l := range s.shop.Links.Links {
			if l.AccountID != account {
				kept = append(kept, l)
			}
		}
		s.shop.Links.Links = kept
		s.shop.save()
		s.shop.mu.Unlock()
		w.WriteHeader(200)
	case p == "/v1/devices/hac/unlink" && r.Method == "POST":
		if device == "" {
			beachErr(w, 401, "1002", "device identity required")
			return
		}
		s.shop.mu.Lock()
		kept := s.shop.Links.Links[:0]
		for _, l := range s.shop.Links.Links {
			if l.DeviceID != device {
				kept = append(kept, l)
			}
		}
		s.shop.Links.Links = kept
		s.shop.save()
		s.shop.mu.Unlock()
		w.WriteHeader(200)
	case p == "/v1/my/membership/free_trial_availability" && r.Method == "GET":
		// OpenPak's catalog has no membership gate; availability false is the honest
		// constant until a capture names the real shape.
		writeJSON(w, 200, map[string]any{"is_available": false})
	// "Has this device redeemed its bundle / its pre-installed software?"
	// [firmware, nim 0x234540: the reply must carry both $.digital_bundle and
	// $.pre_install as booleans, or NIM fails the call; each false becomes a
	// "not yet redeemed" flag handed back to its caller]. Nothing on a console
	// is ever redeemed through OpenPak, so both are false. That is the literal
	// answer, and it is the safe one: "true" would say the pre-installed
	// software was settled, which is what the shop's cleanup bridge calls act on.
	// The old {"redeemed":false} lacked both keys, so NIM rejected it.
	case p == "/v1/devices/redeemed_status":
		log.Printf("[shop] beach %s %s -> nothing redeemed (digital_bundle=false, pre_install=false)", r.Method, p)
		writeJSON(w, 200, map[string]any{"digital_bundle": false, "pre_install": false})
	case p == "/v1/devices/target/set", p == "/v1/devices/target/clear":
		log.Printf("[shop] beach %s %s -> accepted, no download targeting implemented", r.Method, p)
		w.WriteHeader(http.StatusOK)
	// "Which titles came with this device's bundle?" [firmware, nim 0x234bd0,
	// reply handler at 0x328ed8: $.contents is an array of at most 64
	// {application_id (hex string), is_upgrade_edition (bool), redeemed (bool)},
	// and a top-level $.redeemed bool; shop_id is always 4 on hac]. OpenPak
	// sells no bundles, so the collection is empty and nothing is redeemed.
	case p == "/v1/devices/digital_bundle/contents":
		log.Printf("[shop] beach %s %s shop_id=%q -> no bundled contents", r.Method, p, r.URL.Query().Get("shop_id"))
		writeJSON(w, 200, map[string]any{"contents": []any{}, "redeemed": false})
	case p == "/v1/rom_cards" && r.Method == "GET", p == "/v1/rom_cards" && r.Method == "POST",
		p == "/v1/rom_cards/register" && r.Method == "POST":
		// Physical-card registration is not part of the digital catalog journey.
		writeJSON(w, 200, map[string]any{"rom_cards": []any{}})
	default:
		dump(r, body, "!! UNHANDLED beach")
		beachErr(w, 404, "1001", "api not found")
	}
}

func linkObjs(links []*beachDeviceLink) []map[string]any {
	out := make([]map[string]any, 0, len(links))
	for _, l := range links {
		out = append(out, linkObj(l))
	}
	return out
}

func linkObj(l *beachDeviceLink) map[string]any {
	return map[string]any{"device_id": l.DeviceID, "linked_at": l.LinkedAt, "updated_at": l.UpdatedAt}
}

// seg returns the n-th path segment (slash-split, 0 = "v1"-style first element).
func seg(p string, n int) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if n < len(parts) {
		return parts[n]
	}
	return ""
}

// deviceIdentity is the console's id for a shop request: the dauth device token's sub when
// presented, else the SDK User-Agent's did. Never a path/body value: a client cannot name
// someone else's device into the link.
func (s *server) deviceIdentity(r *http.Request) string {
	if c := s.bearerHeader(r, "DeviceAuthorization"); c != nil {
		if sub := str(c, "sub"); sub != "" {
			return sub
		}
	}
	return deviceIDFromUA(r.UserAgent())
}

// shopPrincipal resolves the account acting on a shop request: a verified NA id token (or
// our own BAAS-issued NSA id token) in Authorization or Nintendo-Nsa-Id-Token, corroborated
// by the Nintendo-Account-Id header when present. A header id without a token is not trusted (principal binding).
func (s *server) shopPrincipal(r *http.Request) (accountID, baasUserID string) {
	accountID, baasUserID = s.shopPrincipalUnchecked(r)
	// A banned account is nobody to the store: no acquisition, no tasks, no ownership.
	if accountID != "" && s.naLock(accountID) != "" {
		log.Printf("[shop] principal: account %s is locked; refusing", accountID)
		return "", ""
	}
	return accountID, baasUserID
}

func (s *server) shopPrincipalUnchecked(r *http.Request) (accountID, baasUserID string) {
	headerID := r.Header.Get("Nintendo-Account-Id")
	for _, h := range []string{"Authorization", "Nintendo-Nsa-Id-Token"} {
		claims := s.bearerHeader(r, h)
		if claims == nil {
			continue
		}
		sub := str(claims, "sub")
		iss := str(claims, "iss")
		// The shop page may hold the network service account's id token instead
		// (systemWeb's setNsaIdTokenAvailableCallback): our BAAS signs it, its subject
		// is the BAAS user, and that user carries the Nintendo Account id.
		if iss == baasIssuer && str(claims, "typ") == "id_token" && s.store != nil {
			if u := s.store.User(sub); u != nil && u.NaID != "" {
				if headerID != "" && headerID != u.NaID {
					log.Printf("[shop] principal: header %s disagrees with nsa token's account %s; refusing", headerID, u.NaID)
					return "", ""
				}
				return u.NaID, u.ID
			}
			continue
		}
		// NA id tokens come from our accounts.nintendo.com surface; a token from anywhere
		// else does not name an account here.
		if sub == "" || iss != naIssuer {
			continue
		}
		if headerID != "" && headerID != sub {
			log.Printf("[shop] principal: header %s disagrees with token sub %s; refusing", headerID, sub)
			return "", ""
		}
		// Map the NA id to this adapter's BAAS user so entitlement rows carry both.
		if pid := s.store.PIDForNA(sub); pid != 0 {
			if u := s.store.UserByPID(pid); u != nil {
				return sub, u.ID
			}
		}
		return sub, ""
	}
	return "", ""
}

// bearerHeader verifies one of our own JWTs from "Bearer <token>" on the named header.
func (s *server) bearerHeader(r *http.Request, header string) map[string]any {
	v := r.Header.Get(header)
	if !strings.HasPrefix(v, "Bearer ") {
		return nil
	}
	c, err := parseJWT(strings.TrimPrefix(v, "Bearer "), &s.key.PublicKey)
	if err != nil {
		return nil
	}
	return c
}

// ---------- dragons / dragonst / tigers ----------

// dragonsError answers in the problem shape the dragons wiki documents:
// {type,title,detail,number} with a problems.dragons.nintendo.net URI. We keep the URI
// pattern (it is the documented error contract) and the codes our own clients act on.
func dragonsError(w http.ResponseWriter, status int, code, title, detail string) {
	writeJSON(w, status, map[string]any{
		"type":  fmt.Sprintf("https://problems.dragons.nintendo.net/errors/v1/%d/%s", status, code),
		"title": title, "detail": detail, "number": status,
	})
}

// dragonsEdgeToken is what dragonst mints and atum c2 verifies: our own JWT naming the
// device, the titles it may fetch and a 6-hour life (wiki: expires_in 21600).
func (s *server) dragonsEdgeToken(deviceID string, titleIDs []string) string {
	now := time.Now().Unix()
	ids := []string{}
	for _, t := range titleIDs {
		if validTitleID(t) {
			ids = append(ids, t)
		}
	}
	return signJWT(
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.idKid},
		map[string]any{
			"iss": "lp1.dragons.nintendo.net", "sub": deviceID, "aud": "atum",
			"iat": now, "exp": now + 21600, "jti": uuid4(), "title_ids": ids,
		}, s.key)
}

// verifyDragonsEdgeToken checks a c2 request's X-Nintendo-DenebEdgeToken: our signature,
// unexpired, and (when the caller knows the title) bound to that title.
func (s *server) verifyDragonsEdgeToken(header, titleID string) (deviceID string, ok bool) {
	if !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	c, err := parseJWT(strings.TrimPrefix(header, "Bearer "), &s.key.PublicKey)
	if err != nil {
		return "", false
	}
	if str(c, "aud") != "atum" || int64(numf(c, "exp")) < time.Now().Unix() {
		return "", false
	}
	device := str(c, "sub")
	if titleID != "" {
		found := false
		for _, t := range c["title_ids"].([]any) {
			if fmt.Sprintf("%v", t) == titleID {
				found = true
				break
			}
		}
		if !found {
			return device, false
		}
	}
	return device, true
}

func numf(m map[string]any, k string) float64 {
	if m == nil {
		return 0
	}
	f, _ := m[k].(float64)
	return f
}

// shopRightsRoute: the dragons rights routes the store workstream owns. Everything else on
// the dragons host stays with the dauth handler's setup-critical answers (they keep the
// working console link alive); these are the acquisition surface (SHP-03) and the edge
// token issuer, which NIM may address on dragons. as well as dragonst.
func shopRightsRoute(p string) bool {
	p = strings.TrimPrefix(p, "/v2")
	p = strings.TrimPrefix(p, "/v1")
	return p == "/rights/publish_elicenses" || p == "/rights/available_elicenses" || p == "/elicenses/revoke" ||
		p == "/edge_token/issue" || p == "/edge_token/issuable_titles"
}

// dragons serves the dragons family: dragons.hac.* (elicense/rights), dragonst.hac.*
// (edge tokens), tigers.hac.* (eticket publish). API version is v2 on 22.5.0 (wiki: v2
// from 20.0.0); /v1/ is served identically so older captures still parse.
func (s *server) dragons(w http.ResponseWriter, r *http.Request, body []byte) {
	if s.shop == nil {
		s.shop = newShopState("")
	}
	host, p := hostOf(r), r.URL.Path
	device := s.deviceIdentity(r)
	p = strings.TrimPrefix(p, "/v1")
	p = strings.TrimPrefix(p, "/v2")
	log.Printf("[shop] dragons %s %s host=%s device=%s", r.Method, p, shortHost(host), device)

	switch {
	// dragonst: the edge token issuer for c2 content. wiki: {title_ids, na_id_tokens,
	// vendor} -> {expires_in, dragons_edge_token, title_ids}.
	// Any of the three rights hosts: NIM names the issuer by configuration, and a token
	// request that reached dragons. or tigers. used to fall to the 404 below.
	case p == "/edge_token/issue" && r.Method == "POST":
		var in struct {
			TitleIDs []string `json:"title_ids"`
		}
		json.Unmarshal(body, &in)
		if device == "" {
			dragonsError(w, 401, "unauthorized", "device authorization required", "")
			return
		}
		// Only titles this console's linked accounts own may be tokenized (authorized
		// content delivery, SHP-04). An unlinked device gets nothing.
		allowed := []string{}
		for _, tid := range in.TitleIDs {
			tid = strings.ToLower(tid)
			if !validTitleID(tid) {
				continue
			}
			// An update rides its application's entitlement.
			if s.shop.deviceOwnsTitle(device, s.shop.applicationFor(tid)) {
				allowed = append(allowed, tid)
			}
		}
		writeJSON(w, 200, map[string]any{
			"expires_in": 21600, "dragons_edge_token": s.dragonsEdgeToken(device, allowed), "title_ids": allowed,
		})
	case p == "/edge_token/issuable_titles" && r.Method == "POST":
		var in struct {
			ApplicationIDs []string `json:"application_ids"`
		}
		json.Unmarshal(body, &in)
		allowed := []string{}
		for _, tid := range in.ApplicationIDs {
			if validTitleID(tid) && s.shop.deviceOwnsTitle(device, s.shop.applicationFor(tid)) {
				allowed = append(allowed, tid)
			}
		}
		// Response shape hypothesis: the wiki documents the request only.
		writeJSON(w, 200, map[string]any{"title_ids": allowed})

	// dragons: rights. publish_elicenses is what requestSyncRights drives (SHP-03).
	case p == "/rights/publish_elicenses" && r.Method == "POST":
		var in struct {
			RightsIDs []string `json:"rights_ids"`
		}
		json.Unmarshal(body, &in)
		accounts := s.rightsAccounts(r)
		out := []map[string]any{}
		// NIM reads which of the rights ids it sent were taken and which were passed
		// over [firmware, nim: $.accepted_rights_ids[*], $.skipped_rights_ids[*]]. Every
		// id lands in exactly one of the two, in the order it was sent.
		accepted, skipped := []string{}, []string{}
		for _, rid := range in.RightsIDs {
			tid := titleIDForRights(rid)
			published := false
			for _, account := range accounts {
				if tid == "" {
					break
				}
				if e := s.shop.entitlementFor(account, tid); e != nil && e.Status == "active" {
					out = append(out, elicenseObj(e))
					published = true
				}
			}
			if published {
				accepted = append(accepted, rid)
			} else {
				skipped = append(skipped, rid)
			}
		}
		writeJSON(w, 200, map[string]any{"elicenses": out, "accepted_rights_ids": accepted, "skipped_rights_ids": skipped})
	case p == "/rights/available_elicenses" && r.Method == "POST":
		var in struct {
			RightsIDs []string `json:"rights_ids"`
		}
		json.Unmarshal(body, &in)
		accounts := s.rightsAccounts(r)
		items := []map[string]any{}
		accepted, skipped := []string{}, []string{}
		for _, rid := range in.RightsIDs {
			tid := titleIDForRights(rid)
			available := false
			reason := "no_rights"
			etype, matched := "", ""
			for _, account := range accounts {
				e := s.shop.entitlementFor(account, tid)
				if e == nil {
					continue
				}
				etype, matched = e.ELicenseType, account
				if e.Status == "active" {
					available = true
					reason = ""
				} else {
					available = false
					reason = "revoked_by_cs"
				}
				break
			}
			// NIM also reads account_id and come_back_after off each entry
			// [firmware, $.available_elicenses[%u].*]; eticket_id and
			// release_date are read too but we have no defensible value for
			// either until an eticket can be minted, so they stay absent.
			items = append(items, map[string]any{
				"rights_id": rid, "is_available": available, "reason": reason, "elicense_type": etype,
				"account_id": matched, "come_back_after": 0,
			})
			if available {
				accepted = append(accepted, rid)
			} else {
				skipped = append(skipped, rid)
			}
		}
		writeJSON(w, 200, map[string]any{"available_elicenses": items, "accepted_rights_ids": accepted, "skipped_rights_ids": skipped})
	case p == "/elicenses/revoke" && r.Method == "POST":
		var in struct {
			ELicenseIDs []string `json:"elicense_ids"`
		}
		json.Unmarshal(body, &in)
		for _, id := range in.ELicenseIDs {
			if e := s.shop.entitlementByELicense(id); e != nil {
				s.shop.revoke(e.AccountID, e.TitleID)
				log.Printf("[shop] dragons: elicense %s revoked (title %s account %s)", id, e.TitleID, e.AccountID)
			}
		}
		w.WriteHeader(200)

	// tigers: eticket publish. This is the trust boundary: a native install consumes an
	// ES-validated ticket, and no OpenPak key can produce one. Record everything and fail
	// honestly (SHP-04: a web page or an HTTP 200 must not claim installability).
	case p == "/etickets/publish" && r.Method == "POST":
		dump(r, body, "!! SHOP etickets/publish (recorded for the packaging/trust spike)")
		dragonsError(w, 501, "not_implemented",
			"eticket publish requires console trust this service cannot mint",
			"OpenPak records this request as packaging/trust evidence; see docs/native-shop.md SHP-04.")
	case strings.HasPrefix(host, "tigers."):
		dump(r, body, "!! UNHANDLED tigers")
		dragonsError(w, 501, "not_implemented", "not implemented by OpenPak", "")
	default:
		dump(r, body, "!! UNHANDLED dragons")
		dragonsError(w, 404, "not_found", "no such dragons api", "")
	}
}

// deviceOwnsTitle: does this device hold an active entitlement for the title, through any
// account linked to it? Both the link (beach) and the entitlement (acquire) are durable,
// so this survives restarts (SHP-05).
func (s *shopState) deviceOwnsTitle(deviceID, titleID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.Links.Links {
		if l.DeviceID != deviceID {
			continue
		}
		for _, e := range s.Entitlements {
			if e.AccountID == l.AccountID && e.TitleID == titleID && e.Status == "active" {
				return true
			}
		}
	}
	return false
}

// accountsForDevice lists the accounts linked to a device.
func (s *shopState) accountsForDevice(deviceID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, l := range s.Links.Links {
		if l.DeviceID == deviceID && !seen[l.AccountID] {
			seen[l.AccountID] = true
			out = append(out, l.AccountID)
		}
	}
	return out
}

// rightsAccounts resolves the accounts a dragons rights request acts for. NIM
// authenticates with a device token (DeviceAuthorization), so the accounts come from the
// durable beach link — the link itself was made by an authenticated account. A verified NA
// token on the request names one more account outright; a bare Nintendo-Account-Id header
// never does (principal binding).
func (s *server) rightsAccounts(r *http.Request) []string {
	accounts := s.shop.accountsForDevice(s.deviceIdentity(r))
	if account, _ := s.shopPrincipal(r); account != "" {
		found := false
		for _, a := range accounts {
			if a == account {
				found = true
				break
			}
		}
		if !found {
			accounts = append(accounts, account)
		}
	}
	return accounts
}

// titleIDForRights inverts rightsIDFor; anything that does not parse is not a rights id.
func titleIDForRights(rid string) string {
	if len(rid) != 16 {
		return ""
	}
	if _, err := hex.DecodeString(rid); err != nil {
		return ""
	}
	return rid[:15] + "0"
}

func elicenseObj(e *ShopEntitlement) map[string]any {
	return map[string]any{
		"account_id": e.AccountID, "rights_id": e.RightsID, "device_id": e.DeviceID,
		"status": e.Status, "elicense_id": e.ELicenseID, "elicense_type": e.ELicenseType,
	}
}

func shortHost(h string) string {
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}

// contentsAuthorizationTokenForAauth: dragons mints the token a digital title's launch
// (aauth) consumes. The wiki's captured payload carries title_id, na_id, ticket_id and
// is_owned_rights; we mint the same claim set signed with the key the console already
// trusts from dcert (it is our JWKS). This one we CAN mint: it is verified against our own
// keys, unlike an eticket.
func (s *server) contentsAuthorizationTokenForAauth(e *ShopEntitlement) string {
	now := time.Now().Unix()
	return signJWT(
		map[string]any{"alg": "RS256", "jku": "https://pubkey.lp1.dragons.nintendo.net/cata/v1/jwks", "kid": s.idKid, "typ": "JWT"},
		map[string]any{
			"iss": "lp1.dragons.nintendo.net", "aud": e.TitleID, "iat": now, "exp": now + 86400,
			"device_id": e.DeviceID, "content": map[string]any{
				"title_id": e.TitleID, "na_id": e.AccountID,
				"ticket_id": ticketIDFor(e), "is_owned_rights": true,
			},
		}, s.key)
}

// ticketIDFor: a stable 64-bit-ish decimal ticket number per entitlement. The real ticket
// id is an ES object we cannot mint; this value only fills the claim's shape in a token
// our own keys vouch for.
func ticketIDFor(e *ShopEntitlement) uint64 {
	sum := sha256.Sum256([]byte("openpak/ticket/" + e.ELicenseID))
	return beUint64(sum[:8]) | 1<<63
}

func beUint64(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}
