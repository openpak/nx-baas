// Surfaces the 22.5.0 modules reach that this adapter had no answer for.
//
// Every route here was found in a firmware module's own string table (NIM and
// the friends module; see docs/switch/firmware-22.5.0-followup-2026-09-12.md),
// which means a console can ask for it — an unanswered host is a TLS error and
// an unanswered path is our 404, and either can stall a native journey in a way
// that is hard to attribute afterwards. So each one is answered here with the
// smallest shape that is defensible, logged by name, and labelled with what it
// is for and what is still unknown about it.
//
// The rule these follow: an empty collection is a real answer ("you have none
// of these"), so it is given where the module asks "what do I have?". Where an
// answer would have to carry invented semantics — a licence, an entitlement, a
// signed anything — the request is recorded and refused instead, because a
// plausible lie is worse than a clear no.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// pearljam is the eShop host NIM names beside dragons and tigers
// [firmware, nim strings: "https://pearljam.hac.%.eshop.nintendo.net/civil"
// and "/sugar"]. What NIM does with it (22.5.0, docs/native-shop.md "pearljam"):
//
//   - It is a pass-through. The IPC caller (nim:eca / nim:ecas, task
//     "nn.nim.ShopServiceAccessTask"; live path sf vtable 0x32a680 slot
//     0x32a6a8 -> 0x246090 -> 0x22aec0 -> 0x22afd0) supplies the endpoint
//     selector (0 = sugar, 1 = civil, 0x22ee40), the path-suffix template
//     (ctx+0x50), the method (index into {2,4,5,6} at 0x2c26e0) and the JSON
//     body (ctx+0x60/0x68). NIM only expands {applicationid} (16 hex digits)
//     and {country} in the suffix; any other {token} fails with 0x5089.
//   - sugar (0x22e430: 60 s, 10 attempts) sends X-DeviceAuthorization,
//     X-NINTENDO-NSA-ID-TOKEN and X-Nintendo-Application-Id; civil (0x22eb70:
//     60 s, 30 attempts) sends X-DeviceAuthorization, Authorization: Bearer and
//     X-Nintendo-Application-Id. Body: application/json.
//   - A success body goes back to the IPC caller unread (0x2314b0 only
//     accumulates chunks). On an error status NIM reads $.error.code and
//     nothing else (NIM result 0x905 for sugar, 0x904 for civil).
//   - Failed sends are queued in the savedata file "nim_eca_dbg" (0x1a64e0,
//     filled by 0x22b280 with base + suffix and the body) and retried.
//
// So the paths, verbs and bodies belong to whichever applet drives the IPC
// (none is recovered), and NIM itself needs only a non-error status. Every
// suffix and verb under /civil and /sugar is accepted: the auth headers are
// checked against our own tokens, the request is dumped in full to the log and
// to $NX_DATA/pearljam/, and the answer is 200 {} — the smallest success. Bad
// or missing auth gets {"error":{"code","message"}} with 401, the one reply
// field NIM reads. Unverified on hardware: which suffixes the console sends,
// and whether its caller expects fields in a success body.
func (s *server) pearljam(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	endpoint := ""
	switch {
	case p == "/civil" || strings.HasPrefix(p, "/civil/"):
		endpoint = "civil"
	case p == "/sugar" || strings.HasPrefix(p, "/sugar/"):
		endpoint = "sugar"
	default:
		dump(r, body, "!! UNHANDLED pearljam")
		writeJSON(w, 404, map[string]any{"error": map[string]any{"code": "0404", "message": "not found"}})
		return
	}
	dump(r, body, "!! ESHOP pearljam "+endpoint+" (shape unverified; full request kept)")
	keepPearljamRequest(endpoint, r, body)
	device := s.bearerHeader(r, "X-DeviceAuthorization") != nil
	account := false
	if endpoint == "sugar" {
		account = s.bearerHeader(r, "X-NINTENDO-NSA-ID-TOKEN") != nil
	} else {
		account = s.bearerHeader(r, "Authorization") != nil
	}
	if !device || !account {
		log.Printf("[shop] pearljam %s %s %s -> 401 (device token ok=%v, account token ok=%v)", endpoint, r.Method, p, device, account)
		writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "0401",
			"message": "pearljam " + endpoint + " needs a valid device token and account token"}})
		return
	}
	log.Printf("[shop] pearljam %s %s %s app=%s -> 200 {} (unverified: NIM passes the body to its caller unread)",
		endpoint, r.Method, p, r.Header.Get("X-Nintendo-Application-Id"))
	writeJSON(w, 200, map[string]any{})
}

// keepPearljamRequest writes one pearljam request, headers and body, to
// $NX_DATA/pearljam/ so the first console run can settle the contract.
func keepPearljamRequest(endpoint string, r *http.Request, body []byte) {
	dir := filepath.Join(getenv("NX_DATA", "/data"), "pearljam")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("[shop] pearljam: keep request: %v", err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s%s", r.Method, hostOf(r), r.URL.RequestURI())
	b.WriteString("\n")
	for k, v := range r.Header {
		fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(v, ", "))
	}
	b.WriteString("\n")
	b.Write(body)
	name := fmt.Sprintf("%s-%d-%s.txt", time.Now().UTC().Format("20060102T150405"), time.Now().UnixNano()%1e9, endpoint)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(b.String()), 0o600); err != nil {
		log.Printf("[shop] pearljam: keep request: %v", err)
	}
}

// bvc answers bvc-hac-<env>.cdn.nintendo.net/<major>-<minor>-<micro>, a check
// NIM makes against the running firmware version [firmware, nim: URL builder
// 0x1ed990 formats the first three bytes of set:sys GetFirmwareVersion; the
// check at 0x238460 turns a successful reply into its own error 0x3fc89
// (2137-8164) and an HTTP 404 into success]. The file's existence is the
// answer: a listed version is refused.
//
// The list is the operator's (BlockedFirmware, edited through the store admin
// API): a listed version gets 200, anything else 404. Both answers copy what
// Nintendo's CDN sends (observed 2026-09-23 on bvc-hac-lp1): a listed version
// is 200 with an empty text/plain body, an ETag of the empty body's MD5 and a
// timestamp, and Last-Modified; an unlisted one is 404 with the 10-byte body
// "Not found\n" and no Content-Type. Both carry Server: AkamaiNetStorage and
// Accept-Ranges: bytes.
func (s *server) bvc(w http.ResponseWriter, r *http.Request) {
	s.ensureShop()
	v := strings.Trim(r.URL.Path, "/")
	h := w.Header()
	h.Set("Server", "AkamaiNetStorage")
	h.Set("Accept-Ranges", "bytes")
	if b := s.shop.blockedFirmware(v); b != nil {
		log.Printf("[shop] bvc %s %s%s -> 200: firmware %s is on the blocklist (NIM refuses it with 2137-8164)", r.Method, hostOf(r), r.URL.Path, v)
		h.Set("Content-Type", "text/plain")
		h.Set("Content-Length", "0")
		h.Set("ETag", fmt.Sprintf(`"d41d8cd98f00b204e9800998ecf8427e:%d.000000"`, b.AddedAt))
		h.Set("Last-Modified", time.Unix(b.AddedAt, 0).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		return
	}
	log.Printf("[shop] bvc %s %s%s -> 404: this firmware version is not listed", r.Method, hostOf(r), r.URL.Path)
	h["Content-Type"] = nil // Akamai sends none; nil stops net/http sniffing one
	h.Set("Content-Length", "10")
	w.WriteHeader(http.StatusNotFound)
	if r.Method != http.MethodHead {
		io.WriteString(w, "Not found\n")
	}
}

// BlockedFirmware is one entry of the operator's bvc list.
type BlockedFirmware struct {
	Version string `json:"version"` // "major-minor-micro", as NIM formats it
	Note    string `json:"note,omitempty"`
	AddedAt int64  `json:"added_at"`
}

// normalizeFirmware accepts "22-5-0" or "22.5.0" and returns NIM's "22-5-0" form, or ""
// when the string is not three decimal bytes (NIM formats u8s with %d).
func normalizeFirmware(v string) string {
	parts := strings.FieldsFunc(strings.TrimSpace(v), func(r rune) bool { return r == '-' || r == '.' })
	if len(parts) != 3 {
		return ""
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 || p != strconv.Itoa(n) {
			return ""
		}
		parts[i] = p
	}
	return strings.Join(parts, "-")
}

func (s *shopState) blockedFirmware(v string) *BlockedFirmware {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.BlockedFirmware {
		if s.BlockedFirmware[i].Version == v {
			b := s.BlockedFirmware[i]
			return &b
		}
	}
	return nil
}

// nimUnserved answers the NIM routes that had no handler. They are grouped by
// what the module is asking, because that decides what an honest answer is.
//
// Returns false when the path is not one of them, so the caller can fall
// through to its own routing.
func (s *server) nimUnserved(w http.ResponseWriter, r *http.Request, body []byte) bool {
	p := r.URL.Path
	switch {
	// "Who in this family could lend me this title?" — the virtual-card
	// (vphym) lending surface [nim: /v1/accounts/vphyms,
	// /v1/accounts/vphym-borrowers/candidates, /v1/accounts/in-same-family].
	// OpenPak has no family groups, so nobody is in one and nobody can lend:
	// an empty candidate list is the true answer, not a placeholder.
	case p == "/v1/accounts/vphyms":
		log.Printf("[shop] nim %s %s -> no virtual cards (OpenPak has no family lending)", r.Method, p)
		writeJSON(w, 200, map[string]any{"vphyms": []any{}})
		return true
	case p == "/v1/accounts/vphym-borrowers/candidates":
		log.Printf("[shop] nim %s %s -> no borrowers", r.Method, p)
		writeJSON(w, 200, map[string]any{"candidates": []any{}})
		return true
	case strings.HasPrefix(p, "/v1/accounts/in-same-family"):
		log.Printf("[shop] nim %s %s -> not in a family", r.Method, p)
		writeJSON(w, 200, map[string]any{"inSameFamily": false})
		return true

	// "Is another console of mine nearby?" — the local-transfer proximity
	// checks [nim: /v1/nearness-checks, /prune]. Nothing of ours brokers
	// device-to-device transfers, so there are no checks outstanding.
	case strings.HasPrefix(p, "/v1/nearness-checks"):
		log.Printf("[shop] nim %s %s -> no nearness checks", r.Method, p)
		writeJSON(w, 200, map[string]any{"nearnessChecks": []any{}})
		return true

	// "Is there a system update?" [nim: /v1/system_update_meta?device_id=].
	// An empty list means "you are current", which is what we want a console
	// on OpenPak to believe: we serve no system images and must never point
	// one at an update it cannot get.
	case strings.HasPrefix(p, "/v1/system_update_meta"):
		log.Printf("[shop] nim %s %s -> no system update", r.Method, p)
		writeJSON(w, 200, map[string]any{"system_update_metas": []any{}})
		return true
	// aqua asks the same question with a floor: "which system version must I have?"
	// [nim: aqua.hac.%.d4c.nintendo.net/required_system_update_meta?device_id=]. The
	// reply's fields are not recovered; 404 says there is no requirement on record,
	// which is true, without inventing a version a console would try to reach.
	case strings.HasPrefix(p, "/required_system_update_meta"):
		dump(r, body, "!! ESHOP aqua required system update (response shape unrecovered)")
		writeJSON(w, 404, map[string]any{"status": 404, "title": "no required system update"})
		return true

	// Messages the shop would show the player [nim: /v1/direct-messages] and
	// the family/account notification fan-out [/v1/accounts/notify,
	// /v1/accounts/notify-to-family]. Nothing produces either yet.
	case strings.HasPrefix(p, "/v1/direct-messages"):
		log.Printf("[shop] nim %s %s -> no messages", r.Method, p)
		writeJSON(w, 200, map[string]any{"messages": []any{}, "count": 0})
		return true
	case p == "/v1/accounts/notify", p == "/v1/accounts/notify-to-family":
		log.Printf("[shop] nim %s %s -> accepted, nothing to fan out", r.Method, p)
		w.WriteHeader(http.StatusOK)
		return true

	// "What versions of this application exist?" — NIM's update check on
	// superfly [nim: /v1/a/%016llx/dv, built at 0x1ecbe0; the reply is read by
	// the SAX handler at 0x3280e0]. Answered from the catalog (eshop_nim.go).
	case strings.HasPrefix(p, "/v1/a/") && strings.HasSuffix(p, "/dv"):
		s.versionLookup(w, r, body)
		return true

	// The eShop's own catalogue search [nim: /v1/acds/search]. Answered from
	// the shop catalog rather than with an empty list: the console is asking
	// what this store has, and this store knows. The entry shape mirrors the
	// applet's own listing (shop.go) — the ACD document's native field names
	// are not recovered, so what is served is our catalog's own vocabulary.
	case strings.HasPrefix(p, "/v1/acds/search"):
		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		items := []any{}
		for _, t := range s.shopTitles() {
			name, _ := shopTitleText(t)
			if q != "" && !strings.Contains(strings.ToLower(name), q) && !strings.Contains(strings.ToLower(t.TitleID), q) {
				continue
			}
			items = append(items, map[string]any{
				"application_id": t.TitleID, "name": name, "publisher": t.Publisher,
				"size_bytes": t.SizeBytes, "version": t.Version, "version_label": t.VersionLabel,
				"icon": "/ashigaru/icon/" + t.TitleID,
			})
		}
		log.Printf("[shop] nim %s %s q=%q -> %d title(s)", r.Method, p, q, len(items))
		writeJSON(w, 200, map[string]any{"acds": items, "count": len(items), "original_count": len(items)})
		return true
	}
	return false
}

// friendsAppCatalog answers the two routes the friends module fetches itself
// for a friend-request route or suggestion's external catalog id
// ("https://%s/v1/apps/%016llx%016llx/catalog.json" and ".../nx.jpg",
// host c-%.accounts.nintendo.com), matched here on the path before host
// routing claims it, so it answers on every host that reaches this server
// [friends-contract-22.5.0 §A.10]. The module only builds the nx.jpg URL and
// never downloads it. A catalog id this server does not carry renders as
// "unknown" instead of failing.
func (s *server) friendsAppCatalog(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/v1/apps/") {
		return false
	}
	rest := strings.TrimPrefix(p, "/v1/apps/")
	appID, file, ok := strings.Cut(rest, "/")
	if !ok || appID == "" {
		return false
	}
	// The friends module asks by 128-bit application id; our catalog is keyed
	// by the 64-bit title id, which is its upper half.
	title := s.shopTitleByAppID(appID)
	switch {
	case file == "catalog.json":
		// The external application catalog [friends-contract-22.5.0
		// §A.10]: catalog_id is the 32-hex id it was asked about,
		// application_names carries the shop's localised names (the module
		// copies only its own language key: ja-JP, en-US, fr-FR, de-DE,
		// it-IT, es-ES, zh-CN, ko-KR, nl-NL, pt-PT, ru-RU, zh-TW, en-GB,
		// fr-CA, es-MX, zh-Hans, zh-Hant, pt-BR), and enable_icons holding
		// "nx" is what makes the module build the .../nx.jpg icon URL.
		doc := map[string]any{
			"catalog_id": appID, "application_id": appID,
			"application_names": map[string]any{}, "enable_icons": []any{},
		}
		if title != nil {
			name, names := shopTitleText(title)
			doc["application_names"] = names
			doc["name"] = name
			doc["publisher"] = title.Publisher
			doc["version"] = title.Version
			if title.IconPath != "" {
				doc["enable_icons"] = []any{"nx"}
			}
			log.Printf("[nx-baas] friends app catalog for %s -> %q", appID, name)
		} else {
			// A title this server does not carry: the console asked about
			// something a friend is playing that we have never seen. An empty
			// name map is the honest answer, and it renders as "unknown".
			log.Printf("[nx-baas] friends app catalog for %s -> not in the catalog", appID)
		}
		writeJSON(w, 200, doc)
		return true
	case strings.HasSuffix(file, ".jpg"), strings.HasSuffix(file, ".png"):
		if title != nil && title.IconPath != "" {
			if b, err := os.ReadFile(s.shop.dir + "/" + title.IconPath); err == nil {
				w.Header().Set("Content-Type", "image/jpeg")
				w.Header().Set("Cache-Control", "public, max-age=3600")
				w.Write(b)
				log.Printf("[nx-baas] friends app art %s/%s -> catalog icon", appID, file)
				return true
			}
		}
		// No art for this title: the same neutral mark the shop grid uses,
		// rather than a 404 the console has to render around.
		log.Printf("[nx-baas] friends app art %s/%s -> placeholder", appID, file)
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fmt.Fprint(w, shopPlaceholderIcon)
		return true
	}
	return false
}

// shopTitles lists the catalog under its lock.
func (s *server) shopTitles() []*ShopTitle {
	if s.shop == nil {
		return nil
	}
	s.shop.mu.Lock()
	defer s.shop.mu.Unlock()
	out := make([]*ShopTitle, 0, len(s.shop.Catalog))
	for _, t := range s.shop.Catalog {
		if !t.Unpublished {
			out = append(out, t)
		}
	}
	return out
}

// shopTitleByAppID resolves the friends module's 128-bit application id against
// the catalog's 64-bit title ids: the title id is the id's upper half, and an
// exact 16-digit id is accepted as-is.
func (s *server) shopTitleByAppID(appID string) *ShopTitle {
	if s.shop == nil {
		return nil
	}
	id := strings.ToLower(appID)
	if len(id) >= 16 {
		id = id[:16]
	}
	return s.shop.listed(id)
}

// shopTitleText picks the display name and the localized name map for a title.
func shopTitleText(t *ShopTitle) (string, map[string]any) {
	names := map[string]any{}
	for lang, text := range t.Localized {
		if text.Name != "" {
			names[lang] = text.Name
		}
	}
	name := ""
	if text, ok := t.Localized[t.DefaultLang]; ok {
		name = text.Name
	}
	if name == "" {
		for _, text := range t.Localized {
			if text.Name != "" {
				name = text.Name
				break
			}
		}
	}
	return name, names
}

// shopPlaceholderIcon is the neutral mark the shop grid falls back to; kept
// here so the friends art route and the shop agree on what "no icon" looks like.
const shopPlaceholderIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><rect width="128" height="128" rx="16" fill="#4338ca"/><circle cx="64" cy="64" r="34" fill="none" stroke="#fff" stroke-width="8" opacity=".9"/><circle cx="64" cy="64" r="10" fill="#fff" opacity=".95"/></svg>`
