package main

// The NIM hosts that carry downloads and updates rather than rights: pushmo (the download
// list), tagaya (the version list), superfly (one title's versions), veer (which content
// vendor to use) and the metadata hosts that share atum's d4c domain.
//
// OpenPak's store carries homebrew and the updates for it. A title has an application
// content meta and, once an update is published, a patch under the patch id; everything
// here answers from the catalog in shop_data.go, which is re-read when the operator edits
// catalog.json (reloadCatalog). So publishing an update is: place the patch's files, raise
// the title's patch version in catalog.json, and the next version-list poll carries it.
//
// What is known about each body, and from where [firmware, 22.5.0]:
//
//   - superfly /v1/a/<application id>/dv: a JSON array of {title_id, title_type, version}.
//     NIM's reply handler (vtable 0x3280e0, element callback 0x20f090) reads title_id as a
//     base-16 string, title_type as one of Application, Patch, AddOnContent, DataPatch, and
//     version as an unsigned 32-bit integer. Verified.
//   - tagaya /tagaya/hac_versionlist: ns parses $.last_modified and $.titles[].{id,version,
//     required_version} (ns 0x1f66d0, 0x1f6950), id through a base-16 conversion. NIM sends
//     If-None-Match with the ETag it kept. Field set verified; whether id is the
//     application or the patch id is not — the application id is served, because the
//     version list is ns's per-application record (IVersionListImporter).
//   - pushmo /pushmo/{d,p}/<id>.json: NIM fetches them with If-None-Match and keeps the
//     ETag; nothing in NIM parses the body. The report's candidate ($[].title_id...) turned
//     out to be the superfly dv handler above. The best remaining candidate is ns's download
//     task list parser (ns 0x22a090, 0x22a674): $.tasks[].{id (a 36-character UUID),
//     owner_application, na_id, config, titles[].{id, version, type}}, type being
//     Application, Patch, AddOnContent, Delta or DataPatch. /d/ answers in that shape from
//     the open download tasks; /p/ is served empty. UNCONFIRMED: every pushmo request is
//     logged in full so the first console settles it.
//   - veer /v5/policy.json?context=: $.ttl and $.weights[].{vendor, weight} (NIM
//     0x2277e0, 0x228230). Verified. vendor is the atum subdomain NIM then uses.

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
)

// isNimMetaHost: the d4c hosts that are not content. sun and aqua answer system-update
// questions, superfly the version lookup, atumn* is NIM's other atum family. They route to
// nimUnserved's path table instead of atum.
func isNimMetaHost(host string) bool {
	if !strings.Contains(host, ".d4c.nintendo.net") {
		return false
	}
	for _, p := range []string{"sun.", "superfly.", "aqua.", "atumn"} {
		if strings.HasPrefix(host, p) {
			return true
		}
	}
	return false
}

// writeETagged answers a document with a strong ETag over its bytes, and 304 when the
// console already holds that version. The tag changes exactly when the body does.
func writeETagged(w http.ResponseWriter, r *http.Request, body []byte) {
	sum := sha1.Sum(body)
	etag := `"` + hex.EncodeToString(sum[:10]) + `"`
	w.Header().Set("ETag", etag)
	if m := r.Header.Get("If-None-Match"); m != "" && (m == "*" || strings.Contains(m, etag)) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// ---------- superfly ----------

// versionLookup answers /v1/a/<application id>/dv from the catalog: the application's
// own content meta and, when one is published, its patch. A title this store does not
// carry has no version record here, which is what 404 says.
func (s *server) versionLookup(w http.ResponseWriter, r *http.Request, body []byte) {
	s.ensureShop()
	s.shop.reloadCatalog()
	id := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/a/"), "/dv"))
	t, _ := s.shop.meta(id)
	if t == nil {
		log.Printf("[shop] superfly dv %s -> not in the catalog", id)
		writeJSON(w, 404, map[string]any{"status": 404, "title": "no version record"})
		return
	}
	s.shop.mu.Lock()
	out := []map[string]any{{"title_id": t.TitleID, "title_type": "Application", "version": t.applicationVersion()}}
	if t.Patch != nil {
		out = append(out, map[string]any{"title_id": patchIDFor(t.TitleID), "title_type": "Patch", "version": t.Patch.Version})
	}
	s.shop.mu.Unlock()
	log.Printf("[shop] superfly dv %s -> %d version record(s)", id, len(out))
	writeJSONValue(w, 200, out)
}

func (s *server) ensureShop() {
	if s.shop == nil {
		s.shop = newShopState("")
	}
}

// ---------- tagaya ----------

// tagaya serves the version list: the newest version of every catalog title. last_modified
// is the newest catalog change rather than the clock, so the body — and with it the ETag —
// changes only when a version is published.
func (s *server) tagaya(w http.ResponseWriter, r *http.Request, body []byte) {
	s.ensureShop()
	if r.URL.Path != "/tagaya/hac_versionlist" {
		dump(r, body, "!! UNHANDLED tagaya")
		writeJSON(w, 404, map[string]any{"status": 404, "title": "not found"})
		return
	}
	s.shop.reloadCatalog()
	titles := []map[string]any{}
	var modified int64
	for _, t := range s.shopTitles() {
		titles = append(titles, map[string]any{
			"id": t.TitleID, "version": t.Version, "required_version": 0,
		})
		modified = max(modified, t.UpdatedAt)
	}
	sort.Slice(titles, func(i, j int) bool { return titles[i]["id"].(string) < titles[j]["id"].(string) })
	log.Printf("[shop] tagaya version list: %d title(s), if-none-match=%q", len(titles), r.Header.Get("If-None-Match"))
	writeETagged(w, r, []byte(mustJSON(map[string]any{
		"format_version": 1, "last_modified": modified, "titles": titles,
	})))
}

// ---------- pushmo ----------

// pushmo serves NIM's download lists. <id> is not recovered either (a device id is the
// likeliest reading of the "%s"); the id is matched against device links, then account
// ids, then the requesting device, and the whole request is logged loudly.
func (s *server) pushmo(w http.ResponseWriter, r *http.Request, body []byte) {
	s.ensureShop()
	dump(r, body, "!! ESHOP pushmo (body shape unconfirmed; see eshop_nim.go)")
	p := r.URL.Path
	var kind, id string
	switch {
	case strings.HasPrefix(p, "/pushmo/d/") && strings.HasSuffix(p, ".json"):
		kind, id = "d", strings.TrimSuffix(strings.TrimPrefix(p, "/pushmo/d/"), ".json")
	case strings.HasPrefix(p, "/pushmo/p/") && strings.HasSuffix(p, ".json"):
		kind, id = "p", strings.TrimSuffix(strings.TrimPrefix(p, "/pushmo/p/"), ".json")
	default:
		writeJSON(w, 404, map[string]any{"status": 404, "title": "not found"})
		return
	}
	s.shop.reloadCatalog()
	tasks := []map[string]any{}
	if kind == "d" {
		tasks = s.pushmoTasks(s.pushmoAccounts(id, r))
	}
	log.Printf("[shop] pushmo %s/%s -> %d task(s)", kind, id, len(tasks))
	writeETagged(w, r, []byte(mustJSON(map[string]any{"tasks": tasks})))
}

// pushmoAccounts resolves a pushmo id to the accounts whose downloads it lists.
func (s *server) pushmoAccounts(id string, r *http.Request) []string {
	id = strings.ToLower(id)
	if a := s.shop.accountsForDevice(id); len(a) > 0 {
		return a
	}
	s.shop.mu.Lock()
	for _, l := range s.shop.Links.Links {
		if strings.ToLower(l.AccountID) == id {
			s.shop.mu.Unlock()
			return []string{l.AccountID}
		}
	}
	s.shop.mu.Unlock()
	return s.shop.accountsForDevice(s.deviceIdentity(r))
}

// pushmoTasks renders the open download tasks of the accounts in the download-task-list
// shape: one task per title, listing the application and, when published, its patch.
func (s *server) pushmoTasks(accounts []string) []map[string]any {
	out := []map[string]any{}
	seen := map[string]bool{}
	for _, account := range accounts {
		for _, task := range s.shop.tasksFor(account) {
			if task.State != "queued" && task.State != "downloading" && task.State != "paused" {
				continue
			}
			if seen[task.TitleID] {
				continue
			}
			t, _ := s.shop.meta(task.TitleID)
			if t == nil {
				continue
			}
			seen[task.TitleID] = true
			s.shop.mu.Lock()
			titles := []map[string]any{{"id": t.TitleID, "version": t.applicationVersion(), "type": "Application"}}
			if t.Patch != nil {
				titles = append(titles, map[string]any{"id": patchIDFor(t.TitleID), "version": t.Patch.Version, "type": "Patch"})
			}
			s.shop.mu.Unlock()
			out = append(out, map[string]any{
				"id": taskUUID(task.ID), "owner_application": t.TitleID, "titles": titles,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
	return out
}

// taskUUID formats a task's 32-hex id as the 36-character UUID the task list parser
// requires (ns rejects a task id of any other length).
func taskUUID(id string) string {
	if len(id) != 32 {
		sum := sha1.Sum([]byte(id))
		id = hex.EncodeToString(sum[:16])
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s", id[:8], id[8:12], id[12:16], id[16:20], id[20:])
}

// ---------- veer ----------

// veer tells NIM which content vendor to use. OpenPak has one: the atum host this adapter
// serves. The TTL is a day; the policy does not change while the server runs.
func (s *server) veer(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.URL.Path != "/v5/policy.json" {
		dump(r, body, "!! UNHANDLED veer")
		writeJSON(w, 404, map[string]any{"status": 404, "title": "not found"})
		return
	}
	log.Printf("[shop] veer policy context=%q last_vendor=%q -> atum", r.URL.Query().Get("context"), r.URL.Query().Get("last_vendor"))
	writeJSON(w, 200, map[string]any{
		"ttl":     86400,
		"weights": []any{map[string]any{"vendor": "atum", "weight": 100}},
	})
}
