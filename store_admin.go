package main

// The store admin API: the website's admin pages manage the OpenPak store's catalog through
// here (docs/store-admin-api.md is the contract; keep the two in step). It lives on the
// game-API listener beside the other /internal routes and uses the same X-Internal-Key,
// with one difference: these routes refuse every caller when no key is configured, because
// they write to disk and take multi-gigabyte uploads.
//
// The store carries homebrew and its updates, packaged without a rights ID. An upload is an
// NSP (a PFS0 of NCAs) plus the metadata its uploader supplies; the server verifies what can
// be verified without Nintendo's keys and never decrypts an NCA (the contract explains why).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"nx-baas/redact"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// defaultShopUploadMax is 8 GiB: a large homebrew NSP fits, a runaway client does not.
const defaultShopUploadMax int64 = 8 << 30

// ShopTitleStats counts what the content host served for one title (application and update
// together, keyed by the application id).
type ShopTitleStats struct {
	Downloads       int64 `json:"downloads"`
	ContentRequests int64 `json:"content_requests"`
	BytesServed     int64 `json:"bytes_served"`
	LastDownloadAt  int64 `json:"last_download_at,omitempty"`
}

// noteServed records one atum content response. A download is counted when the meta NCA is
// served from byte 0: every install starts by fetching its content meta, and a resumed
// transfer does not restart at zero. Only that event saves the state file; the byte
// counters ride along with it and the next save, so a crash can lose a tail of bytes_served.
func (s *shopState) noteServed(titleID string, c ShopContent, start, n int64) {
	app := titleID
	if t, _ := s.meta(titleID); t != nil {
		app = t.TitleID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Stats == nil {
		s.Stats = map[string]*ShopTitleStats{}
	}
	st := s.Stats[app]
	if st == nil {
		st = &ShopTitleStats{}
		s.Stats[app] = st
	}
	st.ContentRequests++
	st.BytesServed += n
	if c.ContentType == "meta" && start == 0 {
		st.Downloads++
		st.LastDownloadAt = time.Now().Unix()
		s.save()
	}
}

// ---------- plumbing ----------

type adminError struct {
	status    int
	code, msg string
}

func (e *adminError) Error() string { return e.code + ": " + e.msg }

func adminErr(status int, code, format string, a ...any) *adminError {
	return &adminError{status: status, code: code, msg: fmt.Sprintf(format, a...)}
}

func writeAdminErr(w http.ResponseWriter, err error) {
	var ae *adminError
	if !errors.As(err, &ae) {
		log.Printf("[store-admin] internal: %v", redact.Err(err))
		ae = adminErr(500, "internal", "%v", err)
	}
	writeJSON(w, ae.status, map[string]any{"error": ae.code, "message": ae.msg})
}

// storeAdminAuth is internalOK made strict: same header, same key, but no key configured
// means nobody gets in.
func storeAdminAuth(r *http.Request) error {
	k := getenv("NX_INTERNAL_KEY", getenv("OPENPAK_INTERNAL_KEY", ""))
	if k == "" {
		return adminErr(503, "internal_key_not_configured", "set NX_INTERNAL_KEY to use the store admin API")
	}
	if !hmac.Equal([]byte(k), []byte(r.Header.Get("X-Internal-Key"))) {
		return adminErr(401, "unauthorized", "X-Internal-Key missing or wrong")
	}
	return nil
}

func uploadMax() int64 {
	if n, err := strconv.ParseInt(os.Getenv("NX_SHOP_UPLOAD_MAX_BYTES"), 10, 64); err == nil && n > 0 {
		return n
	}
	return defaultShopUploadMax
}

// storeAdmin routes /internal/store/*.
func (s *server) storeAdmin(w http.ResponseWriter, r *http.Request) {
	if err := storeAdminAuth(r); err != nil {
		writeAdminErr(w, err)
		return
	}
	s.ensureShop()
	seg := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/internal/store"), "/"), "/")
	m := r.Method
	var err error
	switch {
	case len(seg) == 1 && seg[0] == "titles" && m == http.MethodGet:
		err = s.adminListTitles(w)
	case len(seg) == 1 && seg[0] == "titles" && m == http.MethodPost:
		err = s.adminCreateTitle(w, r)
	case len(seg) == 1 && seg[0] == "stats" && m == http.MethodGet:
		writeJSON(w, 200, map[string]any{"titles": s.shop.allStats("")})
	case len(seg) >= 2 && seg[0] == "titles":
		err = s.adminTitle(w, r, strings.ToLower(seg[1]), seg[2:])
	case seg[0] == "firmware-blocklist" && len(seg) <= 2:
		err = s.adminFirmwareBlocklist(w, r, seg[1:])
	case len(seg) == 3 && seg[0] == "accounts" && m == http.MethodGet:
		err = s.adminAccount(w, r, seg[1], seg[2])
	default:
		err = adminErr(404, "not_found", "no such store admin route: %s %s", m, r.URL.Path)
	}
	if err != nil {
		writeAdminErr(w, err)
	}
}

func (s *server) adminTitle(w http.ResponseWriter, r *http.Request, tid string, rest []string) error {
	if !validTitleID(tid) {
		return adminErr(400, "invalid_title_id", "title id must be 16 hex digits")
	}
	m := r.Method
	sub := strings.Join(rest, "/")
	switch {
	case sub == "" && m == http.MethodGet:
		t := s.shop.adminGet(tid)
		if t == nil {
			return adminErr(404, "not_found", "no title %s", tid)
		}
		writeJSON(w, 200, adminTitleObj(t, true))
		return nil
	case sub == "" && m == http.MethodPatch:
		return s.adminPatchTitle(w, r, tid)
	case sub == "" && m == http.MethodDelete:
		return s.adminDeleteTitle(w, tid)
	case sub == "icon" && m == http.MethodPut:
		return s.adminIcon(w, r, tid)
	case strings.HasPrefix(sub, "screenshots/") && m == http.MethodPut:
		return s.adminScreenshot(w, r, tid, strings.TrimPrefix(sub, "screenshots/"))
	case sub == "screenshots" && m == http.MethodDelete:
		return s.adminClearScreenshots(w, tid)
	case sub == "versions" && m == http.MethodPost:
		return s.adminUpload(w, r, tid)
	case sub == "versions/update" && m == http.MethodDelete:
		return s.adminDropUpdate(w, tid)
	case (sub == "publish" || sub == "unpublish") && m == http.MethodPost:
		return s.adminPublish(w, tid, sub == "publish")
	case sub == "stats" && m == http.MethodGet:
		if s.shop.adminGet(tid) == nil {
			return adminErr(404, "not_found", "no title %s", tid)
		}
		writeJSON(w, 200, s.shop.allStats(tid)[0])
		return nil
	}
	return adminErr(405, "method_not_allowed", "%s %s", m, r.URL.Path)
}

// ---------- catalog access (admin sees unpublished titles too) ----------

func (s *shopState) adminGet(tid string) *ShopTitle {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Catalog[tid]
}

// mutateTitle changes a title copy-on-write: console handlers read *ShopTitle fields
// without the lock, so a published entry is replaced, never edited in place. The state file
// and catalog.json are both written, so a restart and a catalog reload agree with the API.
func (s *shopState) mutateTitle(tid string, fn func(t *ShopTitle) error) (*ShopTitle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.Catalog[tid]
	if old == nil {
		return nil, adminErr(404, "not_found", "no title %s", tid)
	}
	t := *old
	if old.Patch != nil {
		p := *old.Patch
		t.Patch = &p
	}
	if err := fn(&t); err != nil {
		return nil, err
	}
	t.UpdatedAt = time.Now().Unix()
	s.Catalog[tid] = &t
	return &t, s.persistLocked()
}

// persistLocked writes state.json and catalog.json. The fixture title is never written to
// catalog.json: it is a stand-in for an empty catalog, not something an operator authored.
func (s *shopState) persistLocked() error {
	s.save()
	if s.dir == "" {
		return nil
	}
	entries := make([]*ShopTitle, 0, len(s.Catalog))
	for id, t := range s.Catalog {
		if id != defaultFixtureID {
			entries = append(entries, t)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].TitleID < entries[j].TitleID })
	b, err := json.MarshalIndent(entries, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	tmp := s.dir + "/catalog.json.tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.dir+"/catalog.json"); err != nil {
		return err
	}
	// The file is now what memory holds: record its time so reloadCatalog does not
	// re-read our own write.
	if st, err := os.Stat(s.dir + "/catalog.json"); err == nil {
		s.catalogMod = st.ModTime()
	}
	return nil
}

// ---------- title object ----------

func contentObjs(cs []ShopContent) []map[string]any {
	out := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		out = append(out, map[string]any{"content_id": c.ContentID, "content_type": c.ContentType, "size": c.Size, "sha256": c.SHA256})
	}
	return out
}

func adminTitleObj(t *ShopTitle, withContent bool) map[string]any {
	o := map[string]any{
		"title_id": t.TitleID, "published": !t.Unpublished, "publisher": t.Publisher,
		"category": t.Category, "localized": t.Localized, "default_lang": t.DefaultLang,
		"languages": t.Languages, "compatibility": t.Compatibility, "screenshots": t.Screenshots,
		"changelog": t.Changelog, "released_at": t.ReleasedAt, "revised_at": t.RevisedAt,
		"distribution": t.Distribution, "icon_path": t.IconPath, "size_bytes": t.SizeBytes,
		"version": t.Version, "version_label": t.VersionLabel, "base_version": t.applicationVersion(),
		"updated_at": t.UpdatedAt, "application": nil, "update": nil, "bundle": bundleObjs(t.Bundle),
	}
	if len(t.Content) > 0 || t.CNMTPath != "" {
		label := t.BaseVersionLabel
		if t.Patch == nil && label == "" {
			label = t.VersionLabel
		}
		app := map[string]any{"version": t.applicationVersion(), "version_label": label}
		if withContent {
			app["content"] = contentObjs(t.Content)
		}
		o["application"] = app
	}
	if t.Patch != nil {
		up := map[string]any{"title_id": patchIDFor(t.TitleID), "version": t.Patch.Version, "version_label": t.Patch.VersionLabel}
		if withContent {
			up["content"] = contentObjs(t.Patch.Content)
		}
		o["update"] = up
	}
	return o
}

func bundleObjs(b []ShopBundleItem) []map[string]any {
	out := make([]map[string]any, 0, len(b))
	for _, it := range b {
		out = append(out, map[string]any{"application_id": it.ApplicationID, "is_upgrade_edition": it.IsUpgradeEdition})
	}
	return out
}

func (s *server) adminListTitles(w http.ResponseWriter) error {
	s.shop.mu.Lock()
	ts := make([]*ShopTitle, 0, len(s.shop.Catalog))
	for _, t := range s.shop.Catalog {
		ts = append(ts, t)
	}
	s.shop.mu.Unlock()
	sort.Slice(ts, func(i, j int) bool { return ts[i].TitleID < ts[j].TitleID })
	out := make([]map[string]any, 0, len(ts))
	for _, t := range ts {
		out = append(out, adminTitleObj(t, false))
	}
	writeJSON(w, 200, map[string]any{"count": len(out), "titles": out})
	return nil
}

// ---------- create / update / delete ----------

// titleMeta is the metadata a create or PATCH may carry. Pointers tell "absent" from "empty".
type titleMeta struct {
	TitleID       string               `json:"title_id"`
	Publisher     *string              `json:"publisher"`
	Category      *string              `json:"category"`
	Localized     *map[string]ShopText `json:"localized"`
	DefaultLang   *string              `json:"default_lang"`
	Languages     *[]string            `json:"languages"`
	Compatibility *[]string            `json:"compatibility"`
	Screenshots   *[]string            `json:"screenshots"`
	Changelog     *string              `json:"changelog"`
	ReleasedAt    *int64               `json:"released_at"`
	RevisedAt     *int64               `json:"revised_at"`
	Distribution  *ShopDistribution    `json:"distribution"`
	Bundle        *[]ShopBundleItem    `json:"bundle"`
}

func (m *titleMeta) apply(t *ShopTitle) error {
	if m.Publisher != nil {
		if strings.TrimSpace(*m.Publisher) == "" {
			return adminErr(400, "invalid_field", "publisher must not be empty")
		}
		t.Publisher = *m.Publisher
	}
	if m.Category != nil {
		t.Category = *m.Category
	}
	if m.Localized != nil {
		named := false
		for _, v := range *m.Localized {
			named = named || strings.TrimSpace(v.Name) != ""
		}
		if !named {
			return adminErr(400, "invalid_field", "localized needs at least one language with a name")
		}
		t.Localized = *m.Localized
	}
	if m.DefaultLang != nil {
		t.DefaultLang = *m.DefaultLang
	}
	if m.Languages != nil {
		t.Languages = *m.Languages
	}
	if m.Compatibility != nil {
		t.Compatibility = *m.Compatibility
	}
	if m.Screenshots != nil {
		t.Screenshots = *m.Screenshots
	}
	if m.Changelog != nil {
		t.Changelog = *m.Changelog
	}
	if m.ReleasedAt != nil {
		t.ReleasedAt = *m.ReleasedAt
	}
	if m.RevisedAt != nil {
		t.RevisedAt = *m.RevisedAt
	}
	if m.Distribution != nil {
		if strings.TrimSpace(m.Distribution.Permission) == "" || strings.TrimSpace(m.Distribution.Source) == "" {
			return adminErr(400, "invalid_field", "distribution needs both source and permission")
		}
		t.Distribution = *m.Distribution
	}
	if m.Bundle != nil {
		b, err := validBundle(t.TitleID, *m.Bundle)
		if err != nil {
			return err
		}
		t.Bundle = b
	}
	return nil
}

// validBundle checks a title's bundle list: application ids (16 hex ending in 000), not the
// title itself, no repeats, at most NIM's 64. Bundled titles need not exist yet; the
// console only sees the ones published (eshop_bundle.go).
func validBundle(self string, in []ShopBundleItem) ([]ShopBundleItem, error) {
	if len(in) > maxBundleContents {
		return nil, adminErr(400, "invalid_field", "bundle holds at most %d applications", maxBundleContents)
	}
	out := make([]ShopBundleItem, 0, len(in))
	seen := map[string]bool{}
	for _, it := range in {
		id := strings.ToLower(it.ApplicationID)
		if !validTitleID(id) || !strings.HasSuffix(id, "000") {
			return nil, adminErr(400, "invalid_field", "bundle application_id %q must be 16 hex digits ending in 000", it.ApplicationID)
		}
		if id == self {
			return nil, adminErr(400, "invalid_field", "a title cannot bundle itself")
		}
		if seen[id] {
			return nil, adminErr(400, "invalid_field", "bundle lists %s twice", id)
		}
		seen[id] = true
		out = append(out, ShopBundleItem{ApplicationID: id, IsUpgradeEdition: it.IsUpgradeEdition})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func decodeStrict(r io.Reader, v any, allowUnknown bool) error {
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	if !allowUnknown {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return adminErr(400, "invalid_field", "%v", err)
		}
		return adminErr(400, "invalid_json", "%v", err)
	}
	return nil
}

func (s *server) adminCreateTitle(w http.ResponseWriter, r *http.Request) error {
	var m titleMeta
	// Create tolerates the read-only fields of a Title object (the contract says they are
	// ignored), so the website can post back what it read.
	if err := decodeStrict(r.Body, &m, true); err != nil {
		return err
	}
	tid := strings.ToLower(m.TitleID)
	if !validTitleID(tid) || !strings.HasSuffix(tid, "000") {
		return adminErr(400, "invalid_title_id", "title_id must be 16 hex digits ending in 000 (an application id)")
	}
	if m.Publisher == nil || m.Localized == nil || m.Distribution == nil {
		return adminErr(400, "invalid_field", "publisher, localized and distribution are required")
	}
	t := &ShopTitle{TitleID: tid, Unpublished: true, Content: []ShopContent{}}
	if err := m.apply(t); err != nil {
		return err
	}
	t.UpdatedAt = time.Now().Unix()
	s.shop.mu.Lock()
	if s.shop.Catalog[tid] != nil {
		s.shop.mu.Unlock()
		return adminErr(409, "already_exists", "title %s is already in the catalog", tid)
	}
	s.shop.Catalog[tid] = t
	err := s.shop.persistLocked()
	s.shop.mu.Unlock()
	if err != nil {
		return err
	}
	log.Printf("[store-admin] created title %s (unpublished)", tid)
	writeJSON(w, 201, adminTitleObj(t, true))
	return nil
}

func (s *server) adminPatchTitle(w http.ResponseWriter, r *http.Request, tid string) error {
	var m titleMeta
	if err := decodeStrict(r.Body, &m, false); err != nil {
		return err
	}
	if m.TitleID != "" && strings.ToLower(m.TitleID) != tid {
		return adminErr(400, "invalid_field", "title_id cannot be changed")
	}
	t, err := s.shop.mutateTitle(tid, m.apply)
	if err != nil {
		return err
	}
	writeJSON(w, 200, adminTitleObj(t, true))
	return nil
}

func (s *server) adminDeleteTitle(w http.ResponseWriter, tid string) error {
	s.shop.mu.Lock()
	t := s.shop.Catalog[tid]
	if t == nil {
		s.shop.mu.Unlock()
		return adminErr(404, "not_found", "no title %s", tid)
	}
	delete(s.shop.Catalog, tid)
	err := s.shop.persistLocked()
	s.shop.mu.Unlock()
	if err != nil {
		return err
	}
	if s.shop.dir != "" {
		os.RemoveAll(filepath.Join(s.shop.dir, "content", tid))
		if strings.HasPrefix(t.IconPath, "icons/") {
			os.Remove(filepath.Join(s.shop.dir, t.IconPath))
		}
		removeHostedScreens(s.shop.dir, t.Screenshots)
	}
	log.Printf("[store-admin] deleted title %s", tid)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *server) adminIcon(w http.ResponseWriter, r *http.Request, tid string) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		return adminErr(400, "invalid_field", "reading icon: %v", err)
	}
	if len(b) > 1<<20 {
		return adminErr(413, "too_large", "icons are at most 1 MiB")
	}
	ext := map[string]string{"image/jpeg": ".jpg", "image/png": ".png"}[http.DetectContentType(b)]
	if ext == "" {
		return adminErr(400, "invalid_field", "icon must be a JPEG or PNG image")
	}
	if s.shop.adminGet(tid) == nil {
		return adminErr(404, "not_found", "no title %s", tid)
	}
	rel := "icons/" + tid + ext
	if s.shop.dir != "" {
		if err := os.MkdirAll(filepath.Join(s.shop.dir, "icons"), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(s.shop.dir, rel), b, 0o644); err != nil {
			return err
		}
	}
	t, err := s.shop.mutateTitle(tid, func(t *ShopTitle) error { t.IconPath = rel; return nil })
	if err != nil {
		return err
	}
	writeJSON(w, 200, adminTitleObj(t, true))
	return nil
}

// maxScreenshots bounds a title's hosted screenshots (slots 0..maxScreenshots-1).
const maxScreenshots = 8

// adminScreenshot stores one screenshot (JPEG or PNG, at most 2 MiB) in slot <i> and lists
// it in the title's screenshots; the shop serves it at /ashigaru/screen/<tid>/<i>.
func (s *server) adminScreenshot(w http.ResponseWriter, r *http.Request, tid, slot string) error {
	i, err := strconv.Atoi(slot)
	if err != nil || i < 0 || i >= maxScreenshots {
		return adminErr(400, "invalid_field", "screenshot slot must be 0..%d", maxScreenshots-1)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 2<<20+1))
	if err != nil {
		return adminErr(400, "invalid_field", "reading screenshot: %v", err)
	}
	if len(b) > 2<<20 {
		return adminErr(413, "too_large", "screenshots are at most 2 MiB")
	}
	ext := map[string]string{"image/jpeg": ".jpg", "image/png": ".png"}[http.DetectContentType(b)]
	if ext == "" {
		return adminErr(400, "invalid_field", "screenshot must be a JPEG or PNG image")
	}
	if s.shop.adminGet(tid) == nil {
		return adminErr(404, "not_found", "no title %s", tid)
	}
	rel := fmt.Sprintf("screens/%s-%d%s", tid, i, ext)
	if s.shop.dir != "" {
		if err := os.MkdirAll(filepath.Join(s.shop.dir, "screens"), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(s.shop.dir, rel), b, 0o644); err != nil {
			return err
		}
	}
	t, err := s.shop.mutateTitle(tid, func(t *ShopTitle) error {
		for len(t.Screenshots) <= i {
			t.Screenshots = append(t.Screenshots, "")
		}
		if old := t.Screenshots[i]; old != rel && strings.HasPrefix(old, "screens/") && s.shop.dir != "" {
			os.Remove(filepath.Join(s.shop.dir, old))
		}
		t.Screenshots[i] = rel
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, 200, adminTitleObj(t, true))
	return nil
}

// adminClearScreenshots drops every screenshot of a title and the files we host for them.
func (s *server) adminClearScreenshots(w http.ResponseWriter, tid string) error {
	var old []string
	t, err := s.shop.mutateTitle(tid, func(t *ShopTitle) error { old, t.Screenshots = t.Screenshots, nil; return nil })
	if err != nil {
		return err
	}
	removeHostedScreens(s.shop.dir, old)
	writeJSON(w, 200, adminTitleObj(t, true))
	return nil
}

func removeHostedScreens(dir string, shots []string) {
	for _, p := range shots {
		if dir != "" && strings.HasPrefix(p, "screens/") {
			os.Remove(filepath.Join(dir, p))
		}
	}
}

func (s *server) adminPublish(w http.ResponseWriter, tid string, publish bool) error {
	t, err := s.shop.mutateTitle(tid, func(t *ShopTitle) error {
		if publish && len(t.Content) == 0 && t.CNMTPath == "" && t.TitleID != defaultFixtureID {
			return adminErr(409, "no_base_version", "upload a base version before publishing")
		}
		t.Unpublished = !publish
		return nil
	})
	if err != nil {
		return err
	}
	log.Printf("[store-admin] %s published=%v", tid, publish)
	writeJSON(w, 200, adminTitleObj(t, true))
	return nil
}

func (s *server) adminDropUpdate(w http.ResponseWriter, tid string) error {
	var gone string
	t, err := s.shop.mutateTitle(tid, func(t *ShopTitle) error {
		if t.Patch == nil {
			return adminErr(404, "not_found", "title %s has no update", tid)
		}
		gone = t.Patch.Package
		t.Version, t.VersionLabel = t.BaseVersion, t.BaseVersionLabel
		t.Patch = nil
		t.SizeBytes = contentSize(t.Content)
		return nil
	})
	if err != nil {
		return err
	}
	s.shop.removePackage(gone)
	log.Printf("[store-admin] %s: update withdrawn", tid)
	writeJSON(w, 200, adminTitleObj(t, true))
	return nil
}

func contentSize(cs []ShopContent) int64 {
	var n int64
	for _, c := range cs {
		n += c.Size
	}
	return n
}

// removePackage deletes an uploaded package that is no longer referenced. Only files under
// content/ are touched: a hand-placed catalog never names a package.
func (s *shopState) removePackage(rel string) {
	if rel == "" || s.dir == "" || !strings.HasPrefix(rel, "content/") || strings.Contains(rel, "..") {
		return
	}
	if err := os.Remove(filepath.Join(s.dir, rel)); err != nil && !os.IsNotExist(err) {
		log.Printf("[store-admin] removing %s: %v", rel, redact.Err(err))
	}
}

// ---------- upload ----------

// versionMeta is the metadata part of an upload.
type versionMeta struct {
	Kind         string `json:"kind"`
	TitleID      string `json:"title_id"`
	Version      uint32 `json:"version"`
	VersionLabel string `json:"version_label"`
	Contents     []struct {
		ContentID   string `json:"content_id"`
		ContentType string `json:"content_type"`
		Size        int64  `json:"size"`
		SHA256      string `json:"sha256"`
	} `json:"contents"`
}

var contentTypes = map[string]bool{
	"meta": true, "program": true, "control": true, "legalinformation": true,
	"htmldocument": true, "data": true, "deltafragment": true,
}

func (s *server) adminUpload(w http.ResponseWriter, r *http.Request, tid string) error {
	if s.shop.adminGet(tid) == nil {
		return adminErr(404, "not_found", "no title %s", tid)
	}
	r.Body = http.MaxBytesReader(w, r.Body, uploadMax())
	mr, err := r.MultipartReader()
	if err != nil {
		return adminErr(400, "invalid_multipart", "expected multipart/form-data: %v", err)
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "metadata" {
		return adminErr(400, "invalid_multipart", "the first part must be \"metadata\"")
	}
	var meta versionMeta
	if err := decodeStrict(part, &meta, false); err != nil {
		return adminErr(400, "invalid_metadata", "%s", err.(*adminError).msg)
	}
	metaID := tid
	switch meta.Kind {
	case "base":
	case "update":
		metaID = patchIDFor(tid)
	default:
		return adminErr(400, "invalid_metadata", "kind must be \"base\" or \"update\"")
	}
	if meta.TitleID != "" && strings.ToLower(meta.TitleID) != metaID && strings.ToLower(meta.TitleID) != tid {
		return adminErr(400, "invalid_metadata", "title_id %s does not belong to %s", meta.TitleID, tid)
	}
	if len(meta.Contents) == 0 {
		return adminErr(400, "invalid_metadata", "contents lists every NCA in the package")
	}
	for _, c := range meta.Contents {
		if !contentTypes[c.ContentType] {
			return adminErr(400, "invalid_metadata", "content_type %q is not one of meta, program, control, legalinformation, htmldocument, data, deltafragment", c.ContentType)
		}
	}
	if cur := s.shop.adminGet(tid); meta.Kind == "update" {
		if len(cur.Content) == 0 && cur.CNMTPath == "" {
			return adminErr(409, "no_base_version", "upload the base version before an update")
		}
		if cur.Patch != nil && meta.Version <= cur.Patch.Version {
			return adminErr(409, "version_not_newer", "update version %d is not above the published %d", meta.Version, cur.Patch.Version)
		}
	}

	part, err = mr.NextPart()
	if err != nil || part.FormName() != "nsp" {
		return adminErr(400, "invalid_multipart", "the second part must be \"nsp\"")
	}
	dir := filepath.Join(s.shop.dir, "content", tid)
	if s.shop.dir == "" {
		dir = filepath.Join(os.TempDir(), "nx-baas-shop", "content", tid)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".upload-*.nsp")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name()) // a no-op once renamed
	}()
	n, err := io.Copy(tmp, part)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return adminErr(413, "too_large", "the upload is larger than %d bytes (NX_SHOP_UPLOAD_MAX_BYTES)", tooBig.Limit)
		}
		return adminErr(400, "invalid_multipart", "reading the package: %v", err)
	}
	contents, err := verifyNSP(tmp, n, &meta)
	if err != nil {
		log.Printf("[store-admin] %s: upload refused: %v", tid, redact.Err(err))
		return err
	}
	var cnmt string
	for _, c := range contents {
		if c.ContentType == "meta" {
			cnmt = c.ContentID
		}
	}
	name := fmt.Sprintf("%s-%d-%s.nsp", meta.Kind, meta.Version, cnmt[:12])
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	rel := "content/" + tid + "/" + name
	for i := range contents {
		contents[i].File = rel
	}

	var replaced string
	t, err := s.shop.mutateTitle(tid, func(t *ShopTitle) error {
		if meta.Kind == "base" {
			replaced = t.Package
			t.Content, t.Package = contents, rel
			t.CNMTPath, t.ControlPath, t.ControlID = "", "", ""
			t.BaseVersion, t.BaseVersionLabel = meta.Version, meta.VersionLabel
			if t.Patch == nil {
				t.Version, t.VersionLabel = meta.Version, meta.VersionLabel
			}
		} else {
			if t.Patch != nil {
				replaced = t.Patch.Package
			}
			if t.Patch == nil {
				// The application's version moves to BaseVersion once a patch exists.
				t.BaseVersion, t.BaseVersionLabel = t.applicationVersion(), firstNonEmpty(t.BaseVersionLabel, t.VersionLabel)
			}
			t.Patch = &ShopPatch{Version: meta.Version, VersionLabel: meta.VersionLabel, Content: contents, Package: rel}
			t.Version, t.VersionLabel = meta.Version, meta.VersionLabel
		}
		for _, c := range contents {
			if c.ContentType == "control" && meta.Kind == "base" {
				t.ControlID = c.ContentID
			}
		}
		t.SizeBytes = contentSize(t.Content)
		if t.Patch != nil {
			t.SizeBytes += contentSize(t.Patch.Content)
		}
		return nil
	})
	if err != nil {
		os.Remove(filepath.Join(dir, name))
		return err
	}
	if replaced != rel {
		s.shop.removePackage(replaced)
	}
	log.Printf("[store-admin] %s: %s version %d uploaded (%d bytes, %d NCAs, %s)", tid, meta.Kind, meta.Version, n, len(contents), rel)
	writeJSON(w, 201, adminTitleObj(t, true))
	return nil
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

// ---------- PFS0 ----------

type pfs0Entry struct {
	Name         string
	Offset, Size int64 // Offset is absolute in the file
}

// readPFS0 parses a PFS0 header: "PFS0", u32 entry count, u32 string table size, u32
// reserved; then per entry u64 data offset, u64 size, u32 name offset, u32 reserved; then
// the string table; the data region follows it. Offsets returned are absolute.
func readPFS0(f io.ReaderAt, size int64) ([]pfs0Entry, error) {
	bad := func(format string, a ...any) error { return adminErr(422, "not_pfs0", format, a...) }
	var hdr [16]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil || string(hdr[:4]) != "PFS0" {
		return nil, bad("the package is not a PFS0 (NSP)")
	}
	n := int64(binary.LittleEndian.Uint32(hdr[4:]))
	strSize := int64(binary.LittleEndian.Uint32(hdr[8:]))
	if n == 0 || n > 4096 || strSize > 1<<20 {
		return nil, bad("implausible PFS0 header: %d entries, %d byte string table", n, strSize)
	}
	dataStart := 16 + 24*n + strSize
	if dataStart > size {
		return nil, bad("PFS0 header runs past the end of the file")
	}
	table := make([]byte, 24*n+strSize)
	if _, err := f.ReadAt(table, 16); err != nil {
		return nil, bad("reading PFS0 header: %v", err)
	}
	strs := table[24*n:]
	out := make([]pfs0Entry, 0, n)
	for i := range n {
		e := table[24*i:]
		off, sz := binary.LittleEndian.Uint64(e), binary.LittleEndian.Uint64(e[8:])
		nameOff := int64(binary.LittleEndian.Uint32(e[16:]))
		if nameOff >= strSize {
			return nil, bad("entry %d name outside the string table", i)
		}
		name := strs[nameOff:]
		if j := indexZero(name); j >= 0 {
			name = name[:j]
		}
		if off > uint64(size) || sz > uint64(size) || dataStart+int64(off)+int64(sz) > size {
			return nil, bad("entry %q lies outside the file", name)
		}
		out = append(out, pfs0Entry{Name: string(name), Offset: dataStart + int64(off), Size: int64(sz)})
	}
	return out, nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// verifyNSP checks a stored package against its declared metadata (contract, "Upload
// verification") and returns the content rows to register: measured size and hash,
// declared type, offset inside the package.
func verifyNSP(f *os.File, size int64, meta *versionMeta) ([]ShopContent, error) {
	entries, err := readPFS0(f, size)
	if err != nil {
		return nil, err
	}
	declared := map[string]int{}
	metas := 0
	for i, c := range meta.Contents {
		id := strings.ToLower(c.ContentID)
		if _, err := hex.DecodeString(id); err != nil || len(id) != 32 {
			return nil, adminErr(400, "invalid_metadata", "content_id %q is not 32 hex digits", c.ContentID)
		}
		if _, dup := declared[id]; dup {
			return nil, adminErr(400, "invalid_metadata", "content_id %s listed twice", id)
		}
		declared[id] = i
		if c.ContentType == "meta" {
			metas++
		}
	}
	if metas != 1 {
		return nil, adminErr(400, "invalid_metadata", "exactly one content must be of type meta, got %d", metas)
	}
	var out []ShopContent
	cnmts := 0
	for _, e := range entries {
		lower := strings.ToLower(e.Name)
		if strings.HasSuffix(lower, ".tik") || strings.HasSuffix(lower, ".cert") {
			return nil, adminErr(422, "rights_id_not_allowed", "the package carries %s: the OpenPak store serves only titles packaged without a rights ID", e.Name)
		}
		if !strings.HasSuffix(lower, ".nca") {
			continue // .cnmt.xml, icons and the like: not content
		}
		isMeta := strings.HasSuffix(lower, ".cnmt.nca")
		id := strings.TrimSuffix(strings.TrimSuffix(lower, ".nca"), ".cnmt")
		if _, err := hex.DecodeString(id); err != nil || len(id) != 32 {
			return nil, adminErr(422, "content_id_mismatch", "NCA entry %q is not named by a 32-hex content id", e.Name)
		}
		if isMeta {
			cnmts++
		}
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(f, e.Offset, e.Size)); err != nil {
			return nil, err
		}
		sum := hex.EncodeToString(h.Sum(nil))
		if sum[:32] != id {
			return nil, adminErr(422, "content_id_mismatch", "%s: content id is not the first 16 bytes of its SHA-256 (%s)", e.Name, sum[:32])
		}
		i, ok := declared[id]
		if !ok {
			return nil, adminErr(422, "content_mismatch", "%s is in the package but not in contents", e.Name)
		}
		d := meta.Contents[i]
		if (d.ContentType == "meta") != isMeta {
			return nil, adminErr(422, "content_mismatch", "%s: the .cnmt.nca must be the content declared meta", e.Name)
		}
		if d.Size != 0 && d.Size != e.Size {
			return nil, adminErr(422, "size_mismatch", "%s: declared %d bytes, package holds %d", e.Name, d.Size, e.Size)
		}
		if d.SHA256 != "" && !strings.EqualFold(d.SHA256, sum) {
			return nil, adminErr(422, "content_id_mismatch", "%s: declared sha256 does not match the bytes", e.Name)
		}
		delete(declared, id)
		out = append(out, ShopContent{ContentID: id, Offset: e.Offset, Size: e.Size, SHA256: sum, ContentType: d.ContentType})
	}
	if cnmts != 1 {
		return nil, adminErr(422, "no_cnmt", "the package must hold exactly one .cnmt.nca, found %d", cnmts)
	}
	for id := range declared {
		return nil, adminErr(422, "content_mismatch", "content %s is declared but not in the package", id)
	}
	return out, nil
}

// ---------- accounts and stats (read-only) ----------

func (s *server) adminAccount(w http.ResponseWriter, r *http.Request, accountID, what string) error {
	naID := strings.ToLower(r.URL.Query().Get("na_id"))
	if naID == "" {
		b, ok := s.acct.(*openpakBackend)
		if !ok {
			return adminErr(404, "not_found", "account lookup needs the openpak backend; pass ?na_id=")
		}
		b.proj.mu.Lock()
		if pr := b.proj.ByAccount[accountID]; pr != nil {
			naID = pr.NaID
		}
		b.proj.mu.Unlock()
		if naID == "" {
			return adminErr(404, "not_found", "account %s has no Switch identity here", accountID)
		}
	}
	out := map[string]any{"account_id": accountID, "na_id": naID}
	switch what {
	case "entitlements":
		items := []map[string]any{}
		s.shop.mu.Lock()
		for _, e := range s.shop.Entitlements {
			if strings.EqualFold(e.AccountID, naID) {
				items = append(items, map[string]any{
					"title_id": e.TitleID, "status": e.Status, "version": e.Version, "elicense_id": e.ELicenseID,
					"device_id": e.DeviceID, "source": firstNonEmpty(e.Source, "purchase"),
					"created_at": e.CreatedAt, "updated_at": e.UpdatedAt,
				})
			}
		}
		s.shop.mu.Unlock()
		out["entitlements"] = items
	case "tasks":
		items := []map[string]any{}
		for _, t := range s.shop.tasksFor(naID) {
			items = append(items, map[string]any{
				"id": t.ID, "title_id": t.TitleID, "version": t.Version, "state": t.State,
				"fail_reason": t.FailReason, "created_at": t.CreatedAt, "updated_at": t.UpdatedAt,
			})
		}
		out["tasks"] = items
	default:
		return adminErr(404, "not_found", "no such account view %q", what)
	}
	writeJSON(w, 200, out)
	return nil
}

// allStats renders per-title statistics: one title when only is set, else every catalog title.
func (s *shopState) allStats(only string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := []string{}
	for id := range s.Catalog {
		if only == "" || id == only {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		st := ShopTitleStats{}
		if p := s.Stats[id]; p != nil {
			st = *p
		}
		ents := 0
		for _, e := range s.Entitlements {
			if e.TitleID == id && e.Status == "active" {
				ents++
			}
		}
		tasks := map[string]int{}
		for _, t := range s.Tasks {
			if t.TitleID == id {
				tasks[t.State]++
			}
		}
		out = append(out, map[string]any{
			"title_id": id, "downloads": st.Downloads, "content_requests": st.ContentRequests,
			"bytes_served": st.BytesServed, "last_download_at": st.LastDownloadAt,
			"entitlements": ents, "tasks": tasks,
		})
	}
	return out
}

// ---------- firmware blocklist (bvc) ----------

// adminFirmwareBlocklist edits the versions bvc refuses (eshop_unserved.go):
// GET lists, PUT replaces the list, PUT/DELETE on /{version} adds or removes one.
func (s *server) adminFirmwareBlocklist(w http.ResponseWriter, r *http.Request, rest []string) error {
	m := r.Method
	switch {
	case len(rest) == 0 && m == http.MethodGet:
	case len(rest) == 0 && m == http.MethodPut:
		var in struct {
			Versions []struct {
				Version string `json:"version"`
				Note    string `json:"note"`
			} `json:"versions"`
		}
		if err := decodeStrict(r.Body, &in, false); err != nil {
			return err
		}
		list := []BlockedFirmware{}
		seen := map[string]bool{}
		now := time.Now().Unix()
		for _, v := range in.Versions {
			n := normalizeFirmware(v.Version)
			if n == "" {
				return adminErr(400, "invalid_field", "firmware version %q must be major-minor-micro, each 0-255", v.Version)
			}
			if seen[n] {
				continue
			}
			seen[n] = true
			added := now
			if old := s.shop.blockedFirmware(n); old != nil {
				added = old.AddedAt
			}
			list = append(list, BlockedFirmware{Version: n, Note: v.Note, AddedAt: added})
		}
		s.shop.mu.Lock()
		s.shop.BlockedFirmware = list
		s.shop.save()
		s.shop.mu.Unlock()
		log.Printf("[store-admin] firmware blocklist replaced: %d version(s)", len(list))
	case len(rest) == 1 && (m == http.MethodPut || m == http.MethodDelete):
		n := normalizeFirmware(rest[0])
		if n == "" {
			return adminErr(400, "invalid_field", "firmware version %q must be major-minor-micro, each 0-255", rest[0])
		}
		var note struct {
			Note string `json:"note"`
		}
		if m == http.MethodPut && r.ContentLength != 0 {
			if err := decodeStrict(r.Body, &note, false); err != nil {
				return err
			}
		}
		s.shop.mu.Lock()
		found := -1
		for i, b := range s.shop.BlockedFirmware {
			if b.Version == n {
				found = i
			}
		}
		switch {
		case m == http.MethodDelete && found < 0:
			s.shop.mu.Unlock()
			return adminErr(404, "not_found", "firmware %s is not on the blocklist", n)
		case m == http.MethodDelete:
			s.shop.BlockedFirmware = append(s.shop.BlockedFirmware[:found], s.shop.BlockedFirmware[found+1:]...)
		case found >= 0:
			s.shop.BlockedFirmware[found].Note = note.Note
		default:
			s.shop.BlockedFirmware = append(s.shop.BlockedFirmware, BlockedFirmware{Version: n, Note: note.Note, AddedAt: time.Now().Unix()})
		}
		s.shop.save()
		s.shop.mu.Unlock()
		log.Printf("[store-admin] firmware blocklist: %s %s", m, n)
	default:
		return adminErr(405, "method_not_allowed", "%s %s", m, r.URL.Path)
	}
	s.shop.mu.Lock()
	list := append([]BlockedFirmware{}, s.shop.BlockedFirmware...)
	s.shop.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return firmwareLess(list[i].Version, list[j].Version) })
	writeJSON(w, 200, map[string]any{"versions": list})
	return nil
}

// firmwareLess orders "major-minor-micro" numerically.
func firmwareLess(a, b string) bool {
	pa, pb := strings.Split(a, "-"), strings.Split(b, "-")
	for i := 0; i < 3 && i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return a < b
}
