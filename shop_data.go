package main

// The OpenPak store's own durable state: catalog, entitlements and download tasks.
//
// Everything here is OpenPak-defined protocol, not a Nintendo wire shape: the storefront is
// our page, the catalog is our file, and the entitlements are our rows. The Nintendo-facing
// projections of this state (Beach device links, dragons elicenses, atum content) live in
// beach.go and atum.go and read from here, so there is exactly one canonical copy.
//
// Persistence is one JSON document under $NX_DATA/shop/, saved through the same
// write-temp-then-rename the user store uses. Entitlements are keyed by (na id, title id)
// and the elicense id is minted once: acquiring twice must return the same entitlement
// (SHP-03 idempotency), and a restart must not mint a new one (SHP-05).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ShopTitle is one catalog entry. Localized carries the per-language text; everything else
// is language-neutral. Distribution records the permission under which OpenPak may serve
// this title at all (SHP-02): a catalog entry without it must not be listed.
type ShopTitle struct {
	TitleID       string   `json:"title_id"` // 16 hex digits, the packager's choice; must be stable
	Publisher     string   `json:"publisher"`
	IconPath      string   `json:"icon_path,omitempty"` // served as-is under /ashigaru/assets/
	Screenshots   []string `json:"screenshots,omitempty"`
	Category      string   `json:"category,omitempty"`
	SizeBytes     int64    `json:"size_bytes"`
	Version       uint32   `json:"version"` // the title's own version number, e.g. 65536 == 1.0.0
	VersionLabel  string   `json:"version_label"`
	Compatibility []string `json:"compatibility,omitempty"` // e.g. "handheld", "docked", "pro-controller"
	Languages     []string `json:"languages,omitempty"`     // BCP-47 tags the title itself supports
	// Content maps content ids to the files the packager placed on this server. The NCA
	// bytes come from the redistributable package; this server never builds NCAs.
	Content []ShopContent `json:"content"`
	// ControlPath/CNMTPath name the files served on /c{1,2}/a/d/... and /t/a/....
	ControlPath string `json:"control_path,omitempty"`       // file served on /c{1,2}/a/d/<tid>[/<ver>]
	CNMTPath    string `json:"cnmt_path,omitempty"`          // file served on /c{1,2}/t/a/<tid>/<ver>
	ControlID   string `json:"control_content_id,omitempty"` // the control NCA's content id
	// Distribution is the recorded permission to redistribute: where the package came
	// from and what allows OpenPak to serve it. Served in the details API and checked at
	// load: an entry without one is skipped, never silently listed.
	Distribution ShopDistribution    `json:"distribution"`
	Localized    map[string]ShopText `json:"localized"`
	DefaultLang  string              `json:"default_lang,omitempty"`
	UpdatedAt    int64               `json:"updated_at"`
	// Patch is the title's current update, when it has one: a content meta of its own
	// under the patch id (the application id with 0x800 in its low bits), served on the
	// same atum routes as the application's. Publishing a new version of a title is
	// replacing this block in catalog.json with the new version's content and raising
	// updated_at; the running server picks the file up on its next read (reloadCatalog).
	// With a patch, Version is the patch's version (the one a download ends on) and
	// BaseVersion is the application content meta's own, normally 0.
	Patch       *ShopPatch `json:"patch,omitempty"`
	BaseVersion uint32     `json:"base_version,omitempty"`
	// Unpublished hides the title from every console surface (storefront, version list,
	// superfly, pushmo, atum). The zero value is published, so hand-written catalog.json
	// entries keep being listed; titles created through the admin API start unpublished.
	Unpublished bool `json:"unpublished,omitempty"`
	// Package names the stored NSP a version was uploaded as (store_admin.go), relative to
	// the shop directory; empty for hand-placed content. The patch has its own.
	Package string `json:"package,omitempty"`
	// BaseVersionLabel is the application version's display label, kept beside
	// VersionLabel (which follows the newest version) by the admin API.
	BaseVersionLabel string `json:"base_version_label,omitempty"`
}

// ShopPatch is one title update: its version and the files that carry it.
type ShopPatch struct {
	Version      uint32        `json:"version"`
	VersionLabel string        `json:"version_label,omitempty"`
	Content      []ShopContent `json:"content"`
	CNMTPath     string        `json:"cnmt_path,omitempty"`    // served on /c{1,2}/t/a/<patch id>/<ver>
	ControlPath  string        `json:"control_path,omitempty"` // served on /c{1,2}/a/d/<patch id>[/<ver>]
	Package      string        `json:"package,omitempty"`      // the uploaded NSP, as ShopTitle.Package
}

// patchIDFor is the id a title's update is published under: the application id with
// 0x800 in its low twelve bits (application ids end in 000).
func patchIDFor(titleID string) string {
	if !validTitleID(titleID) {
		return ""
	}
	return titleID[:13] + "800"
}

// applicationVersion is the version of the application content meta itself: the base
// when an update is published, else the title's only version.
func (t *ShopTitle) applicationVersion() uint32 {
	if t.Patch != nil {
		return t.BaseVersion
	}
	return t.Version
}

// normalize keeps Version the newest version a download can reach, whichever block the
// operator bumped.
func (t *ShopTitle) normalize() {
	if t.Patch != nil && t.Patch.Version > t.Version {
		t.Version = t.Patch.Version
		if t.Patch.VersionLabel != "" {
			t.VersionLabel = t.Patch.VersionLabel
		}
	}
}

// meta resolves a content-meta id to its catalog title: the application id itself, or a
// title's patch id. isPatch says which of the two was asked for.
func (s *shopState) meta(id string) (t *ShopTitle, isPatch bool) {
	id = strings.ToLower(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.Catalog[id]; t != nil && !t.Unpublished {
		return t, false
	}
	if validTitleID(id) && strings.HasSuffix(id, "800") {
		if t := s.Catalog[id[:13]+"000"]; t != nil && t.Patch != nil && !t.Unpublished {
			return t, true
		}
	}
	return nil, false
}

// listed is a catalog title the console surfaces may show: present and not unpublished.
// The admin API (store_admin.go) is the only reader that sees unpublished titles.
func (s *shopState) listed(id string) *ShopTitle {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.Catalog[strings.ToLower(id)]; t != nil && !t.Unpublished {
		return t
	}
	return nil
}

// applicationFor maps a content-meta id to the application id that owns it (itself for
// an application, the parent for a patch). Entitlements and edge tokens are per
// application, so an update is fetched under its application's licence.
func (s *shopState) applicationFor(id string) string {
	if t, _ := s.meta(id); t != nil {
		return t.TitleID
	}
	return id
}

// ShopText is the localized part of a catalog entry. The struct exists so the language
// fallback (SHP-02) has one obvious place: text(fall) walks exact tag, primary subtag,
// entry default, any.
type ShopText struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ShopDistribution struct {
	// Source is where the package was obtained (URL or path), Permission is the
	// human-readable statement that redistribution is allowed (license, author grant...).
	Source     string `json:"source"`
	Permission string `json:"permission"`
}

type ShopContent struct {
	ContentID   string `json:"content_id"`       // 32 hex digits (NCA id convention)
	File        string `json:"file"`             // relative to the shop data dir
	Offset      int64  `json:"offset,omitempty"` // for packages holding several NCAs in one file
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`                 // lowercase hex; must match the file bytes
	ContentType string `json:"content_type,omitempty"` // "meta" (CNMT) or "program"/... informational
}

// ShopEntitlement is one acquired title, per account. ELicenseID is minted once and never
// changes: it is the id dragons hands out and the id a revoke names.
type ShopEntitlement struct {
	AccountID    string `json:"account_id"` // Nintendo Account id (16 hex)
	BaasUserID   string `json:"baas_user_id"`
	TitleID      string `json:"title_id"`
	RightsID     string `json:"rights_id"`   // deterministic from TitleID; see rightsIDFor
	ELicenseID   string `json:"elicense_id"` // 32 hex, minted once
	DeviceID     string `json:"device_id"`   // device the acquisition happened on
	Version      uint32 `json:"version"`
	ELicenseType string `json:"elicense_type"`
	Status       string `json:"status"` // "active" or "revoked"
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

// ShopTask tracks one download (SHP-04/05). State transitions:
// queued -> downloading -> completed, or queued/downloading -> paused -> canceled,
// or any -> failed(reason). A restart resumes where the file's bytes are, not where the
// task says it was: the client re-asks with Range and the server's truth is the file.
type ShopTask struct {
	ID         string `json:"id"`
	AccountID  string `json:"account_id"`
	TitleID    string `json:"title_id"`
	Version    uint32 `json:"version"`
	State      string `json:"state"`                 // queued|downloading|paused|completed|failed|canceled
	FailReason string `json:"fail_reason,omitempty"` // e.g. "insufficient_storage", "corrupt_content", "missing_content"
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

type shopState struct {
	mu  sync.Mutex
	dir string // $NX_DATA/shop; "" keeps everything in memory (tests)

	Catalog      map[string]*ShopTitle `json:"catalog,omitempty"`
	Entitlements []*ShopEntitlement    `json:"entitlements"`
	Tasks        []*ShopTask           `json:"tasks"`
	// Links is the beach device-link table (beach.go): which device is linked to which
	// account, plus the penne/notification registrations NIM pushes through beach.
	Links deviceLinkTable `json:"links"`
	// Stats counts what atum served per application id (store_admin.go).
	Stats map[string]*ShopTitleStats `json:"stats,omitempty"`
	// catalogMod is catalog.json's modification time at the last read (reloadCatalog).
	catalogMod time.Time
}

func newShopState(dir string) *shopState {
	s := &shopState{dir: dir, Catalog: map[string]*ShopTitle{}}
	s.load()
	s.loadCatalogFile()
	if len(s.Catalog) == 0 {
		s.Catalog = defaultShopCatalog()
	}
	return s
}

func (s *shopState) load() {
	if s.dir == "" {
		return
	}
	b, err := os.ReadFile(s.dir + "/state.json")
	if err != nil {
		return
	}
	json.Unmarshal(b, s)
}

func (s *shopState) save() {
	if s.dir == "" {
		return
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		log.Printf("[shop] save: %v", err)
		return
	}
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		log.Printf("[shop] save: %v", err)
		return
	}
	if err := os.WriteFile(s.dir+"/state.json.tmp", b, 0o600); err != nil {
		log.Printf("[shop] save: %v", err)
		return
	}
	os.Rename(s.dir+"/state.json.tmp", s.dir+"/state.json")
}

// loadCatalogFile reads catalog.json when the operator placed one. Entries without a
// distribution permission are dropped with a log line: the store must not list a title it
// cannot show permission for (SHP-02).
func (s *shopState) loadCatalogFile() {
	if s.dir == "" {
		return
	}
	st, err := os.Stat(s.dir + "/catalog.json")
	if err != nil {
		return
	}
	b, err := os.ReadFile(s.dir + "/catalog.json")
	if err != nil {
		return
	}
	var entries []*ShopTitle
	if err := json.Unmarshal(b, &entries); err != nil {
		log.Printf("[shop] catalog.json: %v", err)
		return
	}
	s.catalogMod = st.ModTime()
	for _, t := range entries {
		if t.TitleID == "" || t.Distribution.Permission == "" {
			log.Printf("[shop] catalog: dropping %q: no title_id or no recorded distribution permission", t.TitleID)
			continue
		}
		t.TitleID = strings.ToLower(t.TitleID)
		t.normalize()
		if old := s.Catalog[t.TitleID]; old != nil && old.Version != t.Version {
			log.Printf("[shop] catalog: %s published version %d (was %d)", t.TitleID, t.Version, old.Version)
		}
		s.Catalog[t.TitleID] = t
	}
	if len(entries) > 0 {
		log.Printf("[shop] catalog: %d entr%s from catalog.json", len(entries), pluralY(len(entries)))
	}
}

// reloadCatalog re-reads catalog.json when the operator changed it since the last read,
// so publishing an update is editing the file, not restarting the server. The version
// list, the download lists and the content routes all read through here first.
func (s *shopState) reloadCatalog() {
	if s == nil || s.dir == "" {
		return
	}
	st, err := os.Stat(s.dir + "/catalog.json")
	if err != nil {
		return
	}
	s.mu.Lock()
	changed := !st.ModTime().Equal(s.catalogMod)
	if changed {
		s.loadCatalogFile()
	}
	s.mu.Unlock()
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// defaultShopCatalog is what a fresh deployment serves: one clearly synthetic test title.
// It exists so SHP-01/02 have something deterministic to render before the operator places
// a real redistributable package; its content is synthetic and says so.
const defaultFixtureID = "0f9f0c0ffee00000"

func defaultShopCatalog() map[string]*ShopTitle {
	fixture := &ShopTitle{
		TitleID:       defaultFixtureID,
		Publisher:     "OpenPak",
		Category:      "test",
		SizeBytes:     64,
		Version:       65536,
		VersionLabel:  "1.0.0",
		Compatibility: []string{"handheld", "docked"},
		Languages:     []string{"en-US"},
		Content:       []ShopContent{},
		Distribution: ShopDistribution{
			Source:     "synthetic fixture",
			Permission: "OpenPak original test fixture: the repository's own synthetic data, no third-party material.",
		},
		Localized: map[string]ShopText{
			"en-US": {Name: "OpenPak Store Test Title", Description: "Synthetic fixture for the native store tests. Not a real game."},
			"ja":    {Name: "OpenPak ストア テスト", Description: "ネイティブストアのテスト用フィクスチャ。"},
		},
		DefaultLang: "en-US",
		UpdatedAt:   time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC).Unix(),
	}
	// Title ids in this store end in 0, as every real title id does (the low nibble is
	// where the rights-id mapping stores the title type; see rightsIDFor). The map is
	// keyed by the id field itself so the two cannot drift apart again.
	return map[string]*ShopTitle{fixture.TitleID: fixture}
}

// text applies the language fallback: exact tag, then primary subtag, then the entry's
// default, then any one entry — a title with only Japanese text renders in Japanese rather
// than not rendering.
func (t *ShopTitle) text(lang string) ShopText {
	if len(t.Localized) == 0 {
		return ShopText{Name: t.TitleID}
	}
	if v, ok := t.Localized[lang]; ok {
		return v
	}
	if i := strings.IndexByte(lang, '-'); i > 0 {
		if v, ok := t.Localized[lang[:i]]; ok {
			return v
		}
	}
	if t.DefaultLang != "" {
		if v, ok := t.Localized[t.DefaultLang]; ok {
			return v
		}
	}
	for _, v := range t.Localized {
		return v
	}
	return ShopText{Name: t.TitleID}
}

func validTitleID(id string) bool {
	if len(id) != 16 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// rightsIDFor derives a title's rights id. The conventional digital-title mapping sets the
// last nibble to the title type (3 == digital). OpenPak only needs the mapping to be
// deterministic and stable; the convention is kept because diagnostic captures read better
// beside real ones. Label: convention observed in public research, not a firmware-confirmed
// requirement of our own flow.
func rightsIDFor(titleID string) string {
	if !validTitleID(titleID) {
		return ""
	}
	return titleID[:15] + "3"
}

var errNoEntitlement = errors.New("no entitlement")
var errEntitlementRevoked = errors.New("entitlement revoked")

// entitlementFor returns the (unique) entitlement of an account for a title.
func (s *shopState) entitlementFor(accountID, titleID string) *ShopEntitlement {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.Entitlements {
		if e.AccountID == accountID && e.TitleID == titleID {
			return e
		}
	}
	return nil
}

// acquire creates the account's entitlement for a title, idempotently: a second acquire —
// including one racing the first, including after a restart — returns the same row and
// the same elicense id (SHP-03). The created flag says whether this call minted it. A
// revoked entitlement revives on acquire: the account bought the title; an explicit
// revoke (refund, ban) is a separate act.
func (s *shopState) acquire(accountID, baasUserID, titleID, deviceID string, version uint32) (e *ShopEntitlement, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	title := s.Catalog[titleID]
	if title == nil {
		return nil, false, errNoEntitlement
	}
	now := time.Now().Unix()
	for _, e := range s.Entitlements {
		if e.AccountID == accountID && e.TitleID == titleID {
			e.Status = "active"
			e.UpdatedAt = now
			if version > e.Version {
				e.Version = version
			}
			s.save()
			return e, false, nil
		}
	}
	// Mint the elicense id from stable inputs so even a lost state file cannot mint a
	// second identity for the same purchase.
	sum := sha256.Sum256([]byte("openpak/elicense/" + accountID + "/" + titleID))
	e = &ShopEntitlement{
		AccountID: accountID, BaasUserID: baasUserID, TitleID: titleID,
		RightsID: rightsIDFor(titleID), ELicenseID: hex.EncodeToString(sum[:16]),
		DeviceID: deviceID, Version: version, ELicenseType: "permanent", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	}
	s.Entitlements = append(s.Entitlements, e)
	s.save()
	return e, true, nil
}

func (s *shopState) revoke(accountID, titleID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, e := range s.Entitlements {
		if e.AccountID == accountID && e.TitleID == titleID && e.Status != "revoked" {
			e.Status = "revoked"
			e.UpdatedAt = time.Now().Unix()
			changed = true
		}
	}
	if changed {
		s.save()
	}
	return changed
}

func (s *shopState) entitlementByELicense(elicenseID string) *ShopEntitlement {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.Entitlements {
		if e.ELicenseID == elicenseID {
			return e
		}
	}
	return nil
}

// ownedTitles lists a title ids the account holds an active entitlement for.
func (s *shopState) ownedTitles(accountID string) map[string]*ShopEntitlement {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]*ShopEntitlement{}
	for _, e := range s.Entitlements {
		if e.AccountID == accountID && e.Status == "active" {
			out[e.TitleID] = e
		}
	}
	return out
}

// createTask records a download task. One open task per (account, title): re-requesting
// while one exists returns it instead of stacking duplicates (the cancel/retry journey
// depends on there being exactly one live task). The task targets the catalog's CURRENT
// version — that is what an update is: the title's version moved, the entitlement's
// installed version lags until the task completes.
func (s *shopState) createTask(accountID, titleID string) (*ShopTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	title := s.Catalog[titleID]
	if title == nil {
		return nil, errNoEntitlement
	}
	now := time.Now().Unix()
	for _, t := range s.Tasks {
		if t.AccountID == accountID && t.TitleID == titleID && (t.State == "queued" || t.State == "downloading" || t.State == "paused") {
			return t, nil
		}
	}
	t := &ShopTask{
		ID: randHex(16), AccountID: accountID, TitleID: titleID, Version: title.Version,
		State: "queued", CreatedAt: now, UpdatedAt: now,
	}
	s.Tasks = append(s.Tasks, t)
	s.save()
	return t, nil
}

func (s *shopState) task(id, accountID string) *ShopTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.Tasks {
		if t.ID == id && (accountID == "" || t.AccountID == accountID) {
			return t
		}
	}
	return nil
}

// updateTask moves a task's state. Transitions are checked here, not at call sites, so the
// lifecycle cannot drift between handlers: completed/failed/canceled are terminal.
// Completing a task also moves the entitlement's installed version to the task's — the
// server-side record of "this account has this version installed" (the update flow's
// other half; the update available signal is version_owned < catalog version).
func (s *shopState) updateTask(id, accountID, state, failReason string) *ShopTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.Tasks {
		if t.ID != id || (accountID != "" && t.AccountID != accountID) {
			continue
		}
		if t.State == "completed" || t.State == "failed" || t.State == "canceled" {
			return t
		}
		t.State = state
		t.FailReason = failReason
		t.UpdatedAt = time.Now().Unix()
		if state == "completed" {
			for _, e := range s.Entitlements {
				if e.AccountID == t.AccountID && e.TitleID == t.TitleID && t.Version > e.Version {
					e.Version = t.Version
					e.UpdatedAt = t.UpdatedAt
				}
			}
		}
		s.save()
		return t
	}
	return nil
}

func (s *shopState) tasksFor(accountID string) []*ShopTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*ShopTask
	for _, t := range s.Tasks {
		if t.AccountID == accountID {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// contentFile resolves a content id to the bytes' location on this server. Hash
// verification is the caller's job (it knows whether to stream or seek).
func (s *shopState) contentFile(titleID, contentID string) (path string, c ShopContent, err error) {
	title, isPatch := s.meta(titleID)
	if title == nil {
		return "", c, errNoEntitlement
	}
	contents := title.Content
	if isPatch {
		contents = title.Patch.Content
	}
	for _, c := range contents {
		if c.ContentID == contentID {
			return s.dir + "/" + c.File, c, nil
		}
	}
	return "", c, fmt.Errorf("content %s not in catalog", contentID)
}
