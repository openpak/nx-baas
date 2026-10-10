// SPDX-License-Identifier: AGPL-3.0-only
package main

// Latest version only: every Switch title OpenPak serves goes online on its newest update.
//
// The console asks aauth for an application token each time a title goes online, and sends
// the installed title version as %08x of the u32 (MK8D 3.0.5 is 00150000). An older version
// gets aauth error 0111, which the account module shows as 2124-3001 "A software update is
// required" with Restart / Later — the console's own dialog, before any game server is
// contacted, on every stack (NEX, NPLN, Photon, Battle.net, ...).
//
// Nothing here forces a download: the version list's required_version is left alone, because
// OpenPak hosts no retail updates. Players update through Nintendo's side and come back.
//
// The table (title id -> latest u32 version) comes from blawar/titledb's versions.json, where
// each base title id maps {version: release date} and the latest is the highest key. It is
// refetched every 24 h and cached under NX_DATA; a failed fetch keeps the last good table.
// A title missing from the table, or a version that is not 8 hex digits (Harbor sends the
// display string "3.0.5"), is always allowed: never refuse what can't be read.
//
//	NX_VERSION_GATE            on unless 0/off/false
//	NX_VERSION_GATE_URL        versions.json source (default titledb on GitHub)
//	NX_VERSION_GATE_OVERRIDES  per title: <title id>=<%08x minimum> or <title id>=all

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"nx-baas/redact"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	versionGateDefaultURL = "https://raw.githubusercontent.com/blawar/titledb/master/versions.json"
	versionGateRefresh    = 24 * time.Hour
	versionGateRetry      = time.Hour
	versionGateMaxBytes   = 64 << 20
)

// versionOverride pins a title's minimum (min) or lets every version through (all).
type versionOverride struct {
	all bool
	min uint32
}

type versionGate struct {
	on        bool
	url       string
	cachePath string
	overrides map[uint64]versionOverride
	fetch     func(url string) ([]byte, error) // swapped in tests

	mu     sync.RWMutex
	latest map[uint64]uint32
}

func newVersionGateFromEnv() *versionGate {
	g := &versionGate{
		on:        !isOff(getenv("NX_VERSION_GATE", "1")),
		url:       getenv("NX_VERSION_GATE_URL", versionGateDefaultURL),
		cachePath: filepath.Join(getenv("NX_DATA", "/data"), "title-versions.json"),
		fetch:     httpFetch,
	}
	var err error
	if g.overrides, err = parseVersionOverrides(os.Getenv("NX_VERSION_GATE_OVERRIDES")); err != nil {
		log.Fatalf("[version-gate] NX_VERSION_GATE_OVERRIDES: %v", redact.Err(err))
	}
	return g
}

func isOff(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "off", "false", "no":
		return true
	}
	return false
}

// parseVersionOverrides reads "0100152000022000=00150000,010090100e334000=all".
func parseVersionOverrides(s string) (map[uint64]versionOverride, error) {
	out := map[uint64]versionOverride{}
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		id, val, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("%q: want <title id>=<%%08x version> or <title id>=all", item)
		}
		tid, err := parseTitleID(id)
		if err != nil {
			return nil, fmt.Errorf("%q: %v", item, err)
		}
		if strings.EqualFold(strings.TrimSpace(val), "all") {
			out[tid] = versionOverride{all: true}
			continue
		}
		v, ok := parseAppVersion(strings.TrimSpace(val))
		if !ok {
			return nil, fmt.Errorf("%q: version must be 8 hex digits or all", item)
		}
		out[tid] = versionOverride{min: v}
	}
	return out, nil
}

func parseTitleID(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if len(s) != 16 {
		return 0, fmt.Errorf("title id must be 16 hex digits")
	}
	return strconv.ParseUint(s, 16, 64)
}

// parseAppVersion reads the console's %08x. Anything else (Harbor's "3.0.5") is not a version.
func parseAppVersion(s string) (uint32, bool) {
	if len(s) != 8 {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 32)
	return uint32(v), err == nil
}

// baseTitle maps an update id (base | 0x800) to its application; the table is keyed by base.
func baseTitle(id uint64) uint64 {
	if id&0xfff == 0x800 {
		return id &^ 0x800
	}
	return id
}

// parseTitleVersions turns titledb's versions.json into title id -> highest version.
func parseTitleVersions(body []byte) (map[uint64]uint32, error) {
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make(map[uint64]uint32, len(raw))
	for id, versions := range raw {
		tid, err := parseTitleID(id)
		if err != nil {
			continue
		}
		var best uint32
		found := false
		for k := range versions {
			v, err := strconv.ParseUint(k, 10, 32)
			if err != nil {
				continue
			}
			if !found || uint32(v) > best {
				best, found = uint32(v), true
			}
		}
		if found {
			out[baseTitle(tid)] = best
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no titles in the table")
	}
	return out, nil
}

func (g *versionGate) size() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.latest)
}

// loadCache starts from the last good table on disk, so a restart without network still gates.
func (g *versionGate) loadCache() {
	body, err := os.ReadFile(g.cachePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[version-gate] cache %s: %v", g.cachePath, redact.Err(err))
		}
		return
	}
	t, err := parseTitleVersions(body)
	if err != nil {
		log.Printf("[version-gate] cache %s unreadable: %v", g.cachePath, redact.Err(err))
		return
	}
	g.mu.Lock()
	g.latest = t
	g.mu.Unlock()
	log.Printf("[version-gate] table: %d titles from the cache", len(t))
}

// refresh fetches the table. On any failure the current table stays as it is.
func (g *versionGate) refresh() error {
	body, err := g.fetch(g.url)
	if err != nil {
		return err
	}
	t, err := parseTitleVersions(body)
	if err != nil {
		return fmt.Errorf("parse: %v", err)
	}
	g.mu.Lock()
	g.latest = t
	g.mu.Unlock()
	if g.cachePath != "" {
		tmp := g.cachePath + ".tmp"
		if err := os.WriteFile(tmp, body, 0o644); err == nil {
			err = os.Rename(tmp, g.cachePath)
		}
		if err != nil {
			log.Printf("[version-gate] cache write: %v", redact.Err(err))
		}
	}
	log.Printf("[version-gate] table: %d titles fetched", len(t))
	return nil
}

func (g *versionGate) run() {
	g.loadCache()
	for {
		wait := versionGateRefresh
		if err := g.refresh(); err != nil {
			log.Printf("[version-gate] refresh failed, keeping %d titles: %v", g.size(), redact.Err(err))
			wait = versionGateRetry
		}
		time.Sleep(wait)
	}
}

func httpFetch(url string) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, versionGateMaxBytes))
}

// required answers the minimum version for a title and whether one applies.
func (g *versionGate) required(title uint64) (uint32, bool) {
	title = baseTitle(title)
	if o, ok := g.overrides[title]; ok {
		return o.min, !o.all
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	v, ok := g.latest[title]
	return v, ok
}

// versionVerdict is one title version measured against the table.
type versionVerdict struct {
	title    uint64
	latest   uint32 // the minimum that applies; meaningful only when applies
	applies  bool   // the gate is on and the table (or an override) names a minimum
	have     uint32
	readable bool // the version is the console's 8 hex digits
	outdated bool
}

// verdict measures a title version. Anything unreadable, unknown or ungated is not outdated.
func (g *versionGate) verdict(appID, appVer string) versionVerdict {
	var v versionVerdict
	tid, err := parseTitleID(appID)
	if err != nil {
		return v
	}
	v.title = tid
	v.have, v.readable = parseAppVersion(appVer)
	if g == nil || !g.on {
		return v
	}
	v.latest, v.applies = g.required(tid)
	v.outdated = v.applies && v.readable && v.have < v.latest
	return v
}

// refuse decides an aauth request. It logs one line per refusal and per unreadable version,
// with the title and versions only.
func (g *versionGate) refuse(appID, appVer string) bool {
	v := g.verdict(appID, appVer)
	if !v.applies {
		return false
	}
	if !v.readable {
		log.Printf("[version-gate] title %016x sent unparsed version %q: allowed", v.title, appVer)
		return false
	}
	if !v.outdated {
		return false
	}
	log.Printf("[version-gate] title %016x version %08x below required %08x: 0111 update required", v.title, v.have, v.latest)
	return true
}

// titleVersion answers the game servers (internal API): is this title version outdated, and what
// is the latest? It is the same table and the same rule aauth applies, so a game server that
// refuses an old version in its own protocol (NEX ApplicationVersionIsOld, NPLN
// FAILED_PRECONDITION, ...) never disagrees with the console's 2124-3001. The version is the
// id_token's nintendo.av, as aauth received it.
//
//	GET /internal/title-version?title=<16 hex>&version=<av>
//	-> {"title":"0100152000022000","version":"00140000","latest":"00150000","update_required":true}
//
// latest is "" when no minimum applies (unknown title, an "all" override, the gate off), and
// update_required is false then and for any version that is not 8 hex digits.
func (s *server) titleVersion(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	q := r.URL.Query()
	title, version := q.Get("title"), q.Get("version")
	if _, err := parseTitleID(title); err != nil {
		apiErr(w, http.StatusBadRequest, "title must be 16 hex digits")
		return
	}
	v := s.versions.verdict(title, version)
	latest := ""
	if v.applies {
		latest = fmt.Sprintf("%08x", v.latest)
	}
	if v.outdated {
		log.Printf("[version-gate] game server asked: title %016x version %08x below %s: update required", v.title, v.have, latest)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"title": fmt.Sprintf("%016x", v.title), "version": version,
		"latest": latest, "update_required": v.outdated,
	})
}
