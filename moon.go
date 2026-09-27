package main

// moon is the parental-controls API: `api-<env>.pctl.srv.nintendo.net/moon/v1/…`,
// the only thing the pctl sysmodule (22.5.0 title 010000000000002E) needs from a
// server. Everything the console does on its own -- the PIN, the restriction
// level, the play timer, the bedtime alarm -- lives in pctl's system savedata and
// works offline. What dies without a server is pairing with the parent app and
// the settings sync. Contract: the docs repo, switch/parental-controls-firmware-2026-09-26.md.
//
// Phase 0 of the PRD (docs repo, switch/native-switch-parental-controls-prd.md): log what the
// console sends and refuse in the shape it recognises. The ten paths, their
// verbs and their bodies are not invented here -- one on-console pairing attempt
// against this handler prints them, and the phases after this are written against
// that log.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The error identities pctl carries as literals (study §5). A refusal that does
// not name one of these is a refusal the client cannot classify, which is why
// this handler never answers a bare status.
const (
	moonErrorBase        = "https://moon.nintendo.com/errors/v1/"
	moonNotFound         = "404/resource_is_not_found"
	moonForbidden        = "403/forbidden"
	moonMethodNotAllowed = "405/method_not_allowed"
	moonInvalidToken     = "401/invalid_token"
	moonOverTheTimeLimit = "409/over_the_time_limit"
	moonDevicesMaxed     = "400/devices_maxed"
	moonInternalError    = "500/internal_server_error"
)

// moonError writes a refusal. `type` is the identity above; `status`, `code` and
// `detail` are the other three error keys in pctl's string table (997708 and
// neighbours), so the envelope is those four and nothing guessed beyond them.
// ponytail: four keys because four are evidenced. If hardware shows the client
// reading a fifth, the log will name it.
func moonError(w http.ResponseWriter, slug string) {
	status, code, _ := strings.Cut(slug, "/")
	writeJSON(w, statusOf(status), map[string]any{
		"type":   moonErrorBase + slug,
		"status": statusOf(status),
		"code":   code,
		"detail": code,
	})
}

// statusOf reads the HTTP status out of the identity's own first segment, so the
// status line and the type URI can never disagree.
func statusOf(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 500
		}
		n = n*10 + int(c-'0')
	}
	if n < 100 || n > 599 {
		return 500
	}
	return n
}

// moon answers the pctl host. Anything under /moon/v1 is the parental-controls
// API; anything else on this host keeps the service-status answer it got before
// this handler existed, so nothing regresses while the surface is being learned.
//
// Every request is still dumped in full. The shapes below are built from the
// firmware's own field names (study §4) and are not yet runtime-confirmed: the
// log beside each answer is what corrects them, so it stays on.
func (s *server) moon(w http.ResponseWriter, r *http.Request, body []byte) {
	if !strings.HasPrefix(r.URL.Path, "/moon/v1") {
		s.serviceStatus(w, r, body)
		return
	}
	dump(r, body, "[moon] pctl")

	// The bearer is a dauth device token, signed by this server, so its `sub`
	// is the device id (dauth.go). A request without one can still search for a
	// pairing code -- the console has nothing else to identify itself with
	// before it has claimed a record -- but nothing else.
	device := ""
	if claims := s.bearer(r); claims != nil {
		device = str(claims, "sub")
	}

	rest := strings.TrimPrefix(r.URL.Path, "/moon/v1")
	switch {
	case rest == "/devices" && r.Method == http.MethodGet:
		s.moonSearch(w, r)
	case strings.HasPrefix(rest, "/devices/"):
		s.moonDevice(w, r, body, device, strings.TrimPrefix(rest, "/devices/"))
	default:
		log.Printf("[moon] no handler for %s %s", r.Method, r.URL.Path)
		moonError(w, moonNotFound)
	}
}

// moonSearch is the console's first call: find the record whose pairing code
// this is. Nothing is claimed here -- the console follows with `activate`.
func (s *server) moonSearch(w http.ResponseWriter, r *http.Request) {
	// The query is `filter.links.pairingCode.code.$eq=<code>`. Read it by
	// suffix rather than by exact key, so a different filter spelling still
	// finds the code instead of answering an empty list.
	code := ""
	for k, v := range r.URL.Query() {
		if strings.HasSuffix(k, "pairingCode.code.$eq") && len(v) > 0 {
			code = v[0]
		}
	}
	if code == "" {
		log.Printf("[moon] search with no pairing-code filter: %s", r.URL.RawQuery)
		moonItems(w, nil)
		return
	}
	if !pctlSearchAllowed() {
		// Six digits is a million codes, and this host is reachable from the
		// internet: without a cap, a guesser gets the whole space in minutes and
		// attaches their console to someone else's record.
		// ponytail: one global counter per minute, not per-IP -- Traefik splices
		// the console connection so no handler here sees a source address
		// (docs/switch, §U3). Per-IP when PROXY protocol lands.
		log.Printf("[moon] pairing-code lookups throttled; refusing %q", code)
		moonItems(w, nil)
		return
	}
	d := s.store.PctlByPairingCode(strings.TrimSpace(code))
	if d == nil {
		pctlSearchMiss()
		// An empty list, not a 404: the console asked a question ("which device
		// has this code"), and "none" is an answer to it.
		log.Printf("[moon] pairing code %q: no record", code)
		moonItems(w, nil)
		return
	}
	log.Printf("[moon] pairing code %q -> device %s", code, d.Hex())
	moonItems(w, []any{moonDeviceObj(d)})
}

// moonDevice routes everything under /devices/{id}. The id the console sends is
// whatever it read out of our own search answer, so it is matched tolerantly:
// hex as we spell it, and decimal in case it re-rendered the number.
func (s *server) moonDevice(w http.ResponseWriter, r *http.Request, body []byte, device, rest string) {
	id, tail, _ := strings.Cut(rest, "/")
	d := s.store.PctlByMoonID(id)
	if d == nil {
		log.Printf("[moon] device id %q not found (console spelled it that way)", id)
		moonError(w, moonNotFound)
		return
	}

	switch {
	// activate is where a console claims the record the code found, and the
	// only call that may arrive before this device is bound to it.
	case tail == "activate" && r.Method == http.MethodPost:
		if device == "" {
			moonError(w, moonInvalidToken)
			return
		}
		bound := s.store.PctlActivate(d.Hex(), device)
		if bound == nil {
			log.Printf("[moon] activate refused: %s is claimed by another console", d.Hex())
			moonError(w, moonForbidden)
			return
		}
		log.Printf("[moon] device %s activated by %s", bound.Hex(), device)
		writeJSON(w, 200, moonDeviceObj(bound))
		return
	}

	// Everything else needs this console to be the one that claimed the record.
	if device == "" || d.DauthID != device {
		log.Printf("[moon] %s %s: bearer device %q is not %q", r.Method, r.URL.Path, device, d.DauthID)
		moonError(w, moonForbidden)
		return
	}

	switch {
	case tail == "" && r.Method == http.MethodGet:
		writeJSON(w, 200, moonDeviceObj(d))
	case tail == "" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		// The console renaming itself or reporting its firmware. Stored as sent.
		s.store.PctlUpdateDevice(d.Hex(), jsonObj(body))
		writeJSON(w, 200, moonDeviceObj(d))
	case tail == "" && r.Method == http.MethodDelete:
		s.store.PctlUnlink(d.Hex())
		log.Printf("[moon] device %s unlinked by the console", d.Hex())
		w.WriteHeader(http.StatusNoContent)
	case tail == "parental_control_setting" && r.Method == http.MethodGet:
		s.moonSetting(w, r, d)
	case strings.HasPrefix(tail, "parental_control_setting") && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		// Includes .../whitelisted_applications: both write the document the
		// parent side owns, and the console only writes when a parent changed
		// something on the console itself.
		s.store.PctlSetSetting(d.Hex(), jsonObj(body))
		s.moonSetting(w, r, s.store.PctlByMoonID(d.Hex()))
	case tail == "owners" && r.Method == http.MethodGet:
		moonItems(w, moonOwners(d))
	case strings.HasPrefix(tail, "owners/"):
		na := strings.TrimPrefix(tail, "owners/")
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			s.store.PctlAddOwner(d.Hex(), na)
			log.Printf("[moon] device %s owner %s linked", d.Hex(), na)
			writeJSON(w, 200, map[string]any{"nintendoAccountId": na})
		case http.MethodDelete:
			s.store.PctlRemoveOwner(d.Hex(), na)
			w.WriteHeader(http.StatusNoContent)
		default:
			moonError(w, moonMethodNotAllowed)
		}
	case tail == "events" && r.Method == http.MethodPost:
		// Play-time and state events. Stored as sent and not interpreted: the
		// parent side has nothing to show from them yet, and a console that
		// cannot hand them over spools retries instead.
		n := s.store.PctlAddEvents(d.Hex(), body)
		log.Printf("[moon] device %s uploaded events (%d bytes, %d held)", d.Hex(), len(body), n)
		writeJSON(w, 200, map[string]any{"result": "ok"})
	case strings.HasPrefix(tail, "players") && r.Method == http.MethodGet:
		// The console's players, for the parent app's icons. Empty until the
		// app asks for them.
		moonItems(w, nil)
	case tail == "copy" && r.Method == http.MethodPost:
		// Copying settings from another paired console. There is never a source
		// to copy from on a first console, and inventing one would be a lie.
		moonError(w, moonNotFound)
	default:
		log.Printf("[moon] no handler for %s %s (tail %q)", r.Method, r.URL.Path, tail)
		moonError(w, moonNotFound)
	}
}

// moonSetting answers the conditional GET the console polls with. The ETag is
// the store's, so a document that has not changed costs a 304 and no body.
func (s *server) moonSetting(w http.ResponseWriter, r *http.Request, d *PctlDevice) {
	if d == nil {
		moonError(w, moonNotFound)
		return
	}
	// The same document the record embeds: an empty one refuses everything on
	// the console rather than nothing (2142-0234), so "no restrictions" is
	// stated in full.
	doc := pctlSettingOf(d)
	tag := d.ETag
	if tag == "" {
		tag = pctlETag(doc)
	}
	w.Header().Set("ETag", tag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, 200, doc)
}

// moonItems is the `{items,count}` envelope pctl's strings carry (992493, 986719).
func moonItems(w http.ResponseWriter, items []any) {
	if items == nil {
		items = []any{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "count": len(items)})
}

// moonDeviceObj is one device as the console reads it. The names are the
// firmware's (study §4); the id is spelled the way the console spells it in its
// own paths, `%016llx`, which is the one shape we know it can render.
func moonDeviceObj(d *PctlDevice) map[string]any {
	obj := map[string]any{
		// A number, not the hex string this once sent: the console read that
		// string as zero and asked for `/devices/0000000000000000/owners`, which
		// is the 404 behind error 2142-2009 (hardware, 2026-09-27).
		//
		// Nothing else goes in this object. The same build that made the id a
		// number also added an `id` key beside it, and the console stopped
		// asking anything at all -- 2142-0234, raised with no request behind it,
		// which is a parse and not a network failure. Two changes at once, so
		// the extra key is now removed on its own: pctl's reader looks strict,
		// and a field it has no slot for is the likeliest thing it refused.
		"deviceId": d.MoonID,
		"nickname": d.Nickname,
		// `activated` and `parentalControlSetting` sit beside each other in
		// pctl's own field table, and the console reads the setting straight out
		// of this object: it made no second call before refusing, so an absent
		// setting is what it judged.
		"activated":              d.DauthID != "",
		"pairingActive":          d.DauthID == "" && d.PairingCode != "",
		"parentalControlSetting": pctlSettingOf(d),
		"unlockCode":             d.UnlockCode,
		"updatedAt":              d.UpdatedAt,
		"etag":                   d.ETag,
		"owners":                 moonOwners(d),
	}
	if d.ActivatedAt != 0 {
		obj["synchronizedAt"] = d.ActivatedAt
	}
	if d.PairingCode != "" {
		// The console found the record by this code; echoing the link back is
		// how the shape it filtered on reads.
		obj["links"] = map[string]any{"pairingCode": map[string]any{"code": d.PairingCode}}
	}
	return obj
}

// pctlSettingOf is the record's setting, or the stated permissive default when a
// parent has set nothing. One place decides it, so the document the console
// polls and the one embedded here can never disagree.
func pctlSettingOf(d *PctlDevice) map[string]any {
	if len(d.Setting) > 0 {
		return d.Setting
	}
	return pctlDefaultSetting()
}

func moonOwners(d *PctlDevice) []any {
	out := []any{}
	for _, na := range d.Owners {
		out = append(out, map[string]any{"nintendoAccountId": na})
	}
	return out
}

// jsonObj reads a request body as an object, or nil when it is not one. A body
// we cannot parse is logged by dump already; it must not panic a handler.
func jsonObj(body []byte) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	return m
}

// ---------- the pairing store ----------
//
// Phase 1's data model, and only the part the wire cannot change. A device
// record, an owner, a pairing code with a deadline, and the setting document
// held as received: the console-facing envelope is still unknown (study §7 P1),
// but what has to be *remembered* is not, and the ETag is computed over whatever
// the parent side stores rather than over named fields.

// PctlDevice is one console's parental-controls record. Nintendo's flow creates
// it on the parent side first -- a record with a pairing code and no console --
// and the console adopts it: it searches by code
// (`/devices?filter.links.pairingCode.code.$eq=`) and then calls
// `/devices/{id}/activate`. So DauthID is empty until a console claims it.
type PctlDevice struct {
	// MoonID is the id in every path after the search. The console formats it
	// with `%016llx`, so it is a u64 here and rendered at the edge -- whether
	// the JSON carries it as a number or a hex string is P2, and one line.
	MoonID uint64 `json:"moonId"`
	// DauthID is the device id dauth issued ("cert-<8 bytes>"), which is what
	// the bearer on every moon request proves. Empty until activation.
	DauthID string `json:"dauthId,omitempty"`
	// ManagedBy is the OpenPak account that created the record and manages it
	// from the app. It is ours, and the console never sees it.
	ManagedBy string `json:"managedBy,omitempty"`
	// Nickname is what the console calls itself, as it sent it.
	Nickname string `json:"nickname,omitempty"`
	// UnlockCode is the eight digits that lift a restriction on the console --
	// pctl copies at most eight bytes into its PIN slot and validates the eighth
	// as a digit, so eight digits it is. The parent side holds it, which is why a
	// forgotten PIN is recoverable here rather than through Nintendo support.
	UnlockCode string `json:"unlockCode,omitempty"`
	// Events are the play-time uploads, held as received. Not interpreted: the
	// parent side has nothing to show from them yet, and a console that cannot
	// hand them over spools retries instead of moving on.
	Events []json.RawMessage `json:"events,omitempty"`
	// Owners are what the console spells in `owners/%016llx`: Nintendo-Account
	// -shaped ids. They are learned when the console links an owner, which is
	// why a record can be managed by an account and own none yet.
	Owners []string `json:"owners,omitempty"`
	// PairingCode is live until PairingExpires; both are cleared on activation
	// so a code is good exactly once.
	PairingCode    string `json:"pairingCode,omitempty"`
	PairingExpires int64  `json:"pairingExpires,omitempty"`
	ActivatedAt    int64  `json:"activatedAt,omitempty"`
	// Setting is the parental_control_setting document, stored as the parent
	// side wrote it. Opaque on purpose: the field names are known (study §4) but
	// which of them a phase-2 editor sends is not, and nothing here needs to
	// read them to serve a conditional GET.
	Setting map[string]any `json:"setting,omitempty"`
	// ETag is what `If-None-Match` is compared against, derived from Setting so
	// it cannot drift from the document it describes.
	ETag      string `json:"etag,omitempty"`
	UpdatedAt int64  `json:"updatedAt,omitempty"`
}

// Hex renders MoonID the way the console's own paths spell it.
func (d *PctlDevice) Hex() string { return fmt.Sprintf("%016x", d.MoonID) }

// pctlPairingTTL: long enough to walk to the console, short enough that an
// abandoned code stops being a way in.
const pctlPairingTTL = 15 * time.Minute

// pctlPairingCodeDigits: the console's entry field takes six digits and nothing
// else (observed on hardware 2026-09-27, which settles study §7 P3). A letter in
// the code is a code that cannot be typed, so the space is 10^6 and leading
// zeros are kept.
const pctlPairingCodeDigits = 6

// randU64 is the moon device id: random, not a counter, so a record cannot be
// guessed from another one. Capped at 48 bits because the console reads the id
// as a JSON *number* (hardware, 2026-09-27) and a reader that keeps numbers in a
// double would silently round anything past 2^53. 2^48 is still 281 trillion
// ids, and it formats as the same sixteen hex digits the console's paths use.
func randU64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) >> 16
}

// pctlPairingCode is uniform over the whole six-digit space: modulo over random
// bytes would lean on the low digits, and a code an attacker can predict is a
// console they can attach to someone else's record.
func pctlPairingCode() string {
	max := big.NewInt(1)
	for i := 0; i < pctlPairingCodeDigits; i++ {
		max.Mul(max, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// Never serve a guessable code: an empty one fails the mint instead.
		return ""
	}
	return fmt.Sprintf("%0*d", pctlPairingCodeDigits, n)
}

// pctlSearchMisses caps blind guessing at the pairing-code search. A miss is
// cheap for a console typing a real code once; a guesser makes nothing but
// misses, so the misses are what is counted.
var pctlSearchMisses = struct {
	sync.Mutex
	window time.Time
	n      int
}{}

// pctlSearchMissBudget is generous for a household -- a mistyped code, a retry,
// a second console -- and useless for enumeration: at 30 a minute, a million
// codes take a year.
const pctlSearchMissBudget = 30

func pctlSearchAllowed() bool {
	pctlSearchMisses.Lock()
	defer pctlSearchMisses.Unlock()
	if time.Since(pctlSearchMisses.window) > time.Minute {
		pctlSearchMisses.window, pctlSearchMisses.n = time.Now(), 0
	}
	return pctlSearchMisses.n < pctlSearchMissBudget
}

func pctlSearchMiss() {
	pctlSearchMisses.Lock()
	defer pctlSearchMisses.Unlock()
	pctlSearchMisses.n++
}

// pctlUnlockCode is the eight-digit code that lifts a restriction on the
// console. Same generator shape as the pairing code and for the same reason: a
// predictable one is somebody else's console unlocked.
func pctlUnlockCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%08d", n)
}

// pctlDefaultSetting is what a record carries until a parent sets anything: a
// stated "nothing is restricted", not an absent document.
//
// Absent was the first guess and it was wrong. pctl's check refuses with
// 2142-0234 when the allowed age byte is unset, so silence reads as "block
// everything" rather than "block nothing" (hardware, 2026-09-27). Every name and
// every value below is out of pctl's own tables: safetyLevel takes NONE, CUSTOM,
// CHILDREN, YOUNG_TEENS or OLDER_TEENS; ratingOrganization takes CERO ... GMEDIA
// in that order; a restriction is UNRESTRICTED, RESTRICTED or UNDEFINED.
func pctlDefaultSetting() map[string]any {
	return map[string]any{
		"safetyLevel":                            "NONE",
		"ratingOrganization":                     "PEGI",
		"ratingAge":                              18,
		"isDefaultRatingOrganizationSet":         true,
		"isSnsPostRestricted":                    false,
		"isFreeCommunicationRestrictedByDefault": false,
		"isStereoVisionRestricted":               false,
	}
}

// pctlDevices is the map, created on first use so no migration is needed for a
// store written before parental controls existed. Called with mu held.
func (s *Store) pctlDevices() map[string]*PctlDevice {
	if s.PctlDevices == nil {
		s.PctlDevices = map[string]*PctlDevice{}
	}
	return s.PctlDevices
}

// PctlNewPairing mints the record a console can adopt, managed by one OpenPak
// account.
func (s *Store) PctlNewPairing(managedBy string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	// One live code per account, ever. Asking again replaces the last one rather
	// than adding a record: a code is a pairing capability, so four of them on a
	// screen is four ways in, and only the newest is the one being typed.
	// Records a console has claimed are consoles, not codes, and are untouched.
	for hex, old := range s.pctlDevices() {
		if old.ManagedBy == managedBy && old.DauthID == "" {
			delete(s.pctlDevices(), hex)
		}
	}
	now := time.Now()
	d := &PctlDevice{
		MoonID:         randU64(),
		PairingCode:    pctlPairingCode(),
		PairingExpires: now.Add(pctlPairingTTL).Unix(),
		UpdatedAt:      now.Unix(),
		ManagedBy:      managedBy,
		UnlockCode:     pctlUnlockCode(),
	}
	s.pctlDevices()[d.Hex()] = d
	s.save()
	return d
}

// PctlByPairingCode answers the console's search. An expired code is not found:
// the record stays (the parent can see it went stale) but it is no longer a way
// to claim a console. It is dropped the next time that account asks for a code.
func (s *Store) PctlByPairingCode(code string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for _, d := range s.pctlDevices() {
		if d.PairingCode != "" && d.PairingCode == code && d.PairingExpires > now {
			return d
		}
	}
	return nil
}

// PctlByDauth finds the record a bearer belongs to.
// ponytail: a scan, because a household has a handful of consoles. An index if
// that ever stops being true.
func (s *Store) PctlByDauth(dauthID string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dauthID == "" {
		return nil
	}
	for _, d := range s.pctlDevices() {
		if d.DauthID == dauthID {
			return d
		}
	}
	return nil
}

// PctlDevicesFor is what the app lists: every record this account manages,
// newest first so a code just minted is at the top.
func (s *Store) PctlDevicesFor(managedBy string) []*PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*PctlDevice{}
	if managedBy == "" {
		return out
	}
	for _, d := range s.pctlDevices() {
		if d.ManagedBy == managedBy {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt > out[j].UpdatedAt })
	return out
}

// PctlByMoonID finds a record by the id the console put in the path. The console
// echoes back whatever our search answer gave it, so both spellings of a u64 are
// accepted: hex as we send it, and decimal in case it re-rendered the number.
// ponytail: try hex, then decimal. One of the two is right, and the log says
// which the first time a console asks.
func (s *Store) PctlByMoonID(id string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.pctlDevices()[strings.ToLower(id)]; d != nil {
		return d
	}
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil
	}
	return s.pctlDevices()[fmt.Sprintf("%016x", n)]
}

// PctlUpdateDevice keeps the few fields a console sends about itself. Unknown
// keys are ignored rather than stored: this record is read by the parent app,
// and a console cannot be allowed to invent fields in it.
func (s *Store) PctlUpdateDevice(moonHex string, doc map[string]any) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return nil
	}
	if v, ok := doc["nickname"].(string); ok && v != "" {
		d.Nickname = v
	}
	d.UpdatedAt = time.Now().Unix()
	s.save()
	return d
}

// PctlUnlink is the console saying it is no longer managed. The record stays so
// the parent app can see it happened; what goes is the binding.
func (s *Store) PctlUnlink(moonHex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return
	}
	d.DauthID, d.ActivatedAt, d.Setting, d.ETag = "", 0, nil, ""
	d.UpdatedAt = time.Now().Unix()
	s.save()
}

// PctlAddOwner links a Nintendo-Account-shaped owner id, once.
func (s *Store) PctlAddOwner(moonHex, naID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil || naID == "" {
		return
	}
	for _, o := range d.Owners {
		if o == naID {
			return
		}
	}
	d.Owners = append(d.Owners, naID)
	d.UpdatedAt = time.Now().Unix()
	s.save()
}

func (s *Store) PctlRemoveOwner(moonHex, naID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return
	}
	kept := d.Owners[:0]
	for _, o := range d.Owners {
		if o != naID {
			kept = append(kept, o)
		}
	}
	d.Owners = kept
	d.UpdatedAt = time.Now().Unix()
	s.save()
}

// pctlEventsKept bounds the upload log: a console re-sends what it thinks was
// not accepted, and an unbounded list would grow with every session.
// ponytail: newest 200, dropped oldest first. A real events API replaces this.
const pctlEventsKept = 200

// PctlAddEvents holds one upload as received and returns how many are held.
func (s *Store) PctlAddEvents(moonHex string, body []byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil || len(body) == 0 {
		return 0
	}
	d.Events = append(d.Events, json.RawMessage(append([]byte(nil), body...)))
	if len(d.Events) > pctlEventsKept {
		d.Events = d.Events[len(d.Events)-pctlEventsKept:]
	}
	d.UpdatedAt = time.Now().Unix()
	s.save()
	return len(d.Events)
}

// PctlActivate binds a console to the record its code found and burns the code.
// Activating twice with the same console is not an error -- a retried request
// must not lose the console -- but another console cannot take the record.
func (s *Store) PctlActivate(moonHex, dauthID string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil || dauthID == "" || (d.DauthID != "" && d.DauthID != dauthID) {
		return nil
	}
	d.DauthID = dauthID
	d.PairingCode, d.PairingExpires = "", 0
	if d.ActivatedAt == 0 {
		d.ActivatedAt = time.Now().Unix()
	}
	d.UpdatedAt = time.Now().Unix()
	s.save()
	return d
}

// PctlSetSetting stores the setting document and recomputes its ETag. An
// unchanged document keeps its ETag, which is what makes the console's
// `If-None-Match` answer 304 instead of re-downloading every poll.
func (s *Store) PctlSetSetting(moonHex string, doc map[string]any) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return nil
	}
	tag := pctlETag(doc)
	if tag == d.ETag {
		return d
	}
	d.Setting, d.ETag, d.UpdatedAt = doc, tag, time.Now().Unix()
	s.save()
	return d
}

// pctlETag is a strong validator over the document's canonical JSON. Go's
// encoder sorts map keys, so the same document always hashes the same.
func pctlETag(doc map[string]any) string {
	b, err := json.Marshal(doc)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// POST /internal/pctl/pairing {"account_id":"…"} -> the code to type on the console.
// The parent surface is a screen in the app; this is the call behind it, and
// until that screen exists it is also how a pairing attempt gets a real code to
// type -- which is what turns the phase-0 log from "unknown code" into the
// matched path.
func (s *server) pctlPairing(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	if r.Method != http.MethodPost {
		apiErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var in struct {
		AccountID string `json:"account_id"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
	d := s.store.PctlNewPairing(in.AccountID)
	log.Printf("[moon] pairing code %s for account=%q device=%s (expires %ds)",
		d.PairingCode, in.AccountID, d.Hex(), int(pctlPairingTTL.Seconds()))
	writeJSON(w, 200, map[string]any{
		"moon_id": d.Hex(), "pairing_code": d.PairingCode, "expires_at": d.PairingExpires,
	})
}

// ---------- the explainer video ----------

// pctlMovie serves `parentalcontrols-movie-<env>.cdn.nintendo.net/default/
// switchpc_<lang>.mp4`, the clip the Parental Controls setup screen offers
// (firmware follow-up §22c; study §7 P5). Whether the screen *blocks* on it is
// unproven, so this stays a file we hand over when there is one and a logged 404
// when there is not -- no invented video, and no guess at a codec the console
// would then have to decode.
//
// ponytail: one env var, no asset in the repo. PCTL_MOVIE=/path/to.mp4 and
// http.ServeFile does the Range handling a video player needs.
func (s *server) pctlMovie(w http.ResponseWriter, r *http.Request) {
	path := getenv("PCTL_MOVIE", "")
	if path == "" {
		log.Printf("[moon] movie %s%s -- no PCTL_MOVIE configured, answering 404", hostOf(r), r.URL.Path)
		http.NotFound(w, r)
		return
	}
	log.Printf("[moon] movie %s%s -> %s", hostOf(r), r.URL.Path, path)
	w.Header().Set("Content-Type", "video/mp4")
	http.ServeFile(w, r, path)
}

// GET /internal/pctl/devices?account_id=… -> the records that account manages,
// as the app's list. The pairing code travels only while it is still live: a
// dead code on a screen is worse than none, because someone types it.
func (s *server) pctlDeviceList(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	account := r.URL.Query().Get("account_id")
	if account == "" {
		apiErr(w, http.StatusBadRequest, "account_id required")
		return
	}
	now := time.Now().Unix()
	out := []map[string]any{}
	for _, d := range s.store.PctlDevicesFor(account) {
		item := map[string]any{
			"moon_id":      d.Hex(),
			"paired":       d.DauthID != "",
			"activated_at": d.ActivatedAt,
			"updated_at":   d.UpdatedAt,
			"owners":       d.Owners,
			"has_setting":  len(d.Setting) > 0,
		}
		if d.PairingCode != "" && d.PairingExpires > now {
			item["pairing_code"] = d.PairingCode
			item["expires_at"] = d.PairingExpires
		}
		out = append(out, item)
	}
	writeJSON(w, 200, map[string]any{"devices": out})
}
