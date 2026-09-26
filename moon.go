package main

// moon is the parental-controls API: `api-<env>.pctl.srv.nintendo.net/moon/v1/…`,
// the only thing the pctl sysmodule (22.5.0 title 010000000000002E) needs from a
// server. Everything the console does on its own -- the PIN, the restriction
// level, the play timer, the bedtime alarm -- lives in pctl's system savedata and
// works offline. What dies without a server is pairing with the parent app and
// the settings sync. Contract: docs/switch/parental-controls-firmware-2026-09-26.md.
//
// Phase 0 of nx-baas/prds/native-switch-parental-controls-prd.md: log what the
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
	"net/http"
	"sort"
	"strings"
	"time"
)

// The error identities pctl carries as literals (study §5). A refusal that does
// not name one of these is a refusal the client cannot classify, which is why
// this handler never answers a bare status.
const (
	moonErrorBase        = "https://moon.nintendo.com/errors/v1/"
	moonNotFound         = "404/resource_is_not_found"
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
func (s *server) moon(w http.ResponseWriter, r *http.Request, body []byte) {
	if !strings.HasPrefix(r.URL.Path, "/moon/v1") {
		s.serviceStatus(w, r, body)
		return
	}
	// The whole point of phase 0: the request, in full, in the log. dump keeps
	// the bearer truncated -- it is a device token, not a secret we need whole.
	dump(r, body, "[moon] pctl")
	moonError(w, moonNotFound)
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

// pctlPairingAlphabet has no O/0 or I/1 to confuse, and no lowercase. The real
// alphabet and length are P3 and arrive with the first hardware log; this is one
// const to change when they do.
const pctlPairingAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// randU64 is the moon device id: random, not a counter, so a record cannot be
// guessed from another one.
func randU64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

func pctlPairingCode() string {
	b := make([]byte, 6)
	rand.Read(b)
	for i, c := range b {
		b[i] = pctlPairingAlphabet[int(c)%len(pctlPairingAlphabet)]
	}
	return string(b)
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
	now := time.Now()
	d := &PctlDevice{
		MoonID:         randU64(),
		PairingCode:    pctlPairingCode(),
		PairingExpires: now.Add(pctlPairingTTL).Unix(),
		UpdatedAt:      now.Unix(),
	}
	d.ManagedBy = managedBy
	s.pctlDevices()[d.Hex()] = d
	s.save()
	return d
}

// PctlByPairingCode answers the console's search. An expired code is not found:
// the record stays (the parent can see it went stale) but it is no longer a way
// to claim a console.
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
