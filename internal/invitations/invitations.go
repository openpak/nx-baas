// Package invitations is native online-play invitations: the app.lp1.five.nintendo.net REST surface
// the friends sysmodule drives on Horizon 22.5.0 (PRD INV-01..04, workstream C
// of prds/native-switch-parallel-plan.md).
//
// Route family — firmware-confirmed (friends NSO 8bd39f5b…, string table) and
// source-confirmed (kinnay/NintendoClients wiki, Online-Play-Invitation-Server,
// accessed 2026-09-12); versions are per endpoint, never a blanket rewrite:
//
//	POST  /v2/invitation_groups                        create (22.5.0; v1 kept for pre-20 firmware)
//	GET   /v1|/v2/users/<uid>/invitations/inbox        inbox (?fields=count&read=false&invitation_types=friend)
//	GET   /v1/invitation_groups/<id>                   group detail (still v1 on 22.5.0)
//	PATCH /v1/invitations                              mark chosen invitations read (JSON patch)
//	PATCH /v1/users/<uid>/invitations/mark_as_read     mark the caller's unread read
//
// Ownership (coordination plan): this file owns the durable invitation
// lifecycle — native identity, recipients, title payload, localized messages,
// read/expiry state — plus these handlers. Workstream A owns the shared
// router/authentication/core client this hooks into (the wiring is two lines
// in main.go: the host case and the TLS SAN). Workstream B owns delivering
// the semantic event over Penne; this file only commits state and then calls
// the invitationNotify hook with an idempotent event identity. There is no
// second notification socket and no competing friend graph here.
//
// Canonical state: the core owns moderation truth (Social.CheckInteraction)
// and live-session truth (Sessions.ResolveSession). The invitation rows
// themselves are the adapter's projection — the core's Invitations service is
// session-bound at send (offline recipients are rejected there), while the
// native inbox is store-and-forward, so routing native sends through it would
// break the offline-recipient acceptance case. The gap is filed as a core
// contract request (docs/invitations.md, C-1); until it lands, this store is
// the lifecycle record for native invitations and the core is consulted for
// every policy answer.
package invitations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"nx-baas/internal/core"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/presence"
	"nx-baas/internal/store"
	"nx-baas/redact"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- bounds (all documented in docs/invitations.md) ----------

// FriendInvitationApplicationParameterSizeMax on the console side: the opaque
// title payload never exceeds this, whatever the core would accept.
const invitationMaxAppData = 1024

// Per-group receiver bound; the native cap is unknown, so this is a documented
// adapter bound rather than a protocol claim.
const MaxReceivers = 100

// Localized messages: the languages the create call documents, one message
// each, bounded so one request cannot balloon the store.
var invitationLanguages = map[string]bool{
	"en-US": true, "en-GB": true, "ja": true, "fr": true, "de": true, "es-419": true,
	"es": true, "it": true, "nl": true, "fr-CA": true, "pt": true, "ru": true,
	"zh-Hans": true, "zh-Hant": true, "ko": true, "pt-BR": true,
}

const invitationMaxMessages = 16
const invitationMaxMessageLen = 256

// Native invitations expire server-side (the wire shape carries no expiry).
// 4h: an invitation names a room, and a room nobody is still sitting in is
// worth less than the confusion of offering it. The real service allows a day;
// presence retires most invitations long before either (2026-09-20).
const invitationTTLDefault = 4 * time.Hour

// supersedeLocked retires the sender's earlier invitations to this receiver
// for the same title. An invitation carries a room code, so an older one
// names a room its sender has already left: offering both invites the
// receiver to join the dead one.
func (st *Store) supersedeLocked(fresh *Record, now int64) {
	for _, inv := range st.Invitations {
		if inv.ID == fresh.ID || inv.ReceiverID != fresh.ReceiverID || inv.SenderID != fresh.SenderID {
			continue
		}
		if !strings.EqualFold(inv.ApplicationID, fresh.ApplicationID) || inv.ExpiresAt <= now {
			continue
		}
		inv.ExpiresAt, inv.UpdatedAt = now, now
	}
}

// invitationSenderGrace is how long an invitation is offered regardless of
// what the sender's presence says. Presence arrives late and a host publishes
// its title after the room exists, so a fresh invitation is never judged by it.
const SenderGrace = 2 * time.Minute

// invitationSenderGone reports that the sender has demonstrably left the game
// they invited into: their presence names another title, or no title at all.
// Unknown presence is never taken as evidence — a console publishes presence
// for only some of its profiles — so the 24h expiry remains the backstop.
func (s *Service) invitationSenderGone(inv *Record, now int64) bool {
	if s == nil || s.Store == nil || now-inv.CreatedAt < int64(SenderGrace.Seconds()) {
		return false
	}
	u := s.Store.User(inv.SenderID)
	if u == nil {
		return false
	}
	p := presence.Aggregate(u, now, presence.Lease())
	switch p.State {
	case "PLAYING":
		return inv.ApplicationID != "" && p.AppID != "" && !strings.EqualFold(p.AppID, inv.ApplicationID)
	case "ONLINE", "INACTIVE", "OFFLINE":
		// Signed in with no game, or gone: either way not in that room.
		return true
	}
	return false
}

// Retention: read rows and dead groups are pruned so the store cannot grow
// without bound. Unread invitations survive until expiry — that is the point.
const invitationReadRetention = 7 * 24 * time.Hour

// ---------- durable store ----------

// invitationRecord is one recipient's copy of an invitation: the stable native
// identity, the title payload, and that recipient's read state. IDs are decimal
// strings that render with the firmware's %llu; they are minted once and never
// re-minted on restart (parent PRD §6).
type Record struct {
	ID                 string            `json:"id"`
	GroupID            string            `json:"group_id"`
	Type               string            `json:"type"`
	SenderID           string            `json:"sender_id"`
	ReceiverID         string            `json:"receiver_id"`
	ApplicationID      string            `json:"application_id"`
	ApplicationGroupID string            `json:"application_group_id"`
	ApplicationIDMatch *bool             `json:"application_id_match,omitempty"`
	ACDIndex           *int              `json:"acd_index,omitempty"`
	ApplicationData    string            `json:"application_data,omitempty"` // base64; opaque, never parsed here
	Messages           map[string]string `json:"messages,omitempty"`
	Read               bool              `json:"read"`
	ReadAt             int64             `json:"read_at,omitempty"`
	CreatedAt          int64             `json:"created_at"`
	UpdatedAt          int64             `json:"updated_at"`
	ExpiresAt          int64             `json:"expires_at"`
	// Mailbox marks rows created through the emulator/game-API mailbox. They
	// carry the sender's PID and a short TTL instead of a group.
	Mailbox         bool   `json:"mailbox,omitempty"`
	MailboxFromPID  uint64 `json:"mailbox_from_pid,omitempty"`
	MailboxFromName string `json:"mailbox_from_name,omitempty"`
}

// invitationGroup is the sender-side grouping one create call made. Kept so
// GET /v1/invitation_groups/<id> answers with the shape the console parsed
// when it created the group.
type Group struct {
	ID                 string            `json:"id"`
	SenderID           string            `json:"sender_id"`
	Type               string            `json:"type"`
	ApplicationID      string            `json:"application_id"`
	ApplicationGroupID string            `json:"application_group_id"`
	ApplicationIDMatch *bool             `json:"application_id_match,omitempty"`
	ACDIndex           *int              `json:"acd_index,omitempty"`
	ApplicationData    string            `json:"application_data,omitempty"`
	Messages           map[string]string `json:"messages,omitempty"`
	CreatedAt          int64             `json:"created_at"`
	UpdatedAt          int64             `json:"updated_at"`
	InvitationIDs      []string          `json:"invitation_ids"`
}

type Store struct {
	// Mu guards the maps; FilePath is invitations.json. Neither is persisted.
	Mu          sync.Mutex         `json:"-"`
	FilePath    string             `json:"-"`
	Seq         uint64             `json:"seq"`
	Groups      map[string]*Group  `json:"groups"`
	Invitations map[string]*Record `json:"invitations"`
}

var (
	invStoreOnce sync.Once
	invStore     *Store
	// invStoreOverride lets tests install a store before first use.
	StoreOverride *Store
)

// invitationStoreFor lazily opens the durable invitation store under NX_DATA.
// A package singleton because the store is process-global state (like the
// BAAS store) and the game API handlers reach it without a server argument.
func StoreFor() *Store {
	if StoreOverride != nil {
		return StoreOverride
	}
	invStoreOnce.Do(func() {
		invStore = LoadStore(httpx.Getenv("NX_DATA", "/data") + "/invitations.json")
	})
	return invStore
}

func LoadStore(path string) *Store {
	st := &Store{
		FilePath:    path,
		Groups:      map[string]*Group{},
		Invitations: map[string]*Record{},
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, st)
	}
	// The id sequence must never go backwards, or a restored backup would mint
	// a second row under an id the console already saw.
	if hi := st.highestIDLocked(); st.Seq <= hi {
		st.Seq = hi
	}
	st.pruneLocked(time.Now())
	st.saveLocked()
	return st
}

func (st *Store) highestIDLocked() uint64 {
	var hi uint64
	for id := range st.Invitations {
		if n, err := strconv.ParseUint(id, 10, 64); err == nil && n > hi {
			hi = n
		}
	}
	for id := range st.Groups {
		if n, err := strconv.ParseUint(id, 10, 64); err == nil && n > hi {
			hi = n
		}
	}
	return hi
}

func (st *Store) saveLocked() {
	b, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		log.Printf("[nx-baas] invitations: marshal: %v", redact.Err(err))
		return
	}
	tmp := st.FilePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("[nx-baas] invitations: save: %v", redact.Err(err))
		return
	}
	if err := os.Rename(tmp, st.FilePath); err != nil {
		log.Printf("[nx-baas] invitations: save: %v", redact.Err(err))
	}
}

// nextIDLocked mints the next stable decimal id. Microsecond time plus a
// sequence stays far below 2^53, so the id is safe for any JSON consumer and
// renders exactly as the firmware's %llu expects.
func (st *Store) nextIDLocked(now time.Time) string {
	if st.Seq == 0 {
		st.Seq = uint64(now.UnixNano()) / 1000 // µs since epoch, ~2^50
	}
	st.Seq++
	id := strconv.FormatUint(st.Seq, 10)
	for st.Invitations[id] != nil || st.Groups[id] != nil {
		st.Seq++
		id = strconv.FormatUint(st.Seq, 10)
	}
	return id
}

// pruneLocked drops dead rows: anything expired longer than the read
// retention, and read rows past retention. Runs with the lock held.
func (st *Store) pruneLocked(now time.Time) {
	for id, inv := range st.Invitations {
		deadline := inv.ExpiresAt
		if inv.Read && inv.ReadAt+int64(invitationReadRetention.Seconds()) > deadline {
			deadline = inv.ReadAt + int64(invitationReadRetention.Seconds())
		}
		if now.Unix() > deadline {
			st.dropLocked(inv)
			delete(st.Invitations, id)
		}
	}
	for id, g := range st.Groups {
		if len(g.InvitationIDs) == 0 && now.Unix() > g.UpdatedAt+int64(invitationReadRetention.Seconds()) {
			delete(st.Groups, id)
		}
	}
}

func (st *Store) dropLocked(inv *Record) {
	if g := st.Groups[inv.GroupID]; g != nil {
		kept := g.InvitationIDs[:0]
		for _, id := range g.InvitationIDs {
			if id != inv.ID {
				kept = append(kept, id)
			}
		}
		g.InvitationIDs = kept
	}
}

// unreadCountLocked counts live, unread rows for one receiver.
// unreadCountLocked counts what the badge should show. gone, when given,
// drops invitations whose sender has left the game they invited into.
func (st *Store) unreadCountLocked(receiverID string, now int64, gone func(*Record) bool) int {
	n := 0
	for _, inv := range st.Invitations {
		if inv.ReceiverID != receiverID || inv.Read || inv.ExpiresAt <= now {
			continue
		}
		if gone != nil && gone(inv) {
			continue
		}
		n++
	}
	return n
}

// ---------- core surfaces (moderation + session truth) ----------

// invitationCore is the core-moderation/session surface invitations consult.
// The openpak backend implements it over A's shared gRPC clients; any other
// backend yields nil and the adapter falls back to its own projections.
type CoreAPI interface {
	// CheckInteraction answers whether actor may invite target, consulting
	// friendship, blocks and account status in the core. reason is the core's
	// DenialReason name ("blocked", "not_friends", …) or "" when allowed.
	CheckInteraction(ctx context.Context, actorAccountID, targetAccountID string) (allowed bool, reason string, err error)
	// ResolveSession reports whether the account holds a live session for the
	// title — the join-time truth an expired room must defer to (INV-04).
	ResolveSession(ctx context.Context, accountID, titleID string) (bool, error)
	// AccountForBaas maps a BAAS user id to the core account id.
	AccountForBaas(baasUID string) (accountID string, ok bool)
}

// ---------- semantic event seam (workstream B delivers it) ----------

// InvitationEvent is the idempotent semantic event the friends module's
// invitation workflow needs. EventID is stable across retries, so delivery
// can dedup without a second canonical store.
type Event struct {
	EventID       string `json:"event_id"` // "invitation:<id>"
	Type          string `json:"type"`     // "friend_invitation_received"
	ReceiverID    string `json:"receiver_id"`
	SenderID      string `json:"sender_id"`
	InvitationID  string `json:"invitation_id"`
	GroupID       string `json:"group_id"`
	ApplicationID string `json:"application_id"`
	UnreadCount   int    `json:"unread_count"`
}

// invitationNotify is B's delivery seam (Penne friend_invitation_received).
// The event parser paths on the console side are firmware-confirmed:
// $.type, $.invitation.{id, sender_id, application_id, invitation_group_id}.
// Nil until B wires it; REST completeness never depends on it — the console
// also polls the unread count on its own cooldown.
var NotifyHook func(Event)

// notifyCommitted must be called strictly after the store write returns: the
// event promises an invitation the inbox really has. A failed hook never
// fails the REST call — delivery converges through the unread-count poll.
func NotifyCommitted(ev Event) {
	if NotifyHook == nil {
		return
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[nx-baas] invitations: notify panicked: %s", redact.IDs(fmt.Sprint(r)))
			}
		}()
		NotifyHook(ev)
	}()
}

// ---------- authentication (INV-01: bind principal to the action) ----------

// fiveAuth validates the bearer as our own BAAS user access token: signature,
// lifetime, issuer, token type, grant and subject are each checked here
// (audit P1: jwt.go alone does not do this). The returned user is the
// principal every path/body id is bound against.
func (s *Service) fiveAuth(r *http.Request) *store.User {
	// Integration: the base rules (signature, issuer, type, expiry) are A's
	// validBearer, so the two surfaces cannot drift apart -- the shared
	// contract names one token validator. The checks below are the extra
	// binding this host needs on top, not a second copy of the base rules.
	c := s.ValidBearer(r)
	if c == nil {
		return nil
	}
	now := time.Now().Unix()
	if iat, ok := c["iat"].(float64); ok && now+60 < int64(iat) {
		return nil
	}
	if httpx.Str(c, "aud") != core.BaasAudience {
		return nil
	}
	// Grant 2 is a user token. Grant 1 (anonymous device) tokens carry a
	// "pz…" subject that must never reach an inbox.
	if g, ok := c["bs:grt"].(float64); !ok || int(g) != 2 {
		return nil
	}
	u := s.Store.User(httpx.Str(c, "sub"))
	if u == nil || u.PID == 0 {
		return nil
	}
	return u
}

// ---------- native error contract ----------

// fiveError renders the documented error body (wiki: error.code 4 digits +
// error.message) using the message strings the 22.5.0 friends module is
// verifiably able to map. Codes are the wiki's known set; unknown cases take
// the closest documented code rather than an invented one.
func fiveError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	httpx.WriteJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

// ---------- host entry ----------

// five is the router entry for *.five.nintendo.net (main.go routes the host
// here and lists app.lp1.five.nintendo.net on the fixed TLS certificate).
func (s *Service) Five(w http.ResponseWriter, r *http.Request, body []byte) {
	seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// A banned account neither sends nor reads invitations (bans.go). 403 with the code
	// the module already knows for a refused operation.
	if lock := s.Locks.UserLock(s.fiveAuth(r)); lock != "" {
		fiveError(w, r, http.StatusForbidden, "0006", "operation_is_not_permitted")
		return
	}
	// …/invitation_groups[/<id>]
	if len(seg) >= 2 && seg[1] == "invitation_groups" {
		switch {
		case len(seg) == 2 && r.Method == http.MethodPost && (seg[0] == "v1" || seg[0] == "v2"):
			s.invitationGroupCreate(w, r, body, seg[0])
			return
		case len(seg) == 3 && r.Method == http.MethodGet && seg[0] == "v1":
			s.invitationGroupDetail(w, r, seg[2])
			return
		}
		httpx.Dump(r, body, "!! five invitation_groups")
		fiveError(w, r, http.StatusNotFound, "0003", "resource_is_not_found")
		return
	}
	// …/invitations (JSON-patch read state)
	if len(seg) == 2 && seg[1] == "invitations" && seg[0] == "v1" && r.Method == http.MethodPatch {
		s.invitationPatch(w, r, body)
		return
	}
	// …/v1|v2/users/<uid>/invitations/{inbox,mark_as_read}
	if len(seg) == 5 && seg[0] != "" && seg[1] == "users" && seg[3] == "invitations" && (seg[0] == "v1" || seg[0] == "v2") {
		switch {
		case seg[4] == "inbox" && r.Method == http.MethodGet:
			s.invitationInbox(w, r, seg[2], r.URL.Query())
			return
		case seg[4] == "mark_as_read" && r.Method == http.MethodPatch && seg[0] == "v1":
			s.invitationMarkAllRead(w, r, seg[2], body)
			return
		}
	}
	httpx.Dump(r, body, "!! UNHANDLED five")
	fiveError(w, r, http.StatusNotFound, "0003", "resource_is_not_found")
}

// ---------- create ----------

type invitationCreateIn struct {
	ReceiverIDs        []string          `json:"receiver_ids"`
	InvitationType     string            `json:"invitation_type"`
	ApplicationID      string            `json:"application_id"`
	ApplicationGroupID string            `json:"application_group_id"`
	ApplicationIDMatch *bool             `json:"application_id_match"`
	ACDIndex           *int              `json:"acd_index"`
	ApplicationData    string            `json:"application_data"`
	Messages           map[string]string `json:"messages"`
}

var hexID = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

// invitationGroupCreate implements POST /v1|v2/invitation_groups. v2 (22.5.0)
// requires invitation_type=friend; v1 predates the field.
func (s *Service) invitationGroupCreate(w http.ResponseWriter, r *http.Request, body []byte, version string) {
	me := s.fiveAuth(r)
	if me == nil {
		fiveError(w, r, http.StatusUnauthorized, "0006", "invalid_token")
		return
	}
	var in invitationCreateIn
	if err := json.Unmarshal(body, &in); err != nil {
		fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
		return
	}
	if version == "v2" && in.InvitationType != "friend" {
		// The friends sysmodule hardcodes "friend"; anything else is a client bug.
		if in.InvitationType != "" {
			fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
			return
		}
		in.InvitationType = "friend"
	}
	if in.ApplicationID == "" || !hexID.MatchString(in.ApplicationID) {
		fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
		return
	}
	if in.ApplicationGroupID == "" {
		// The presence group is usually the title id; an absent one falls back
		// rather than failing a client that relied on that.
		in.ApplicationGroupID = in.ApplicationID
	}
	if !hexID.MatchString(in.ApplicationGroupID) {
		fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
		return
	}
	appData := ""
	if in.ApplicationData != "" {
		raw, err := base64.StdEncoding.DecodeString(in.ApplicationData)
		if err != nil {
			fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
			return
		}
		if len(raw) > invitationMaxAppData {
			fiveError(w, r, http.StatusBadRequest, "0011", "application_data_is_too_large")
			return
		}
		appData = in.ApplicationData
	}
	if len(in.Messages) > invitationMaxMessages {
		fiveError(w, r, http.StatusBadRequest, "0002", "not_acceptable_language")
		return
	}
	for lang, msg := range in.Messages {
		if !invitationLanguages[lang] || msg == "" || len(msg) > invitationMaxMessageLen {
			fiveError(w, r, http.StatusBadRequest, "0002", "not_acceptable_language")
			return
		}
	}
	// Deduplicate receivers; a repeated id is one invitation.
	seen := map[string]bool{}
	var receivers []string
	for _, id := range in.ReceiverIDs {
		if !hexID.MatchString(id) {
			fiveError(w, r, http.StatusBadRequest, "0002", "could_not_retrieve_receiver")
			return
		}
		if id == me.ID {
			fiveError(w, r, http.StatusBadRequest, "0002", "receiver_must_be_different_from_sender")
			return
		}
		if !seen[id] {
			seen[id] = true
			receivers = append(receivers, id)
		}
	}
	if len(receivers) == 0 {
		fiveError(w, r, http.StatusBadRequest, "0002", "could_not_retrieve_receiver")
		return
	}
	if len(receivers) > MaxReceivers {
		fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
		return
	}

	// Policy, one receiver at a time, through the core when there is one.
	// Denied or unknown receivers are omitted from the group (their invitation
	// is never committed); the sender sees only what exists. If nothing
	// survives, the native error names why.
	core := s.CoreFor()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var accepted, unknown, denied []string
	for _, uid := range receivers {
		if s.Store.User(uid) == nil {
			unknown = append(unknown, uid)
			continue
		}
		ok, reason := true, ""
		if core != nil {
			targetID, okID := core.AccountForBaas(uid)
			if !okID {
				unknown = append(unknown, uid)
				continue
			}
			actorID, _ := core.AccountForBaas(me.ID)
			allowed, why, err := core.CheckInteraction(ctx, actorID, targetID)
			if err != nil {
				// A core outage must not read as policy: fail the call, the
				// console retries and nothing is committed.
				identity.LogErr("invitation check-interaction", err)
				fiveError(w, r, http.StatusBadGateway, "0001", "internal_server_error")
				return
			}
			ok, reason = allowed, why
		} else {
			ok = s.fallbackMayInvite(me, uid)
			if !ok {
				reason = "not_friends"
			}
		}
		if ok {
			accepted = append(accepted, uid)
		} else {
			denied = append(denied, uid)
			_ = reason
		}
	}
	if len(accepted) == 0 {
		switch {
		case len(denied) > 0:
			fiveError(w, r, http.StatusBadRequest, "0002", "sender_blocks_receiver")
		case len(unknown) > 0:
			fiveError(w, r, http.StatusBadRequest, "0002", "could_not_retrieve_receiver")
		default:
			fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
		}
		return
	}

	ttl := invitationTTLDefault
	if v := httpx.Getenv("NX_INVITATION_TTL_SECONDS", ""); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 && time.Duration(secs)*time.Second <= invitationTTLDefault {
			ttl = time.Duration(secs) * time.Second
		}
	}
	now := time.Now()
	st := StoreFor()
	group := &Group{
		SenderID: me.ID, Type: in.InvitationType,
		ApplicationID: strings.ToLower(in.ApplicationID), ApplicationGroupID: strings.ToLower(in.ApplicationGroupID),
		ApplicationIDMatch: in.ApplicationIDMatch, ACDIndex: in.ACDIndex,
		ApplicationData: appData, Messages: in.Messages,
		CreatedAt: now.Unix(), UpdatedAt: now.Unix(),
	}
	var invitations []*Record
	st.Mu.Lock()
	group.ID = st.nextIDLocked(now)
	for _, uid := range accepted {
		inv := &Record{
			GroupID: group.ID, Type: group.Type,
			SenderID: me.ID, ReceiverID: uid,
			ApplicationID: group.ApplicationID, ApplicationGroupID: group.ApplicationGroupID,
			ApplicationIDMatch: in.ApplicationIDMatch, ACDIndex: in.ACDIndex,
			ApplicationData: appData, Messages: in.Messages,
			CreatedAt: now.Unix(), UpdatedAt: now.Unix(),
			ExpiresAt: now.Add(ttl).Unix(),
		}
		inv.ID = st.nextIDLocked(now)
		st.supersedeLocked(inv, now.Unix())
		st.Invitations[inv.ID] = inv
		group.InvitationIDs = append(group.InvitationIDs, inv.ID)
		invitations = append(invitations, inv)
	}
	st.Groups[group.ID] = group
	st.pruneLocked(now)
	st.saveLocked() // committed before the response or the event: no false success
	unread := map[string]int{}
	for _, inv := range invitations {
		unread[inv.ReceiverID] = st.unreadCountLocked(inv.ReceiverID, now.Unix(), nil)
	}
	st.Mu.Unlock()

	log.Printf("[nx-baas] five: group %s by %s -> %d/%d receiver(s) (denied=%d unknown=%d)",
		redact.Tag(group.ID), redact.Tag(me.ID), len(invitations), len(receivers), len(denied), len(unknown))
	for _, inv := range invitations {
		NotifyCommitted(Event{
			EventID: "invitation:" + inv.ID, Type: "friend_invitation_received",
			ReceiverID: inv.ReceiverID, SenderID: inv.SenderID,
			InvitationID: inv.ID, GroupID: inv.GroupID, ApplicationID: inv.ApplicationID,
			UnreadCount: unread[inv.ReceiverID],
		})
	}
	httpx.WriteJSON(w, 200, s.invitationGroupObj(group, invitations))
}

// invitationCoreFor returns the core surface when the adapter runs on the
// openpak core; nil otherwise (the fallback uses projections).
// Tests install a fake through invCoreOverride.
var CoreOverride CoreAPI

func (s *Service) CoreFor() CoreAPI {
	if CoreOverride != nil {
		return CoreOverride
	}
	if b, ok := s.Acct.(*identity.OpenpakBackend); ok && b.Social != nil {
		return b
	}
	return nil
}

// fallbackMayInvite is the non-core fallback: the plain friend list plus
// local block lists on both sides. The core path (CheckInteraction) is the
// authoritative one; this exists so the proven earlier deployment keeps
// working unchanged.
func (s *Service) fallbackMayInvite(me *store.User, targetUID string) bool {
	target := s.Store.User(targetUID)
	if target == nil || target.PID == 0 {
		return false
	}
	id, err := s.Acct.Identity(me.PID)
	if err != nil || id == nil {
		return false
	}
	for _, f := range id.Friends {
		if f.PID == target.PID {
			return !MeBlocks(me, targetUID) && !TargetBlocksUser(s, targetUID, me.ID)
		}
	}
	return false
}

func MeBlocks(u *store.User, other string) bool {
	for _, b := range u.Blocks {
		if b == other {
			return true
		}
	}
	return false
}

// targetBlocksUser reads the target's own block list; a directional block by
// the receiver refuses the invitation exactly like the core's enforcement.
func TargetBlocksUser(s *Service, uid, other string) bool {
	t := s.Store.User(uid)
	return t != nil && MeBlocks(t, other)
}

// ---------- shapes ----------

func (s *Service) invitationGroupObj(g *Group, invitations []*Record) map[string]any {
	obj := invitationGroupFields(g)
	items := []any{}
	for _, inv := range invitations {
		items = append(items, invitationGroupEntry(inv))
	}
	obj["invitations"] = items
	return obj
}

func invitationGroupFields(g *Group) map[string]any {
	obj := map[string]any{
		"id":                   JSONUint(g.ID),
		"sender_id":            g.SenderID,
		"invitation_type":      g.Type,
		"application_id":       g.ApplicationID,
		"application_group_id": g.ApplicationGroupID,
		"application_data":     nil,
		"messages":             g.Messages,
		"created_at":           g.CreatedAt,
		"updated_at":           g.UpdatedAt,
	}
	if g.ApplicationData != "" {
		obj["application_data"] = g.ApplicationData
	}
	if g.ApplicationIDMatch != nil {
		obj["application_id_match"] = *g.ApplicationIDMatch
	}
	if g.ACDIndex != nil {
		obj["acd_index"] = *g.ACDIndex
	}
	return obj
}

// invitationGroupEntry is one element of a group's invitations array: the
// firmware reads $.invitations[*].receiver_id and the invitation id beside it.
func invitationGroupEntry(inv *Record) map[string]any {
	return map[string]any{
		"id":          JSONUint(inv.ID),
		"receiver_id": inv.ReceiverID,
	}
}

// jsonUint renders a decimal id as a JSON number: the firmware parses group
// and invitation ids with %llu, so a string would not survive the parser.
func JSONUint(dec string) uint64 {
	n, err := strconv.ParseUint(dec, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// ---------- group detail ----------

func (s *Service) invitationGroupDetail(w http.ResponseWriter, r *http.Request, id string) {
	me := s.fiveAuth(r)
	if me == nil {
		fiveError(w, r, http.StatusUnauthorized, "0006", "invalid_token")
		return
	}
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		fiveError(w, r, http.StatusNotFound, "0010", "resource_is_not_found")
		return
	}
	st := StoreFor()
	st.Mu.Lock()
	g := st.Groups[id]
	var invitations []*Record
	if g != nil {
		if g.SenderID != me.ID && !s.groupReceiver(g, me.ID) {
			// Not the sender and not a receiver: the group does not exist for
			// this caller, and 404 says less than a 403 would.
			g = nil
		}
		if g != nil {
			for _, iid := range g.InvitationIDs {
				if inv := st.Invitations[iid]; inv != nil && inv.ExpiresAt > time.Now().Unix() {
					invitations = append(invitations, inv)
				}
			}
		}
	}
	st.Mu.Unlock()
	if g == nil {
		fiveError(w, r, http.StatusNotFound, "0010", "resource_is_not_found")
		return
	}
	httpx.WriteJSON(w, 200, s.invitationGroupObj(g, invitations))
}

func (s *Service) groupReceiver(g *Group, uid string) bool {
	for _, iid := range g.InvitationIDs {
		if inv := StoreFor().Invitations[iid]; inv != nil && inv.ReceiverID == uid {
			return true
		}
	}
	return false
}

// ---------- inbox ----------

// invitationInbox implements GET /v1|v2/users/<uid>/invitations/inbox. The
// uid in the path is bound to the authenticated principal: a valid token for
// another user reads an empty error, never someone else's invitations.
func (s *Service) invitationInbox(w http.ResponseWriter, r *http.Request, uid string, q url.Values) {
	me := s.fiveAuth(r)
	if me == nil {
		fiveError(w, r, http.StatusUnauthorized, "0006", "invalid_token")
		return
	}
	if uid != me.ID {
		log.Printf("[nx-baas] five: cross-account inbox denied: principal=%s path=%s", redact.Tag(me.ID), redact.Tag(uid))
		fiveError(w, r, http.StatusForbidden, "0006", "operation_is_not_permitted")
		return
	}
	now := time.Now().Unix()
	unreadOnly := q.Get("read") == "false"
	countOnly := false
	for _, f := range strings.Split(q.Get("fields"), ",") {
		if strings.TrimSpace(f) == "count" {
			countOnly = true
		}
	}
	if v := q.Get("invitation_types"); v != "" && v != "friend" {
		// Only the friend type exists on this surface; an unknown type is an
		// empty inbox rather than an error (filters select, they do not fail).
		httpx.WriteJSON(w, 200, map[string]any{"count": 0})
		return
	}

	st := StoreFor()
	st.Mu.Lock()
	var items []*Record
	for _, inv := range st.Invitations {
		if inv.ReceiverID != me.ID || inv.ExpiresAt <= now {
			continue
		}
		if unreadOnly && inv.Read {
			continue
		}
		if s.invitationSenderGone(inv, now) {
			continue
		}
		items = append(items, inv)
	}
	sort.Slice(items, func(i, j int) bool { // newest first, like the other lists
		if items[i].CreatedAt != items[j].CreatedAt {
			return items[i].CreatedAt > items[j].CreatedAt
		}
		return items[i].ID > items[j].ID
	})
	count := len(items)
	const inboxLimit = 100
	if len(items) > inboxLimit {
		items = items[:inboxLimit]
	}
	list := make([]any, 0, len(items))
	for _, inv := range items {
		list = append(list, invitationInboxItem(inv))
	}
	st.Mu.Unlock()

	if countOnly {
		httpx.WriteJSON(w, 200, map[string]any{"count": count, "original_count": count})
		return
	}
	// The console reads $.original_count beside $.count [firmware, friends
	// module]: the total before this page's slice, which is the same number
	// here because the inbox is answered whole.
	httpx.WriteJSON(w, 200, map[string]any{"count": count, "original_count": count, "items": list})
}

func invitationInboxItem(inv *Record) map[string]any {
	obj := map[string]any{
		"id":                   JSONUint(inv.ID),
		"invitation_group_id":  JSONUint(inv.GroupID),
		"sender_id":            inv.SenderID,
		"application_id":       inv.ApplicationID,
		"application_group_id": inv.ApplicationGroupID,
		"application_data":     nil,
		"read":                 inv.Read,
		"created_at":           inv.CreatedAt,
		"updated_at":           inv.UpdatedAt,
	}
	if inv.Type != "" {
		obj["invitation_type"] = inv.Type
	}
	if inv.ApplicationData != "" {
		obj["application_data"] = inv.ApplicationData
	}
	if inv.ApplicationIDMatch != nil {
		obj["application_id_match"] = *inv.ApplicationIDMatch
	}
	if inv.ACDIndex != nil {
		obj["acd_index"] = *inv.ACDIndex
	}
	if len(inv.Messages) > 0 {
		obj["messages"] = inv.Messages
	}
	// Two more the friends module reads off an inbox item [firmware,
	// $.items[*].receiver_id and $.items[*].extras.receiver.read]: the
	// recipient it is addressed to, and the same read state it already has at
	// the top level, where the module looks for it a second time. Both are
	// facts we hold — neither is a guess.
	obj["receiver_id"] = inv.ReceiverID
	obj["extras"] = map[string]any{"receiver": map[string]any{"read": inv.Read}}
	return obj
}

// ---------- read state (INV-02: durable, idempotent, cross-device) ----------

// invitationMarkAllRead implements PATCH /v1/users/<uid>/invitations/mark_as_read:
// every unread invitation addressed to the caller becomes read. An empty body
// means all; a body naming ids narrows the operation to those.
func (s *Service) invitationMarkAllRead(w http.ResponseWriter, r *http.Request, uid string, body []byte) {
	me := s.fiveAuth(r)
	if me == nil {
		fiveError(w, r, http.StatusUnauthorized, "0006", "invalid_token")
		return
	}
	if uid != me.ID {
		log.Printf("[nx-baas] five: cross-account mark_as_read denied: principal=%s path=%s", redact.Tag(me.ID), redact.Tag(uid))
		fiveError(w, r, http.StatusForbidden, "0006", "operation_is_not_permitted")
		return
	}
	ids := map[string]bool{}
	if len(body) > 0 {
		var in struct {
			IDs         []string `json:"ids"`
			Invitations []string `json:"invitations"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
			return
		}
		for _, id := range append(in.IDs, in.Invitations...) {
			ids[id] = true
		}
	}
	s.applyRead(w, me.ID, ids)
}

// invitationPatch implements PATCH /v1/invitations (Content-Type
// application/json-patch+json on the wire). The console's patch paths end in
// /extras/receiver/read (firmware string table); the invitation id appears in
// the path. Paths we cannot bind to an id are a 400 — never a silent success.
func (s *Service) invitationPatch(w http.ResponseWriter, r *http.Request, body []byte) {
	me := s.fiveAuth(r)
	if me == nil {
		fiveError(w, r, http.StatusUnauthorized, "0006", "invalid_token")
		return
	}
	// The console sends this form-encoded, not as a JSON patch: PATCH
	// /v1/invitations with "read=true&ids=<id>%2C<id>…" [firmware, friends
	// module 0x1e24b0 — the body prefix "read=true&ids=" is assembled inline
	// and the ids are joined with an encoded comma]. The JSON-patch shape the
	// wiki documents is still accepted, because both cost one branch.
	if form, err := url.ParseQuery(string(body)); err == nil && form.Get("ids") != "" {
		ids := map[string]bool{}
		for _, id := range strings.Split(form.Get("ids"), ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids[id] = true
			}
		}
		if form.Get("read") == "false" {
			// Nothing in the module ever sends this, and an unread flag is not
			// a state this store can return to: say so rather than pretend.
			log.Printf("[nx-baas] five: PATCH /v1/invitations asked to unread %d invitation(s); refused", len(ids))
			fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
			return
		}
		s.applyRead(w, me.ID, ids)
		return
	}
	var ops []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}
	if err := json.Unmarshal(body, &ops); err != nil || len(ops) == 0 {
		fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
		return
	}
	ids := map[string]bool{}
	for _, o := range ops {
		if !strings.HasSuffix(o.Path, "/extras/receiver/read") && o.Path != "/read" {
			fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
			return
		}
		id, ok := invitationIDFromPath(o.Path)
		if !ok {
			// Maybe the id rode along in the query string instead.
			if q := r.URL.Query().Get("invitation_id"); q != "" {
				id, ok = q, true
			}
		}
		if !ok {
			httpx.Dump(r, body, "!! five patch: unbindable path")
			fiveError(w, r, http.StatusBadRequest, "0002", "invalid_params")
			return
		}
		ids[id] = true
	}
	s.applyRead(w, me.ID, ids)
}

// invitationIDFromPath finds a decimal id in a JSON-patch path.
func invitationIDFromPath(path string) (string, bool) {
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if n, err := strconv.ParseUint(seg, 10, 64); err == nil && n > 0 {
			return strconv.FormatUint(n, 10), true
		}
	}
	return "", false
}

// applyRead commits read state for the caller's own invitations. Unknown ids
// are ignored (idempotent re-apply), ownership is enforced by the receiver
// clause, and the write lands before the response.
func (s *Service) applyRead(w http.ResponseWriter, receiverID string, ids map[string]bool) {
	now := time.Now().Unix()
	st := StoreFor()
	st.Mu.Lock()
	applied := 0
	for _, inv := range st.Invitations {
		if inv.ReceiverID != receiverID || inv.ExpiresAt <= now {
			continue
		}
		if len(ids) > 0 && !ids[inv.ID] {
			continue
		}
		if !inv.Read {
			inv.Read = true
			inv.ReadAt = now
			inv.UpdatedAt = now
			applied++
		}
	}
	st.pruneLocked(time.Unix(now, 0))
	st.saveLocked()
	unread := st.unreadCountLocked(receiverID, now, func(inv *Record) bool {
		return s.invitationSenderGone(inv, now)
	})
	st.Mu.Unlock()
	log.Printf("[nx-baas] five: mark read for %s: %d applied, %d unread left", redact.Tag(receiverID), applied, unread)
	httpx.WriteJSON(w, 200, map[string]any{"count": unread})
}

// ---------- game-API mailbox (emulator/console title path) ----------

// The /api/invitations mailbox keeps its wire shape (Outbound and the
// emulator pop it) but is now a view over this durable store: a restart no
// longer loses queued invitations, native and mailbox sends land in one
// lifecycle, and a stale room fails the pop cleanly instead of joining into
// nothing (INV-04). The five-minute TTL stands: it is the room-staleness bound.

func invitationMailboxTTL() time.Duration { return 5 * time.Minute }

// maxQueuedPerTarget keeps the mailbox per-target queue depth bound (unchanged
// from the in-memory implementation).
const MaxQueuedMailboxPerTarget = 8

// mailboxSessionLive answers whether the sender's room plausibly still exists.
// Presence is the adapter's own truth (the Photon room wrote it); a live core
// session counts too. Only positive staleness drops an invitation: a row with
// no recorded title never carried a room we could judge, so its five-minute
// TTL is the bound. When the adapter cannot tell, the invitation is delivered
// and the title fails the join cleanly, which is the gate INV-04 keeps
// separate from delivery.
func (s *Service) mailboxSessionLive(senderUID, appID string) bool {
	if appID == "" {
		return true // no title recorded: nothing to judge, TTL decides
	}
	u := s.Store.User(senderUID)
	if u == nil {
		return false
	}
	if u.Presence.State == "PLAYING" && (u.Presence.AppID == "" || u.Presence.AppID == appID) {
		return true
	}
	if core := s.CoreFor(); core != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if accountID, ok := core.AccountForBaas(senderUID); ok {
			if live, err := core.ResolveSession(ctx, accountID, appID); err == nil && live {
				return true
			}
		}
	}
	return false
}

// createMailboxInvitation stores one emulator-sent invitation. The friend and
// policy checks are the caller's (gameapi.sendInvitation kept its behavior).
func CreateMailbox(sender *store.User, senderName string, receiver *store.User, appParamB64, appID string) (string, bool) {
	now := time.Now()
	st := StoreFor()
	st.Mu.Lock()
	defer st.Mu.Unlock()
	// Bound: oldest mailbox rows for this receiver are dropped first.
	var queue []*Record
	for _, inv := range st.Invitations {
		if inv.Mailbox && inv.ReceiverID == receiver.ID && inv.ExpiresAt > now.Unix() {
			queue = append(queue, inv)
		}
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].CreatedAt < queue[j].CreatedAt })
	for len(queue) >= MaxQueuedMailboxPerTarget {
		dropped := queue[0]
		queue = queue[1:]
		delete(st.Invitations, dropped.ID)
		log.Printf("[nx-baas] invitation: queue full for %s, dropped %s", redact.Tag(receiver.ID), redact.Tag(dropped.ID))
	}
	inv := &Record{
		Type: "friend", SenderID: sender.ID, ReceiverID: receiver.ID,
		ApplicationID:   strings.ToLower(appID),
		ApplicationData: appParamB64,
		CreatedAt:       now.Unix(),
		UpdatedAt:       now.Unix(),
		ExpiresAt:       now.Add(invitationMailboxTTL()).Unix(),
		Mailbox:         true, MailboxFromPID: sender.PID, MailboxFromName: senderName,
	}
	inv.ID = st.nextIDLocked(now)
	st.Invitations[inv.ID] = inv
	st.saveLocked()
	return inv.ID, true
}

// popMailboxInvitations returns and removes the caller's live mailbox
// invitations. Rows whose room went stale are dropped, not delivered: joining
// a dead room must fail quietly on the sender's side of the wire (INV-04).
func PopMailbox(s *Service, receiver *store.User) []*Record {
	now := time.Now()
	st := StoreFor()
	st.Mu.Lock()
	defer st.Mu.Unlock()
	var out []*Record
	for id, inv := range st.Invitations {
		if !inv.Mailbox || inv.ReceiverID != receiver.ID {
			continue
		}
		if inv.ExpiresAt <= now.Unix() { // room presumed long gone
			delete(st.Invitations, id)
			continue
		}
		if !s.mailboxSessionLive(inv.SenderID, inv.ApplicationID) {
			log.Printf("[nx-baas] invitation: dropping stale room invite %s (sender %s offline)", redact.Tag(inv.ID), redact.Tag(inv.SenderID))
			delete(st.Invitations, id)
			continue
		}
		out = append(out, inv)
		delete(st.Invitations, id) // popped is consumed, as before
	}
	if len(out) > 0 {
		st.saveLocked()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// Service is the invitations surface over the shared state. Locks refuses banned accounts.
type Service struct {
	*core.Core
	Locks interface{ UserLock(u *store.User) string }
}
