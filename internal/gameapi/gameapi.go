// Package gameapi is the game-facing HTTP API on a plain internal port (ports.md: 20070). These are the endpoints
// the Photon server and the emulator used to get from the earlier account server:
//
//	POST /internal/photon-room   Photon publishes the room a player just entered, so the
//	                             host shows up as joinable in a friend's list.
//	POST /internal/mint-token    Rig tooling mints a bearer for a PID (replaces the offline
//	                             HMAC in scripts/mint-host-token.sh).
//	GET/POST /api/invitations    The friend-invitation mailbox: the game builds the opaque
//	                             app parameter (Outbound = its Fusion room code), the target's
//	                             client pops it. This server never parses those bytes.
//
// Anything else under /api/ is forwarded to ACCOUNT_API while the rest of the account surface
// (friends, presence, saves...) still lives there.
// ponytail: drop the forwarder once the OpenPak core serves those directly.
package gameapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"nx-baas/internal/baas"
	"nx-baas/internal/bans"
	"nx-baas/internal/core"
	"nx-baas/internal/dauth"
	"nx-baas/internal/friends"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/invitations"
	"nx-baas/internal/nxaccount"
	"nx-baas/internal/penne"
	"nx-baas/internal/presence"
	"nx-baas/redact"
	"os"
	"strconv"
	"strings"
	"time"
)

// An invitation older than this is presumed stale (the sender is almost certainly no longer
// hosting that room) and is dropped rather than delivered late into a different context.
const invitationTTL = 5 * time.Minute

// Cap per-target queue depth so a misbehaving sender cannot grow this unbounded.
const maxQueuedPerTarget = 8

// FriendInvitationApplicationParameterSizeMax on the console side.
const maxAppParam = 1024

// Superseded by the durable invitation store (invitations.go); the five-minute
// staleness bound is kept there (invitationMailboxTTL).

// ---------- bearer ----------

// verifyNexToken checks the "nx2." token both this server and the earlier account server mint
// (nexToken): HMAC-SHA256 over "nex:<pid>.<username>.<expiry>". Returning the PID is the
// whole point -- it is what binds a request to an account.
func VerifyNexToken(key []byte, tok string) (uint64, string, bool) {
	parts := strings.Split(tok, ".")
	if len(key) == 0 || len(parts) != 3 || parts[0] != "nx2" {
		return 0, "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, "", false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(append([]byte("nex:"), payload...))
	if !hmac.Equal(mac.Sum(nil), sig) {
		return 0, "", false
	}
	// <pid>.<username>.<expiry>; a username may itself contain dots.
	dot, lastDot := strings.IndexByte(string(payload), '.'), strings.LastIndexByte(string(payload), '.')
	if dot < 0 || lastDot <= dot {
		return 0, "", false
	}
	pid, err := strconv.ParseUint(string(payload[:dot]), 10, 64)
	if err != nil || pid == 0 {
		return 0, "", false
	}
	exp, err := strconv.ParseInt(string(payload[lastDot+1:]), 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return 0, "", false
	}
	return pid, string(payload[dot+1 : lastDot]), true
}

// callerPID authenticates an /api request. 401 makes the emulator drop its session, so it is
// returned only for a token that is actually bad.
func (s *Service) callerPID(r *http.Request) (uint64, string, bool) {
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	return VerifyNexToken(s.Acct.NexSigningKey(), tok)
}

// ---------- room presence ----------

// pidForIdentity resolves what the Photon server extracted from a client's id_token:
// "nex:<nx2 token>" (emulators; account-signed, so it identifies an account) or
// "bsdid:<bs:did>" (consoles) -- see AccountIdentityRegistry.ExtractToken.
func (s *Service) pidForIdentity(identity string) uint64 {
	if tok, ok := strings.CutPrefix(identity, "nex:"); ok {
		pid, _, valid := VerifyNexToken(s.Acct.NexSigningKey(), tok)
		if !valid {
			return 0
		}
		return pid
	}
	bsDid := strings.TrimPrefix(identity, "bsdid:")
	if u := s.Store.UserByBsDid(bsDid); u != nil {
		return u.PID
	}
	return 0
}

// POST /internal/photon-room {"identity":"nex:...|bsdid:...","room":"ABC123","app_id":"0100..."}
// The room becomes the player's friend presence: app_field carries the exact application
// parameter the title expects (Outbound: u32_le(1) || u8(len) || ascii(code)), so a friend
// joins the same way whether a console or an emulator hosts.
func (s *Service) photonRoom(w http.ResponseWriter, r *http.Request) {
	if !httpx.InternalOK(r) {
		httpx.APIErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		Identity string `json:"identity"`
		Room     string `json:"room"`
		AppID    string `json:"app_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		httpx.APIErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.AppID == "" || !validRoomCode(in.Room) {
		httpx.APIErr(w, http.StatusBadRequest, "invalid session")
		return
	}
	pid := s.pidForIdentity(in.Identity)
	u := s.Store.UserByPID(pid)
	if pid == 0 || u == nil {
		httpx.APIErr(w, http.StatusBadRequest, "unknown identity")
		return
	}
	if lock := s.Locks.PIDLock(pid); lock != "" {
		bans.InternalLocked(w, lock)
		return
	}
	appParam := append([]byte{1, 0, 0, 0, byte(len(in.Room))}, in.Room...)
	// A title's room is one device's claim, keyed by that identity, so a
	// friend's list shows PLAYING for exactly as long as the room lives —
	// and not one request longer than the lease if the game never reports
	// the departure.
	s.Presence.NoteDevicePresence(u, "photon:"+in.Identity, "PLAYING", in.AppID,
		base64.StdEncoding.EncodeToString(appParam), in.AppID, -1)
	log.Printf("[nx-baas] photon-room pid=%s app=%s room=%s", redact.Tag(pid), in.AppID, redact.Tag(in.Room))
	httpx.WriteJSON(w, 200, map[string]any{"ok": true})
}

// POST /internal/photon-room-leave {"identity":"nex:...|bsdid:..."}
// The room a player left is not a room they are in: without this the PLAYING
// claim outlived the game and a friend's list offered a join into nothing
// (PRE-02, room leave).
func (s *Service) photonRoomLeave(w http.ResponseWriter, r *http.Request) {
	if !httpx.InternalOK(r) {
		httpx.APIErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		Identity string `json:"identity"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || in.Identity == "" {
		httpx.APIErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	pid := s.pidForIdentity(in.Identity)
	u := s.Store.UserByPID(pid)
	if pid == 0 || u == nil {
		httpx.APIErr(w, http.StatusBadRequest, "unknown identity")
		return
	}
	s.Presence.NoteDevicePresence(u, "photon:"+in.Identity, "OFFLINE", "", "", "", -1)
	log.Printf("[nx-baas] photon-room-leave pid=%s", redact.Tag(pid))
	httpx.WriteJSON(w, 200, map[string]any{"ok": true})
}

// POST /internal/photon-identity {"identity":"nex:...|bsdid:..."} -> {"pid":..,"country":"AU"}
// The Photon master asks this when a player authenticates, so a room they create can be placed
// on the region node for their country. Same identity shapes as photon-room.
func (s *Service) photonIdentity(w http.ResponseWriter, r *http.Request) {
	if !httpx.InternalOK(r) {
		httpx.APIErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		Identity string `json:"identity"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		httpx.APIErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	pid := s.pidForIdentity(in.Identity)
	if pid == 0 {
		httpx.APIErr(w, http.StatusBadRequest, "unknown identity")
		return
	}
	if lock := s.Locks.PIDLock(pid); lock != "" {
		bans.InternalLocked(w, lock)
		return
	}
	id, err := s.Acct.Identity(pid)
	if err != nil {
		httpx.APIErr(w, http.StatusNotFound, "unknown pid")
		return
	}
	s.MarkLoginOnline(pid) // the Photon master authenticated this player: playtime starts here
	httpx.WriteJSON(w, 200, map[string]any{"pid": pid, "country": id.Country, "baas_user_id": id.BaasUserID})
}

func validRoomCode(room string) bool {
	if len(room) < 4 || len(room) > 8 {
		return false
	}
	for _, c := range room {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// ---------- invitations ----------

// The mailbox is now a view over the durable invitation store
// (invitations.go): the emulator and the console title path keep their exact
// wire shape, but a restart no longer loses queued invitations, native and
// mailbox sends land in one lifecycle, and a stale room fails the pop cleanly
// (INV-03/INV-04). The five-minute TTL stands as the room-staleness bound.

func (s *Service) invitations(w http.ResponseWriter, r *http.Request) {
	pid, name, ok := s.callerPID(r)
	if !ok {
		httpx.APIErr(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}
	if lock := s.Locks.PIDLock(pid); lock != "" {
		bans.InternalLocked(w, lock)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.pollInvitations(w, pid)
	case http.MethodPost:
		s.sendInvitation(w, r, pid, name)
	default:
		httpx.APIErr(w, http.StatusMethodNotAllowed, "GET or POST expected")
	}
}

// POST /api/invitations {"target_pids":[...],"app_param_base64":"..."}
// Only queues to the sender's mutual friends -- the console's own Invite Friends only ever
// lists friends, and without the check this is a generic spam relay. With the OpenPak core
// attached, the core's own interaction check (friendship, blocks, account status) is the
// authority; the friend list is the fallback for the earlier account backend.
func (s *Service) sendInvitation(w http.ResponseWriter, r *http.Request, from uint64, name string) {
	var in struct {
		TargetPIDs     []uint64 `json:"target_pids"`
		AppParamBase64 string   `json:"app_param_base64"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		httpx.APIErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(in.TargetPIDs) == 0 {
		httpx.APIErr(w, http.StatusBadRequest, "target_pids required")
		return
	}
	appParam, err := base64.StdEncoding.DecodeString(in.AppParamBase64)
	if err != nil || len(appParam) > maxAppParam {
		httpx.APIErr(w, http.StatusBadRequest, "invalid app_param_base64")
		return
	}
	id, err := s.Acct.Identity(from)
	if err != nil {
		identity.LogErr("identity", err)
		httpx.APIErr(w, http.StatusBadGateway, "account lookup failed")
		return
	}
	if id.Nickname != "" {
		name = id.Nickname
	}
	sender := s.Store.UserByPID(from)
	if sender == nil {
		httpx.APIErr(w, http.StatusBadRequest, "unknown identity")
		return
	}
	// The sender's title now, so the invitation carries an application id and
	// the staleness check can answer "is this room still alive" later.
	appID := sender.Presence.AppID
	core := s.Invitations.CoreFor()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	sent := 0
	for _, pid := range in.TargetPIDs {
		target := s.Store.UserByPID(pid)
		if target == nil || !isFriend(id, pid) || s.Locks.PIDLock(pid) != "" {
			continue
		}
		if core != nil {
			actorID, _ := core.AccountForBaas(sender.ID)
			targetID, ok := core.AccountForBaas(target.ID)
			if !ok {
				continue
			}
			allowed, _, err := core.CheckInteraction(ctx, actorID, targetID)
			if err != nil || !allowed {
				continue
			}
		} else if invitations.MeBlocks(sender, target.ID) || invitations.TargetBlocksUser(s.Invitations, target.ID, sender.ID) {
			continue
		}
		invitations.CreateMailbox(sender, name, target, in.AppParamBase64, appID)
		sent++
	}
	log.Printf("[nx-baas] invitation %s(%s) -> %d/%d target(s)", redact.Text(name), redact.Tag(from), sent, len(in.TargetPIDs))
	httpx.WriteJSON(w, 200, map[string]any{"ok": true, "sent": sent})
}

func isFriend(id *identity.Identity, pid uint64) bool {
	for _, f := range id.Friends {
		if f.PID == pid {
			return true
		}
	}
	return false
}

// GET /api/invitations -- pops every invitation queued for the caller, matching the console's
// own TryPopFromFriendInvitationStorageChannel (a poll-until-something's-there call).
func (s *Service) pollInvitations(w http.ResponseWriter, pid uint64) {
	receiver := s.Store.UserByPID(pid)
	if receiver == nil {
		httpx.WriteJSON(w, 200, map[string]any{"invitations": []any{}})
		return
	}
	out := make([]map[string]any, 0, 4)
	for _, inv := range invitations.PopMailbox(s.Invitations, receiver) {
		out = append(out, map[string]any{"from_pid": inv.MailboxFromPID, "from_name": inv.MailboxFromName,
			"app_param_base64": inv.ApplicationData})
	}
	httpx.WriteJSON(w, 200, map[string]any{"invitations": out})
}

// POST /internal/mint-token {"pid":1800000003} -> the fields scripts write into a profile's
// openpak_account.txt. Dev-rig tooling: it mints a bearer for any PID without a password.
func (s *Service) mintToken(w http.ResponseWriter, r *http.Request) {
	if !httpx.InternalOK(r) {
		httpx.APIErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		PID uint64 `json:"pid"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in); err != nil || in.PID == 0 {
		httpx.APIErr(w, http.StatusBadRequest, "pid required")
		return
	}
	if lock := s.Locks.PIDLock(in.PID); lock != "" {
		bans.InternalLocked(w, lock)
		return
	}
	id, err := s.Acct.Identity(in.PID)
	if err != nil {
		identity.LogErr("identity", err)
		httpx.APIErr(w, http.StatusNotFound, "unknown pid")
		return
	}
	tok := s.Acct.NexToken(in.PID, id.Nickname)
	if tok == "" {
		httpx.APIErr(w, http.StatusServiceUnavailable, "no signing key")
		return
	}
	log.Printf("[nx-baas] minted token for pid=%s (%s)", redact.Tag(in.PID), redact.Text(id.Nickname))
	httpx.WriteJSON(w, 200, map[string]any{"pid": in.PID, "username": id.Nickname, "friend_code": id.FriendCode, "token": tok})
}

// POST /internal/notifications/test {"user_id":"…","kind":"presence_updated","payload":{...}}
// B workstream, DEVELOPMENT ONLY: a synthetic event source so the notification
// pipeline (submit -> outbox -> frontline frame) can be exercised without the
// real A/C feeds. It permits development, not end-to-end completion (PRD:
// "A synthetic event source permits development, not end-to-end completion").
// Native acceptance still requires the real core events on two consoles.
func (s *Service) penneTestNotification(w http.ResponseWriter, r *http.Request) {
	if !httpx.InternalOK(r) {
		httpx.APIErr(w, http.StatusUnauthorized, "internal")
		return
	}
	if r.Method != http.MethodPost {
		httpx.APIErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var in struct {
		UserID  string         `json:"user_id"`
		Kind    string         `json:"kind"`
		Payload map[string]any `json:"payload"`
		ID      string         `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || in.UserID == "" || in.Kind == "" {
		httpx.APIErr(w, http.StatusBadRequest, "user_id and kind required")
		return
	}
	res := s.Submit(penne.Delivery{
		ID: in.ID, UserID: in.UserID, Kind: in.Kind, Payload: in.Payload,
	}, true)
	log.Printf("[nx-baas] penne: test notification user=%s kind=%s -> %s", redact.Tag(in.UserID), in.Kind, res.Outcome)
	httpx.WriteJSON(w, 200, map[string]any{"accepted": res.Accepted, "duplicate": res.Duplicate, "outcome": string(res.Outcome), "id": res.ID})
}

// ---------- mux ----------

// Handler is the game API mux.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/photon-room", s.photonRoom)
	mux.HandleFunc("/internal/photon-room-leave", s.photonRoomLeave)
	mux.HandleFunc("/internal/photon-identity", s.photonIdentity)
	mux.HandleFunc("/internal/mint-token", s.mintToken)
	mux.HandleFunc("/internal/switch/identity", s.switchIdentity)
	mux.HandleFunc("/internal/switch/friend-code", s.switchFriendCode)
	mux.HandleFunc("/internal/switch/account-by-friend-code", s.SwitchAccountByFriendCode)
	mux.HandleFunc("/internal/switch/emulator", s.switchEmulator)
	mux.HandleFunc("/internal/switch/emulator/friend", s.switchEmulatorFriend)
	mux.HandleFunc("/internal/switch/emulator/link-token", s.switchEmulatorLinkToken)
	mux.HandleFunc("/internal/switch/ca", s.switchCA)
	mux.HandleFunc("/internal/title-version", s.Dauth.TitleVersion)
	mux.HandleFunc("/api/invitations", s.invitations)
	mux.HandleFunc("/internal/notifications/test", s.penneTestNotification)
	mux.HandleFunc("/internal/news/push", s.Penne.NewsPush)
	if s.PctlFwd != nil {
		// The website's parent routes are nx-pctl's now; forwarded until it points there.
		mux.Handle("/internal/pctl/", s.PctlFwd)
	}
	if s.ShopFwd != nil {
		mux.Handle("/internal/store/", s.ShopFwd)
	}
	// What the split-out services ask the core (internal_identity.go).
	mux.HandleFunc("/internal/identity/users/", s.identityUsers)
	mux.HandleFunc("/internal/identity/na/", s.identityNA)
	mux.HandleFunc("/internal/identity/accounts/", s.identityAccounts)
	mux.HandleFunc("/internal/identity/presence", s.identityPresence)
	mux.HandleFunc("/internal/identity/presence/renew", s.identityPresence)
	if s.PenneFwd != nil {
		// Penne's API is nx-penne's; a caller still pointed here is forwarded.
		mux.Handle("/internal/penne/", s.PenneFwd)
	}
	if base := os.Getenv("ACCOUNT_API"); base != "" {
		if u, err := url.Parse(strings.TrimRight(base, "/")); err == nil {
			proxy := httputil.NewSingleHostReverseProxy(u)
			mux.Handle("/", proxy)
			log.Printf("[nx-baas] game API: unhandled paths forwarded to %s", base)
		}
	}
	return mux
}

// Service is the game-facing internal API (plain HTTP on NX_API_ADDR): what game servers,
// the website and the split-out services ask the core. It holds no state of its own.
type Service struct {
	*core.Core
	Locks       *bans.Checker
	Dauth       *dauth.Service
	Invitations *invitations.Service
	Presence    *presence.Service
	NA          *nxaccount.Service
	BAAS        *baas.Service
	Friends     *friends.Service
	// Submit hands a checked notification to Penne; wait asks for nx-penne's outcome.
	Submit func(d penne.Delivery, wait bool) penne.Submission
	// The forwarders to the split-out services whose admin routes the website still calls here.
	ShopFwd, PctlFwd, PenneFwd *httputil.ReverseProxy
}
