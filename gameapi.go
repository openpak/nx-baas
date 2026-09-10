package main

// Game-facing HTTP API on a plain internal port (ports.md: 20070). These are the endpoints
// the Photon server and the emulator used to get from openpak-account:
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

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// An invitation older than this is presumed stale (the sender is almost certainly no longer
// hosting that room) and is dropped rather than delivered late into a different context.
const invitationTTL = 5 * time.Minute

// Cap per-target queue depth so a misbehaving sender cannot grow this unbounded.
const maxQueuedPerTarget = 8

// FriendInvitationApplicationParameterSizeMax on the console side.
const maxAppParam = 1024

type pendingInvitation struct {
	FromPID  uint64
	FromName string
	AppParam []byte // opaque, game-defined bytes -- never inspected here
	Created  time.Time
}

var (
	invitationsMu sync.Mutex
	invitationsBy = map[uint64][]pendingInvitation{} // target pid -> queued invitations
)

func apiErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// ---------- bearer ----------

// verifyNexToken checks the "nx2." token both this server and openpak-account mint
// (nexToken): HMAC-SHA256 over "nex:<pid>.<username>.<expiry>". Returning the PID is the
// whole point -- it is what binds a request to an account.
func verifyNexToken(key []byte, tok string) (uint64, string, bool) {
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
func (s *server) callerPID(r *http.Request) (uint64, string, bool) {
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	return verifyNexToken(s.acct.nexSigningKey(), tok)
}

// internalOK guards the /internal endpoints. The API port is internal (compose network or
// loopback); the key is the second lock, and its absence is loud at startup.
func (s *server) internalOK(r *http.Request) bool {
	k := getenv("NX_INTERNAL_KEY", getenv("OPENPAK_INTERNAL_KEY", ""))
	return k == "" || hmac.Equal([]byte(k), []byte(r.Header.Get("X-Internal-Key")))
}

// ---------- room presence ----------

// pidForIdentity resolves what the Photon server extracted from a client's id_token:
// "nex:<nx2 token>" (emulators; account-signed, so it identifies an account) or
// "bsdid:<bs:did>" (consoles) -- see AccountIdentityRegistry.ExtractToken.
func (s *server) pidForIdentity(identity string) uint64 {
	if tok, ok := strings.CutPrefix(identity, "nex:"); ok {
		pid, _, valid := verifyNexToken(s.acct.nexSigningKey(), tok)
		if !valid {
			return 0
		}
		return pid
	}
	bsDid := strings.TrimPrefix(identity, "bsdid:")
	if u := s.store.UserByBsDid(bsDid); u != nil {
		return u.PID
	}
	return 0
}

// POST /internal/photon-room {"identity":"nex:...|bsdid:...","room":"ABC123","app_id":"0100..."}
// The room becomes the player's friend presence: app_field carries the exact application
// parameter the title expects (Outbound: u32_le(1) || u8(len) || ascii(code)), so a friend
// joins the same way whether a console or an emulator hosts.
func (s *server) photonRoom(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		Identity string `json:"identity"`
		Room     string `json:"room"`
		AppID    string `json:"app_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.AppID == "" || !validRoomCode(in.Room) {
		apiErr(w, http.StatusBadRequest, "invalid session")
		return
	}
	pid := s.pidForIdentity(in.Identity)
	u := s.store.UserByPID(pid)
	if pid == 0 || u == nil {
		apiErr(w, http.StatusBadRequest, "unknown identity")
		return
	}
	appParam := append([]byte{1, 0, 0, 0, byte(len(in.Room))}, in.Room...)
	s.store.Update(u, func(u *User) {
		u.Presence = Presence{State: "PLAYING", AppField: base64.StdEncoding.EncodeToString(appParam),
			AppID: in.AppID, PresenceGroupID: in.AppID, UpdatedAt: time.Now().Unix()}
	})
	log.Printf("[nx-baas] photon-room pid=%d app=%s room=%s", pid, in.AppID, in.Room)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /internal/photon-identity {"identity":"nex:...|bsdid:..."} -> {"pid":..,"country":"AU"}
// The Photon master asks this when a player authenticates, so a room they create can be placed
// on the region node for their country. Same identity shapes as photon-room.
func (s *server) photonIdentity(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		Identity string `json:"identity"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	pid := s.pidForIdentity(in.Identity)
	if pid == 0 {
		apiErr(w, http.StatusBadRequest, "unknown identity")
		return
	}
	id, err := s.acct.Identity(pid)
	if err != nil {
		apiErr(w, http.StatusNotFound, "unknown pid")
		return
	}
	writeJSON(w, 200, map[string]any{"pid": pid, "country": id.Country})
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

func pruneInvitationsLocked(pid uint64) []pendingInvitation {
	queue := invitationsBy[pid]
	if len(queue) == 0 {
		return queue
	}
	fresh, now := queue[:0], time.Now()
	for _, inv := range queue {
		if now.Sub(inv.Created) <= invitationTTL {
			fresh = append(fresh, inv)
		}
	}
	invitationsBy[pid] = fresh
	return fresh
}

func (s *server) invitations(w http.ResponseWriter, r *http.Request) {
	pid, name, ok := s.callerPID(r)
	if !ok {
		apiErr(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.pollInvitations(w, pid)
	case http.MethodPost:
		s.sendInvitation(w, r, pid, name)
	default:
		apiErr(w, http.StatusMethodNotAllowed, "GET or POST expected")
	}
}

// POST /api/invitations {"target_pids":[...],"app_param_base64":"..."}
// Only queues to the sender's mutual friends -- the console's own Invite Friends only ever
// lists friends, and without the check this is a generic spam relay.
func (s *server) sendInvitation(w http.ResponseWriter, r *http.Request, from uint64, name string) {
	var in struct {
		TargetPIDs     []uint64 `json:"target_pids"`
		AppParamBase64 string   `json:"app_param_base64"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(in.TargetPIDs) == 0 {
		apiErr(w, http.StatusBadRequest, "target_pids required")
		return
	}
	appParam, err := base64.StdEncoding.DecodeString(in.AppParamBase64)
	if err != nil || len(appParam) > maxAppParam {
		apiErr(w, http.StatusBadRequest, "invalid app_param_base64")
		return
	}
	id, err := s.acct.Identity(from)
	if err != nil {
		logErr("identity", err)
		apiErr(w, http.StatusBadGateway, "account lookup failed")
		return
	}
	if id.Nickname != "" {
		name = id.Nickname
	}
	sent := 0
	invitationsMu.Lock()
	for _, pid := range in.TargetPIDs {
		if !isFriend(id, pid) {
			continue
		}
		queue := pruneInvitationsLocked(pid)
		if len(queue) >= maxQueuedPerTarget {
			queue = queue[1:]
		}
		invitationsBy[pid] = append(queue, pendingInvitation{FromPID: from, FromName: name, AppParam: appParam, Created: time.Now()})
		sent++
	}
	invitationsMu.Unlock()
	log.Printf("[nx-baas] invitation %s(%d) -> %d/%d target(s)", name, from, sent, len(in.TargetPIDs))
	writeJSON(w, 200, map[string]any{"ok": true, "sent": sent})
}

func isFriend(id *Identity, pid uint64) bool {
	for _, f := range id.Friends {
		if f.PID == pid {
			return true
		}
	}
	return false
}

// GET /api/invitations -- pops every invitation queued for the caller, matching the console's
// own TryPopFromFriendInvitationStorageChannel (a poll-until-something's-there call).
func (s *server) pollInvitations(w http.ResponseWriter, pid uint64) {
	invitationsMu.Lock()
	queue := pruneInvitationsLocked(pid)
	delete(invitationsBy, pid)
	invitationsMu.Unlock()

	out := make([]map[string]any, 0, len(queue))
	for _, inv := range queue {
		out = append(out, map[string]any{"from_pid": inv.FromPID, "from_name": inv.FromName,
			"app_param_base64": base64.StdEncoding.EncodeToString(inv.AppParam)})
	}
	writeJSON(w, 200, map[string]any{"invitations": out})
}

// POST /internal/mint-token {"pid":1800000003} -> the fields scripts write into a profile's
// openpak_account.txt. Dev-rig tooling: it mints a bearer for any PID without a password.
func (s *server) mintToken(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		PID uint64 `json:"pid"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in); err != nil || in.PID == 0 {
		apiErr(w, http.StatusBadRequest, "pid required")
		return
	}
	id, err := s.acct.Identity(in.PID)
	if err != nil {
		logErr("identity", err)
		apiErr(w, http.StatusNotFound, "unknown pid")
		return
	}
	tok := s.acct.nexToken(in.PID, id.Nickname)
	if tok == "" {
		apiErr(w, http.StatusServiceUnavailable, "no signing key")
		return
	}
	log.Printf("[nx-baas] minted token for pid=%d (%s)", in.PID, id.Nickname)
	writeJSON(w, 200, map[string]any{"pid": in.PID, "username": id.Nickname, "friend_code": id.FriendCode, "token": tok})
}

// ---------- mux ----------

func (s *server) gameAPI() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/photon-room", s.photonRoom)
	mux.HandleFunc("/internal/photon-identity", s.photonIdentity)
	mux.HandleFunc("/internal/mint-token", s.mintToken)
	mux.HandleFunc("/internal/switch/identity", s.switchIdentity)
	mux.HandleFunc("/internal/switch/friend-code", s.switchFriendCode)
	mux.HandleFunc("/internal/switch/emulator", s.switchEmulator)
	mux.HandleFunc("/internal/switch/emulator/friend", s.switchEmulatorFriend)
	mux.HandleFunc("/internal/switch/ca", s.switchCA)
	mux.HandleFunc("/api/invitations", s.invitations)
	if base := os.Getenv("ACCOUNT_API"); base != "" {
		if u, err := url.Parse(strings.TrimRight(base, "/")); err == nil {
			proxy := httputil.NewSingleHostReverseProxy(u)
			mux.Handle("/", proxy)
			log.Printf("[nx-baas] game API: unhandled paths forwarded to %s", base)
		}
	}
	return mux
}
