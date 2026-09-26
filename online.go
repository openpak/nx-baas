package main

// POST /internal/switch/online: a game server's roll call. Playtime on openpak.org counts only
// time a game server saw the player connected, so every ~30 s each server lists who is on it and
// this forwards that to the core's MarkOnline. Game servers hold no core credentials; this does.
//
//	{"title_id":"0100…","players":[{"pid":1800000001},{"account_id":"<uuid>"},{"baas_user_id":"…"}]}
//	-> {"marked":N,"unknown":M}
//
// marked is what the core counted (a player with no live titled session is not marked); unknown
// is entries that resolve to no OpenPak account and were never sent.

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	accountv1 "nx-baas/accountpb"
)

// maxOnlineMarks matches the core's per-call cap on MarkOnline.
const maxOnlineMarks = 1000

var titleIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

type onlineEntry struct {
	PID        uint64 `json:"pid"`
	AccountID  string `json:"account_id"`
	BaasUserID string `json:"baas_user_id"`
}

func (s *server) switchOnline(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	if r.Method != http.MethodPost {
		apiErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var in struct {
		TitleID string        `json:"title_id"`
		Players []onlineEntry `json:"players"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(in.Players) > maxOnlineMarks {
		apiErr(w, http.StatusBadRequest, "at most 1000 players per call")
		return
	}
	title := strings.ToLower(in.TitleID)
	if title != "" && !titleIDRe.MatchString(title) {
		apiErr(w, http.StatusBadRequest, "title_id must be 16 hex digits")
		return
	}
	b, ok := s.acct.(*openpakBackend)
	if !ok || b.sessions == nil {
		apiErr(w, http.StatusNotImplemented, "openpak backend only")
		return
	}

	seen := map[string]bool{}
	players := make([]*accountv1.OnlinePlayer, 0, len(in.Players))
	unknown := 0
	for _, e := range in.Players {
		id := s.onlineAccount(b, e)
		if id == "" {
			unknown++
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		players = append(players, &accountv1.OnlinePlayer{AccountId: id, Namespace: b.namespace, TitleId: title})
	}
	var marked int32
	if len(players) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		res, err := b.sessions.MarkOnline(ctx, &accountv1.MarkOnlineRequest{Players: players})
		if err != nil {
			logErr("mark online", err)
			apiErr(w, http.StatusBadGateway, "core unavailable")
			return
		}
		marked = res.GetMarked()
	}
	writeJSON(w, http.StatusOK, map[string]any{"marked": marked, "unknown": unknown})
}

// onlineAccount maps one roll-call entry to its OpenPak account, through the same projection
// the identity endpoint answers from. "" is an account this adapter does not know.
func (s *server) onlineAccount(b *openpakBackend, e onlineEntry) string {
	pid := e.PID
	if pid == 0 && e.AccountID == "" && e.BaasUserID != "" && s.store != nil {
		// The BAAS user id is the store's own key (see pidForIDToken). Looked up before taking
		// the projection lock so the two locks are never held together.
		if u := s.store.User(e.BaasUserID); u != nil {
			pid = u.PID
		}
	}
	b.proj.mu.Lock()
	defer b.proj.mu.Unlock()
	switch {
	case pid != 0:
		return b.proj.ByPID[pid]
	case e.AccountID != "":
		if _, ok := b.proj.ByAccount[e.AccountID]; ok {
			return e.AccountID
		}
	case e.BaasUserID != "":
		return b.proj.ByBaas[e.BaasUserID]
	}
	return ""
}
