package main

// POST /internal/switch/identity {"openpak":"nx2…"} or {"pid":18…} -> the player's Switch
// projection plus the friends that have one. The title-server surface (PRD §8): an NPLN or
// NEX server hands over the openpak claim it found in a client's id_token, or a pid it already
// proved from its own bearer, and never needs the signing key or the core.

import (
	"encoding/json"
	"net/http"
)

type switchPlayer struct {
	PID        uint64 `json:"pid"`
	BaasUserID string `json:"baas_user_id"` // the NSA id titles see
	Nickname   string `json:"nickname"`
}

func (s *server) switchIdentity(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	var in struct {
		OpenPak string `json:"openpak"`
		PID  uint64 `json:"pid"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	pid := in.PID
	if in.OpenPak != "" {
		var ok bool
		if pid, _, ok = verifyNexToken(s.acct.nexSigningKey(), in.OpenPak); !ok {
			apiErr(w, http.StatusUnauthorized, "openpak not proven")
			return
		}
	}
	id, err := s.acct.Identity(pid)
	if err != nil {
		logErr("identity", err)
		apiErr(w, http.StatusNotFound, "unknown pid")
		return
	}
	friends := make([]switchPlayer, 0, len(id.Friends))
	for _, f := range id.Friends {
		friends = append(friends, switchPlayer{PID: f.PID, BaasUserID: f.BaasUserID, Nickname: f.Nickname})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pid": id.PID, "baas_user_id": id.BaasUserID, "nickname": id.Nickname, "friends": friends})
}

// switchFriendCode answers "what is this account's friend code" for the
// website, which cannot know: the code is minted here and the core holds only
// the link subject, which is the BAAS user id. The site was formatting that
// hex id as SW-xxxx-xxxx-xxxx, so people were being shown, and reading out, an
// identifier that is not their friend code.
func (s *server) switchFriendCode(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	accountID := r.URL.Query().Get("account_id")
	if accountID == "" {
		apiErr(w, http.StatusBadRequest, "account_id required")
		return
	}
	code, ok := s.acct.friendCodeForAccount(accountID)
	if !ok {
		apiErr(w, http.StatusNotFound, "no console linked to that account")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"friend_code": code})
}
