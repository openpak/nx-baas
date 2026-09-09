package main

// POST /internal/switch/identity {"openpak":"nx2…"}, {"id_token":"eyJ…"} or {"pid":18…} -> the
// player's Switch projection plus the friends that have one. The title-server surface (PRD §8):
// an NPLN or NEX server hands over the openpak claim it found in a client's id_token, the whole
// id_token when there is no claim to find, or a pid it already proved from its own bearer, and
// never needs the signing key or the core.

import (
	"encoding/json"
	"net/http"
	"time"
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
		OpenPak    string `json:"openpak"`
		IDToken string `json:"id_token"`
		PID     uint64 `json:"pid"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	pid := in.PID
	switch {
	case in.OpenPak != "":
		var ok bool
		if pid, _, ok = verifyNexToken(s.acct.nexSigningKey(), in.OpenPak); !ok {
			apiErr(w, http.StatusUnauthorized, "openpak not proven")
			return
		}
	case in.IDToken != "":
		var ok bool
		if pid, ok = s.pidForIDToken(in.IDToken); !ok {
			apiErr(w, http.StatusUnauthorized, "id_token not proven")
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
		"pid": id.PID, "baas_user_id": id.BaasUserID, "nickname": id.Nickname, "friends": friends,
		// Where the player lives, so a game server can place their room on the region node for it.
		"country": id.Country})
}

// pidForIDToken proves a BAAS id_token this server issued and answers with the account behind
// it. A retail console sends a plain id_token with no binding claim -- only an emulator build
// adds one -- so treating a missing claim as an error refuses every real console. The signature
// is the proof, and it is one we can check because we minted the token.
//
// Every token this server signs uses the same key, so the signature alone does not say what kind
// of token this is: "typ" and "iss" are what keep an access token, a Nintendo-Account token or a
// refresh token from being spent here as a login.
func (s *server) pidForIDToken(tok string) (uint64, bool) {
	c, err := parseJWT(tok, &s.key.PublicKey)
	if err != nil {
		return 0, false
	}
	if str(c, "typ") != "id_token" || str(c, "iss") != baasIssuer {
		return 0, false
	}
	exp, _ := c["exp"].(float64)
	if int64(exp) <= time.Now().Unix() {
		return 0, false
	}
	// ponytail: the subject is the BAAS user id, which is the store's own key, so the lookup is
	// the mapping. A session table is the upgrade if a token ever has to be revocable before it
	// expires.
	u := s.store.User(str(c, "sub"))
	if u == nil || u.PID == 0 {
		return 0, false
	}
	return u.PID, true
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
