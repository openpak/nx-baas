package acbaa

import (
	"log"
	"net/http"
	"nx-baas/internal/httpx"
	"nx-baas/internal/msgpack"
	"strconv"
	"strings"
	"time"
)

// Recovered from matching ACNH main FF1D1C05670DB6021C85B624A710B963:
// request 006a9800, response 006a9ca0, user parser 006a9e50 (Ghidra VA).
// This exchanges existing island/resident credentials; it does not move saves.
func (s *Service) acbaaEmigration(w http.ResponseWriter, r *http.Request, body []byte) {
	caller, valid := acbaaVerifyToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if !valid && s.Key != nil {
		claims := s.Bearer(r)
		exp, _ := claims["exp"].(float64)
		if claims != nil && int64(exp) > time.Now().Unix() {
			caller, _ = strconv.ParseUint(httpx.Str(claims, "sub"), 16, 64)
			valid = caller != 0
		}
	}
	if !valid || caller == 0 {
		acbaaError(w, 401, "4001")
		return
	}
	v, err := msgpack.Decode(body)
	doc, ok := v.(map[string]any)
	if err != nil || !ok {
		acbaaError(w, 400, "3001")
		return
	}
	land, landOK := acbaaUnsigned(doc["land_id"])
	myUser, userOK := acbaaUnsigned(doc["my_user_id"])
	ids, arrayOK := doc["user_ids"].([]any)
	if !landOK || !userOK || !arrayOK || len(ids) == 0 || len(ids) > 8 {
		acbaaError(w, 400, "3001")
		return
	}
	caller = s.acbaaResolveUID(caller)
	if s.acbaaResolveUID(myUser) != caller {
		log.Printf("[acbaa] departure refused: player identity does not match authenticated account")
		acbaaError(w, 403, "4001")
		return
	}
	users := make([]any, 0, len(ids))
	seen := map[uint64]bool{}
	for _, value := range ids {
		id, ok := acbaaUnsigned(value)
		if !ok || seen[id] {
			acbaaError(w, 400, "3001")
			return
		}
		seen[id] = true
		// Credentials belong to the caller, never another resident's account.
		// The recovered parser explicitly accepts a nil password and removes
		// that entry from the resident output; preserve the requested ID.
		var password any
		if s.acbaaResolveUID(id) == caller {
			password = acbaaUserPassword(id)
		}
		users = append(users, map[string]any{"id": id, "password": password})
	}
	if !seen[myUser] {
		acbaaError(w, 400, "3001")
		return
	}
	// Match land registration: its credential is derived from the supplied
	// island ID, not from an optional resident-to-island cache. Warm clients
	// and restored saves can have profiles without that cache row. Requiring
	// it here rejected an authenticated, correctly migrated player (2026-10-13).
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(msgpack.Encode(map[string]any{"land": map[string]any{"id": land, "password": acbaaLandPassword(land)}, "users": users}))
	log.Printf("[acbaa] departure credential exchange accepted; requested residents=%d", len(ids))
}

func acbaaUnsigned(value any) (uint64, bool) {
	switch number := value.(type) {
	case uint64:
		return number, number != 0
	case int64:
		return uint64(number), number > 0
	default:
		return 0, false
	}
}
