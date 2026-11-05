package gameapi

// POST /internal/admin/orphans?step=plan|backup|delete -- the one-shot cleanup of BAAS
// users that belong to no core account (card openpak/prds#131 phase 3). Same
// authorization and listener as account erasure. Counts only in the reply and the log.
//
// The backup is staged inside the data volume (mode 600); the operator copies it to the
// box's ~/backups and verifies it before asking for step=delete, which refuses without a
// matching backup and removes the staged copy once the rows are gone.

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	accountv1 "github.com/openpak/account-api/openpak/account/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/orphans"
	"nx-baas/internal/pgdoc"
	"nx-baas/internal/store"
)

const orphanBackupName = "nxbaas-orphan-users-20261105.json"

func (s *Service) orphanAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.APIErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	key := os.Getenv("ACCOUNT_ERASE_KEY")
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if key == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare([]byte(got), []byte(key)) != 1 {
		httpx.APIErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	b, ok := s.Acct.(*identity.OpenpakBackend)
	if !ok {
		httpx.APIErr(w, http.StatusServiceUnavailable, "account core backend not in use")
		return
	}
	data := httpx.Getenv("NX_DATA", "/data")
	rep := orphans.Classify(s.Store, linkedFn(r.Context(), b),
		docOrNil(data+"/invitations.json"), docOrNil(data+"/acbaa.json"))
	path := filepath.Join(data, "backups", orphanBackupName)
	out := map[string]any{"report": rep}
	switch r.URL.Query().Get("step") {
	case "plan", "":
	case "backup":
		n, err := orphans.Backup(s.Store, rep, path)
		if err != nil {
			log.Printf("[nx-baas] orphan backup failed: %v", err)
			httpx.APIErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		fi, _ := os.Stat(path)
		out["backupUsers"], out["backupBytes"], out["backupMode"] = n, fi.Size(), fi.Mode().Perm().String()
		log.Printf("[nx-baas] orphan backup: users=%d devices=%d bytes=%d", n, rep.OrphanDevices, fi.Size())
	case "delete":
		u, d, err := orphans.Delete(s.Store, rep, path)
		if err != nil {
			log.Printf("[nx-baas] orphan delete refused: %v", err)
			httpx.APIErr(w, http.StatusConflict, err.Error())
			return
		}
		out["deletedUsers"], out["deletedDevices"] = u, d
		log.Printf("[nx-baas] orphan delete: users=%d devices=%d", u, d)
		_ = os.Remove(path) // the operator's copy under ~/backups is the one that stays
	default:
		httpx.APIErr(w, http.StatusBadRequest, "step must be plan, backup or delete")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func docOrNil(path string) []byte {
	b, ok := pgdoc.Read(path)
	if !ok {
		return nil
	}
	return b
}

// linkedFn places a BAAS user in the core: by the projection first, then by the core's
// own Switch link for the user's id. A PID or Nintendo-Account id the core cannot place
// is unresolved (kept, reported).
func linkedFn(ctx context.Context, b *identity.OpenpakBackend) orphans.Linked {
	return func(u *store.User) (bool, bool) {
		b.Proj.Mu.Lock()
		_, byBaas := b.Proj.ByBaas[u.ID]
		_, byPID := b.Proj.ByPID[u.PID]
		b.Proj.Mu.Unlock()
		if byBaas || (u.PID != 0 && byPID) {
			return true, false
		}
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if b.Links != nil {
			if got, err := b.Links.GetLinkBySubject(c, &accountv1.GetLinkBySubjectRequest{Namespace: b.Namespace, SubjectId: u.ID}); err == nil && got.GetAccountId() != "" {
				return true, false
			} else if err != nil && !isNotFound(err) {
				return false, true // the core did not answer: never delete on a guess
			}
		}
		return false, u.PID != 0
	}
}

func isNotFound(err error) bool { return status.Code(err) == codes.NotFound }
