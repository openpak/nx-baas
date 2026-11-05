// Package orphans finds and removes BAAS users that belong to no core account: device
// accounts a console created and never linked, and test users (card openpak/prds#131
// phase 3). Nothing here prints a name, id or any personal value; counts only.
//
// The run is two steps so a deletion can never precede its backup: Backup writes the
// full rows to a mode-600 file, Delete refuses unless that file exists and still
// matches the set it is about to remove. Both are idempotent.
package orphans

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"nx-baas/internal/store"
)

// Linked answers whether a BAAS user belongs to a core account. unresolved means the
// user carries a PID or Nintendo-Account id the core could not place: kept, reported.
type Linked func(u *store.User) (linked, unresolved bool)

// Report is the counts of one classification. Orphans lists nothing personal: ids stay
// inside the process.
type Report struct {
	Users             int    `json:"users"`
	Devices           int    `json:"devices"`
	NaToPID           int    `json:"naToPid"`
	Requests          int    `json:"requests"`
	Linked            int    `json:"linked"`
	Unresolved        int    `json:"unresolved"`
	Candidates        int    `json:"candidates"`        // unlinked users before exclusions
	KeptNaToPID       int    `json:"keptNaToPid"`       // referenced by naToPid
	KeptRequests      int    `json:"keptRequests"`      // referenced by a linked user's request
	KeptInvitations   int    `json:"keptInvitations"`   // named in invitations.json
	KeptAcbaa         int    `json:"keptAcbaa"`         // named in acbaa.json
	Orphans           int    `json:"orphans"`           // users to back up and delete
	OrphanDevices     int    `json:"orphanDevices"`     // devices owned only by orphans
	DanglingDevices   int    `json:"danglingDevices"`   // devices whose user does not exist (kept)
	LinkedDevices     int    `json:"linkedDevices"`     // devices owned by linked users (kept)
	KeptOrphanDevices int    `json:"keptOrphanDevices"` // devices of kept candidates (kept)
	Digest            string `json:"digest,omitempty"`  // of the orphan id set, ties backup to delete

	userIDs   []string
	deviceIDs []string
}

// Classify computes the orphan set. docs are the raw invitations and acbaa documents
// (nil when absent); a reference is any string or number in them equal to a user's id,
// PID, Nintendo-Account id or (for a number) its hex rendering, which is how the
// acbaa user ids are keyed.
func Classify(st *store.Store, linked Linked, docs ...[]byte) *Report {
	st.Mu.Lock()
	defer st.Mu.Unlock()
	r := &Report{Users: len(st.Users), Devices: len(st.Devices), NaToPID: len(st.NaToPID), Requests: len(st.Requests)}

	invTokens, acbaaTokens := map[string]bool{}, map[string]bool{}
	if len(docs) > 0 {
		collect(docs[0], invTokens)
	}
	if len(docs) > 1 {
		collect(docs[1], acbaaTokens)
	}

	linkedPIDs := map[uint64]bool{}
	linkedDev := map[string]bool{}
	linkedUser := map[string]bool{}
	var cand []*store.User
	for _, u := range st.Users {
		lk, un := linked(u)
		switch {
		case lk:
			r.Linked++
			linkedUser[u.ID] = true
			if u.PID != 0 {
				linkedPIDs[u.PID] = true
			}
			for _, d := range u.DeviceAccounts {
				linkedDev[d] = true
			}
		case un:
			r.Unresolved++
			linkedUser[u.ID] = true
			for _, d := range u.DeviceAccounts {
				linkedDev[d] = true
			}
		default:
			cand = append(cand, u)
		}
	}
	naPID := map[uint64]bool{}
	naKey := map[string]bool{}
	for na, p := range st.NaToPID {
		naKey[na] = true
		naPID[p] = true
	}
	reqPID := map[uint64]bool{}
	for _, q := range st.Requests {
		if linkedPIDs[q.FromPID] || linkedPIDs[q.ToPID] {
			reqPID[q.FromPID], reqPID[q.ToPID] = true, true
		}
	}

	r.Candidates = len(cand)
	keptDev := map[string]bool{}
	orphan := map[string]*store.User{}
	for _, u := range cand {
		keep := false
		if (u.NaID != "" && naKey[u.NaID]) || (u.PID != 0 && naPID[u.PID]) {
			r.KeptNaToPID++
			keep = true
		}
		if u.PID != 0 && reqPID[u.PID] {
			r.KeptRequests++
			keep = true
		}
		if refers(invTokens, u) {
			r.KeptInvitations++
			keep = true
		}
		if refers(acbaaTokens, u) {
			r.KeptAcbaa++
			keep = true
		}
		if keep {
			for _, d := range u.DeviceAccounts {
				keptDev[d] = true
			}
			continue
		}
		orphan[u.ID] = u
	}
	for id := range orphan {
		r.userIDs = append(r.userIDs, id)
	}
	sort.Strings(r.userIDs)
	inOrphan := map[string]bool{}
	for _, u := range orphan {
		for _, x := range u.DeviceAccounts {
			inOrphan[x] = true
		}
	}
	for id, d := range st.Devices {
		switch {
		case linkedDev[id] || linkedUser[d.UserID]:
			r.LinkedDevices++
		case keptDev[id]:
			r.KeptOrphanDevices++
		case orphan[d.UserID] != nil || inOrphan[id]:
			r.deviceIDs = append(r.deviceIDs, id)
		case st.Users[d.UserID] == nil:
			r.DanglingDevices++
		default:
			r.KeptOrphanDevices++
		}
	}
	sort.Strings(r.deviceIDs)
	r.Orphans, r.OrphanDevices = len(r.userIDs), len(r.deviceIDs)
	h := sha256.New()
	for _, id := range r.userIDs {
		h.Write([]byte(id + "\n"))
	}
	for _, id := range r.deviceIDs {
		h.Write([]byte("d:" + id + "\n"))
	}
	r.Digest = hex.EncodeToString(h.Sum(nil))[:16]
	return r
}

func refers(tokens map[string]bool, u *store.User) bool {
	for _, k := range []string{u.ID, u.NaID, u.BsDid} {
		if k != "" && tokens[k] {
			return true
		}
	}
	if u.PID != 0 && tokens[strconv.FormatUint(u.PID, 10)] {
		return true
	}
	return false
}

// collect gathers every string, and every number in decimal and as 16-digit hex, from a
// JSON document, map keys included.
func collect(doc []byte, into map[string]bool) {
	if len(doc) == 0 {
		return
	}
	d := json.NewDecoder(bytes.NewReader(doc))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return
	}
	walk(v, into)
}

func walk(v any, into map[string]bool) {
	switch x := v.(type) {
	case string:
		into[x] = true
	case json.Number:
		into[x.String()] = true
		if n, err := strconv.ParseUint(x.String(), 10, 64); err == nil {
			into[fmt.Sprintf("%016x", n)] = true
			into[fmt.Sprintf("%x", n)] = true
		}
	case map[string]any:
		for k, e := range x {
			into[k] = true
			if n, err := strconv.ParseUint(k, 10, 64); err == nil {
				into[fmt.Sprintf("%016x", n)] = true
			}
			walk(e, into)
		}
	case []any:
		for _, e := range x {
			walk(e, into)
		}
	}
}

// BackupFile is what Backup writes: the full rows being removed.
type BackupFile struct {
	CreatedAt int64                           `json:"createdAt"`
	Digest    string                          `json:"digest"`
	Users     map[string]*store.User          `json:"users"`
	Devices   map[string]*store.DeviceAccount `json:"devices"`
}

// Backup writes the orphan rows to path (mode 600, parent 700) and returns the number
// of users in the file. An existing file with the same digest is kept (idempotent); one
// with another digest is an error, never overwritten.
func Backup(st *store.Store, r *Report, path string) (int, error) {
	if r.Orphans == 0 {
		return 0, errors.New("nothing to back up")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	if b, err := os.ReadFile(path); err == nil {
		var f BackupFile
		if json.Unmarshal(b, &f) == nil && f.Digest == r.Digest {
			return len(f.Users), os.Chmod(path, 0o600)
		}
		return 0, errors.New("a backup with another digest already exists at the path")
	}
	st.Mu.Lock()
	f := BackupFile{CreatedAt: time.Now().Unix(), Digest: r.Digest, Users: map[string]*store.User{}, Devices: map[string]*store.DeviceAccount{}}
	for _, id := range r.userIDs {
		if u := st.Users[id]; u != nil {
			f.Users[id] = u
		}
	}
	for _, id := range r.deviceIDs {
		if d := st.Devices[id]; d != nil {
			f.Devices[id] = d
		}
	}
	b, err := json.MarshalIndent(f, "", " ")
	st.Mu.Unlock()
	if err != nil {
		return 0, err
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	if _, err := out.Write(b); err != nil {
		out.Close()
		return 0, err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return 0, err
	}
	if err := out.Close(); err != nil {
		return 0, err
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 || fi.Mode().Perm() != 0o600 {
		return 0, errors.New("backup file failed verification")
	}
	return len(f.Users), nil
}

// Delete removes the classified orphans, but only when the backup at path exists with
// this report's digest and holds every user about to go. It returns the users and
// devices removed. Idempotent: a second run classifies zero orphans.
func Delete(st *store.Store, r *Report, path string) (users, devices int, err error) {
	if r.Orphans == 0 {
		return 0, 0, nil
	}
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		return 0, 0, errors.New("no backup: refusing to delete")
	}
	var f BackupFile
	if json.Unmarshal(b, &f) != nil || f.Digest != r.Digest || len(f.Users) != r.Orphans || len(f.Devices) != r.OrphanDevices {
		return 0, 0, errors.New("backup does not match the set to delete: refusing")
	}
	return st.DeleteUsers(r.userIDs, r.deviceIDs)
}
