// Package erase deletes everything nx-baas keeps for one erased OpenPak account
// (card openpak/prds#120). Both entry points use it: the account_deleted core event and
// DELETE /internal/accounts/{id}/data. It is idempotent.
package erase

import (
	"context"
	"strconv"

	"nx-baas/internal/acbaa"
	"nx-baas/internal/identity"
	"nx-baas/internal/invitations"
	"nx-baas/internal/store"

	accountv1 "github.com/openpak/account-api/openpak/account/v1"
)

// Targets are the durable stores to erase from. Nil members are skipped.
type Targets struct {
	Store       *store.Store
	Invitations *invitations.Store
	Acbaa       *acbaa.Service
}

// Account erases the account. Its Switch ids come from nx-baas's own projection (the
// core drops its links in the same transaction that emits account_deleted, so the event
// path must not ask it). With coreFallback, an account whose projection is already gone
// is looked up in the core's link table once more (the HTTP path runs before the core
// deletes links). The projection goes last, so a failed write leaves the ids to retry with.
func Account(ctx context.Context, b *identity.OpenpakBackend, t Targets, accountID string, coreFallback bool) (int, error) {
	pr, hadProj := b.LookupProjection(accountID)
	if !hadProj && coreFallback && b.Links != nil {
		if got, err := b.Links.GetActiveLinkByAccount(ctx, &accountv1.GetActiveLinkByAccountRequest{
			Namespace: b.Namespace, AccountId: accountID}); err == nil && got.GetSubjectId() != "" {
			pr.BaasUserID = got.GetSubjectId()
			if t.Store != nil {
				if u := t.Store.User(pr.BaasUserID); u != nil {
					pr.PID, pr.NaID = u.PID, u.NaID
				}
			}
		}
	}
	return Ids(b, t, accountID, pr)
}

// Ids erases by an already resolved projection (the event handler captures it before
// anything else touches it).
func Ids(b *identity.OpenpakBackend, t Targets, accountID string, pr identity.Projection) (int, error) {
	rows := 0
	if t.Store != nil {
		// A user the store holds under the BAAS id may carry the PID/NA id the projection lacks.
		if pr.BaasUserID != "" && (pr.PID == 0 || pr.NaID == "") {
			if u := t.Store.User(pr.BaasUserID); u != nil {
				if pr.PID == 0 {
					pr.PID = u.PID
				}
				if pr.NaID == "" {
					pr.NaID = u.NaID
				}
			}
		}
		n, err := t.Store.EraseAccount(pr.BaasUserID, pr.PID, pr.NaID)
		rows += n
		if err != nil {
			return rows, err
		}
	}
	if t.Invitations != nil {
		n, err := t.Invitations.EraseUser(pr.BaasUserID, pr.PID)
		rows += n
		if err != nil {
			return rows, err
		}
	}
	if t.Acbaa != nil {
		var uids []uint64
		for _, h := range []string{pr.BaasUserID, pr.NaID} {
			if v, err := strconv.ParseUint(h, 16, 64); err == nil {
				uids = append(uids, v)
			}
		}
		uids = append(uids, pr.PID)
		n, err := t.Acbaa.Erase(uids)
		rows += n
		if err != nil {
			return rows, err
		}
	}
	dropped, err := b.DropProjectionErr(accountID)
	if dropped {
		rows++
	}
	return rows, err
}
