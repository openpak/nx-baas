// SPDX-License-Identifier: AGPL-3.0-only
package presence

// Presence that changed on another platform, as the core tells it.
//
// The core emits presence_changed to each friend who is online on a network, naming whose
// presence moved. A console only re-reads its list when told something happened, so this is what
// turns "somebody signed in on Pier" into the same presence_updated a Switch friend produces.
// Only the friend's own console hears it: a network where none of the person's friends are
// online is never sent anything.

import (
	"context"
	"fmt"
	"nx-baas/internal/identity"
	"nx-baas/internal/penne"
	"nx-baas/internal/store"
	"strings"
	"time"
)

// notifyCorePresence sends one viewer (a Switch user, by core account) the presence of subject
// (the core account whose presence moved).
func (s *Service) NotifyCorePresence(b *identity.OpenpakBackend, viewerAccount, subjectAccount string) {
	b.Proj.Mu.Lock()
	vpr, spr := b.Proj.ByAccount[viewerAccount], b.Proj.ByAccount[subjectAccount]
	b.Proj.Mu.Unlock()
	if vpr == nil {
		return // not a Switch user here
	}
	if spr == nil { // never on a console: the friend list mints its identity, so do it now
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var err error
		if spr, err = b.Ensure(ctx, subjectAccount); err != nil {
			identity.LogErr("presence push ensure", err)
			return
		}
	}
	viewer := s.Store.User(vpr.BaasUserID)
	if viewer == nil || ContainsID(viewer.Blocks, spr.BaasUserID) {
		return
	}
	now := time.Now().Unix()
	// A friend with a live Switch presence is pushed by notifyPresenceIfChanged.
	if u := s.Store.User(spr.BaasUserID); u != nil && Aggregate(u, now, Lease()).State != "OFFLINE" {
		return
	}
	s.CoreSeen().Forget(subjectAccount) // the event is the news; the 10 s cache would answer with the old state
	if p, ok := s.CorePresenceOf(subjectAccount); ok && strings.EqualFold(p.Namespace, b.Namespace) {
		return
	}
	agg, live := s.FromCore(subjectAccount, b.Namespace, now)
	if !live {
		agg = store.Presence{State: "OFFLINE", UpdatedAt: now, LogoutAt: now, ACDIndex: -1}
	}
	snap := agg.State + "|" + agg.AppID + "|" + agg.AppField
	createdAt := NextStamp(spr.BaasUserID, viewer.ID, agg.UpdatedAt)
	s.Notify(penne.Delivery{
		ID:     fmt.Sprintf("presence:%s:%s:%d:%s", spr.BaasUserID, viewer.ID, createdAt, snap),
		UserID: viewer.ID,
		Kind:   penne.EventPresenceUpdated,
		Payload: map[string]any{
			"friendId":  spr.BaasUserID,
			"createdAt": createdAt,
			"value":     EventValue(spr.BaasUserID, agg),
		},
	})
}
