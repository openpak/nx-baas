// SPDX-License-Identifier: AGPL-3.0-only
package main

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
	"strings"
	"time"
)

// notifyCorePresence sends one viewer (a Switch user, by core account) the presence of subject
// (the core account whose presence moved).
func (s *server) notifyCorePresence(b *openpakBackend, viewerAccount, subjectAccount string) {
	b.proj.mu.Lock()
	vpr, spr := b.proj.ByAccount[viewerAccount], b.proj.ByAccount[subjectAccount]
	b.proj.mu.Unlock()
	if vpr == nil {
		return // not a Switch user here
	}
	if spr == nil { // never on a console: the friend list mints its identity, so do it now
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var err error
		if spr, err = b.ensure(ctx, subjectAccount); err != nil {
			logErr("presence push ensure", err)
			return
		}
	}
	viewer := s.store.User(vpr.BaasUserID)
	if viewer == nil || containsID(viewer.Blocks, spr.BaasUserID) {
		return
	}
	now := time.Now().Unix()
	// A friend with a live Switch presence is pushed by notifyPresenceIfChanged.
	if u := s.store.User(spr.BaasUserID); u != nil && aggregatePresence(u, now, presenceLease()).State != "OFFLINE" {
		return
	}
	s.coreSeen().forget(subjectAccount) // the event is the news; the 10 s cache would answer with the old state
	if p, ok := s.corePresenceOf(subjectAccount); ok && strings.EqualFold(p.Namespace, b.namespace) {
		return
	}
	agg, live := s.presenceFromCore(subjectAccount, b.namespace, now)
	if !live {
		agg = Presence{State: "OFFLINE", UpdatedAt: now, LogoutAt: now, ACDIndex: -1}
	}
	snap := agg.State + "|" + agg.AppID + "|" + agg.AppField
	createdAt := nextPresenceStamp(spr.BaasUserID, viewer.ID, agg.UpdatedAt)
	s.SubmitNotification(PenneDelivery{
		ID:     fmt.Sprintf("presence:%s:%s:%d:%s", spr.BaasUserID, viewer.ID, createdAt, snap),
		UserID: viewer.ID,
		Kind:   EventPresenceUpdated,
		Payload: map[string]any{
			"friendId":  spr.BaasUserID,
			"createdAt": createdAt,
			"value":     presenceEventValue(spr.BaasUserID, agg),
		},
	})
}
