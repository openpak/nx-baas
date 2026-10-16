// SPDX-License-Identifier: AGPL-3.0-only
package main

// Pushing presence that changed on another platform.
//
// presenceFromCore lets a console READ a friend who is on Pier, Xbox or a
// Wii U, but the core announces no presence change, and a console only
// re-reads its list when told something happened. So a friend signing in on
// another platform never produced the "<friend> is online" a Switch friend
// does. This loop closes that: it looks at the core's presence for the
// non-Switch friends of every Switch user, and submits a presence_updated for
// each change, the same notification notifyPresenceIfChanged sends for a Switch
// friend.
//
// ponytail: polling at corePushEvery, one GetPresence per friend through the
// 10 s cache; a presence-change event in the core's stream (and a batched
// lookup) replaces this if the friend count ever makes it matter.

import (
	"context"
	"fmt"
	"strings"
	"time"

	accountv1 "nx-baas/accountpb"
)

const corePushEvery = 5 * time.Second

func (s *server) followCorePresence(b *openpakBackend) {
	last := map[string]string{} // friend account -> state|app|appField last pushed
	for ; ; time.Sleep(corePushEvery) {
		s.pushCorePresence(b, last)
	}
}

func (s *server) pushCorePresence(b *openpakBackend, last map[string]string) {
	b.proj.mu.Lock()
	var viewers []*User
	for _, pr := range b.proj.ByAccount {
		if u := s.store.User(pr.BaasUserID); u != nil {
			viewers = append(viewers, u)
		}
	}
	b.proj.mu.Unlock()

	// friend account -> the Switch users who have them as a friend
	watchers := map[string][]*User{}
	for _, v := range viewers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		acc := b.accountFor(v.PID)
		res, err := b.social.ListFriends(ctx, &accountv1.ListFriendsRequest{AccountId: acc})
		cancel()
		if err != nil {
			logErr("core presence push list-friends", err)
			continue
		}
		for _, f := range res.GetFriends() {
			watchers[f.GetAccountId()] = append(watchers[f.GetAccountId()], v)
		}
	}

	now := time.Now().Unix()
	for friendID, vs := range watchers {
		b.proj.mu.Lock()
		pr := b.proj.ByAccount[friendID]
		b.proj.mu.Unlock()
		if pr == nil {
			continue // no Switch identity yet: the friend list mints one, this waits
		}
		// A friend with a live Switch presence is pushed by notifyPresenceIfChanged.
		if u := s.store.User(pr.BaasUserID); u != nil && aggregatePresence(u, now, presenceLease()).State != "OFFLINE" {
			delete(last, friendID)
			continue
		}
		if p, ok := s.corePresenceOf(friendID); ok && strings.EqualFold(p.Namespace, b.namespace) {
			continue
		}
		agg, live := s.presenceFromCore(friendID, b.namespace, now)
		if !live {
			agg = Presence{State: "OFFLINE", UpdatedAt: now, LogoutAt: now, ACDIndex: -1}
		}
		snap := agg.State + "|" + agg.AppID + "|" + agg.AppField
		prev, seen := last[friendID]
		last[friendID] = snap
		if !seen {
			if !live {
				continue // first sight of an offline friend is not news
			}
		} else if prev == snap {
			continue
		}
		for _, v := range vs {
			if containsID(v.Blocks, pr.BaasUserID) {
				continue
			}
			createdAt := nextPresenceStamp(pr.BaasUserID, v.ID, agg.UpdatedAt)
			s.SubmitNotification(PenneDelivery{
				ID:     fmt.Sprintf("presence:%s:%s:%d:%s", pr.BaasUserID, v.ID, createdAt, snap),
				UserID: v.ID,
				Kind:   EventPresenceUpdated,
				Payload: map[string]any{
					"friendId":  pr.BaasUserID,
					"createdAt": createdAt,
					"value":     presenceEventValue(pr.BaasUserID, agg),
				},
			})
		}
	}
}
