package main

// What a friend's page lists as "Play Activity", computed here because a console never publishes it
// (friends-contract §A.1: "the server has to compute it"). The account core records every titled
// session of every client, so the log is built from its per-title history. A play log a console
// uploaded itself (PATCH extras/<group>/playLog) still wins.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	accountv1 "nx-baas/accountpb"
)

// playEntry is one title of a play log.
type playEntry struct {
	TitleID                 string
	Sessions                int32
	TotalSeconds            int64
	FirstPlayed, LastPlayed int64
}

type playHistoryCache struct {
	mu      sync.Mutex
	entries map[string]cachedPlayHistory
	loading map[string]bool
}

type cachedPlayHistory struct {
	at      time.Time
	entries []playEntry
}

const playHistoryTTL = 60 * time.Second

func (b *openpakBackend) playCache() *playHistoryCache {
	b.playOnce.Do(func() {
		b.plays = &playHistoryCache{entries: map[string]cachedPlayHistory{}, loading: map[string]bool{}}
	})
	return b.plays
}

// fetchPlayHistory asks the core. A core that is away, or that predates the RPC, is no history.
func (b *openpakBackend) fetchPlayHistory(accountID string) []playEntry {
	if b.sessions == nil || accountID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := b.sessions.GetPlayHistory(ctx, &accountv1.GetPlayHistoryRequest{
		AccountId: accountID, Namespace: b.namespace, Limit: 20})
	if err != nil {
		logErr("play history", err)
		return nil
	}
	out := make([]playEntry, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		out = append(out, playEntry{TitleID: e.GetTitleId(), Sessions: e.GetSessions(),
			TotalSeconds: e.GetTotalSeconds(), FirstPlayed: e.GetFirstPlayedUnix(), LastPlayed: e.GetLastPlayedUnix()})
	}
	return out
}

// playHistory is an account's history. wait=false never blocks: it answers what it has (nothing, the
// first time) and refreshes in the background, so a friend list of fifty is not fifty round trips.
func (b *openpakBackend) playHistory(accountID string, wait bool) []playEntry {
	c := b.playCache()
	c.mu.Lock()
	hit, ok := c.entries[accountID]
	fresh := ok && time.Since(hit.at) < playHistoryTTL
	if fresh {
		c.mu.Unlock()
		return hit.entries
	}
	if !wait {
		if !c.loading[accountID] {
			c.loading[accountID] = true
			go func() {
				e := b.fetchPlayHistory(accountID)
				c.mu.Lock()
				c.entries[accountID], c.loading[accountID] = cachedPlayHistory{at: time.Now(), entries: e}, false
				c.mu.Unlock()
			}()
		}
		c.mu.Unlock()
		return hit.entries // stale or nil
	}
	c.mu.Unlock()
	e := b.fetchPlayHistory(accountID)
	c.mu.Lock()
	c.entries[accountID] = cachedPlayHistory{at: time.Now(), entries: e}
	c.mu.Unlock()
	return e
}

// playLogJSON is a history as the friends module's parser reads it: a JSON array in a string, ids as
// 16 hex digits, counters and times as numbers [friends-contract-22.5.0 §A.1].
func playLogJSON(entries []playEntry) string {
	type item struct {
		AppID string `json:"appInfo:appId"`
		ACD   int    `json:"appInfo:acdIndex"`
		Group string `json:"appInfo:presenceGroupId"`
		Count int32  `json:"totalPlayCount"`
		Time  int64  `json:"totalPlayTime"`
		First int64  `json:"firstPlayedAt"`
		Last  int64  `json:"lastPlayedAt"`
	}
	items := make([]item, 0, len(entries))
	for _, e := range entries {
		id := strings.ToLower(e.TitleID)
		if len(id) != 16 { // a title the console could not draw
			continue
		}
		items = append(items, item{AppID: id, Group: id, Count: e.Sessions, Time: e.TotalSeconds,
			First: e.FirstPlayed, Last: e.LastPlayed})
	}
	if len(items) == 0 {
		return ""
	}
	b, _ := json.Marshal(items)
	return string(b)
}

// synthPlayLog is the play log the core can give for subject, "" when there is none. wait as in
// playHistory.
func (s *server) synthPlayLog(subject *User, wait bool) string {
	b, ok := s.acct.(*openpakBackend)
	if !ok || subject == nil || subject.PID == 0 {
		return ""
	}
	return playLogJSON(b.playHistory(b.accountFor(subject.PID), wait))
}

// parsePlayLog reads a play log string back into entries, for the console records that carry it as
// fields: at most 20, entries it cannot read skipped.
func parsePlayLog(pl string) []detailPlay {
	var raw []struct {
		AppID string `json:"appInfo:appId"`
		Group string `json:"appInfo:presenceGroupId"`
		Count int64  `json:"totalPlayCount"`
		Time  int64  `json:"totalPlayTime"`
		First int64  `json:"firstPlayedAt"`
		Last  int64  `json:"lastPlayedAt"`
	}
	if json.Unmarshal([]byte(pl), &raw) != nil {
		return nil
	}
	out := []detailPlay{}
	for _, r := range raw {
		var app, grp uint64
		if _, err := fmt.Sscanf(r.AppID, "%x", &app); err != nil || app == 0 {
			continue
		}
		fmt.Sscanf(r.Group, "%x", &grp)
		out = append(out, detailPlay{App: app, Group: grp, Count: clampU32(r.Count), Time: clampU32(r.Time),
			First: r.First, Last: r.Last})
		if len(out) == 20 {
			break
		}
	}
	return out
}

func clampU32(v int64) uint32 {
	switch {
	case v < 0:
		return 0
	case v > 0xFFFFFFFF:
		return 0xFFFFFFFF
	}
	return uint32(v)
}
