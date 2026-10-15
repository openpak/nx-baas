package main

// The friend page's record, built here. Harbor emulates the friends module and used to build the
// 0x800-byte FriendDetailedInfo itself; every field it got wrong (the friendship time, the play
// log) needed a Harbor build to fix. Now Harbor asks for the bytes (GET /2.0.0/users/<me>/
// friend_details) and hands them to the page: the layout lives in one place, and a correction is a
// deploy of this service. Layout: docs/switch/friends-contract-22.5.0.md §B.3, the friendship time
// measured on 2026-10-15.

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

// detailPlay is one entry of the record's play-log block (20 x 0x28). ASSUMED layout, fixed by what
// the page shows: title id, group id, play count, play time, first played, last played.
type detailPlay struct {
	App, Group  uint64
	Count, Time uint32
	First, Last int64
}

const (
	detailSize      = 0x800
	detailNetworkID = 0x10
	detailNickname  = 0x18 // char[0x21]
	detailThumbnail = 0x40 // char[0xA0]
	detailPlayLog   = 0xE0 // 20 x 0x28
	detailPlayValid = 0x400
	detailChannel   = 0x4B8
	detailValid     = 0x520
	detailSince     = 0x5D0 // "When You Became Friends", an i64 of seconds
	playEntrySize   = 0x28
	maxPlayEntries  = 20
)

// putText writes s into a fixed field of size bytes, NUL-terminated, never cutting a character.
func putText(field []byte, s string) {
	limit := len(field) - 1
	if len(s) > limit {
		s = s[:limit]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	copy(field, s)
}

// detailedInfoRecord is the 0x800-byte record for one friend. The caller's own Uid (bytes 0..0x10)
// is the console's and is left zero: the emulator fills it in.
func detailedInfoRecord(networkID uint64, nickname, thumbnail string, channel uint32, plays []detailPlay, since int64) []byte {
	b := make([]byte, detailSize)
	le := binary.LittleEndian
	le.PutUint64(b[detailNetworkID:], networkID)
	putText(b[detailNickname:detailNickname+0x21], nickname)
	putText(b[detailThumbnail:detailThumbnail+0xA0], thumbnail)
	if len(plays) > maxPlayEntries {
		plays = plays[:maxPlayEntries]
	}
	for i, p := range plays {
		e := b[detailPlayLog+i*playEntrySize:]
		le.PutUint64(e[0x00:], p.App)
		le.PutUint64(e[0x08:], p.Group)
		le.PutUint32(e[0x10:], p.Count)
		le.PutUint32(e[0x14:], p.Time)
		le.PutUint64(e[0x18:], uint64(p.First))
		le.PutUint64(e[0x20:], uint64(p.Last))
	}
	if len(plays) > 0 {
		b[detailPlayValid] = 1
	}
	le.PutUint32(b[detailChannel:], channel)
	b[detailValid] = 1
	if since > 0 {
		le.PutUint64(b[detailSince:], uint64(since))
	}
	return b
}

// friendDetails answers GET /2.0.0/users/<me>/friend_details: the page record of every friend of the
// caller, keyed by friend id, as the list shows them (same name, picture, privacy rules).
func (s *server) friendDetails(w http.ResponseWriter, r *http.Request, me *User, myID *Identity, now int64) {
	items := map[string]string{}
	if myID != nil {
		// The play history of every friend, fetched together: the core is a round trip each.
		if b, ok := s.acct.(*openpakBackend); ok {
			var wg sync.WaitGroup
			for _, f := range myID.Friends {
				if sub := s.store.User(f.BaasUserID); sub != nil && sub.PID != 0 {
					wg.Add(1)
					go func(accountID string) {
						defer wg.Done()
						b.playHistory(accountID, true)
					}(b.accountFor(sub.PID))
				}
			}
			wg.Wait()
		}
		for i, f := range myID.Friends {
			if i >= maxListEntries {
				break
			}
			id, err := strconv.ParseUint(f.BaasUserID, 16, 64)
			if err != nil {
				continue
			}
			user := s.friendObj(f, now)
			nickname, _ := user["nickname"].(string)
			thumbnail, _ := user["thumbnailUrl"].(string)
			var plays []detailPlay
			if _, pl := s.visiblePlayLog(me, s.store.User(f.BaasUserID), true); pl != "" {
				plays = parsePlayLog(pl)
			}
			items[f.BaasUserID] = base64.StdEncoding.EncodeToString(
				detailedInfoRecord(id, nickname, thumbnail, 0, plays, f.CreatedAt))
		}
	}
	writeJSON(w, 200, map[string]any{"items": items, "generatedAt": time.Now().Unix()})
}
