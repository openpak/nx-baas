package main

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"google.golang.org/grpc"

	accountv1 "nx-baas/accountpb"
)

// The record is what the friend page reads, byte for byte: offsets measured on the firmware's own
// page (the friendship time at 0x5D0), the rest from the contract notes.
func TestDetailedInfoRecordLayout(t *testing.T) {
	le := binary.LittleEndian
	plays := []detailPlay{{App: 0x0100a5a020d5e000, Group: 0x0100a5a020d5e000, Count: 12, Time: 3600, First: 1758000000, Last: 1758290000}}
	b := detailedInfoRecord(0xaabbccddeeff0011, "Harbor PC", "https://cdn.example/1/x.jpg?v=3", 2, plays, 1788000000)
	if len(b) != 0x800 {
		t.Fatalf("size %#x", len(b))
	}
	if le.Uint64(b[0x00:]) != 0 || le.Uint64(b[0x08:]) != 0 {
		t.Fatal("the console's own Uid belongs to the emulator, not to us")
	}
	if le.Uint64(b[0x10:]) != 0xaabbccddeeff0011 {
		t.Fatalf("network user id %x", le.Uint64(b[0x10:]))
	}
	if got := string(b[0x18 : 0x18+9]); got != "Harbor PC" || b[0x18+9] != 0 {
		t.Fatalf("nickname %q", got)
	}
	if !strings.HasPrefix(string(b[0x40:]), "https://cdn.example/1/x.jpg?v=3\x00") {
		t.Fatal("thumbnail url")
	}
	if le.Uint64(b[0xE0:]) != 0x0100a5a020d5e000 || le.Uint64(b[0xE8:]) != 0x0100a5a020d5e000 ||
		le.Uint32(b[0xF0:]) != 12 || le.Uint32(b[0xF4:]) != 3600 ||
		int64(le.Uint64(b[0xF8:])) != 1758000000 || int64(le.Uint64(b[0x100:])) != 1758290000 {
		t.Fatalf("play log entry 0: % x", b[0xE0:0x108])
	}
	if b[0x400] != 1 || le.Uint32(b[0x4B8:]) != 2 || b[0x520] != 1 || int64(le.Uint64(b[0x5D0:])) != 1788000000 {
		t.Fatalf("flags/channel/valid/since: %d %d %d %d", b[0x400], le.Uint32(b[0x4B8:]), b[0x520], le.Uint64(b[0x5D0:]))
	}
}

// Text is cut at the field, never in the middle of a character, and always terminated; no log means
// the "valid" flag stays clear (which is how the module says there is nothing to list).
func TestDetailedInfoRecordLimits(t *testing.T) {
	long := strings.Repeat("é", 40) // 80 bytes
	b := detailedInfoRecord(1, long, long, 0, nil, 0)
	name := b[0x18 : 0x18+0x21]
	end := strings.IndexByte(string(name), 0)
	if end < 0 || end > 0x20 || !strings.HasSuffix(string(name[:end]), "é") || end%2 != 0 {
		t.Fatalf("nickname cut badly: %d bytes % x", end, name)
	}
	if b[0x400] != 0 {
		t.Fatal("no play log must leave the valid flag clear")
	}
	if binary.LittleEndian.Uint64(b[0x5D0:]) != 0 {
		t.Fatal("an unknown friendship time stays 0")
	}
	many := make([]detailPlay, 30)
	for i := range many {
		many[i] = detailPlay{App: uint64(i + 1)}
	}
	b = detailedInfoRecord(1, "x", "y", 0, many, 5)
	if binary.LittleEndian.Uint64(b[0xE0+19*0x28:]) != 20 || binary.LittleEndian.Uint64(b[0x400-8:]) != 0 {
		t.Fatal("only twenty entries fit, and none spills past the block")
	}
}

type fakePlayHistory struct {
	accountv1.SessionsClient
	history map[string][]*accountv1.PlayHistoryEntry
	calls   int
}

func (f *fakePlayHistory) GetPlayHistory(_ context.Context, in *accountv1.GetPlayHistoryRequest, _ ...grpc.CallOption) (*accountv1.GetPlayHistoryResponse, error) {
	f.calls++
	return &accountv1.GetPlayHistoryResponse{Entries: f.history[in.GetAccountId()]}, nil
}

// A friend's play log is what the core says they played, in the form the console's parser reads, and
// the record carries the same entries.
func TestPlayLogFromTheCore(t *testing.T) {
	b, _ := newTestBackend(t)
	fs := &fakePlayHistory{history: map[string][]*accountv1.PlayHistoryEntry{
		"acc-1": {
			{TitleId: "0100A5A020D5E000", Sessions: 3, TotalSeconds: 5400, FirstPlayedUnix: 1000, LastPlayedUnix: 9000},
			{TitleId: "NPUB00000", Sessions: 1}, // not a Switch title id: skipped
		},
	}}
	b.sessions = fs
	pl := playLogJSON(b.playHistory("acc-1", true))
	want := `[{"appInfo:appId":"0100a5a020d5e000","appInfo:acdIndex":0,"appInfo:presenceGroupId":"0100a5a020d5e000","totalPlayCount":3,"totalPlayTime":5400,"firstPlayedAt":1000,"lastPlayedAt":9000}]`
	if pl != want {
		t.Fatalf("play log:\n got %s\nwant %s", pl, want)
	}
	plays := parsePlayLog(pl)
	if len(plays) != 1 || plays[0].App != 0x0100a5a020d5e000 || plays[0].Count != 3 || plays[0].Time != 5400 || plays[0].First != 1000 || plays[0].Last != 9000 {
		t.Fatalf("parsed: %+v", plays)
	}
	// Cached: asking again inside the minute is no second round trip, and a non-waiting ask never blocks.
	b.playHistory("acc-1", true)
	b.playHistory("acc-1", false)
	if fs.calls != 1 {
		t.Fatalf("the core was asked %d times", fs.calls)
	}
	if playLogJSON(nil) != "" || len(parsePlayLog("not json")) != 0 {
		t.Fatal("no history is no log")
	}
}
