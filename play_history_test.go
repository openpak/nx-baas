package main

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	accountv1 "nx-baas/accountpb"
)

type fakePlayHistory struct {
	accountv1.SessionsClient
	history map[string][]*accountv1.PlayHistoryEntry
	calls   int
}

func (f *fakePlayHistory) GetPlayHistory(_ context.Context, in *accountv1.GetPlayHistoryRequest, _ ...grpc.CallOption) (*accountv1.GetPlayHistoryResponse, error) {
	f.calls++
	return &accountv1.GetPlayHistoryResponse{Entries: f.history[in.GetAccountId()]}, nil
}

// A friend's play log is what the core says they played, in the form the console's parser reads.
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
	// Cached: asking again inside the minute is no second round trip, and a non-waiting ask never blocks.
	b.playHistory("acc-1", true)
	b.playHistory("acc-1", false)
	if fs.calls != 1 {
		t.Fatalf("the core was asked %d times", fs.calls)
	}
	if playLogJSON(nil) != "" {
		t.Fatal("no history is no log")
	}
}
