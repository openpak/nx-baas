package main

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

// 23.x eupld fails the whole upload (2178-1681) unless all four backpressure values come back,
// and keeps the batch queued; a statistic it cannot find must be a plain 404, which it skips.
func TestTabijiAcceptsPlayHistoriesAndHasNoStatistics(t *testing.T) {
	s := testServer(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.Key, s.IDKid, s.AccKid = key, "test-id-kid", "test-acc-kid"
	tok := s.idToken(s.Store.User("aaaa"), nil, "Leia", nil)
	const host = "api.hac.lp1.tabiji.srv.nintendo.net"

	w := hostReq(s, host, "POST", "/console/v1/play_histories", tok, `{"play_histories":[]}`)
	if w.Code != 200 {
		t.Fatalf("upload answered %d %s", w.Code, w.Body)
	}
	for _, k := range []string{`"standard"`, `"catchup"`, `"max_play_histories_count"`, `"min_interval_sec"`} {
		if strings.Count(w.Body.String(), k) < 1 {
			t.Fatalf("upload reply lacks %s: %s", k, w.Body)
		}
	}
	if w := hostReq(s, host, "GET", "/console/v1/play_statistics/0100c6f01c4f8000", tok, ""); w.Code != 404 {
		t.Fatalf("statistic answered %d, want 404 (no record)", w.Code)
	}
	if w := hostReq(s, host, "POST", "/console/v1/play_histories", "", `{}`); w.Code != 401 {
		t.Fatalf("upload without an id token answered %d, want 401", w.Code)
	}
	if w := hostReq(s, host, "POST", "/console/v1/play_histories", s.accessToken("aaaa", 2, "", "", ""), `{}`); w.Code != 401 {
		t.Fatalf("an access token was taken as an id token: %d", w.Code)
	}
}
