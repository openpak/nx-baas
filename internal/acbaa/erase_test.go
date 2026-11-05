package acbaa

import "testing"

func TestEraseRemovesOnlyThatUser(t *testing.T) {
	s := testServer(t)
	const gone, keep, land = 11, 22, 99
	s.acbaaProfiles = map[uint64]acbaaProfile{gone: {SHA: "a"}, keep: {SHA: "b"}}
	s.acbaaResources = map[uint64]map[string][]byte{gone: {"x": {1}}, keep: {"x": {2}}}
	s.acbaaNames = map[uint64]acbaaNames{gone: {User: "g"}, keep: {User: "k"}}
	s.acbaaUserLand = map[uint64]uint64{gone: land, keep: 100}
	s.acbaaLandProfiles = map[uint64]acbaaProfile{land: {SHA: "l"}, 100: {SHA: "m"}}
	s.acbaaUIDMap = map[uint64]uint64{5: gone, 6: keep}
	s.acbaaFriendReqs = map[uint64]acbaaFriendReq{1: {From: gone, To: keep}, 2: {From: keep, To: 33}}
	s.acbaaFriendList = map[uint64][]uint64{gone: {keep}, keep: {gone, 33}}
	n, err := s.Erase([]uint64{gone, 0})
	if err != nil || n == 0 {
		t.Fatalf("erase = %d, %v", n, err)
	}
	if _, ok := s.acbaaProfiles[gone]; ok || s.acbaaResources[gone] != nil || len(s.acbaaNames) != 1 ||
		len(s.acbaaUserLand) != 1 || len(s.acbaaLandProfiles) != 1 || len(s.acbaaUIDMap) != 1 ||
		len(s.acbaaFriendReqs) != 1 || s.acbaaFriendList[gone] != nil {
		t.Fatalf("rows of the erased user remain: %+v", s)
	}
	if got := s.acbaaFriendList[keep]; len(got) != 1 || got[0] != 33 {
		t.Fatalf("friend list of another user = %v", got)
	}
	if s.acbaaProfiles[keep].SHA != "b" || s.acbaaLandProfiles[100].SHA != "m" || s.acbaaUIDMap[6] != keep {
		t.Fatal("another user's rows were touched")
	}
	if n, err := s.Erase([]uint64{gone}); err != nil || n != 0 {
		t.Fatalf("second erase = %d, %v", n, err)
	}
}
