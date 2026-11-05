package acbaa

// Erase removes everything Animal Crossing's web API keeps for an erased account, whose
// ACNH user id is the BAAS user id read as hex, the PID, or the earlier ids the
// uid-migration moved (all passed in uids): profile, web resources, names, the island
// profile it owns, uid moves from or to it, its best-friend list and requests, and its
// entry in other players' best-friend lists. Durable before returning.
func (s *Service) Erase(uids []uint64) (int, error) {
	gone := map[uint64]bool{}
	for _, u := range uids {
		if u != 0 {
			gone[u] = true
		}
	}
	if len(gone) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := 0
	for u := range gone {
		if land, ok := s.acbaaUserLand[u]; ok {
			if _, ok := s.acbaaLandProfiles[land]; ok {
				delete(s.acbaaLandProfiles, land)
				rows++
			}
			delete(s.acbaaUserLand, u)
			rows++
		}
		if _, ok := s.acbaaProfiles[u]; ok {
			delete(s.acbaaProfiles, u)
			rows++
		}
		if _, ok := s.acbaaResources[u]; ok {
			delete(s.acbaaResources, u)
			rows++
		}
		if _, ok := s.acbaaNames[u]; ok {
			delete(s.acbaaNames, u)
			rows++
		}
		if _, ok := s.acbaaFriendList[u]; ok {
			delete(s.acbaaFriendList, u)
			rows++
		}
	}
	for k, v := range s.acbaaUIDMap {
		if gone[k] || gone[v] {
			delete(s.acbaaUIDMap, k)
			rows++
		}
	}
	for id, req := range s.acbaaFriendReqs {
		if gone[req.From] || gone[req.To] {
			delete(s.acbaaFriendReqs, id)
			rows++
		}
	}
	for owner, list := range s.acbaaFriendList {
		kept := list[:0]
		for _, f := range list {
			if gone[f] {
				rows++
				continue
			}
			kept = append(kept, f)
		}
		s.acbaaFriendList[owner] = kept
	}
	return rows, s.acbaaSaveErrLocked()
}
