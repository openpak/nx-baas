package store

// EraseAccount removes everything this store keeps for one erased OpenPak account
// (card openpak/prds#120): its BAAS users, their device accounts, the Nintendo-Account
// map entries, the friend-request id mappings it took part in, and every other user's
// reference to it (blocks, block details, favourites, per-friend preferences).
// Other users' own rows stay; only the entries that name the erased user go, which
// anonymises nothing because a reference to a deleted id has no meaning left.
// The pctlDevices blob is console-keyed and carried verbatim; it names no account.
//
// Matching is by BAAS user id, PID or Nintendo-Account id, whichever is known (zero
// values are ignored). The write is durable before the call returns: a failed
// write is returned so the caller can retry (the operation is idempotent).
func (s *Store) EraseAccount(baasID string, pid uint64, naID string) (int, error) {
	if baasID == "" && pid == 0 && naID == "" {
		return 0, nil
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()
	rows := 0
	gone := map[string]bool{}
	if baasID != "" {
		gone[baasID] = true
	}
	devices := map[string]bool{}
	for id, u := range s.Users {
		if (baasID != "" && id == baasID) || (pid != 0 && u.PID == pid) || (naID != "" && u.NaID == naID) {
			gone[id] = true
			for _, d := range u.DeviceAccounts {
				devices[d] = true
			}
			delete(s.Users, id)
			rows++
		}
	}
	for id, d := range s.Devices {
		if devices[id] || gone[d.UserID] {
			delete(s.Devices, id)
			rows++
		}
	}
	for na, p := range s.NaToPID {
		if (naID != "" && na == naID) || (pid != 0 && p == pid) {
			delete(s.NaToPID, na)
			rows++
		}
	}
	for id, r := range s.Requests {
		if pid != 0 && (r.FromPID == pid || r.ToPID == pid) {
			delete(s.Requests, id)
			rows++
		}
	}
	for _, u := range s.Users {
		for id := range gone {
			if _, ok := u.FriendPrefs[id]; ok {
				delete(u.FriendPrefs, id)
				rows++
			}
			if _, ok := u.BlockDetails[id]; ok {
				delete(u.BlockDetails, id)
				rows++
			}
			u.Blocks, rows = dropString(u.Blocks, id, rows)
			u.Favourites, rows = dropString(u.Favourites, id, rows)
		}
	}
	return rows, s.saveErr()
}

func dropString(list []string, v string, rows int) ([]string, int) {
	out := list[:0]
	for _, x := range list {
		if x == v {
			rows++
			continue
		}
		out = append(out, x)
	}
	return out, rows
}

// DeleteUsers removes the named BAAS users and device accounts (the orphan cleanup,
// card openpak/prds#131) and every other user's reference to the removed ids. The write
// is durable before it returns; a second call finds nothing to do.
func (s *Store) DeleteUsers(userIDs, deviceIDs []string) (users, devices int, err error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	gone := map[string]bool{}
	for _, id := range userIDs {
		if _, ok := s.Users[id]; ok {
			delete(s.Users, id)
			users++
		}
		gone[id] = true
	}
	for _, id := range deviceIDs {
		if _, ok := s.Devices[id]; ok {
			delete(s.Devices, id)
			devices++
		}
	}
	for _, u := range s.Users {
		for id := range gone {
			delete(u.FriendPrefs, id)
			delete(u.BlockDetails, id)
			u.Blocks, _ = dropString(u.Blocks, id, 0)
			u.Favourites, _ = dropString(u.Favourites, id, 0)
		}
	}
	if users == 0 && devices == 0 {
		return 0, 0, nil
	}
	return users, devices, s.saveErr()
}
