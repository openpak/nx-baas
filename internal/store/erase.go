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
