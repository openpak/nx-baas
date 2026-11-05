package invitations

// EraseUser removes every invitation the erased user sent or received (matched by BAAS
// user id, and for mailbox rows by sender PID) and the groups they created. Rows other
// users received from other senders stay; a group that listed a removed row forgets it.
// The write is durable before the call returns.
func (st *Store) EraseUser(baasID string, pid uint64) (int, error) {
	if baasID == "" && pid == 0 {
		return 0, nil
	}
	st.Mu.Lock()
	defer st.Mu.Unlock()
	rows := 0
	for id, inv := range st.Invitations {
		if (baasID != "" && (inv.SenderID == baasID || inv.ReceiverID == baasID)) ||
			(pid != 0 && inv.Mailbox && inv.MailboxFromPID == pid) {
			st.dropLocked(inv)
			delete(st.Invitations, id)
			rows++
		}
	}
	for id, g := range st.Groups {
		if baasID != "" && g.SenderID == baasID {
			delete(st.Groups, id)
			rows++
		}
	}
	return rows, st.saveErrLocked()
}
