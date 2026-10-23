package main

// Playtime on openpak.org counts only time a game server confirmed the player online, and the
// confirmation is the login itself: when a game server asks who a player is and gets an answer,
// that player is on it. Each successful identity lookup therefore tells the core's MarkOnline,
// which starts the playtime clock on the player's live titled Switch session (a player with no
// such session is a no-op there).

// onlineMarker is the backend's side: the openpak backend reaches the core; a stub records.
type onlineMarker interface {
	MarkOnline(pid uint64)
}

// markLoginOnline is called after a game server's identity lookup succeeded.
func (s *server) markLoginOnline(pid uint64) {
	if m, ok := s.acct.(onlineMarker); ok && pid != 0 {
		m.MarkOnline(pid)
	}
}
