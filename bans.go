package main

import (
	"nx-baas/internal/identity"
)

// ---------- the refusals, one per surface ----------

// closeAccountSessions ends every live Penne connection of a core account; the console's
// reconnect then meets the frontline's ban check.
func (s *server) closeAccountSessions(b *identity.OpenpakBackend, accountID string) {
	b.Proj.Mu.Lock()
	pr := b.Proj.ByAccount[accountID]
	b.Proj.Mu.Unlock()
	if pr == nil {
		return
	}
	s.penneCloseUser(pr.BaasUserID)
}
