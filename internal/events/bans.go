package events

import (
	"nx-baas/internal/identity"
)

// closeAccountSessions ends every live Penne connection of a core account; the console's
// reconnect then meets the frontline's ban check.
func (s *Follower) closeAccountSessions(b *identity.OpenpakBackend, accountID string) {
	b.Proj.Mu.Lock()
	pr := b.Proj.ByAccount[accountID]
	b.Proj.Mu.Unlock()
	if pr == nil {
		return
	}
	s.Penne.CloseUser(pr.BaasUserID)
}
