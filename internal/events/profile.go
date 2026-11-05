package events

import (
	"log"
	"time"

	"nx-baas/internal/identity"
	"nx-baas/internal/store"
	"nx-baas/redact"
)

// ProfileTTL is the backup refresh: if a profile_updated event is missed, a linked
// user's cached profile is at most this stale.
const ProfileTTL = 5 * time.Minute

// ApplyProfile levels a BAAS user's cached profile with the core's. The core is the
// only source: the copies exist so the console path has something to compare against
// and are never ahead of it. A field the user never had locally stays unset (a read
// fills it from the core). Reports whether anything changed.
func ApplyProfile(u *store.User, cp identity.CoreProfile) bool {
	changed := false
	if u.Nickname != "" && cp.DisplayName != "" && u.Nickname != cp.DisplayName {
		u.Nickname, changed = cp.DisplayName, true
	}
	if u.Country != "" && cp.Country != "" && u.Country != cp.Country {
		u.Country, changed = cp.Country, true
	}
	if u.Birthday == store.BirthdayPlaceholder { // never keep the wire placeholder
		u.Birthday, changed = "", true
	}
	if u.Birthday != "" && cp.Birthday != "" && u.Birthday != cp.Birthday {
		u.Birthday, changed = cp.Birthday, true
	}
	if cp.Version != 0 && u.ProfileVersion != cp.Version {
		u.ProfileVersion, changed = cp.Version, true
	}
	return changed
}

// RefreshProfile re-reads one account from the core and levels its BAAS user.
func (s *Follower) RefreshProfile(b *identity.OpenpakBackend, accountID string) {
	pr, ok := b.LookupProjection(accountID)
	if !ok {
		return
	}
	cp, err := b.CoreProfile(accountID)
	if err != nil {
		log.Printf("[nx-baas] profile refresh: %v", redact.Err(err))
		return
	}
	// The projection (accounts.json by_account) holds a nickname copy too. It was only ever
	// written at console login, so a rename made elsewhere left it stale: level it on every
	// refresh, before the user-record shortcut below, whatever the version says.
	b.LevelProjectionNickname(accountID, cp.DisplayName)
	u := s.Store.User(pr.BaasUserID)
	if u == nil {
		return
	}
	s.Store.Mu.Lock()
	same := cp.Version != 0 && u.ProfileVersion == cp.Version
	s.Store.Mu.Unlock()
	if same {
		return
	}
	s.Store.Update(u, func(u *store.User) { ApplyProfile(u, cp) })
}

// ProfileSweepLoop is the TTL backup: every ProfileTTL every linked user is compared
// with the core (profile_version makes a quiet account a single cheap read).
func (s *Follower) ProfileSweepLoop(b *identity.OpenpakBackend) {
	for {
		time.Sleep(ProfileTTL)
		b.Proj.Mu.Lock()
		ids := make([]string, 0, len(b.Proj.ByAccount))
		for id := range b.Proj.ByAccount {
			ids = append(ids, id)
		}
		b.Proj.Mu.Unlock()
		for _, id := range ids {
			s.RefreshProfile(b, id)
		}
	}
}
