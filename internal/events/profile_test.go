package events

import (
	"testing"

	"nx-baas/internal/identity"
	"nx-baas/internal/store"
)

func TestApplyProfileLevelsOnlyWhatIsCached(t *testing.T) {
	u := &store.User{Nickname: "Old", Birthday: "0000-00-00"}
	cp := identity.CoreProfile{DisplayName: "New", Country: "SE", Birthday: "2000-01-01", Version: 4}
	if !ApplyProfile(u, cp) {
		t.Fatal("expected a change")
	}
	if u.Nickname != "New" || u.ProfileVersion != 4 {
		t.Fatalf("nickname not levelled: %+v", u)
	}
	if u.Country != "" || u.Birthday != "0000-00-00" {
		t.Fatalf("a field that was never cached was written first: %+v", u)
	}
	if ApplyProfile(u, cp) {
		t.Fatal("second apply must be a no-op")
	}
}
