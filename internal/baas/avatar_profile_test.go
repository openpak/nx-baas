package baas

import "testing"

func TestOps2ProfilePicksOnlyNonEmptyNicknameAndCountry(t *testing.T) {
	ops := []struct {
		Op, Path string
		Value    any
	}{
		{Path: "/nickname", Value: "Name"},
		{Path: "/country", Value: ""},
		{Path: "/birthday", Value: "2000-01-01"},
	}
	p := ops2profile(ops)
	if p.nickname == nil || *p.nickname != "Name" || p.country != nil {
		t.Fatalf("got %+v", p)
	}
}
