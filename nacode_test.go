package main

// Authorization codes are bearer credentials: spent once at the token
// endpoint (checked, not spent, at the session_token step before it),
// dead after ten minutes, and purged so the map cannot grow.

import (
	"nx-baas/internal/core"
	"testing"
	"time"
)

func TestTakeCodeSingleUse(t *testing.T) {
	s := &server{Core: &core.Core{}, codes: map[string]naCode{}}
	s.codes["c1"] = naCode{PID: 7, Created: time.Now()}
	// session_token step: checks, does not spend.
	if _, ok := s.takeCode("c1", false); !ok {
		t.Fatal("fresh code refused")
	}
	// token step: spends.
	if _, ok := s.takeCode("c1", true); !ok {
		t.Fatal("unspent code refused at the token step")
	}
	// Replay: refused.
	if _, ok := s.takeCode("c1", true); ok {
		t.Fatal("spent code spent again")
	}
	if _, ok := s.takeCode("nope", true); ok {
		t.Fatal("unknown code accepted")
	}
}

func TestTakeCodeExpiresAndPurges(t *testing.T) {
	s := &server{Core: &core.Core{}, codes: map[string]naCode{}}
	s.codes["old"] = naCode{PID: 7, Created: time.Now().Add(-11 * time.Minute)}
	s.codes["fresh"] = naCode{PID: 8, Created: time.Now()}
	if _, ok := s.takeCode("old", true); ok {
		t.Fatal("expired code accepted")
	}
	if _, ok := s.codes["old"]; ok {
		t.Error("expired code not purged")
	}
	if _, ok := s.takeCode("fresh", true); !ok {
		t.Fatal("fresh code refused after a purge")
	}
}
