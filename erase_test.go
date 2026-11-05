package main

import (
	"net/http/httptest"
	"nx-baas/internal/identity"
	"nx-baas/internal/invitations"
	"nx-baas/internal/store"
	"strings"
	"testing"
)

const (
	eraseAcct = "11111111-2222-3333-4444-555555555555"
	keepAcct  = "66666666-7777-8888-9999-000000000000"
)

func eraseServer(t *testing.T) *server {
	s := testServer(t)
	f := newFakeCore()
	b := identity.NewOpenpakBackendWithClients(t.TempDir(), fakeIdentity{f: f}, fakeLinks{f: f}, fakeSocial{f: f}, []byte(strings.Repeat("k", 32)))
	s.Acct = b
	b.Proj.ByAccount[eraseAcct] = &identity.Projection{AccountID: eraseAcct, PID: hostPID, BaasUserID: "aaaa"}
	b.Proj.ByAccount[keepAcct] = &identity.Projection{AccountID: keepAcct, PID: joinerPID, BaasUserID: "bbbb"}
	b.Proj.ByPID[hostPID], b.Proj.ByBaas["aaaa"] = eraseAcct, eraseAcct
	b.Proj.ByPID[joinerPID], b.Proj.ByBaas["bbbb"] = keepAcct, keepAcct
	s.Store.Users["bbbb"].FriendPrefs = map[string]*store.FriendPreference{"aaaa": {Favorite: true}}
	inv := invitations.StoreFor()
	inv.Invitations["1"] = &invitations.Record{ID: "1", SenderID: "aaaa", ReceiverID: "bbbb"}
	inv.Invitations["2"] = &invitations.Record{ID: "2", SenderID: "bbbb", ReceiverID: "cccc"}
	return s
}

func eraseCall(s *server, method, acct, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://nx-baas:20070/internal/accounts/"+acct+"/data", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	s.gameAPI().ServeHTTP(rec, req)
	return rec
}

func TestEraseEndpointAuth(t *testing.T) {
	s := eraseServer(t)
	t.Setenv("ACCOUNT_ERASE_KEY", "")
	if rec := eraseCall(s, "DELETE", eraseAcct, "Bearer k"); rec.Code != 503 {
		t.Fatalf("no key configured: %d", rec.Code)
	}
	t.Setenv("ACCOUNT_ERASE_KEY", "erase-key")
	for _, a := range []string{"", "Bearer wrong", "erase-key"} {
		if rec := eraseCall(s, "DELETE", eraseAcct, a); rec.Code != 401 {
			t.Fatalf("auth %q: %d", a, rec.Code)
		}
	}
	if rec := eraseCall(s, "DELETE", "not-a-uuid", "Bearer erase-key"); rec.Code != 400 {
		t.Fatalf("bad id: %d", rec.Code)
	}
	if s.Store.Users["aaaa"] == nil {
		t.Fatal("a refused call erased data")
	}
}

func TestEraseEndpointRemovesOnlyThatAccount(t *testing.T) {
	s := eraseServer(t)
	t.Setenv("ACCOUNT_ERASE_KEY", "erase-key")
	rec := eraseCall(s, "DELETE", eraseAcct, "Bearer erase-key")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"service":"nx-baas"`) || strings.Contains(rec.Body.String(), `"rows":0`) {
		t.Fatalf("erase = %d %s", rec.Code, rec.Body)
	}
	b := s.Acct.(*identity.OpenpakBackend)
	if s.Store.Users["aaaa"] != nil || b.Proj.ByAccount[eraseAcct] != nil || b.Proj.ByPID[hostPID] != "" || b.Proj.ByBaas["aaaa"] != "" {
		t.Fatal("the erased account's rows remain")
	}
	inv := invitations.StoreFor()
	if inv.Invitations["1"] != nil || inv.Invitations["2"] == nil {
		t.Fatalf("invitations = %v", inv.Invitations)
	}
	k := s.Store.Users["bbbb"]
	if k == nil || b.Proj.ByAccount[keepAcct] == nil || k.FriendPrefs["aaaa"] != nil {
		t.Fatal("other account lost data or still references the erased one")
	}
	// Idempotent, and an unknown account is 200 with 0 rows.
	for _, a := range []string{eraseAcct, "00000000-0000-0000-0000-000000000000"} {
		rec = eraseCall(s, "DELETE", a, "Bearer erase-key")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rows":0`) {
			t.Fatalf("repeat erase of %s = %d %s", a, rec.Code, rec.Body)
		}
	}
}
