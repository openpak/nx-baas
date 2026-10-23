package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	accountv1 "nx-baas/accountpb"
)

// fakeBans stands in for the core: pid -> account, account -> status, and a lookup count.
type fakeBans struct {
	mu      sync.Mutex
	status  map[string]accountv1.AccountStatus
	lookups int
	down    bool
}

func (f *fakeBans) accountFor(pid uint64) string {
	if pid == 0 {
		return ""
	}
	return fmt.Sprintf("acc-%d", pid%10)
}

func (f *fakeBans) accountStatus(_ context.Context, id string) (accountv1.AccountStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if f.down {
		return 0, errors.New("core unavailable")
	}
	if st, ok := f.status[id]; ok {
		return st, nil
	}
	return accountv1.AccountStatus_ACCOUNT_STATUS_ACTIVE, nil
}

func (f *fakeBans) set(pid uint64, st accountv1.AccountStatus) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[f.accountFor(pid)] = st
}

// banServer is the game-API test server with an RSA key, so BaaS and NA surfaces work too,
// and hostPID banned.
func banServer(t *testing.T) (*server, *fakeBans) {
	t.Helper()
	s := testServer(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.key, s.idKid, s.accKid, s.naKid = key, "id", "acc", "na"
	s.codes = map[string]naCode{}
	s.device = map[string]string{}
	f := &fakeBans{status: map[string]accountv1.AccountStatus{}}
	f.set(hostPID, accountv1.AccountStatus_ACCOUNT_STATUS_BANNED)
	s.banSource = f
	return s, f
}

func baasReq(s *server, method, path, token, form string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+baasHost+path, strings.NewReader(form))
	r.Host = baasHost
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func errorCodeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]any
	json.Unmarshal(w.Body.Bytes(), &m)
	if c, ok := m["errorCode"].(string); ok {
		return c
	}
	if c, ok := m["error_detail"].(string); ok {
		return c
	}
	if c, ok := m["error"].(string); ok {
		return c
	}
	return ""
}

// The console's own sign-in: a device account linked to a banned account gets banned_user
// (2124-5110 on screen) and no token; unbanned, the same login goes through.
func TestBannedAccountCannotSignInOnTheConsole(t *testing.T) {
	s, f := banServer(t)
	u, d := s.store.NewUser()
	s.store.Update(u, func(u *User) { u.PID = hostPID })
	form := url.Values{"id": {d.ID}, "password": {d.Password}}.Encode()

	w := baasReq(s, "POST", "/1.0.0/login", "", form)
	if w.Code != 403 || errorCodeOf(t, w) != "banned_user" {
		t.Fatalf("banned login = %d %s, want 403 banned_user", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "accessToken") {
		t.Fatal("a banned login was handed a token")
	}

	f.set(hostPID, accountv1.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	s.forgetBan(f.accountFor(hostPID)) // what the core's account_unbanned event does
	if w := baasReq(s, "POST", "/1.0.0/login", "", form); w.Code != 200 {
		t.Fatalf("unbanned login = %d %s", w.Code, w.Body)
	}

	f.set(hostPID, accountv1.AccountStatus_ACCOUNT_STATUS_DELETION_PENDING)
	s.forgetBan(f.accountFor(hostPID))
	if w := baasReq(s, "POST", "/1.0.0/login", "", form); w.Code != 404 || errorCodeOf(t, w) != "deleted_user" {
		t.Fatalf("deleted login = %d %s, want 404 deleted_user", w.Code, w.Body)
	}
}

// A token minted before the ban stops working for every user-scoped call.
func TestBannedAccountsLiveTokenStopsWorking(t *testing.T) {
	s, _ := banServer(t)
	tok := s.accessToken("aaaa", 2, "hostbsdid", "", "")
	for _, p := range []string{"/1.0.0/users/aaaa", "/2.0.0/users/aaaa/friends"} {
		if w := baasReq(s, "GET", p, tok, ""); w.Code != 403 || errorCodeOf(t, w) != "banned_user" {
			t.Errorf("GET %s = %d %s", p, w.Code, w.Body)
		}
	}
	// Somebody else is unaffected.
	other := s.accessToken("bbbb", 2, "joinerbsdid", "", "")
	if w := baasReq(s, "GET", "/1.0.0/users/bbbb", other, ""); w.Code != 200 {
		t.Errorf("unbanned user = %d %s", w.Code, w.Body)
	}
}

// Nintendo Account: no token on any grant, and a silent authorize redirects with the error
// pair the account module maps.
func TestBannedAccountGetsNoNintendoAccountToken(t *testing.T) {
	s, _ := banServer(t)
	s.codes["c0de"] = naCode{PID: hostPID, NaID: "00aa00aa00aa00aa", Created: time.Now()}
	r := httptest.NewRequest("POST", "https://accounts.nintendo.com/connect/1.0.0/api/token", strings.NewReader("code=c0de"))
	r.Host = "accounts.nintendo.com"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 400 || errorCodeOf(t, w) != "user_banned" {
		t.Fatalf("token = %d %s, want 400 invalid_grant/user_banned", w.Code, w.Body)
	}

	s.store.RememberNA("00aa00aa00aa00aa", hostPID)
	at := s.naAccessToken(naCode{PID: hostPID, NaID: "00aa00aa00aa00aa"})
	form := url.Values{"prompt": {"none"}, "redirect_uri": {"nintendo://app"}, "state": {"st"}}.Encode()
	r = httptest.NewRequest("POST", "https://accounts.nintendo.com/connect/1.0.0/authorize", strings.NewReader(form))
	r.Host = "accounts.nintendo.com"
	r.Header.Set("Authorization", "Bearer "+at)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	loc := w.Header().Get("Location")
	if w.Code != 302 || !strings.Contains(loc, "error=interaction_required") || !strings.Contains(loc, "error_detail=user_banned") {
		t.Fatalf("silent authorize = %d %q", w.Code, loc)
	}
}

// Title servers and the game API: 403 account_banned, never 401.
func TestBannedAccountIsRefusedByTheGameAPI(t *testing.T) {
	s, _ := banServer(t)
	w := do(t, s, "POST", "/internal/switch/identity", "", `{"pid":1800000003}`)
	if w.Code != 403 || errorCodeOf(t, w) != "account_banned" {
		t.Fatalf("identity = %d %s, want 403 account_banned", w.Code, w.Body)
	}
	w = do(t, s, "POST", "/internal/switch/identity", "", `{"pid":1800000004}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"account_id":"acc-4"`) {
		t.Fatalf("unbanned identity = %d %s (want account_id)", w.Code, w.Body)
	}
	host := s.acct.nexToken(hostPID, "OutboundHost")
	if w := do(t, s, "GET", "/api/invitations", host, ""); w.Code != 403 {
		t.Fatalf("invitations for a banned caller = %d", w.Code)
	}
	// Nobody can invite a banned player either.
	joiner := s.acct.nexToken(joinerPID, "OutboundJoiner")
	w = do(t, s, "POST", "/api/invitations", joiner, `{"target_pids":[1800000003],"app_param_base64":"AQ=="}`)
	if !strings.Contains(w.Body.String(), `"sent":0`) {
		t.Fatalf("invitation to a banned player: %s", w.Body)
	}
	if w := do(t, s, "POST", "/internal/photon-identity", "", `{"identity":"bsdid:hostbsdid"}`); w.Code != 403 {
		t.Fatalf("photon identity = %d", w.Code)
	}
	if w := do(t, s, "POST", "/internal/mint-token", "", `{"pid":1800000003}`); w.Code != 403 {
		t.Fatalf("mint-token = %d", w.Code)
	}
}

// The answer is cached (one core read per TTL), a forget re-reads at once, and a core that
// cannot be reached lets people in rather than locking everyone out.
func TestBanCacheAndFailOpen(t *testing.T) {
	s, f := banServer(t)
	for range 5 {
		if s.pidLock(hostPID) != lockBanned {
			t.Fatal("banned account read as allowed")
		}
	}
	if f.lookups != 1 {
		t.Fatalf("%d core lookups for 5 checks, want 1", f.lookups)
	}
	s.forgetBan(f.accountFor(hostPID))
	s.pidLock(hostPID)
	if f.lookups != 2 {
		t.Fatalf("forget did not force a re-read (%d lookups)", f.lookups)
	}
	f.down = true
	if s.pidLock(joinerPID) != "" {
		t.Fatal("an unreachable core locked an account out")
	}
	t.Setenv("NX_BAN_CACHE_SECONDS", "3600")
	if got := banTTL(); got.Seconds() != 60 {
		t.Fatalf("ttl %v, want capped at 60s", got)
	}
}

// Penne: a banned account's console gets no notification channel.
func TestBannedAccountGetsNoNotificationChannel(t *testing.T) {
	s, ticket := frontlineServer(t, "dev1")
	s.store = loadStore(t.TempDir() + "/baas.json")
	s.store.Users["u_dev1"] = &User{ID: "u_dev1", PID: hostPID}
	f := &fakeBans{status: map[string]accountv1.AccountStatus{}}
	f.set(hostPID, accountv1.AccountStatus_ACCOUNT_STATUS_BANNED)
	s.banSource = f
	w := httptest.NewRecorder()
	s.frontline(w, frontlineRequest(ticket, "dev1"))
	if w.Code != 403 {
		t.Fatalf("frontline for a banned account = %d %s", w.Code, w.Body)
	}
}

// The store treats a banned account as nobody.
func TestBannedAccountIsNobodyToTheStore(t *testing.T) {
	s := shopServerFor(t)
	f := &fakeBans{status: map[string]accountv1.AccountStatus{}}
	f.set(7, accountv1.AccountStatus_ACCOUNT_STATUS_BANNED)
	s.banSource = f
	rec := shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", naIDTokenFor(s), "")
	if rec.Code != 401 {
		t.Fatalf("banned acquire = %d %s, want 401", rec.Code, rec.Body)
	}
}
