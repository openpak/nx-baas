package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accountv1 "nx-baas/accountpb"
)

// fakeCore implements the core client surfaces the OpenPak backend
// uses, mirroring the core's rules: one active link per (namespace, account),
// verified logins only, one pending request per pair (reverse pending fails),
// directional blocks that deny interactions both ways.
type fakeCore struct {
	accounts   map[string]*accountv1.GetAccountResponse
	passwords  map[string]string
	activeLink map[string]string // "ns\x00account" -> subject
	friends    map[string][]string
	incoming   map[string][]string
	outgoing   map[string][]string
	blocks     map[string]bool // "blocker\x00blocked"
	// friendsSince is when the core says each account became somebody's friend.
	friendsSince map[string]int64
	// twoFA marks accounts with an enabled second factor; totp is the code
	// the fake accepts for them; totpLocked simulates the core lockout.
	twoFA        map[string]bool
	totp         map[string]string
	totpLocked   map[string]bool
	sawSupported bool // whether any caller declared second-factor support
}

func newFakeCore() *fakeCore {
	return &fakeCore{
		accounts:   map[string]*accountv1.GetAccountResponse{},
		passwords:  map[string]string{},
		activeLink: map[string]string{},
		friends:    map[string][]string{},
		incoming:   map[string][]string{},
		outgoing:   map[string][]string{},
		blocks:     map[string]bool{},
		twoFA:      map[string]bool{},
		totp:       map[string]string{},
		totpLocked: map[string]bool{},
	}
}

func (f *fakeCore) add2FAAccount(id, display, password, code string) {
	f.addAccount(id, display, password)
	f.twoFA[id] = true
	f.totp[id] = code
}

func (f *fakeCore) addAccount(id, display, password string) {
	f.accounts[id] = &accountv1.GetAccountResponse{AccountId: id, DisplayName: display,
		Status: accountv1.AccountStatus_ACCOUNT_STATUS_ACTIVE, EmailVerified: true}
	f.passwords[id] = password
}

func (f *fakeCore) befriend(a, b string) {
	f.friends[a] = append(f.friends[a], b)
	f.friends[b] = append(f.friends[b], a)
}

func (f *fakeCore) block(a, b string) { f.blocks[a+"\x00"+b] = true }

// blockedEither mirrors requireNoBlock: a block in either direction denies
// the interaction.
func (f *fakeCore) blockedEither(a, b string) bool {
	return f.blocks[a+"\x00"+b] || f.blocks[b+"\x00"+a]
}

func (f *fakeCore) isFriend(a, b string) bool { return containsStr(f.friends[a], b) }

func (f *fakeCore) pendingFromTo(from, to string) bool {
	return containsStr(f.outgoing[from], to) && containsStr(f.incoming[to], from)
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

type fakeIdentity struct {
	accountv1.IdentityClient
	f *fakeCore
}

func (x fakeIdentity) VerifyPassword(ctx context.Context, r *accountv1.VerifyPasswordRequest, _ ...grpc.CallOption,
) (*accountv1.VerifyPasswordResponse, error) {
	// The core authenticates by email and returns the account id.
	x.f.sawSupported = x.f.sawSupported || r.GetSecondFactorSupported()
	for id, pw := range x.f.passwords {
		if id != "" && strings.EqualFold(id, r.GetEmail()) && pw == r.GetPassword() {
			resp := &accountv1.VerifyPasswordResponse{AccountId: id,
				Status: x.f.accounts[id].GetStatus(), EmailVerified: true}
			if x.f.twoFA[id] {
				if !r.GetSecondFactorSupported() {
					return nil, status.Error(codes.FailedPrecondition, "two-factor authentication required")
				}
				resp.TwoFactorRequired = true
			}
			return resp, nil
		}
	}
	return nil, status.Error(codes.Unauthenticated, "invalid credentials")
}

func (x fakeIdentity) VerifySecondFactor(ctx context.Context, r *accountv1.VerifySecondFactorRequest, _ ...grpc.CallOption,
) (*accountv1.VerifySecondFactorResponse, error) {
	id := r.GetAccountId()
	if x.f.totpLocked[id] {
		return nil, status.Error(codes.ResourceExhausted, "too many two-factor attempts")
	}
	if x.f.twoFA[id] && (r.GetCode() == x.f.totp[id] || r.GetRecoveryCode() == "recovery-"+id) {
		return &accountv1.VerifySecondFactorResponse{}, nil
	}
	return nil, status.Error(codes.Unauthenticated, "invalid code")
}

func (x fakeIdentity) GetAccount(ctx context.Context, r *accountv1.GetAccountRequest, _ ...grpc.CallOption,
) (*accountv1.GetAccountResponse, error) {
	if a := x.f.accounts[r.GetAccountId()]; a != nil {
		return a, nil
	}
	return nil, status.Error(codes.NotFound, "account not found")
}

type fakeLinks struct {
	accountv1.LinksClient
	f *fakeCore
}

func (x fakeLinks) GetActiveLinkByAccount(ctx context.Context, r *accountv1.GetActiveLinkByAccountRequest, _ ...grpc.CallOption,
) (*accountv1.GetLinkBySubjectResponse, error) {
	subject, ok := x.f.activeLink[r.GetNamespace()+"\x00"+r.GetAccountId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no active link")
	}
	return &accountv1.GetLinkBySubjectResponse{SubjectId: subject, AccountId: r.GetAccountId(),
		State: accountv1.LinkState_LINK_STATE_ACTIVE}, nil
}

func (x fakeLinks) ReserveLink(ctx context.Context, r *accountv1.ReserveLinkRequest, _ ...grpc.CallOption,
) (*accountv1.ReserveLinkResponse, error) {
	key := r.GetNamespace() + "\x00" + r.GetAccountId()
	if _, taken := x.f.activeLink[key]; taken {
		return nil, status.Error(codes.AlreadyExists, "account already has an active link in namespace")
	}
	x.f.activeLink[key] = r.GetSubjectId()
	return &accountv1.ReserveLinkResponse{LinkId: r.GetSubjectId(), State: accountv1.LinkState_LINK_STATE_PENDING}, nil
}

func (x fakeLinks) ActivateLink(ctx context.Context, r *accountv1.ActivateLinkRequest, _ ...grpc.CallOption,
) (*accountv1.ActivateLinkResponse, error) {
	return &accountv1.ActivateLinkResponse{State: accountv1.LinkState_LINK_STATE_ACTIVE}, nil
}

type fakeSocial struct {
	accountv1.SocialClient
	f *fakeCore
}

func (x fakeSocial) ListFriends(ctx context.Context, r *accountv1.ListFriendsRequest, _ ...grpc.CallOption,
) (*accountv1.ListFriendsResponse, error) {
	out := &accountv1.ListFriendsResponse{}
	for _, id := range x.f.friends[r.GetAccountId()] {
		if a := x.f.accounts[id]; a != nil {
			out.Friends = append(out.Friends, &accountv1.Friend{AccountId: id, DisplayName: a.GetDisplayName(),
				FriendsSinceUnix: x.f.friendsSince[id]})
		}
	}
	return out, nil
}

func (x fakeSocial) ListIncomingRequests(ctx context.Context, r *accountv1.ListIncomingRequestsRequest, _ ...grpc.CallOption,
) (*accountv1.ListIncomingRequestsResponse, error) {
	out := &accountv1.ListIncomingRequestsResponse{}
	for _, id := range x.f.incoming[r.GetAccountId()] {
		if a := x.f.accounts[id]; a != nil {
			out.Requesters = append(out.Requesters, &accountv1.Friend{AccountId: id, DisplayName: a.GetDisplayName()})
		}
	}
	return out, nil
}

func (x fakeSocial) ListOutgoingRequests(ctx context.Context, r *accountv1.ListOutgoingRequestsRequest, _ ...grpc.CallOption,
) (*accountv1.ListOutgoingRequestsResponse, error) {
	out := &accountv1.ListOutgoingRequestsResponse{}
	for _, id := range x.f.outgoing[r.GetAccountId()] {
		if a := x.f.accounts[id]; a != nil {
			out.Addressees = append(out.Addressees, &accountv1.Friend{AccountId: id, DisplayName: a.GetDisplayName()})
		}
	}
	return out, nil
}

func (x fakeSocial) RequestFriend(ctx context.Context, r *accountv1.RequestFriendRequest, _ ...grpc.CallOption,
) (*accountv1.RequestFriendResponse, error) {
	from, to := r.GetRequesterId(), r.GetAddresseeId()
	if from == "" || to == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	if from == to {
		return nil, status.Error(codes.InvalidArgument, "self-request")
	}
	if x.f.blockedEither(from, to) {
		return nil, status.Error(codes.FailedPrecondition, "blocked")
	}
	if x.f.isFriend(from, to) {
		return &accountv1.RequestFriendResponse{State: accountv1.FriendState_FRIEND_STATE_ACCEPTED}, nil
	}
	if x.f.pendingFromTo(to, from) { // they already asked us
		return nil, status.Error(codes.FailedPrecondition, "addressee already requested")
	}
	if !x.f.pendingFromTo(from, to) { // idempotent while pending
		x.f.incoming[to] = append(x.f.incoming[to], from)
		x.f.outgoing[from] = append(x.f.outgoing[from], to)
	}
	return &accountv1.RequestFriendResponse{State: accountv1.FriendState_FRIEND_STATE_PENDING}, nil
}

func (x fakeSocial) AcceptFriend(ctx context.Context, r *accountv1.AcceptFriendRequest, _ ...grpc.CallOption,
) (*accountv1.AcceptFriendResponse, error) {
	addressee, requester := r.GetAddresseeId(), r.GetRequesterId()
	if x.f.pendingFromTo(requester, addressee) {
		x.f.befriend(addressee, requester)
		x.f.dropRequest(requester, addressee)
		return &accountv1.AcceptFriendResponse{State: accountv1.FriendState_FRIEND_STATE_ACCEPTED}, nil
	}
	if x.f.isFriend(addressee, requester) {
		return &accountv1.AcceptFriendResponse{State: accountv1.FriendState_FRIEND_STATE_ACCEPTED}, nil
	}
	return nil, status.Error(codes.FailedPrecondition, "request not pending")
}

func (x fakeSocial) RemoveFriend(ctx context.Context, r *accountv1.RemoveFriendRequest, _ ...grpc.CallOption,
) (*accountv1.RemoveFriendResponse, error) {
	a, b := r.GetAccountId(), r.GetOtherId()
	// Pending or accepted, either side, idempotent when absent (the core's
	// RemoveFriend rule).
	x.f.dropRequest(a, b)
	x.f.dropRequest(b, a)
	x.f.friends[a] = removeID(x.f.friends[a], b)
	x.f.friends[b] = removeID(x.f.friends[b], a)
	return &accountv1.RemoveFriendResponse{}, nil
}

func (x fakeSocial) Block(ctx context.Context, r *accountv1.BlockRequest, _ ...grpc.CallOption,
) (*accountv1.BlockResponse, error) {
	x.f.block(r.GetBlockerId(), r.GetBlockedId())
	return &accountv1.BlockResponse{}, nil
}

func (x fakeSocial) Unblock(ctx context.Context, r *accountv1.UnblockRequest, _ ...grpc.CallOption,
) (*accountv1.UnblockResponse, error) {
	delete(x.f.blocks, r.GetBlockerId()+"\x00"+r.GetBlockedId())
	return &accountv1.UnblockResponse{}, nil
}

func (x fakeSocial) GetRelationship(ctx context.Context, r *accountv1.GetRelationshipRequest, _ ...grpc.CallOption,
) (*accountv1.GetRelationshipResponse, error) {
	me, other := r.GetAccountId(), r.GetOtherId()
	rel := accountv1.Relationship_RELATIONSHIP_NONE
	switch {
	case x.f.blocks[me+"\x00"+other]:
		rel = accountv1.Relationship_RELATIONSHIP_BLOCKED_BY_SELF
	case x.f.blocks[other+"\x00"+me]:
		rel = accountv1.Relationship_RELATIONSHIP_BLOCKED_BY_OTHER
	case x.f.isFriend(me, other):
		rel = accountv1.Relationship_RELATIONSHIP_FRIENDS
	case x.f.pendingFromTo(other, me):
		rel = accountv1.Relationship_RELATIONSHIP_PENDING_INCOMING
	case x.f.pendingFromTo(me, other):
		rel = accountv1.Relationship_RELATIONSHIP_PENDING_OUTGOING
	}
	return &accountv1.GetRelationshipResponse{Relationship: rel}, nil
}

func (f *fakeCore) dropRequest(from, to string) {
	f.outgoing[from] = removeID(f.outgoing[from], to)
	f.incoming[to] = removeID(f.incoming[to], from)
}

func removeID(list []string, id string) []string {
	out := list[:0]
	for _, v := range list {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}

func newTestBackend(t *testing.T) (*openpakBackend, *fakeCore) {
	t.Helper()
	f := newFakeCore()
	// Tests drive the fake core through the backend's client surfaces.
	return newOpenpakBackendWithClients(t.TempDir(), fakeIdentity{f: f}, fakeLinks{f: f}, fakeSocial{f: f}, []byte(strings.Repeat("k", 32))), f
}

func TestOpenpakLoginMintsStableProjection(t *testing.T) {
	b, f := newTestBackend(t)
	f.addAccount("acc-1", "StardewHost", "correct horse battery")

	res, err := b.LoginPID("acc-1", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if res.Username != "StardewHost" || res.PID == 0 || res.Need2FA {
		t.Fatalf("login: pid=%d username=%q need2fa=%v", res.PID, res.Username, res.Need2FA)
	}
	// Retry returns the same identifiers (SW-01: no duplicate subjects).
	res2, err := b.LoginPID("acc-1", "correct horse battery")
	if err != nil || res2.PID != res.PID || res2.Username != res.Username {
		t.Fatalf("retry mismatch: pid %d/%d name %q/%q err %v", res.PID, res2.PID, res.Username, res2.Username, err)
	}
	// The core link was established once, for the minted BAAS subject.
	pr := b.proj.ByAccount["acc-1"]
	if got := f.activeLink[b.namespace+"\x00"+"acc-1"]; got != pr.BaasUserID {
		t.Fatalf("core link subject %q != projection baas id %q", got, pr.BaasUserID)
	}
	if len(pr.BaasUserID) != 16 {
		t.Fatalf("baas user id must be 16 hex, got %q", pr.BaasUserID)
	}
	if !strings.HasPrefix(pr.FriendCode, "SW-") {
		t.Fatalf("friend code shape: %q", pr.FriendCode)
	}
	if len(pr.NaID) != 16 || len(pr.BsDid) != 16 {
		t.Fatalf("na_id/bs_did must be 16 hex: %q %q", pr.NaID, pr.BsDid)
	}
	if id, err := b.Identity(res.PID); err != nil || id.NaID != pr.NaID {
		t.Fatalf("identity NaID: %+v %v", id, err)
	}
}

func TestOpenpakIdentityRendersFriends(t *testing.T) {
	b, f := newTestBackend(t)
	f.addAccount("acc-1", "Host", "pw-1-xxxxxxxxxxx")
	f.addAccount("acc-2", "Guest", "pw-2-xxxxxxxxxxx")

	r1, err := b.LoginPID("acc-1", "pw-1-xxxxxxxxxxx")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b.LoginPID("acc-2", "pw-2-xxxxxxxxxxx")
	if err != nil {
		t.Fatal(err)
	}
	// Host sends a request to Guest; Guest accepts.
	if err := b.FriendRequest(r1.PID, r2.PID); err != nil {
		t.Fatal(err)
	}
	id, err := b.Identity(r2.PID)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.FriendRequests) != 1 || id.FriendRequests[0].PID != r1.PID {
		t.Fatalf("incoming request: %+v", id.FriendRequests)
	}
	if err := b.FriendAccept(r2.PID, r1.PID, true); err != nil {
		t.Fatal(err)
	}
	id, err = b.Identity(r1.PID)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Friends) != 1 || id.Friends[0].PID != r2.PID || id.Friends[0].Nickname != "Guest" {
		t.Fatalf("friends: %+v", id.Friends)
	}

	// Resolve by friend code and by BAAS user id.
	pr2 := b.proj.ByAccount["acc-2"]
	byCode, err := b.Resolve(url.Values(strMap("code", pr2.FriendCode)))
	if err != nil || byCode.PID != r2.PID {
		t.Fatalf("resolve code: %+v %v", byCode, err)
	}
	byBaas, err := b.Resolve(url.Values(strMap("baas", pr2.BaasUserID)))
	if err != nil || byBaas.BaasUserID != pr2.BaasUserID {
		t.Fatalf("resolve baas: %+v %v", byBaas, err)
	}
}

func TestOpenpakNexTokenShape(t *testing.T) {
	b, _ := newTestBackend(t)
	tok := b.nexToken(1800000001, "Host")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != "nx2" {
		t.Fatalf("token shape: %q", tok)
	}
	// Byte-identical verification path with account.go's format.
	ref := (&accountClient{secret: b.nexKey}).nexToken(1800000001, "Host")
	if ref == "" || strings.Split(ref, ".")[0] != "nx2" {
		t.Fatalf("reference token shape: %q", ref)
	}
}

func strMap(kv ...string) map[string][]string {
	m := map[string][]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = []string{kv[i+1]}
	}
	return m
}

// One check for the title-server surface: an openpak token this backend signed resolves to the player
// and their friend projections; a forged one and a wrong key are refused.
func TestInternalSwitchIdentity(t *testing.T) {
	b, f := newTestBackend(t)
	f.addAccount("host@example.com", "Host", "pw")
	f.addAccount("friend@example.com", "Friend", "pw")
	f.befriend("host@example.com", "friend@example.com")
	hostRes, err := b.LoginPID("host@example.com", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.LoginPID("friend@example.com", "pw"); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("i", 32)
	t.Setenv("NX_INTERNAL_KEY", key)
	srv := httptest.NewServer((&server{acct: b}).gameAPI())
	defer srv.Close()
	post := func(body, k string) (int, struct {
		switchPlayer
		Friends []switchPlayer `json:"friends"`
	}) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/internal/switch/identity", strings.NewReader(body))
		req.Header.Set("X-Internal-Key", k)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			switchPlayer
			Friends []switchPlayer `json:"friends"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	code, id := post(`{"openpak":"`+b.nexToken(hostRes.PID, "Host")+`"}`, key)
	if code != 200 || id.PID != hostRes.PID || id.BaasUserID == "" || len(id.Friends) != 1 || id.Friends[0].Nickname != "Friend" {
		t.Fatalf("openpak path: code=%d id=%+v", code, id)
	}
	if code, _ := post(`{"pid":`+strconv.FormatUint(hostRes.PID, 10)+`}`, key); code != 200 {
		t.Fatalf("pid path: code=%d", code)
	}
	if code, _ := post(`{"openpak":"nx2.a.b"}`, key); code != 401 {
		t.Fatalf("forged openpak accepted: code=%d", code)
	}
	if code, _ := post(`{"pid":1}`, "wrong"); code != 401 {
		t.Fatalf("wrong key accepted: code=%d", code)
	}
}

// The cursor may only ever advance to a version that belongs to an event we
// actually received. The core echoes SinceVersion back as MaxVersion when a
// page is empty, so trusting MaxVersion as a "head" marker parks the cursor
// above every version that will ever exist and silently kills the whole event
// feed -- which is exactly what happened in production.
func TestCursorNeverAdvancesPastARealEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core-events.cursor")

	if _, known := readCursor(path); known {
		t.Fatal("a missing cursor must read as unknown, so the poller starts from the beginning")
	}

	// What the old head-probe wrote. A cursor this large can never be exceeded.
	writeCursor(path, 1<<62-1)
	got, known := readCursor(path)
	if !known || got != 1<<62-1 {
		t.Fatalf("readCursor = %d/%v", got, known)
	}
	if got <= 41 {
		t.Fatal("fixture wrong")
	}

	// A cursor written from a real event is small and keeps working.
	writeCursor(path, 41)
	if got, known := readCursor(path); !known || got != 41 {
		t.Fatalf("readCursor = %d/%v, want 41", got, known)
	}
}

// TestLoginDeclaresSecondFactorSupport: the adapter must tell the core it can
// run the second step, or every 2FA account fails closed into a dead end.
func TestLoginDeclaresSecondFactorSupport(t *testing.T) {
	b, f := newTestBackend(t)
	f.addAccount("acc-1", "Plain", "correct horse battery")
	if _, err := b.LoginPID("acc-1", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if !f.sawSupported {
		t.Error("LoginPID did not declare second-factor support to the core")
	}
}

// TestLoginReturnsNeed2FA: a correct password on a 2FA account proves the
// password and owes the code — PID minted, nothing signed in.
func TestLoginReturnsNeed2FA(t *testing.T) {
	b, f := newTestBackend(t)
	f.add2FAAccount("2fa@example.com", "TwoFA", "correct horse battery", "123456")
	res, err := b.LoginPID("2fa@example.com", "correct horse battery")
	if err != nil {
		t.Fatalf("2FA password step: %v", err)
	}
	if !res.Need2FA || res.AccountID != "2fa@example.com" || res.PID == 0 {
		t.Fatalf("need2fa=%v account=%q pid=%d, want the pending shape", res.Need2FA, res.AccountID, res.PID)
	}
}

// TestVerifySecondFactorMappings: code, recovery code, wrong code, lockout.
func TestVerifySecondFactorMappings(t *testing.T) {
	b, f := newTestBackend(t)
	f.add2FAAccount("2fa@example.com", "TwoFA", "correct horse battery", "123456")
	if err := b.VerifySecondFactor("2fa@example.com", "123456", ""); err != nil {
		t.Fatalf("good code: %v", err)
	}
	if err := b.VerifySecondFactor("2fa@example.com", "", "recovery-2fa@example.com"); err != nil {
		t.Fatalf("recovery code: %v", err)
	}
	if err := b.VerifySecondFactor("2fa@example.com", "000000", ""); !errors.Is(err, errSecondFactorInvalid) {
		t.Fatalf("wrong code = %v, want invalid", err)
	}
	f.totpLocked["2fa@example.com"] = true
	if err := b.VerifySecondFactor("2fa@example.com", "123456", ""); !errors.Is(err, errSecondFactorLocked) {
		t.Fatalf("locked = %v, want locked", err)
	}
}

// TestEarlierBackendStepUpUnsupported: the earlier account server speaks no second
// factor, so its step-up refuses instead of pretending.
func TestEarlierBackendStepUpUnsupported(t *testing.T) {
	a := &accountClient{http: http.DefaultClient}
	if err := a.VerifySecondFactor("acc-1", "123456", ""); !errors.Is(err, errSecondFactorUnsupported) {
		t.Fatalf("earlier-backend step-up = %v, want unsupported", err)
	}
}
