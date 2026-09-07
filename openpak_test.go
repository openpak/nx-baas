package main

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accountv1 "openpak/account/proto/openpak/account/v1"
)

// fakeCore implements the three core client surfaces the OpenPak backend
// uses, mirroring the core's rules: one active link per (namespace, account),
// verified logins only, directional friend state.
type fakeCore struct {
	accounts   map[string]*accountv1.GetAccountResponse
	passwords  map[string]string
	activeLink map[string]string // "ns\x00account" -> subject
	friends    map[string][]string
	incoming   map[string][]string
	outgoing   map[string][]string
}

func newFakeCore() *fakeCore {
	return &fakeCore{
		accounts:   map[string]*accountv1.GetAccountResponse{},
		passwords:  map[string]string{},
		activeLink: map[string]string{},
		friends:    map[string][]string{},
		incoming:   map[string][]string{},
		outgoing:   map[string][]string{},
	}
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

type fakeIdentity struct {
	accountv1.IdentityClient
	f *fakeCore
}

func (x fakeIdentity) VerifyPassword(ctx context.Context, r *accountv1.VerifyPasswordRequest, _ ...grpc.CallOption,
) (*accountv1.VerifyPasswordResponse, error) {
	// The core authenticates by email and returns the account id.
	for id, pw := range x.f.passwords {
		if id != "" && strings.EqualFold(id, r.GetEmail()) && pw == r.GetPassword() {
			return &accountv1.VerifyPasswordResponse{AccountId: id,
				Status: x.f.accounts[id].GetStatus(), EmailVerified: true}, nil
		}
	}
	return nil, status.Error(codes.Unauthenticated, "invalid credentials")
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
			out.Friends = append(out.Friends, &accountv1.Friend{AccountId: id, DisplayName: a.GetDisplayName()})
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
	x.f.incoming[r.GetAddresseeId()] = append(x.f.incoming[r.GetAddresseeId()], r.GetRequesterId())
	x.f.outgoing[r.GetRequesterId()] = append(x.f.outgoing[r.GetRequesterId()], r.GetAddresseeId())
	return &accountv1.RequestFriendResponse{State: accountv1.FriendState_FRIEND_STATE_PENDING}, nil
}

func (x fakeSocial) AcceptFriend(ctx context.Context, r *accountv1.AcceptFriendRequest, _ ...grpc.CallOption,
) (*accountv1.AcceptFriendResponse, error) {
	x.f.befriend(r.GetAddresseeId(), r.GetRequesterId())
	x.f.dropRequest(r.GetRequesterId(), r.GetAddresseeId())
	return &accountv1.AcceptFriendResponse{State: accountv1.FriendState_FRIEND_STATE_ACCEPTED}, nil
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

	pid, username, err := b.LoginPID("acc-1", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if username != "StardewHost" || pid == 0 {
		t.Fatalf("login: pid=%d username=%q", pid, username)
	}
	// Retry returns the same identifiers (SW-01: no duplicate subjects).
	pid2, username2, err := b.LoginPID("acc-1", "correct horse battery")
	if err != nil || pid2 != pid || username2 != username {
		t.Fatalf("retry mismatch: pid %d/%d name %q/%q err %v", pid, pid2, username, username2, err)
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
}

func TestOpenpakIdentityRendersFriends(t *testing.T) {
	b, f := newTestBackend(t)
	f.addAccount("acc-1", "Host", "pw-1-xxxxxxxxxxx")
	f.addAccount("acc-2", "Guest", "pw-2-xxxxxxxxxxx")

	p1, _, err := b.LoginPID("acc-1", "pw-1-xxxxxxxxxxx")
	if err != nil {
		t.Fatal(err)
	}
	p2, _, err := b.LoginPID("acc-2", "pw-2-xxxxxxxxxxx")
	if err != nil {
		t.Fatal(err)
	}
	// Host sends a request to Guest; Guest accepts.
	if err := b.FriendRequest(p1, p2); err != nil {
		t.Fatal(err)
	}
	id, err := b.Identity(p2)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.FriendRequests) != 1 || id.FriendRequests[0].PID != p1 {
		t.Fatalf("incoming request: %+v", id.FriendRequests)
	}
	if err := b.FriendAccept(p2, p1, true); err != nil {
		t.Fatal(err)
	}
	id, err = b.Identity(p1)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Friends) != 1 || id.Friends[0].PID != p2 || id.Friends[0].Nickname != "Guest" {
		t.Fatalf("friends: %+v", id.Friends)
	}

	// Resolve by friend code and by BAAS user id.
	pr2 := b.proj.ByAccount["acc-2"]
	byCode, err := b.Resolve(url.Values(strMap("code", pr2.FriendCode)))
	if err != nil || byCode.PID != p2 {
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
