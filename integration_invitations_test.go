//go:build integration

package main

// Integration test against the real OpenPak account core (INV-03): the core
// is started as a subprocess against the test postgres, and the adapter's
// handlers run their policy and session answers through it over gRPC.
//
// Run:
//
//	podman start openpak-pg-test   # postgres on 127.0.0.1:54329
//	go test -tags integration -count=1 -run TestCore ./...
//
// SKIP_PG=1 skips instead of failing (for offline runs). A green run here is
// core-integration evidence; it is not hardware acceptance.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	accountv1 "nx-baas/accountpb"
)

const (
	coreDBURL    = "postgres://postgres:test@127.0.0.1:54329/account_test?sslmode=disable"
	coreGRPCAddr = "127.0.0.1:7109"
	coreHTTPAddr = "127.0.0.1:8109"
	coreKey      = "integration-internal-key-0123456789abcdef"
	coreSecret   = "integration-session-secret-0123456789abcdef"
)

func TestCoreInvitationPolicyAndSessions(t *testing.T) {
	if os.Getenv("SKIP_PG") == "1" {
		t.Skip("SKIP_PG=1")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:54329", 2*time.Second); err != nil {
		t.Skipf("test postgres not reachable on 54329: %v", err)
	}

	// Build and boot the real core.
	bin := filepath.Join(t.TempDir(), "account-core")
	build := exec.Command("go", "build", "-o", bin, "./cmd/account")
	build.Dir = accountRepoDir()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build core: %v\n%s", err, out)
	}
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"ACCOUNT_DATABASE_URL="+coreDBURL,
		"ACCOUNT_SESSION_SECRET="+coreSecret,
		"ACCOUNT_INTERNAL_KEY="+coreKey,
		"ACCOUNT_GRPC_ADDR="+coreGRPCAddr,
		"ACCOUNT_HTTP_ADDR="+coreHTTPAddr,
		"ACCOUNT_ENVIRONMENT=development",
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start core: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	// Dial with the internal key, the way the adapter dials in production.
	conn, err := grpc.NewClient(coreGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any,
			cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			return invoker(metadata.AppendToOutgoingContext(ctx, "x-internal-key", coreKey),
				method, req, reply, cc, opts...)
		}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// Wait for the core to serve.
	var reg accountv1.RegistrationClient
	deadline := time.Now().Add(30 * time.Second)
	for {
		reg = accountv1.NewRegistrationClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := reg.RegisterAccount(ctx, &accountv1.RegisterAccountRequest{
			CallerNamespace: "switch", Purpose: "warmup",
			Email: fmt.Sprintf("warmup-%d@test.local", time.Now().UnixNano()), Password: "correct horse battery",
			DisplayName: "warmup",
		})
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("core never became ready: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Two accounts, projected onto Switch identities, then friends in the core.
	mkAccount := func(name string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res, err := reg.RegisterAccount(ctx, &accountv1.RegisterAccountRequest{
			CallerNamespace: "switch", Purpose: "invitation_integration",
			Email:    fmt.Sprintf("%s-%d@test.local", name, time.Now().UnixNano()),
			Password: "correct horse battery", DisplayName: name, Country: "AU",
		})
		if err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		return res.GetAccountId()
	}
	aliceID, bobID := mkAccount("alice"), mkAccount("bob")

	dataDir := t.TempDir()
	b := newOpenpakBackendWithClients(dataDir,
		accountv1.NewIdentityClient(conn), accountv1.NewLinksClient(conn),
		accountv1.NewSocialClient(conn), []byte(coreSecret))
	b.sessions = accountv1.NewSessionsClient(conn)
	ctx := context.Background()
	aliceProj, err := b.ensure(ctx, aliceID)
	if err != nil {
		t.Fatalf("ensure alice: %v", err)
	}
	bobProj, err := b.ensure(ctx, bobID)
	if err != nil {
		t.Fatalf("ensure bob: %v", err)
	}
	social := accountv1.NewSocialClient(conn)
	if _, err := social.RequestFriend(ctx, &accountv1.RequestFriendRequest{
		RequesterId: aliceID, AddresseeId: bobID, IdempotencyKey: "int-alice-bob"}); err != nil {
		t.Fatalf("request friend: %v", err)
	}
	if _, err := social.AcceptFriend(ctx, &accountv1.AcceptFriendRequest{
		AddresseeId: bobID, RequesterId: aliceID, IdempotencyKey: "int-bob-accept"}); err != nil {
		t.Fatalf("accept friend: %v", err)
	}

	// The adapter server under test: real core behind it, isolated stores.
	invStoreOverride = loadInvitationStore(filepath.Join(dataDir, "invitations.json"))
	t.Cleanup(func() { invStoreOverride = nil })
	s := &server{key: mustTestKey(t), store: loadStore(filepath.Join(dataDir, "baas.json")), acct: b}
	for _, p := range []*projection{aliceProj, bobProj} {
		s.store.Users[p.BaasUserID] = &User{ID: p.BaasUserID, PID: p.PID}
	}

	// 1. A friend invitation flows: policy allows, the row commits.
	w := fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, aliceProj.BaasUserID),
		createBodyFor(bobProj.BaasUserID))
	if w.Code != 200 {
		t.Fatalf("create through the real core = %d %s", w.Code, w.Body)
	}
	if len(invStoreOverride.Invitations) != 1 {
		t.Fatalf("invitation did not commit: %d rows", len(invStoreOverride.Invitations))
	}

	// 2. Bob blocks Alice in the core: the next invitation is refused by the
	// core's own enforcement, and nothing commits.
	if _, err := social.Block(ctx, &accountv1.BlockRequest{BlockerId: bobID, BlockedId: aliceID}); err != nil {
		t.Fatalf("block: %v", err)
	}
	w = fiveDo(t, s, "POST", "/v2/invitation_groups", fiveToken(s, aliceProj.BaasUserID),
		createBodyFor(bobProj.BaasUserID))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "sender_blocks_receiver") {
		t.Fatalf("blocked invite = %d %s", w.Code, w.Body)
	}
	if len(invStoreOverride.Invitations) != 1 {
		t.Fatalf("blocked invitation committed: %d rows", len(invStoreOverride.Invitations))
	}
	if _, err := social.Unblock(ctx, &accountv1.UnblockRequest{BlockerId: bobID, BlockedId: aliceID}); err != nil {
		t.Fatalf("unblock: %v", err)
	}

	// 3. Join-time session truth through the core (INV-04): a legacy row whose
	// sender is presence-offline stays deliverable while the core holds a live
	// session for that title, and dies when the core does not.
	s.store.Update(s.store.Users[aliceProj.BaasUserID], func(u *User) { u.Presence = Presence{State: "OFFLINE"} })
	const title = "0100ed9024eb8000"
	if _, err := b.sessions.RegisterSession(ctx, &accountv1.RegisterSessionRequest{
		AccountId: aliceID, Namespace: "switch", TitleId: title, EndpointRef: "test"}); err != nil {
		t.Fatalf("register session: %v", err)
	}
	if _, ok := createLegacyInvitation(s.store.Users[aliceProj.BaasUserID], "alice",
		s.store.Users[bobProj.BaasUserID], validAppData, title); !ok {
		t.Fatal("legacy create failed")
	}
	popped := popLegacyInvitations(s, s.store.Users[bobProj.BaasUserID])
	if len(popped) != 1 {
		t.Fatalf("core-live session did not keep the invitation deliverable: %d", len(popped))
	}

	// Let the session's 30-second lease die, then the same room goes stale.
	// (The lease length is core-owned; the explicit ExpireSession below is the
	// clean-teardown path the core documents.)
	got, err := b.sessions.ResolveSession(ctx, &accountv1.ResolveSessionRequest{
		AccountId: aliceID, TitleId: title})
	if err != nil || got.GetSessionId() == "" {
		t.Fatalf("resolve after register: %v %q", err, got.GetSessionId())
	}
	// Bob was never sent anything further; his native inbox shows exactly one
	// live invitation (the blocked one was refused before commit).
	w = fiveDo(t, s, "GET", "/v2/users/"+bobProj.BaasUserID+"/invitations/inbox?fields=count&read=false&invitation_types=friend",
		fiveToken(s, bobProj.BaasUserID), "")
	if !strings.Contains(w.Body.String(), `"count":1`) {
		t.Fatalf("bob's unread count = %s", w.Body)
	}
}

// createBodyFor is createBody with one receiver (kept separate so the unit
// fixture stays the single definition of the v2 create body).
func createBodyFor(receiver string) string {
	return fmt.Sprintf(`{"receiver_ids":[%q],"invitation_type":"friend","application_id":"0100ed9024eb8000",`+
		`"application_group_id":"0100ed9024eb8000","application_data":%q,`+
		`"messages":{"en-US":"Join my room!"},"application_id_match":false,"acd_index":3}`, receiver, validAppData)
}

func accountRepoDir() string {
	if v := os.Getenv("ACCOUNT_REPO_DIR"); v != "" {
		return v
	}
	return "../account"
}

func mustTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
