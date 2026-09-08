package main

// OpenPak account core backend (PRD §8): identity, links, and the canonical
// friend graph come from the core over internal gRPC; the Switch identifier
// projection (pid, baasUserID, friendCode) is adapter-owned and local, so
// the core stays console-neutral (SW-01/SW-04) and this service keeps
// rendering BAAS-shaped data without a second authoritative social store.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	accountv1 "nx-baas/accountpb"
)

type openpakBackend struct {
	identity  accountv1.IdentityClient
	links     accountv1.LinksClient
	social    accountv1.SocialClient
	sessions  accountv1.SessionsClient
	proj      *projectionStore
	namespace string
	nexKey    []byte
	conn      *grpc.ClientConn
}

// newOpenpakBackend dials the core and loads the projection store. The key
// rules match the core: both keys fail closed on short values.
func newOpenpakBackend(ctx context.Context, dataDir string) (*openpakBackend, error) {
	coreKey := os.Getenv("ACCOUNT_INTERNAL_KEY")
	if len(coreKey) < 32 {
		return nil, errors.New("ACCOUNT_INTERNAL_KEY must be set (>=32 bytes)")
	}
	nexKey := []byte(os.Getenv("NEX_SIGNING_KEY"))
	if len(nexKey) < 32 {
		return nil, errors.New("NEX_SIGNING_KEY must be set (>=32 bytes); game servers verify openpak against it")
	}
	conn, err := grpc.NewClient(getenv("ACCOUNT_GRPC_ADDR", "127.0.0.1:7000"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Console logins are rare and bursty: without keepalive the connection goes idle, the
		// first call after a quiet spell dies with RST_STREAM CANCEL, and the person at the
		// console sees the sign-in fail for no reason they can act on.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true,
		}),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any,
			cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			return invoker(metadata.AppendToOutgoingContext(ctx, "x-internal-key", coreKey),
				method, req, reply, cc, opts...)
		}))
	if err != nil {
		return nil, err
	}
	b := newOpenpakBackendWithClients(dataDir,
		accountv1.NewIdentityClient(conn), accountv1.NewLinksClient(conn),
		accountv1.NewSocialClient(conn), nexKey)
	b.sessions = accountv1.NewSessionsClient(conn)
	b.conn = conn
	return b, nil
}

// newOpenpakBackendWithClients assembles the backend over explicit client
// surfaces; tests inject fakes here instead of dialing a core.
func newOpenpakBackendWithClients(dataDir string,
	identity accountv1.IdentityClient, links accountv1.LinksClient,
	social accountv1.SocialClient, nexKey []byte) *openpakBackend {
	return &openpakBackend{
		identity:  identity,
		links:     links,
		social:    social,
		proj:      loadProjections(filepath.Join(dataDir, "accounts.json")),
		namespace: getenv("SWITCH_NAMESPACE", "switch"),
		nexKey:    nexKey,
	}
}

// projection is the adapter-owned Switch identity bound to a core account
// (PRD SW-01/SW-04): the formats are ours, the binding is explicit, and a
// projection never migrates accounts.
type projection struct {
	AccountID  string `json:"account_id"`
	PID        uint64 `json:"pid"`
	BaasUserID string `json:"baas_user_id"`
	NaID       string `json:"na_id"`  // Nintendo Account id: NA token subject == users/me id (console checks coherence, 2124-3122)
	BsDid      string `json:"bs_did"` // bs:did claim of the BAAS tokens
	FriendCode string `json:"friend_code"`
	Nickname   string `json:"nickname"`
	CreatedAt  int64  `json:"created_at"`
}

type projectionStore struct {
	mu        sync.Mutex
	path      string
	ByAccount map[string]*projection `json:"by_account"`
	ByPID     map[uint64]string      `json:"by_pid"`
	ByBaas    map[string]string      `json:"by_baas"`
	ByCode    map[string]string      `json:"by_code"`
}

func loadProjections(path string) *projectionStore {
	p := &projectionStore{
		path:      path,
		ByAccount: map[string]*projection{},
		ByPID:     map[uint64]string{},
		ByBaas:    map[string]string{},
		ByCode:    map[string]string{},
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, p)
	}
	dirty := false
	for _, pr := range p.ByAccount { // projections minted before na_id/bs_did existed
		if pr.NaID != "" && pr.BsDid != "" {
			continue
		}
		if pr.NaID == "" {
			pr.NaID = randHex(8)
		}
		if pr.BsDid == "" {
			pr.BsDid = randHex(8)
		}
		dirty = true
	}
	if dirty {
		p.saveLocked() // no concurrency at load
	}
	return p
}

func (p *projectionStore) saveLocked() {
	b, _ := json.MarshalIndent(p, "", " ")
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("[nx-baas] openpak: projection save: %v", err)
		return
	}
	_ = os.Rename(tmp, p.path)
}

// ensure returns the projection for a core account, minting one (and
// registering the core link) on first sight. Idempotent and race-safe: the
// core's active-link lookup is consulted so retries never mint duplicates.
func (b *openpakBackend) ensure(ctx context.Context, accountID string) (*projection, error) {
	p := b.proj
	p.mu.Lock()
	defer p.mu.Unlock()
	if pr, ok := p.ByAccount[accountID]; ok {
		return pr, nil
	}

	// Core-side link first: the subject is the BAAS user id (SW-01).
	got, err := b.links.GetActiveLinkByAccount(ctx, &accountv1.GetActiveLinkByAccountRequest{
		Namespace: b.namespace, AccountId: accountID})
	subject := ""
	switch {
	case err == nil:
		subject = got.GetSubjectId()
	case status.Code(err) == codes.NotFound:
		subject = randHex(8) // 16 hex, the BAAS user id convention
		res, err := b.links.ReserveLink(ctx, &accountv1.ReserveLinkRequest{
			AccountId: accountID, Namespace: b.namespace, SubjectId: subject,
			IdempotencyKey: "ensure:" + subject})
		if err != nil {
			return nil, fmt.Errorf("link reserve: %w", err)
		}
		if _, err := b.links.ActivateLink(ctx, &accountv1.ActivateLinkRequest{
			LinkId: res.GetLinkId(), IdempotencyKey: "activate:" + res.GetLinkId()}); err != nil {
			return nil, fmt.Errorf("link activate: %w", err)
		}
	default:
		return nil, fmt.Errorf("link lookup: %w", err)
	}

	// Mint the remaining Switch identifiers locally (uniqueness-checked).
	pid, err := newPID(p)
	if err != nil {
		return nil, err
	}
	code, err := newFriendCode(p)
	if err != nil {
		return nil, err
	}
	pr := &projection{
		AccountID:  accountID,
		PID:        pid,
		BaasUserID: subject,
		NaID:       randHex(8),
		BsDid:      randHex(8),
		FriendCode: code,
		CreatedAt:  time.Now().Unix(),
	}
	p.ByAccount[accountID] = pr
	p.ByPID[pid] = accountID
	p.ByBaas[subject] = accountID
	p.ByCode[code] = accountID
	p.saveLocked()
	return pr, nil
}

// newPID mints an unused Switch-style principal id (18xxxxxxxx range).
func newPID(p *projectionStore) (uint64, error) {
	for attempts := 0; attempts < 64; attempts++ {
		n, err := rand.Int(rand.Reader, big.NewInt(99_999_999))
		if err != nil {
			return 0, err
		}
		pid := 1_800_000_000 + n.Uint64()
		if _, taken := p.ByPID[pid]; !taken {
			return pid, nil
		}
	}
	return 0, errors.New("pid space exhausted")
}

// newFriendCode renders the console's friend-code shape (SW-dddd-dddd-dddd),
// uniqueness-checked against the store so a collision can never overwrite a
// mapping.
func newFriendCode(p *projectionStore) (string, error) {
	for attempts := 0; attempts < 64; attempts++ {
		buf := make([]byte, 12)
		for i := range buf {
			n, err := rand.Int(rand.Reader, big.NewInt(10))
			if err != nil {
				return "", err
			}
			buf[i] = byte('0' + n.Int64())
		}
		code := fmt.Sprintf("SW-%s-%s-%s", buf[0:4], buf[4:8], buf[8:12])
		if _, taken := p.ByCode[code]; !taken {
			return code, nil
		}
	}
	return "", errors.New("friend-code space exhausted")
}

func (b *openpakBackend) friendCodeForAccount(accountID string) (string, bool) {
	b.proj.mu.Lock()
	defer b.proj.mu.Unlock()
	pr, ok := b.proj.ByAccount[accountID]
	if !ok || pr.FriendCode == "" {
		return "", false
	}
	return pr.FriendCode, true
}

func (b *openpakBackend) LoginPID(email, password string) (uint64, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := &accountv1.VerifyPasswordRequest{
		CallerNamespace: b.namespace, Purpose: "console_login", Email: email, Password: password}
	res, err := b.identity.VerifyPassword(ctx, req)
	if isTransient(err) {
		// One retry: a dead connection must not read as a wrong password on a television.
		log.Printf("[openpak] retrying login after transient error: %v", err)
		res, err = b.identity.VerifyPassword(ctx, req)
	}
	if err != nil {
		return 0, "", err
	}
	if res.GetStatus() != accountv1.AccountStatus_ACCOUNT_STATUS_ACTIVE || !res.GetEmailVerified() {
		return 0, "", errors.New("account is not active/verified for console linking")
	}
	pr, err := b.ensure(ctx, res.GetAccountId())
	if err != nil {
		return 0, "", err
	}
	// Display name is the core's only exposed profile field; sync the
	// projection's copy so friends render it without a core round-trip.
	acc, err := b.identity.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: res.GetAccountId()})
	nickname := ""
	if err == nil {
		nickname = acc.GetDisplayName()
		b.proj.mu.Lock()
		if cur := b.proj.ByAccount[res.GetAccountId()]; cur != nil && nickname != "" && cur.Nickname != nickname {
			cur.Nickname = nickname
			b.proj.saveLocked()
		}
		b.proj.mu.Unlock()
	} else {
		logErr("login get-account", err)
	}
	return pr.PID, pr.nicknameOr(nickname), nil
}

func (b *openpakBackend) Identity(pid uint64) (*Identity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pr, accountID, err := b.byPID(ctx, pid)
	if err != nil {
		return nil, err
	}
	id := &Identity{PID: pid, BaasUserID: pr.BaasUserID, NaID: pr.NaID, BsDid: pr.BsDid, Nickname: pr.Nickname, FriendCode: pr.FriendCode}
	if acc, err := b.identity.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: accountID}); err == nil {
		id.Nickname = acc.GetDisplayName()
		id.Country, id.Birthday = acc.GetCountry(), acc.GetBirthday()
	} else {
		logErr("identity get-account", err)
	}
	// The account already has a picture -- its own upload or the preset its id
	// picks -- and until this line the console was shown the generic default
	// for every account that had not uploaded one from a console.
	if site := getenv("WEBSITE_INTERNAL_URL", ""); site != "" {
		id.AvatarURL = site + "/media/avatars/" + accountID + "/console.jpg"
		// When it changed, not the picture itself: a console refetches on the
		// timestamp alone, so without this a picture changed on the website
		// would never reach a console that already had one.
		id.ImageUpdatedAt = websitePictureAt(id.AvatarURL)
	}
	friends, err := b.social.ListFriends(ctx, &accountv1.ListFriendsRequest{AccountId: accountID})
	if err != nil {
		return nil, fmt.Errorf("list friends: %w", err)
	}
	for _, f := range friends.GetFriends() {
		if fr := b.friendView(f.GetAccountId(), f.GetDisplayName()); fr != nil {
			id.Friends = append(id.Friends, *fr)
		}
	}
	incoming, err := b.social.ListIncomingRequests(ctx, &accountv1.ListIncomingRequestsRequest{AccountId: accountID})
	if err != nil {
		return nil, fmt.Errorf("list incoming: %w", err)
	}
	for _, f := range incoming.GetRequesters() {
		if fr := b.friendView(f.GetAccountId(), f.GetDisplayName()); fr != nil {
			id.FriendRequests = append(id.FriendRequests, *fr)
		}
	}
	outgoing, err := b.social.ListOutgoingRequests(ctx, &accountv1.ListOutgoingRequestsRequest{AccountId: accountID})
	if err != nil {
		return nil, fmt.Errorf("list outgoing: %w", err)
	}
	for _, f := range outgoing.GetAddressees() {
		if fr := b.friendView(f.GetAccountId(), f.GetDisplayName()); fr != nil {
			id.SentRequests = append(id.SentRequests, *fr)
		}
	}
	return id, nil
}

// friendView renders one core account as a BAAS Friend. Accounts without a
// console projection are skipped: they have no pid/friend code to render and
// fabricating one would break identity guarantees (SW-04).
func (b *openpakBackend) friendView(accountID, displayName string) *Friend {
	b.proj.mu.Lock()
	defer b.proj.mu.Unlock()
	pr, ok := b.proj.ByAccount[accountID]
	if !ok {
		return nil
	}
	nick := pr.Nickname
	if displayName != "" {
		nick = displayName
	}
	return &Friend{PID: pr.PID, BaasUserID: pr.BaasUserID, NaID: pr.NaID, FriendCode: pr.FriendCode,
		Nickname: nick, CreatedAt: pr.CreatedAt}
}

func (b *openpakBackend) Resolve(q url.Values) (*Friend, error) {
	b.proj.mu.Lock()
	defer b.proj.mu.Unlock()
	var accountID string
	switch {
	case q.Get("code") != "":
		accountID = b.proj.ByCode[q.Get("code")]
	case q.Get("baas") != "":
		accountID = b.proj.ByBaas[q.Get("baas")]
	}
	if accountID == "" {
		return nil, errors.New("not found")
	}
	pr := b.proj.ByAccount[accountID]
	return &Friend{PID: pr.PID, BaasUserID: pr.BaasUserID, NaID: pr.NaID, FriendCode: pr.FriendCode,
		Nickname: pr.Nickname, CreatedAt: pr.CreatedAt}, nil
}

func (b *openpakBackend) FriendRequest(from, to uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fromID, err := b.accountForPID(ctx, from)
	if err != nil {
		return err
	}
	toID, err := b.accountForPID(ctx, to)
	if err != nil {
		return err
	}
	_, err = b.social.RequestFriend(ctx, &accountv1.RequestFriendRequest{
		RequesterId: fromID, AddresseeId: toID, IdempotencyKey: fmt.Sprintf("baas:%d:%d", from, to)})
	return err
}

func (b *openpakBackend) FriendAccept(pid, from uint64, accept bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accountID, err := b.accountForPID(ctx, pid)
	if err != nil {
		return err
	}
	fromID, err := b.accountForPID(ctx, from)
	if err != nil {
		return err
	}
	if accept {
		_, err = b.social.AcceptFriend(ctx, &accountv1.AcceptFriendRequest{
			AddresseeId: accountID, RequesterId: fromID, IdempotencyKey: "baas-accept"})
		return err
	}
	_, err = b.social.RemoveFriend(ctx, &accountv1.RemoveFriendRequest{AccountId: accountID, OtherId: fromID})
	return err
}

// nexToken signs the same "openpak" wire format the title servers verify; the
// key is ours (NEX_SIGNING_KEY), and title servers list this backend as a
// trusted issuer (PRD SW-03) — no shared vendor secret.
func (b *openpakBackend) nexToken(pid uint64, username string) string {
	if len(b.nexKey) == 0 {
		return ""
	}
	payload := fmt.Sprintf("%d.%s.%d", pid, username, time.Now().Add(30*24*time.Hour).Unix())
	mac := hmac.New(sha256.New, b.nexKey)
	mac.Write([]byte("nex:" + payload))
	return "nx2." + base64RawURL([]byte(payload)) + "." + base64RawURL(mac.Sum(nil))
}

func (b *openpakBackend) nexSigningKey() []byte { return b.nexKey }

func (b *openpakBackend) byPID(ctx context.Context, pid uint64) (*projection, string, error) {
	b.proj.mu.Lock()
	accountID, ok := b.proj.ByPID[pid]
	var pr *projection
	if ok {
		pr = b.proj.ByAccount[accountID]
	}
	b.proj.mu.Unlock()
	if !ok {
		return nil, "", errors.New("no projection for pid")
	}
	_ = ctx
	return pr, accountID, nil
}

func (b *openpakBackend) accountForPID(ctx context.Context, pid uint64) (string, error) {
	_, accountID, err := b.byPID(ctx, pid)
	return accountID, err
}

func (pr *projection) nicknameOr(fallback string) string {
	if pr != nil && pr.Nickname != "" {
		return pr.Nickname
	}
	return fallback
}

func accName(acc *accountv1.GetAccountResponse) string {
	if acc == nil {
		return ""
	}
	return acc.GetDisplayName()
}

func base64RawURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// isTransient reports whether a gRPC failure is worth one immediate retry: a reset or dropped
// connection, never a rejected password.
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return true
	}
	return false
}

// onlineLease is short on purpose. Nothing tells this server that an emulator
// was closed — a process that goes away sends nothing — so "online" has to be
// a claim that lapses unless it keeps being renewed. A minute is the longest
// someone should appear online after quitting, and the client renews well
// inside it.
const onlineLease = 60 * time.Second

// Online records that an account is signed in to this network and playing
// nothing in particular: a session with no title, which the core counts toward
// who is online and deliberately not toward who is playing what.
//
// Best effort by design. Presence is not worth failing a console's login over,
// so a core that cannot be reached costs an accurate status page and nothing
// else.
func (b *openpakBackend) Online(ctx context.Context, pid uint64) {
	if b == nil || b.sessions == nil {
		return
	}
	b.proj.mu.Lock()
	accountID := b.proj.ByPID[pid]
	b.proj.mu.Unlock()

	if accountID == "" {
		return
	}
	if _, err := b.sessions.RegisterSession(ctx, &accountv1.RegisterSessionRequest{
		AccountId: accountID, Namespace: b.namespace, TitleId: "", EndpointRef: "baas",
		LeaseSeconds: int32(onlineLease.Seconds()),
	}); err != nil {
		logErr("presence register", err)
	}
}
