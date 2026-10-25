package identity

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
	"nx-baas/internal/httpx"
	"nx-baas/internal/token"
	"nx-baas/redact"
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

	accountv1 "github.com/openpak/account-api/openpak/account/v1"
)

type OpenpakBackend struct {
	IdentityClient accountv1.IdentityClient
	Links          accountv1.LinksClient
	Social         accountv1.SocialClient
	Sessions       accountv1.SessionsClient
	Register       accountv1.RegistrationClient // nil in tests that do not rename
	Proj           *ProjectionStore
	Namespace      string
	NexKey         []byte
	Conn           *grpc.ClientConn

	// account id -> the live "online" session, so a clean goodbye can end it.
	onlineMu sync.Mutex
	online   map[string]string
}

// newOpenpakBackend dials the core and loads the projection store. The key
// rules match the core: both keys fail closed on short values.
func NewOpenpakBackend(ctx context.Context, dataDir string) (*OpenpakBackend, error) {
	coreKey := os.Getenv("ACCOUNT_INTERNAL_KEY")
	if len(coreKey) < 32 {
		return nil, errors.New("ACCOUNT_INTERNAL_KEY must be set (>=32 bytes)")
	}
	nexKey := []byte(os.Getenv("NEX_SIGNING_KEY"))
	if len(nexKey) < 32 {
		return nil, errors.New("NEX_SIGNING_KEY must be set (>=32 bytes); game servers verify openpak against it")
	}
	conn, err := grpc.NewClient(httpx.Getenv("ACCOUNT_GRPC_ADDR", "127.0.0.1:7000"),
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
	b := NewOpenpakBackendWithClients(dataDir,
		accountv1.NewIdentityClient(conn), accountv1.NewLinksClient(conn),
		accountv1.NewSocialClient(conn), nexKey)
	b.Sessions = accountv1.NewSessionsClient(conn)
	b.Register = accountv1.NewRegistrationClient(conn)
	b.Conn = conn
	return b, nil
}

// newOpenpakBackendWithClients assembles the backend over explicit client
// surfaces; tests inject fakes here instead of dialing a core.
func NewOpenpakBackendWithClients(dataDir string,
	identity accountv1.IdentityClient, links accountv1.LinksClient,
	social accountv1.SocialClient, nexKey []byte) *OpenpakBackend {
	return &OpenpakBackend{
		IdentityClient: identity,
		Links:          links,
		Social:         social,
		Proj:           LoadProjections(filepath.Join(dataDir, "accounts.json")),
		Namespace:      httpx.Getenv("SWITCH_NAMESPACE", "switch"),
		NexKey:         nexKey,
	}
}

// projection is the adapter-owned Switch identity bound to a core account
// (PRD SW-01/SW-04): the formats are ours, the binding is explicit, and a
// projection never migrates accounts.
type Projection struct {
	AccountID  string `json:"account_id"`
	PID        uint64 `json:"pid"`
	BaasUserID string `json:"baas_user_id"`
	NaID       string `json:"na_id"`  // Nintendo Account id: NA token subject == users/me id (console checks coherence, 2124-3122)
	BsDid      string `json:"bs_did"` // bs:did claim of the BAAS tokens
	FriendCode string `json:"friend_code"`
	Nickname   string `json:"nickname"`
	CreatedAt  int64  `json:"created_at"`
}

type ProjectionStore struct {
	// Mu guards the maps; FilePath is accounts.json. Neither is persisted.
	Mu        sync.Mutex             `json:"-"`
	FilePath  string                 `json:"-"`
	ByAccount map[string]*Projection `json:"by_account"`
	ByPID     map[uint64]string      `json:"by_pid"`
	ByBaas    map[string]string      `json:"by_baas"`
	ByCode    map[string]string      `json:"by_code"`
}

func LoadProjections(path string) *ProjectionStore {
	p := &ProjectionStore{
		FilePath:  path,
		ByAccount: map[string]*Projection{},
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
			pr.NaID = token.RandHex(8)
		}
		if pr.BsDid == "" {
			pr.BsDid = token.RandHex(8)
		}
		dirty = true
	}
	if dirty {
		p.SaveLocked() // no concurrency at load
	}
	return p
}

func (p *ProjectionStore) SaveLocked() {
	b, _ := json.MarshalIndent(p, "", " ")
	tmp := p.FilePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("[nx-baas] openpak: projection save: %v", redact.Err(err))
		return
	}
	_ = os.Rename(tmp, p.FilePath)
}

// dropProjection forgets a core account's Switch identifiers from every
// index and persists. Called only on account_deleted (final destruction):
// banned, pending-deletion and unlinked accounts keep theirs, because those
// accounts may come back and SW-01 identifiers never migrate. Friends'
// projections reference PIDs, never this row, so dropping it orphans
// nothing: their consoles re-fetch and learn the account is gone.
func (b *OpenpakBackend) DropProjection(accountID string) {
	p := b.Proj
	p.Mu.Lock()
	defer p.Mu.Unlock()
	pr, ok := p.ByAccount[accountID]
	if !ok {
		return
	}
	delete(p.ByAccount, accountID)
	delete(p.ByPID, pr.PID)
	delete(p.ByBaas, pr.BaasUserID)
	delete(p.ByCode, pr.FriendCode)
	p.SaveLocked()
	log.Printf("[nx-baas] openpak: projection dropped for a deleted account")
}

// ensure returns the projection for a core account, minting one (and
// registering the core link) on first sight. Idempotent and race-safe: the
// core's active-link lookup is consulted so retries never mint duplicates.
func (b *OpenpakBackend) Ensure(ctx context.Context, accountID string) (*Projection, error) {
	p := b.Proj
	p.Mu.Lock()
	defer p.Mu.Unlock()
	if pr, ok := p.ByAccount[accountID]; ok {
		return pr, nil
	}

	// Core-side link first: the subject is the BAAS user id (SW-01).
	got, err := b.Links.GetActiveLinkByAccount(ctx, &accountv1.GetActiveLinkByAccountRequest{
		Namespace: b.Namespace, AccountId: accountID})
	subject := ""
	switch {
	case err == nil:
		subject = got.GetSubjectId()
	case status.Code(err) == codes.NotFound:
		subject = token.RandHex(8) // 16 hex, the BAAS user id convention
		res, err := b.Links.ReserveLink(ctx, &accountv1.ReserveLinkRequest{
			AccountId: accountID, Namespace: b.Namespace, SubjectId: subject,
			IdempotencyKey: "ensure:" + subject})
		if err != nil {
			return nil, fmt.Errorf("link reserve: %w", err)
		}
		if _, err := b.Links.ActivateLink(ctx, &accountv1.ActivateLinkRequest{
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
	pr := &Projection{
		AccountID:  accountID,
		PID:        pid,
		BaasUserID: subject,
		NaID:       token.RandHex(8),
		BsDid:      token.RandHex(8),
		FriendCode: code,
		CreatedAt:  time.Now().Unix(),
	}
	p.ByAccount[accountID] = pr
	p.ByPID[pid] = accountID
	p.ByBaas[subject] = accountID
	p.ByCode[code] = accountID
	p.SaveLocked()
	return pr, nil
}

// newPID mints an unused Switch-style principal id (18xxxxxxxx range).
func newPID(p *ProjectionStore) (uint64, error) {
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
func newFriendCode(p *ProjectionStore) (string, error) {
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

// accountForFriendCode resolves a Switch friend code to the OpenPak account
// that holds it. Codes are compared on their digits alone, so every way a
// person can type one -- "SW-1000-0000-0001", "sw100000000001", with spaces --
// finds the same account. The stored form keeps its dashes for display.
func (b *OpenpakBackend) AccountForFriendCode(code string) (string, bool) {
	want := friendCodeDigits(code)
	if want == "" {
		return "", false
	}
	b.Proj.Mu.Lock()
	defer b.Proj.Mu.Unlock()
	for stored, accountID := range b.Proj.ByCode {
		if friendCodeDigits(stored) == want {
			return accountID, true
		}
	}
	return "", false
}

// friendCodeDigits reduces a friend code to the twelve digits that identify it:
// the "SW" prefix, dashes and spacing are presentation.
func friendCodeDigits(code string) string {
	out := make([]rune, 0, 12)
	for _, c := range code {
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	if len(out) != 12 {
		return ""
	}
	return string(out)
}

func (b *OpenpakBackend) FriendCodeForAccount(accountID string) (string, bool) {
	b.Proj.Mu.Lock()
	defer b.Proj.Mu.Unlock()
	pr, ok := b.Proj.ByAccount[accountID]
	if !ok || pr.FriendCode == "" {
		return "", false
	}
	return pr.FriendCode, true
}

// RegenerateFriendCode mints a new code and retires the old one, so the code
// somebody handed out stops working -- which is the point of regenerating it.
func (b *OpenpakBackend) RegenerateFriendCode(pid uint64) error {
	b.Proj.Mu.Lock()
	defer b.Proj.Mu.Unlock()
	accountID, ok := b.Proj.ByPID[pid]
	if !ok {
		return errors.New("no projection for that pid")
	}
	pr := b.Proj.ByAccount[accountID]
	code, err := newFriendCode(b.Proj)
	if err != nil {
		return err
	}
	delete(b.Proj.ByCode, pr.FriendCode)
	pr.FriendCode = code
	b.Proj.ByCode[code] = accountID
	b.Proj.SaveLocked()
	return nil
}

func (b *OpenpakBackend) LoginPID(email, password string) (LoginResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := &accountv1.VerifyPasswordRequest{
		CallerNamespace: b.Namespace, Purpose: "console_login", Email: email, Password: password,
		// Declared: a 2FA account comes back Need2FA instead of failing
		// closed, so the caller can run the second step. Leaving this false
		// would turn every 2FA account into a dead end here.
		SecondFactorSupported: true,
	}
	res, err := b.IdentityClient.VerifyPassword(ctx, req)
	if isTransient(err) {
		// One retry: a dead connection must not read as a wrong password on a television.
		log.Printf("[openpak] retrying login after transient error: %v", redact.Err(err))
		res, err = b.IdentityClient.VerifyPassword(ctx, req)
	}
	if err != nil {
		// Unreachable against a current core (support is always declared),
		// but a skew must read as "2FA owed", never as "wrong password".
		if status.Code(err) == codes.FailedPrecondition {
			return LoginResult{}, ErrSecondFactorRequired
		}
		return LoginResult{}, err
	}
	switch res.GetStatus() {
	case accountv1.AccountStatus_ACCOUNT_STATUS_BANNED, accountv1.AccountStatus_ACCOUNT_STATUS_DELETION_PENDING,
		accountv1.AccountStatus_ACCOUNT_STATUS_DELETED:
		return LoginResult{}, fmt.Errorf("console login: %w (%s)", ErrAccountLocked, res.GetStatus())
	}
	if res.GetStatus() != accountv1.AccountStatus_ACCOUNT_STATUS_ACTIVE || !res.GetEmailVerified() {
		return LoginResult{}, errors.New("account is not active/verified for console linking")
	}
	pr, err := b.Ensure(ctx, res.GetAccountId())
	if err != nil {
		return LoginResult{}, err
	}
	// Display name is the core's only exposed profile field; sync the
	// projection's copy so friends render it without a core round-trip.
	acc, err := b.IdentityClient.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: res.GetAccountId()})
	nickname := ""
	if err == nil {
		nickname = acc.GetDisplayName()
		b.Proj.Mu.Lock()
		if cur := b.Proj.ByAccount[res.GetAccountId()]; cur != nil && nickname != "" && cur.Nickname != nickname {
			cur.Nickname = nickname
			b.Proj.SaveLocked()
		}
		b.Proj.Mu.Unlock()
	} else {
		LogErr("login get-account", err)
	}
	out := LoginResult{PID: pr.PID, Username: pr.nicknameOr(nickname),
		Need2FA: res.GetTwoFactorRequired(), AccountID: res.GetAccountId()}
	if out.Need2FA {
		// Password proved, nothing signed in: the projection row exists but
		// no session, link or approval may use it until VerifySecondFactor.
		log.Printf("[openpak] login pid=%s needs its second factor", redact.Tag(out.PID))
	}
	return out, nil
}

// VerifySecondFactor completes a Need2FA login. The password is not re-asked
// (and was never stored); the pending record carries only the account id.
func (b *OpenpakBackend) VerifySecondFactor(accountID, code, recoveryCode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := b.IdentityClient.VerifySecondFactor(ctx, &accountv1.VerifySecondFactorRequest{
		AccountId: accountID, Code: code, RecoveryCode: recoveryCode})
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.Unauthenticated:
		return ErrSecondFactorInvalid
	case codes.ResourceExhausted:
		return ErrSecondFactorLocked
	case codes.FailedPrecondition:
		return ErrSecondFactorUnsupported
	default:
		return err
	}
}

func (b *OpenpakBackend) Identity(pid uint64) (*Identity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pr, accountID, err := b.byPID(ctx, pid)
	if err != nil {
		return nil, err
	}
	id := &Identity{PID: pid, BaasUserID: pr.BaasUserID, NaID: pr.NaID, BsDid: pr.BsDid, Nickname: pr.Nickname, FriendCode: pr.FriendCode}
	if acc, err := b.IdentityClient.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: accountID}); err == nil {
		id.Nickname = acc.GetDisplayName()
		id.Country, id.Birthday, id.Email = acc.GetCountry(), acc.GetBirthday(), acc.GetEmail()
	} else {
		LogErr("identity get-account", err)
	}
	// The account already has a picture -- its own upload or the preset its id
	// picks -- and until this line the console was shown the generic default
	// for every account that had not uploaded one from a console.
	if site := httpx.Getenv("WEBSITE_INTERNAL_URL", ""); site != "" {
		id.AvatarURL = site + "/media/avatars/" + accountID + "/console.jpg"
		// When it changed, not the picture itself: a console refetches on the
		// timestamp alone, so without this a picture changed on the website
		// would never reach a console that already had one.
		id.ImageUpdatedAt = WebsitePictureAt(id.AvatarURL)
	}
	friends, err := b.Social.ListFriends(ctx, &accountv1.ListFriendsRequest{AccountId: accountID})
	if err != nil {
		return nil, fmt.Errorf("list friends: %w", err)
	}
	for _, f := range friends.GetFriends() {
		if fr := b.friendView(f.GetAccountId(), f.GetDisplayName(), f.GetFriendsSinceUnix()); fr != nil {
			id.Friends = append(id.Friends, *fr)
		}
	}
	incoming, err := b.Social.ListIncomingRequests(ctx, &accountv1.ListIncomingRequestsRequest{AccountId: accountID})
	if err != nil {
		return nil, fmt.Errorf("list incoming: %w", err)
	}
	for _, f := range incoming.GetRequesters() {
		if fr := b.friendView(f.GetAccountId(), f.GetDisplayName(), 0); fr != nil {
			id.FriendRequests = append(id.FriendRequests, *fr)
		}
	}
	outgoing, err := b.Social.ListOutgoingRequests(ctx, &accountv1.ListOutgoingRequestsRequest{AccountId: accountID})
	if err != nil {
		return nil, fmt.Errorf("list outgoing: %w", err)
	}
	for _, f := range outgoing.GetAddressees() {
		if fr := b.friendView(f.GetAccountId(), f.GetDisplayName(), 0); fr != nil {
			id.SentRequests = append(id.SentRequests, *fr)
		}
	}
	return id, nil
}

// friendView renders one core account as a BAAS Friend, minting its console
// projection first if it has none (ensure is idempotent and core-linked, so
// the identity is real, not fabricated: SW-04).
// friendView renders a friend of the core's list. since is when the friendship was accepted (0 for a
// pending request, which has none): what a console's friend page shows as "When You Became Friends".
// Before the core said, this carried the time the friend was first seen here, which is not it.
func (b *OpenpakBackend) friendView(accountID, displayName string, since int64) *Friend {
	// Copy the projection under the lock; the core call below must not hold
	// it (SOC-05: a global lock across per-friend network calls serialises a
	// whole friend list behind the slowest identity lookup).
	b.Proj.Mu.Lock()
	pr := b.Proj.ByAccount[accountID]
	var prCopy *Projection
	if pr != nil {
		c := *pr
		prCopy = &c
	}
	b.Proj.Mu.Unlock()
	if prCopy == nil {
		// Every account has a Switch identity: one that has never been on a
		// console gets its pid, BAAS id and friend code on first sight here.
		ectx, ecancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer ecancel()
		minted, err := b.Ensure(ectx, accountID)
		if err != nil {
			LogErr("friendView ensure", err)
			return nil
		}
		c := *minted
		prCopy = &c
	}
	nick := prCopy.Nickname
	if displayName != "" {
		nick = displayName
	}
	f := &Friend{PID: prCopy.PID, BaasUserID: prCopy.BaasUserID, NaID: prCopy.NaID, FriendCode: prCopy.FriendCode,
		Nickname: nick, CreatedAt: prCopy.CreatedAt}
	if since > 0 {
		f.CreatedAt = since
	}
	// Country, same as a looked-up user gets. Without it a friend list entry
	// goes out with country "" -- which is the state the console refused in a
	// search result, and a friend list that stays empty after a friendship the
	// server thinks it made.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if acc, err := b.IdentityClient.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: accountID}); err == nil {
		f.Country = acc.GetCountry()
		if f.Nickname == "" {
			f.Nickname = acc.GetDisplayName() // a projection minted by ensure has none
		}
	} else {
		LogErr("friendView get-account", err)
	}
	if site := httpx.Getenv("WEBSITE_INTERNAL_URL", ""); site != "" {
		f.PictureAt = WebsitePictureAt(site + "/media/avatars/" + accountID + "/console.jpg")
	}
	return f
}

func (b *OpenpakBackend) Resolve(q url.Values) (*Friend, error) {
	// Same rule as friendView: copy under the lock, network outside it.
	b.Proj.Mu.Lock()
	var accountID string
	switch {
	case q.Get("code") != "":
		accountID = b.Proj.ByCode[q.Get("code")]
	case q.Get("baas") != "":
		accountID = b.Proj.ByBaas[q.Get("baas")]
	}
	var prCopy *Projection
	if pr := b.Proj.ByAccount[accountID]; accountID != "" && pr != nil {
		c := *pr
		prCopy = &c
	}
	b.Proj.Mu.Unlock()
	if prCopy == nil {
		return nil, errors.New("not found")
	}
	pr := prCopy
	f := &Friend{PID: pr.PID, BaasUserID: pr.BaasUserID, NaID: pr.NaID, FriendCode: pr.FriendCode,
		Nickname: pr.Nickname, CreatedAt: pr.CreatedAt}
	// Country comes from the core; the projection never held one, so every
	// looked-up user went out with country "" while the capture the console
	// accepted carries a real one.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if acc, err := b.IdentityClient.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: accountID}); err == nil {
		f.Country = acc.GetCountry()
		if f.Nickname == "" {
			f.Nickname = acc.GetDisplayName()
		}
	} else {
		LogErr("resolve get-account", err) // silence here is why country stayed empty
	}
	return f, nil
}

func (b *OpenpakBackend) FriendRequest(from, to uint64) error {
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
	_, err = b.Social.RequestFriend(ctx, &accountv1.RequestFriendRequest{
		RequesterId: fromID, AddresseeId: toID, IdempotencyKey: fmt.Sprintf("baas:%d:%d", from, to)})
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.FailedPrecondition {
		// One pending request per pair: FailedPrecondition is either the
		// reverse rule or a block. Ask the core which, so the console sees
		// the pending incoming request instead of an unexplained failure.
		rel, rerr := b.Social.GetRelationship(ctx, &accountv1.GetRelationshipRequest{AccountId: fromID, OtherId: toID})
		if rerr == nil && rel.GetRelationship() == accountv1.Relationship_RELATIONSHIP_PENDING_INCOMING {
			return ErrReversePending
		}
	}
	return coreErr(err)
}

func (b *OpenpakBackend) FriendAccept(pid, from uint64, accept bool) error {
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
		_, err = b.Social.AcceptFriend(ctx, &accountv1.AcceptFriendRequest{
			AddresseeId: accountID, RequesterId: fromID, IdempotencyKey: "baas-accept"})
		return coreErr(err)
	}
	_, err = b.Social.RemoveFriend(ctx, &accountv1.RemoveFriendRequest{AccountId: accountID, OtherId: fromID})
	return coreErr(err)
}

// RemoveFriend ends a pending or accepted friendship from either side. The
// core is idempotent when absent, so a retried removal stays a success.
func (b *OpenpakBackend) RemoveFriend(pid, other uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accountID, err := b.accountForPID(ctx, pid)
	if err != nil {
		return err
	}
	otherID, err := b.accountForPID(ctx, other)
	if err != nil {
		return err
	}
	_, err = b.Social.RemoveFriend(ctx, &accountv1.RemoveFriendRequest{AccountId: accountID, OtherId: otherID})
	return coreErr(err)
}

// Block commits a durable directional block in the core. Blocking does not
// remove a friendship; enforcement denies interactions either way.
func (b *OpenpakBackend) Block(pid, other uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accountID, err := b.accountForPID(ctx, pid)
	if err != nil {
		return err
	}
	otherID, err := b.accountForPID(ctx, other)
	if err != nil {
		return err
	}
	_, err = b.Social.Block(ctx, &accountv1.BlockRequest{BlockerId: accountID, BlockedId: otherID})
	return coreErr(err)
}

// Unblock lifts a block this account made. Unblocking does not restore a
// friendship; only a new request does.
func (b *OpenpakBackend) Unblock(pid, other uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accountID, err := b.accountForPID(ctx, pid)
	if err != nil {
		return err
	}
	otherID, err := b.accountForPID(ctx, other)
	if err != nil {
		return err
	}
	_, err = b.Social.Unblock(ctx, &accountv1.UnblockRequest{BlockerId: accountID, BlockedId: otherID})
	return coreErr(err)
}

// coreErr translates core failures into the adapter's domain errors, so the
// HTTP layer maps them uniformly whichever backend answered.
func coreErr(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.InvalidArgument:
		return ErrCoreInvalid
	case codes.NotFound:
		return ErrCoreNotFound
	case codes.FailedPrecondition:
		return ErrStateConflict
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return ErrCoreUnavailable
	default:
		return ErrCoreInternal
	}
}

// nexToken signs the same "openpak" wire format the title servers verify; the
// key is ours (NEX_SIGNING_KEY), and title servers list this backend as a
// trusted issuer (PRD SW-03) — no shared vendor secret.
func (b *OpenpakBackend) NexToken(pid uint64, username string) string {
	if len(b.NexKey) == 0 {
		return ""
	}
	payload := fmt.Sprintf("%d.%s.%d", pid, username, time.Now().Add(30*24*time.Hour).Unix())
	mac := hmac.New(sha256.New, b.NexKey)
	mac.Write([]byte("nex:" + payload))
	return "nx2." + base64RawURL([]byte(payload)) + "." + base64RawURL(mac.Sum(nil))
}

func (b *OpenpakBackend) NexSigningKey() []byte { return b.NexKey }

func (b *OpenpakBackend) byPID(ctx context.Context, pid uint64) (*Projection, string, error) {
	b.Proj.Mu.Lock()
	accountID, ok := b.Proj.ByPID[pid]
	var pr *Projection
	if ok {
		pr = b.Proj.ByAccount[accountID]
	}
	b.Proj.Mu.Unlock()
	if !ok {
		return nil, "", errors.New("no projection for pid")
	}
	_ = ctx
	return pr, accountID, nil
}

// SetNickname makes a name a person chose on their console the account's display name,
// which is what the website, the app and every friend's console show.
func (b *OpenpakBackend) SetNickname(pid uint64, name string) error {
	if b.Register == nil {
		return errors.New("no registration client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accountID, err := b.accountForPID(ctx, pid)
	if err != nil {
		return err
	}
	_, err = b.Register.SetDisplayName(ctx, &accountv1.SetDisplayNameRequest{
		CallerNamespace: b.Namespace, AccountId: accountID, DisplayName: name})
	return err
}

func (b *OpenpakBackend) accountForPID(ctx context.Context, pid uint64) (string, error) {
	_, accountID, err := b.byPID(ctx, pid)
	return accountID, err
}

func (pr *Projection) nicknameOr(fallback string) string {
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

// onlineLease is short on purpose. A clean quit says goodbye and drops the
// session immediately, but a crash, a kill or a yanked cable say nothing at
// all, so "online" is a claim that lapses unless it keeps being renewed. Half
// a minute is the longest anyone should linger after their machine stopped
// talking; the client renews three times inside it, so one lost request is not
// somebody blinking offline.
const OnlineLease = 30 * time.Second

// Online records that an account is signed in to this network and playing
// nothing in particular: a session with no title, which the core counts toward
// who is online and deliberately not toward who is playing what.
//
// Best effort by design. Presence is not worth failing a console's login over,
// so a core that cannot be reached costs an accurate status page and nothing
// else.
//
// client is carried to the core with the session (see Presence.Client). The
// core prefers a titled session over this title-less one when answering
// presence, so a login landing after the game was registered does not hide it.
func (b *OpenpakBackend) Online(ctx context.Context, pid uint64, client, clientOS string) {
	if b == nil || b.Sessions == nil {
		return
	}
	accountID := b.AccountFor(pid)
	if accountID == "" {
		return
	}
	resp, err := b.Sessions.RegisterSession(ctx, &accountv1.RegisterSessionRequest{
		AccountId: accountID, Namespace: b.Namespace, TitleId: "", EndpointRef: "baas",
		LeaseSeconds: int32(OnlineLease.Seconds()), Client: client, Os: clientOS,
	})
	if err != nil {
		LogErr("presence register", err)
		return
	}
	// Kept only so a goodbye can name the session it is ending. Losing this map
	// on a restart costs nothing: the lease still lapses on its own.
	b.onlineMu.Lock()
	if b.online == nil {
		b.online = map[string]string{}
	}
	b.online[accountID] = resp.GetSessionId()
	b.onlineMu.Unlock()
}

// Offline ends the session at once, for the case where someone actually said
// they were leaving. Everything else — a crash, a kill, a network that went
// away — is covered by the lease, which is why this is an optimisation and not
// the mechanism.
func (b *OpenpakBackend) Offline(ctx context.Context, pid uint64) {
	if b == nil || b.Sessions == nil {
		return
	}
	accountID := b.AccountFor(pid)
	if accountID == "" {
		return
	}
	b.onlineMu.Lock()
	sessionID := b.online[accountID]
	delete(b.online, accountID)
	b.onlineMu.Unlock()

	if sessionID == "" {
		return
	}
	if _, err := b.Sessions.ExpireSession(ctx, &accountv1.ExpireSessionRequest{SessionId: sessionID}); err != nil {
		LogErr("presence expire", err)
	}
}

func (b *OpenpakBackend) AccountFor(pid uint64) string {
	b.Proj.Mu.Lock()
	defer b.Proj.Mu.Unlock()

	return b.Proj.ByPID[pid]
}
