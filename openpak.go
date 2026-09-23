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

	// account id -> the live "online" session, so a clean goodbye can end it.
	onlineMu sync.Mutex
	online   map[string]string
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

// accountForFriendCode resolves a Switch friend code to the OpenPak account
// that holds it. Codes are compared on their digits alone, so every way a
// person can type one -- "SW-1000-0000-0001", "sw100000000001", with spaces --
// finds the same account. The stored form keeps its dashes for display.
func (b *openpakBackend) accountForFriendCode(code string) (string, bool) {
	want := friendCodeDigits(code)
	if want == "" {
		return "", false
	}
	b.proj.mu.Lock()
	defer b.proj.mu.Unlock()
	for stored, accountID := range b.proj.ByCode {
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

func (b *openpakBackend) friendCodeForAccount(accountID string) (string, bool) {
	b.proj.mu.Lock()
	defer b.proj.mu.Unlock()
	pr, ok := b.proj.ByAccount[accountID]
	if !ok || pr.FriendCode == "" {
		return "", false
	}
	return pr.FriendCode, true
}

// RegenerateFriendCode mints a new code and retires the old one, so the code
// somebody handed out stops working -- which is the point of regenerating it.
func (b *openpakBackend) RegenerateFriendCode(pid uint64) error {
	b.proj.mu.Lock()
	defer b.proj.mu.Unlock()
	accountID, ok := b.proj.ByPID[pid]
	if !ok {
		return errors.New("no projection for that pid")
	}
	pr := b.proj.ByAccount[accountID]
	code, err := newFriendCode(b.proj)
	if err != nil {
		return err
	}
	delete(b.proj.ByCode, pr.FriendCode)
	pr.FriendCode = code
	b.proj.ByCode[code] = accountID
	b.proj.saveLocked()
	return nil
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
	// Copy the projection under the lock; the core call below must not hold
	// it (SOC-05: a global lock across per-friend network calls serialises a
	// whole friend list behind the slowest identity lookup).
	b.proj.mu.Lock()
	pr := b.proj.ByAccount[accountID]
	var prCopy *projection
	if pr != nil {
		c := *pr
		prCopy = &c
	}
	b.proj.mu.Unlock()
	if prCopy == nil {
		return nil
	}
	nick := prCopy.Nickname
	if displayName != "" {
		nick = displayName
	}
	f := &Friend{PID: prCopy.PID, BaasUserID: prCopy.BaasUserID, NaID: prCopy.NaID, FriendCode: prCopy.FriendCode,
		Nickname: nick, CreatedAt: prCopy.CreatedAt}
	// Country, same as a looked-up user gets. Without it a friend list entry
	// goes out with country "" -- which is the state the console refused in a
	// search result, and a friend list that stays empty after a friendship the
	// server thinks it made.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if acc, err := b.identity.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: accountID}); err == nil {
		f.Country = acc.GetCountry()
	} else {
		logErr("friendView get-account", err)
	}
	return f
}

func (b *openpakBackend) Resolve(q url.Values) (*Friend, error) {
	// Same rule as friendView: copy under the lock, network outside it.
	b.proj.mu.Lock()
	var accountID string
	switch {
	case q.Get("code") != "":
		accountID = b.proj.ByCode[q.Get("code")]
	case q.Get("baas") != "":
		accountID = b.proj.ByBaas[q.Get("baas")]
	}
	var prCopy *projection
	if pr := b.proj.ByAccount[accountID]; accountID != "" && pr != nil {
		c := *pr
		prCopy = &c
	}
	b.proj.mu.Unlock()
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
	if acc, err := b.identity.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: accountID}); err == nil {
		f.Country = acc.GetCountry()
	} else {
		logErr("resolve get-account", err) // silence here is why country stayed empty
	}
	return f, nil
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
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.FailedPrecondition {
		// One pending request per pair: FailedPrecondition is either the
		// reverse rule or a block. Ask the core which, so the console sees
		// the pending incoming request instead of an unexplained failure.
		rel, rerr := b.social.GetRelationship(ctx, &accountv1.GetRelationshipRequest{AccountId: fromID, OtherId: toID})
		if rerr == nil && rel.GetRelationship() == accountv1.Relationship_RELATIONSHIP_PENDING_INCOMING {
			return errReversePending
		}
	}
	return coreErr(err)
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
		return coreErr(err)
	}
	_, err = b.social.RemoveFriend(ctx, &accountv1.RemoveFriendRequest{AccountId: accountID, OtherId: fromID})
	return coreErr(err)
}

// RemoveFriend ends a pending or accepted friendship from either side. The
// core is idempotent when absent, so a retried removal stays a success.
func (b *openpakBackend) RemoveFriend(pid, other uint64) error {
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
	_, err = b.social.RemoveFriend(ctx, &accountv1.RemoveFriendRequest{AccountId: accountID, OtherId: otherID})
	return coreErr(err)
}

// Block commits a durable directional block in the core. Blocking does not
// remove a friendship; enforcement denies interactions either way.
func (b *openpakBackend) Block(pid, other uint64) error {
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
	_, err = b.social.Block(ctx, &accountv1.BlockRequest{BlockerId: accountID, BlockedId: otherID})
	return coreErr(err)
}

// Unblock lifts a block this account made. Unblocking does not restore a
// friendship; only a new request does.
func (b *openpakBackend) Unblock(pid, other uint64) error {
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
	_, err = b.social.Unblock(ctx, &accountv1.UnblockRequest{BlockerId: accountID, BlockedId: otherID})
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
		return errCoreInvalid
	case codes.NotFound:
		return errCoreNotFound
	case codes.FailedPrecondition:
		return errStateConflict
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return errCoreUnavailable
	default:
		return errCoreInternal
	}
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

// onlineLease is short on purpose. A clean quit says goodbye and drops the
// session immediately, but a crash, a kill or a yanked cable say nothing at
// all, so "online" is a claim that lapses unless it keeps being renewed. Half
// a minute is the longest anyone should linger after their machine stopped
// talking; the client renews three times inside it, so one lost request is not
// somebody blinking offline.
const onlineLease = 30 * time.Second

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
func (b *openpakBackend) Online(ctx context.Context, pid uint64, client string) {
	if b == nil || b.sessions == nil {
		return
	}
	accountID := b.accountFor(pid)
	if accountID == "" {
		return
	}
	resp, err := b.sessions.RegisterSession(ctx, &accountv1.RegisterSessionRequest{
		AccountId: accountID, Namespace: b.namespace, TitleId: "", EndpointRef: "baas",
		LeaseSeconds: int32(onlineLease.Seconds()), Client: client,
	})
	if err != nil {
		logErr("presence register", err)
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
func (b *openpakBackend) Offline(ctx context.Context, pid uint64) {
	if b == nil || b.sessions == nil {
		return
	}
	accountID := b.accountFor(pid)
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
	if _, err := b.sessions.ExpireSession(ctx, &accountv1.ExpireSessionRequest{SessionId: sessionID}); err != nil {
		logErr("presence expire", err)
	}
}

func (b *openpakBackend) accountFor(pid uint64) string {
	b.proj.mu.Lock()
	defer b.proj.mu.Unlock()

	return b.proj.ByPID[pid]
}
