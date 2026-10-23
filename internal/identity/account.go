package identity

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"nx-baas/redact"
	"strings"
	"time"
)

// OpenPak account server client: the source of truth for identity, friend
// codes and the friend graph. Its /internal/* endpoints are guarded by source network
// (internal_net.conf), so this service must run on the same compose network.
type AccountClient struct {
	Base     string
	AdminKey string
	Secret   []byte
	HTTP     *http.Client
}

type Friend struct {
	PID              uint64 `json:"pid"`
	Country          string `json:"country"`
	BaasUserID       string `json:"baasUserID"`
	NaID             string `json:"naID"`
	Nickname         string `json:"nickname"`
	FriendCode       string `json:"friendCode"`
	Avatar           string `json:"avatar"`
	CreatedAt        int64  `json:"createdAt"`
	PictureAt        int64  `json:"-"` // when the account's website picture last changed; 0 = none
	PresenceStatus   int    `json:"presenceStatus"`
	PresenceAppField string `json:"presenceAppField"`
	PresenceAppID    string `json:"presenceAppId"`
}

type Identity struct {
	PID        uint64 `json:"pid"`
	NaID       string `json:"naID"`
	BaasUserID string `json:"baasUserID"`
	BsDid      string `json:"bsDid"`
	Nickname   string `json:"nickname"`
	FriendCode string `json:"friendCode"`
	// The console's user object carries both and rejects it when either is malformed.
	Country  string `json:"country"`
	Birthday string `json:"birthday"`
	// The sign-in address, for users/me only (the openpak backend's GetAccount). Never marshalled
	// and never logged.
	Email  string `json:"-"`
	Avatar string `json:"avatar"`
	// AvatarURL is where the account's own picture lives when the adapter does
	// not hold the bytes: the website's media store. Fetched only when a
	// console actually asks for the thumbnail, never on the login path.
	AvatarURL      string   `json:"avatarURL"`
	ImageUpdatedAt int64    `json:"imageUpdatedAt"`
	PlayLog        any      `json:"playLog"`
	Friends        []Friend `json:"friends"`
	FriendRequests []Friend `json:"friendRequests"`
	SentRequests   []Friend `json:"sentRequests"`
}

func (a *AccountClient) get(path string, out any) error {
	req, _ := http.NewRequest("GET", a.Base+path, nil)
	if a.AdminKey != "" {
		req.Header.Set("X-Internal-Key", a.AdminKey)
	}
	res, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s -> %d %s", path, res.StatusCode, bytes.TrimSpace(b))
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func (a *AccountClient) postJSON(path string, in any, out any) error {
	body, _ := json.Marshal(in)
	req, _ := http.NewRequest("POST", a.Base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if a.AdminKey != "" {
		req.Header.Set("X-Internal-Key", a.AdminKey)
		req.Header.Set("X-Admin-Key", a.AdminKey) // exempts /api/login from Turnstile
	}
	res, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s -> %d %s", path, res.StatusCode, bytes.TrimSpace(b))
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

func (a *AccountClient) Identity(pid uint64) (*Identity, error) {
	var id Identity
	if err := a.get(fmt.Sprintf("/internal/identity?pid=%d", pid), &id); err != nil {
		return nil, err
	}
	return &id, nil
}

// Resolve looks up any account by friend code or BAAS user id (16 hex).
func (a *AccountClient) Resolve(q url.Values) (*Friend, error) {
	var out struct {
		Friend
		Found *bool `json:"found"`
	}
	if err := a.get("/internal/resolve?"+q.Encode(), &out); err != nil {
		return nil, err
	}
	if out.Found != nil && !*out.Found {
		return nil, fmt.Errorf("not found")
	}
	return &out.Friend, nil
}

// LoginPID checks a OpenPak e-mail + password (the "Link Nintendo Account" web page).
// The earlier account server speaks no second factor, so this never returns
// Need2FA: a 2FA account's posture here is whatever that server enforces, and
// alpha operation requires ACCOUNT_BACKEND=openpak (the OpenpakBackend path
// declares support and runs the second step). VerifySecondFactor on this
// backend always refuses rather than pretending.
func (a *AccountClient) LoginPID(email, password string) (LoginResult, error) {
	var out struct {
		Account struct {
			PID      uint64 `json:"pid"`
			Username string `json:"username"`
		} `json:"account"`
	}
	if err := a.postJSON("/api/login", map[string]string{"Login": email, "Password": password}, &out); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{PID: out.Account.PID, Username: out.Account.Username}, nil
}

// VerifySecondFactor has nothing to complete on the earlier account backend: fail
// closed instead of inventing a code check the account server never sees.
func (a *AccountClient) VerifySecondFactor(string, string, string) error {
	return ErrSecondFactorUnsupported
}

func (a *AccountClient) FriendRequest(from, to uint64) error {
	return a.postJSON("/internal/friend-request", map[string]uint64{"from": from, "to": to}, nil)
}

func (a *AccountClient) FriendAccept(pid, from uint64, accept bool) error {
	return a.postJSON("/internal/friend-accept", map[string]any{"pid": pid, "from": from, "accept": accept}, nil)
}

// RemoveFriend on the earlier account stack: its only lever is friend-accept with
// accept=false, which ends a pending request and is best-effort for an
// accepted friendship. The core contract request for a real removal there is
// in the ledger; until it lands, a removal that could not commit comes back
// as an error, never as a success.
func (a *AccountClient) RemoveFriend(pid, other uint64) error {
	return a.FriendAccept(pid, other, false)
}

// Block/Unblock on the earlier account stack: that core has no block contract, so the
// adapter's local mirror is the enforcement surface there. The openpak core —
// the target backend — owns the durable block; this is a documented
// limitation of the fallback backend, not a model to copy.
func (a *AccountClient) Block(uint64, uint64) error { return nil }

func (a *AccountClient) Unblock(uint64, uint64) error { return nil }

// nexToken matches the earlier account server's NEX token signing, byte for byte: the "openpak" claim the game servers
// (Photon, NPLN) use to bind a login to a PID. Shared OPENPAK_SECRET.
func (a *AccountClient) NexToken(pid uint64, username string) string {
	if len(a.Secret) == 0 {
		return ""
	}
	payload := fmt.Sprintf("%d.%s.%d", pid, username, time.Now().Add(30*24*time.Hour).Unix())
	mac := hmac.New(sha256.New, a.Secret)
	mac.Write([]byte("nex:" + payload))
	return "nx2." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *AccountClient) NexSigningKey() []byte { return a.Secret }

// The earlier account backend keeps no account-id projection: friend codes come from
// the account server there, and nothing asks this path for one.
func (a *AccountClient) FriendCodeForAccount(string) (string, bool) { return "", false }

func (a *AccountClient) AccountForFriendCode(string) (string, bool) { return "", false }

// Codes belong to the account server on this backend, which offers no way to
// regenerate one. Saying so beats pretending it worked.
func (a *AccountClient) RegenerateFriendCode(uint64) error {
	return errors.New("friend codes are the account server's on this backend")
}

func LogErr(what string, err error) {
	if err != nil {
		log.Printf("[nx-baas] account: %s: %v", what, redact.Err(err))
	}
}

// normaliseFriendCode accepts what a console sends (1234-5678-9012), what a
// person types (SW-1234-5678-9012, any case, spaces) and what we store.
func NormaliseFriendCode(code string) string {
	c := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	c = strings.TrimPrefix(c, "SW-")
	return "SW-" + c
}
