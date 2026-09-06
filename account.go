package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// OpenPak account server (openpak-account) client: the source of truth for identity, friend
// codes and the friend graph. Its /internal/* endpoints are guarded by source network
// (internal_net.conf), so this service must run on the same compose network.
type accountClient struct {
	base     string
	adminKey string
	secret   []byte
	http     *http.Client
}

type Friend struct {
	PID              uint64 `json:"pid"`
	BaasUserID       string `json:"baasUserID"`
	NaID             string `json:"naID"`
	Nickname         string `json:"nickname"`
	FriendCode       string `json:"friendCode"`
	Avatar           string `json:"avatar"`
	CreatedAt        int64  `json:"createdAt"`
	PresenceStatus   int    `json:"presenceStatus"`
	PresenceAppField string `json:"presenceAppField"`
	PresenceAppID    string `json:"presenceAppId"`
}

type Identity struct {
	PID            uint64   `json:"pid"`
	NaID           string   `json:"naID"`
	BaasUserID     string   `json:"baasUserID"`
	BsDid          string   `json:"bsDid"`
	Nickname       string   `json:"nickname"`
	FriendCode     string   `json:"friendCode"`
	Avatar         string   `json:"avatar"`
	ImageUpdatedAt int64    `json:"imageUpdatedAt"`
	PlayLog        any      `json:"playLog"`
	Friends        []Friend `json:"friends"`
	FriendRequests []Friend `json:"friendRequests"`
	SentRequests   []Friend `json:"sentRequests"`
}

func (a *accountClient) get(path string, out any) error {
	req, _ := http.NewRequest("GET", a.base+path, nil)
	if a.adminKey != "" {
		req.Header.Set("X-Internal-Key", a.adminKey)
	}
	res, err := a.http.Do(req)
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

func (a *accountClient) postJSON(path string, in any, out any) error {
	body, _ := json.Marshal(in)
	req, _ := http.NewRequest("POST", a.base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if a.adminKey != "" {
		req.Header.Set("X-Internal-Key", a.adminKey)
		req.Header.Set("X-Admin-Key", a.adminKey) // exempts /api/login from Turnstile
	}
	res, err := a.http.Do(req)
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

func (a *accountClient) Identity(pid uint64) (*Identity, error) {
	var id Identity
	if err := a.get(fmt.Sprintf("/internal/identity?pid=%d", pid), &id); err != nil {
		return nil, err
	}
	return &id, nil
}

// Resolve looks up any account by friend code or BAAS user id (16 hex).
func (a *accountClient) Resolve(q url.Values) (*Friend, error) {
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
func (a *accountClient) LoginPID(email, password string) (uint64, string, error) {
	var out struct {
		Account struct {
			PID      uint64 `json:"pid"`
			Username string `json:"username"`
		} `json:"account"`
	}
	if err := a.postJSON("/api/login", map[string]string{"Login": email, "Password": password}, &out); err != nil {
		return 0, "", err
	}
	return out.Account.PID, out.Account.Username, nil
}

func (a *accountClient) FriendRequest(from, to uint64) error {
	return a.postJSON("/internal/friend-request", map[string]uint64{"from": from, "to": to}, nil)
}

func (a *accountClient) FriendAccept(pid, from uint64, accept bool) error {
	return a.postJSON("/internal/friend-accept", map[string]any{"pid": pid, "from": from, "accept": accept}, nil)
}

// nexToken is openpak-account's signNexToken, byte for byte: the "openpak" claim the game servers
// (Photon, NPLN) use to bind a login to a PID. Shared OPENPAK_SECRET.
func (a *accountClient) nexToken(pid uint64, username string) string {
	if len(a.secret) == 0 {
		return ""
	}
	payload := fmt.Sprintf("%d.%s.%d", pid, username, time.Now().Add(30*24*time.Hour).Unix())
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte("nex:" + payload))
	return "nx2." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func logErr(what string, err error) {
	if err != nil {
		log.Printf("[nx-baas] account: %s: %v", what, err)
	}
}
