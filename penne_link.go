package main

// The core's side of Penne once Penne has its own service (docs/service-split.md).
//
// The core keeps deciding what to tell whom -- friend events, presence visibility,
// invitations, news, bans -- and the push side keeps the registrations, the outbox and the
// connections. Every place the core touched the push state goes through one of the
// functions below. With NX_PENNE_URL unset they are the in-process calls they always were;
// set, they are calls to nx-penne's /internal/penne API (nx-common/nxapi's JSON).
//
// Calls nobody waits on for an answer -- a console binding, a push channel, a token
// binding, a notification from the core's event loop, a ban's close -- go through one
// ordered worker, so a slow or restarting nx-penne never holds up a console's login or the
// core's event poller. Calls whose answer matters (news and device pushes, which report how
// many connections took them; the shop's registration lookup) are synchronous with a short
// timeout.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nx-baas/internal/penne"
)

// penneRemote calls nx-penne's internal API.
type penneRemote struct {
	base  string
	http  *http.Client
	queue chan penneJob
}

type penneJob struct {
	what string
	run  func() error
}

func newPenneRemote(base string) *penneRemote {
	p := &penneRemote{
		base:  strings.TrimRight(base, "/"),
		http:  &http.Client{Timeout: 5 * time.Second},
		queue: make(chan penneJob, 4096),
	}
	go p.work()
	return p
}

// call sends in as JSON and decodes the reply into out (nil discards it).
func (p *penneRemote) call(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, p.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", getenv("NX_INTERNAL_KEY", getenv("OPENPAK_INTERNAL_KEY", "")))
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(msg))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// later queues a call nobody waits on. A full queue is a dead nx-penne: the job is dropped
// and said so, rather than blocking the caller.
func (p *penneRemote) later(what string, run func() error) {
	select {
	case p.queue <- penneJob{what, run}:
	default:
		log.Printf("[nx-baas] penne: queue to nx-penne is full; dropped %s", what)
	}
}

func (p *penneRemote) work() {
	for j := range p.queue {
		if err := j.run(); err != nil {
			log.Printf("[nx-baas] penne: %s to nx-penne failed: %v", j.what, err)
		}
	}
}

// ---------- the core's calls ----------

// penneBindConsole records which BAAS user is signed in on the console a device
// certificate names.
func (s *server) penneBindConsole(deviceID, userID string) {
	if p := s.penneRemote; p != nil {
		p.later("console binding", func() error {
			return p.call("POST", "/internal/penne/consoles", map[string]any{"device_id": deviceID, "user_id": userID}, nil)
		})
		return
	}
	s.notifStore().BindConsole(deviceID, userID)
}

// penneRecordPushChannel keeps the BAAS push_channels association.
func (s *server) penneRecordPushChannel(userID, deviceAccountID, service, deviceToken string) {
	if p := s.penneRemote; p != nil {
		p.later("push channel", func() error {
			return p.call("POST", "/internal/penne/push-channels", map[string]any{
				"user_id": userID, "device_account_id": deviceAccountID, "service": service, "device_token": deviceToken,
			}, nil)
		})
		return
	}
	s.notifStore().RecordPushChannel(userID, deviceAccountID, service, deviceToken, time.Now())
}

// penneSubmitRemote hands a checked notification to nx-penne. wait says whether the caller
// needs the outcome (the test route) or only that it was handed over (everything else).
func (s *server) penneSubmitRemote(d PenneDelivery, wait bool) PenneSubmission {
	p := s.penneRemote
	in := map[string]any{"id": d.ID, "user_id": d.UserID, "kind": d.Kind, "payload": d.Payload}
	if !wait {
		p.later("notification "+d.ID, func() error { return p.call("POST", "/internal/penne/notifications", in, nil) })
		return PenneSubmission{Accepted: true, Outcome: "handed_to_nx_penne", ID: d.ID}
	}
	var out struct {
		Accepted  bool   `json:"accepted"`
		Duplicate bool   `json:"duplicate"`
		Outcome   string `json:"outcome"`
		ID        string `json:"id"`
	}
	if err := p.call("POST", "/internal/penne/notifications", in, &out); err != nil {
		log.Printf("[nx-baas] notify: %s for %s -> nx-penne unreachable: %v", d.Kind, d.UserID, err)
		return PenneSubmission{Outcome: "nx_penne_unreachable", ID: d.ID}
	}
	return PenneSubmission{Accepted: out.Accepted, Duplicate: out.Duplicate, Outcome: penneOutcome(out.Outcome), ID: out.ID}
}

// penneTopicMessage writes one message to every live connection subscribed to a topic.
func (s *server) penneTopicMessage(topic, name, receivers, body string) (subscribers, delivered int) {
	if p := s.penneRemote; p != nil {
		var out struct{ Subscribers, Delivered int }
		if err := p.call("POST", "/internal/penne/topic-messages", map[string]any{
			"topic": topic, "name": name, "receivers": receivers, "body": body,
		}, &out); err != nil {
			log.Printf("[nx-baas] penne: topic message %q to nx-penne failed: %v", topic, err)
		}
		return out.Subscribers, out.Delivered
	}
	return s.localTopicMessage(topic, name, receivers, body)
}

// penneBindToken tells the push side which user a console profile's notification token
// belongs to (olsc's upload). The caller has checked the user exists.
func (s *server) penneBindToken(token, userID string) {
	if p := s.penneRemote; p != nil {
		p.later("token binding", func() error {
			return p.call("POST", "/internal/penne/token-bindings", map[string]any{"notification_token": token, "user_id": userID}, nil)
		})
		return
	}
	s.localBindToken(token, userID)
}

// penneCloseUser ends a BAAS user's live frontline connections (a ban).
func (s *server) penneCloseUser(userID string) {
	if p := s.penneRemote; p != nil {
		p.later("close "+userID, func() error {
			return p.call("POST", "/internal/penne/users/"+url.PathEscape(userID)+"/close", map[string]any{}, nil)
		})
		return
	}
	if s.penneHub != nil {
		if n := s.penneHub.closeUser(userID); n > 0 {
			log.Printf("[bans] closed %d notification connection(s) of user %s", n, userID)
		}
	}
}

// penneDeviceMessage writes one message to the live connections of one registration: the
// penne id when the caller has it, else the registration made under a device certificate.
func (s *server) penneDeviceMessage(penneID, dauthUser, name, receivers, body string) (string, int) {
	if p := s.penneRemote; p != nil {
		var out struct {
			PenneID     string `json:"penne_id"`
			Connections int    `json:"connections"`
		}
		if err := p.call("POST", "/internal/penne/device-messages", map[string]any{
			"penne_id": penneID, "dauth_user": dauthUser, "name": name, "receivers": receivers, "body": body,
		}, &out); err != nil {
			log.Printf("[nx-baas] penne: device message %s to nx-penne failed: %v", name, err)
		}
		return out.PenneID, out.Connections
	}
	return s.localDeviceMessage(penneID, dauthUser, name, receivers, body)
}

// penneRegistration is a registration's liveness, its user and every user on its console.
func (s *server) penneRegistration(penneID string) (live bool, userID string, users []string) {
	if p := s.penneRemote; p != nil {
		var out struct {
			Live   bool     `json:"live"`
			UserID string   `json:"user_id"`
			Users  []string `json:"users"`
		}
		if err := p.call("GET", "/internal/penne/registrations/"+url.PathEscape(penneID), nil, &out); err != nil {
			log.Printf("[nx-baas] penne: registration %s from nx-penne: %v", penneID, err)
		}
		return out.Live, out.UserID, out.Users
	}
	ps := s.notifStore()
	a := ps.AssocIfLive(penneID)
	if a == nil {
		return false, "", nil
	}
	return true, a.UserID, ps.UsersOn(penneID)
}

// ---------- the in-process halves ----------

// pennePushFrame is a kind-1 message addressed to a receiver token: what news and parental
// controls send a console.
func pennePushFrame(name, receivers, body string, now uint64) []byte {
	return penne.BuildMessage(penne.Message{Name: name, Type: 1, Receivers: receivers, Body: body}, now, now+penneSyncTTL)
}

// localTopicMessage is news.go's delivery, for any message name and receiver token.
func (s *server) localTopicMessage(topic, name, receivers, body string) (subscribers, delivered int) {
	subs := s.notifStore().TopicSubscribers(topic)
	subscribers = len(subs)
	if subscribers == 0 {
		return 0, 0
	}
	now := uint64(time.Now().Unix())
	frame := pennePushFrame(name, receivers, body, now)
	h := s.notifHub()
	h.mu.Lock()
	var targets []*penneSession
	for _, list := range h.sessions {
		for _, sess := range list {
			for _, sub := range subs {
				if (sub.DeviceID != "" && sub.DeviceID == sess.device) || (sub.DeviceID == "" && sub.UserID == sess.user) {
					targets = append(targets, sess)
					break
				}
			}
		}
	}
	h.mu.Unlock()
	for _, sess := range targets {
		sess.offer("", frame)
	}
	return subscribers, len(targets)
}

// localBindToken is services.go's binding: token -> profile (recorded at mint) -> user.
func (s *server) localBindToken(tok, userID string) bool {
	store := s.notifStore()
	if acct := store.TokenAccount(tok); acct != "" && store.BindAccount(acct, userID) {
		log.Printf("[nx-baas] penne: console account %s is %s (olsc token upload)", acct, userID)
		return true
	}
	return false
}

// localDeviceMessage is moon.go's push: the registration the token names (or the one made
// under the device certificate), and every live connection of it.
func (s *server) localDeviceMessage(penneID, dauthUser, name, receivers, body string) (string, int) {
	if penneID == "" && dauthUser != "" {
		penneID = s.notifStore().AssocIDForUser(dauthUser)
	}
	if penneID == "" {
		return "", 0
	}
	frame := pennePushFrame(name, receivers, body, uint64(time.Now().Unix()))
	h := s.notifHub()
	h.mu.Lock()
	var live []*penneSession
	for _, list := range h.sessions {
		for _, sess := range list {
			if sess.penneID == penneID {
				live = append(live, sess)
			}
		}
	}
	h.mu.Unlock()
	for _, sess := range live {
		sess.offer("", frame)
	}
	return penneID, len(live)
}
