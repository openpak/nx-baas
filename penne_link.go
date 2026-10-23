package main

// The core's side of Penne once Penne has its own service (docs/service-split.md).
//
// The core keeps deciding what to tell whom -- friend events, presence visibility,
// invitations, news, bans -- and the push side keeps the registrations, the outbox and the
// connections. Every place the core touched the push state goes through one of the
// functions below: calls to nx-penne's /internal/penne API (nx-common/nxapi's JSON) at
// NX_PENNE_URL, which main requires.
//
// Calls nobody waits on for an answer -- a console binding, a push channel, a token
// binding, a notification from the core's event loop, a ban's close -- go through one
// ordered worker, so a slow or restarting nx-penne never holds up a console's login or the
// core's event poller; the worker retries through an nx-penne restart. Calls whose answer matters (news and device pushes, which report how
// many connections took them) are synchronous with a short timeout. A server built without
// main's wiring (a test) has no nx-penne, and these do nothing.

import (
	"bytes"
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
		return retryable{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(msg))
		// nx-penne restarting behind a proxy, or failing, is worth waiting for. A 501 or
		// nx-penne saying it has no internal key is a deployment fault no retry mends.
		if resp.StatusCode >= 500 && resp.StatusCode != http.StatusNotImplemented &&
			!bytes.Contains(msg, []byte("internal_key_not_configured")) {
			return retryable{err}
		}
		return err
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

// retryable marks a failure worth trying again: nx-penne unreachable or answering 5xx.
type retryable struct{ error }

// penneRetryFor is the outage the worker waits out, shared by every job: a restart of
// nx-penne (seconds) loses nothing, the queue waiting behind the job being retried, in
// order. Past it nx-penne is down, not restarting: from then on a job is tried only when a
// probe is due (one every pennePauseProbe), and the rest are dropped at once, each said so,
// so a dead nx-penne costs the queue milliseconds per job rather than a minute each.
var (
	penneRetryFor   = time.Minute
	pennePauseProbe = 5 * time.Second
)

func (p *penneRemote) work() {
	var downSince, lastTry time.Time
	for j := range p.queue {
		wait := 250 * time.Millisecond
		for {
			if !downSince.IsZero() && time.Since(downSince) > penneRetryFor && time.Since(lastTry) < pennePauseProbe {
				log.Printf("[nx-baas] penne: nx-penne down since %s; dropped %s", downSince.Format(time.TimeOnly), j.what)
				break
			}
			lastTry = time.Now()
			err := j.run()
			var again retryable
			if err == nil || !errors.As(err, &again) {
				if !downSince.IsZero() {
					log.Printf("[nx-baas] penne: nx-penne answering again (down since %s)", downSince.Format(time.TimeOnly))
					downSince = time.Time{}
				}
				if err != nil {
					log.Printf("[nx-baas] penne: %s to nx-penne failed: %v", j.what, redact.Err(err))
				}
				break
			}
			if downSince.IsZero() {
				downSince = time.Now()
			}
			left := penneRetryFor - time.Since(downSince)
			if left <= 0 {
				log.Printf("[nx-baas] penne: %s to nx-penne failed: %v", j.what, redact.Err(err))
				break
			}
			time.Sleep(min(wait, left))
			wait = min(2*wait, 5*time.Second)
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
	}
}

// penneRecordPushChannel keeps the BAAS push_channels association.
func (s *server) penneRecordPushChannel(userID, deviceAccountID, service, deviceToken string) {
	if p := s.penneRemote; p != nil {
		p.later("push channel", func() error {
			return p.call("POST", "/internal/penne/push-channels", map[string]any{
				"user_id": userID, "device_account_id": deviceAccountID, "service": service, "device_token": deviceToken,
			}, nil)
		})
	}
}

// submit hands a checked notification to nx-penne. wait says whether the caller
// needs the outcome (the test route) or only that it was handed over (everything else).
func (p *penneRemote) submit(d PenneDelivery, wait bool) PenneSubmission {
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
		log.Printf("[nx-baas] notify: %s for %s -> nx-penne unreachable: %v", d.Kind, redact.Tag(d.UserID), redact.Err(err))
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
			log.Printf("[nx-baas] penne: topic message %q to nx-penne failed: %v", topic, redact.Err(err))
		}
		return out.Subscribers, out.Delivered
	}
	return 0, 0
}

// penneBindToken tells the push side which user a console profile's notification token
// belongs to (olsc's upload). The caller has checked the user exists.
func (s *server) penneBindToken(token, userID string) {
	if p := s.penneRemote; p != nil {
		p.later("token binding", func() error {
			return p.call("POST", "/internal/penne/token-bindings", map[string]any{"notification_token": token, "user_id": userID}, nil)
		})
	}
}

// penneCloseUser ends a BAAS user's live frontline connections (a ban).
func (s *server) penneCloseUser(userID string) {
	if p := s.penneRemote; p != nil {
		p.later("close "+userID, func() error {
			return p.call("POST", "/internal/penne/users/"+url.PathEscape(userID)+"/close", map[string]any{}, nil)
		})
	}
}
