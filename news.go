package main

// The News channel's two halves that live in this adapter: forwarding the console's News
// fetches to the news service, and pushing "this topic changed" to the consoles that
// follow it.
//
// Fetch. The bcat module fetches a followed topic's list from
// bcat-list-<env>.cdn.nintendo.net/api/nx/v1/list/<topic>?l=<lang>[&c[]=CC] and, for
// auto-subscription at title launch, bcat-topics-<env>.cdn.nintendo.net/api/nx/v1/titles/
// <tid>/topics [firmware, bcat; native-news-eshop-nso-gap-22.5.0 report]. Both documents
// are signed and encrypted by the news service, which is the only thing holding the News
// key, so this adapter does not answer them: with NEWS_INTERNAL_URL set it forwards the
// OpenPak topics (openpak_*) and the title topic lookups verbatim — path, query and the
// conditional/range headers in; status, headers and body out. Every other bcat path keeps
// bcat.go's answers, and with the variable unset nothing changes.
//
// Push. The module does not poll: a topic refreshes on an NPNS message
// {"type":"news","topic_id":…,"revision":…[,"wait_range":…]}, which schedules a fetch at a
// random delay within wait_range (default 3600 s) [firmware, bcat push parser]. Consoles
// subscribe topics over the Penne frontline (penne_conn.go records every SubscribeTopic).
// Which topic string the bcat module subscribes a followed News channel under is not
// recovered — the only topics seen on hardware so far are nx_data_<titleId>. So delivery
// here is keyed on the raw subscribed topic string: POST /internal/news/push names the
// topic, every live connection subscribed to exactly that string gets the message, and
// the subscriptions are logged so a console on hardware shows the naming. The message's
// Penne receiver is the bcat program id by the friends precedent (a module listens under
// its own id), overridable with NX_PENNE_NEWS_RECEIVER; that too is unconfirmed.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"nx-baas/internal/penne"
)

// newsForwarder carries the console's News fetches to the news service.
type newsForwarder struct {
	base   *url.URL
	client *http.Client
}

// newNewsForwarder builds the forwarder. The news service may speak TLS with its own
// private CA and a certificate issued for a Nintendo name (the experiment container does):
// caFile adds that CA and serverName is the name to verify against.
func newNewsForwarder(base, caFile, serverName string) (*newsForwarder, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%q is not an absolute URL", base)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// The body goes back to the console byte for byte, so no transparent gzip.
	tr.DisableCompression = true
	if caFile != "" || serverName != "" {
		conf := &tls.Config{ServerName: serverName}
		if caFile != "" {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("%s holds no certificate", caFile)
			}
			conf.RootCAs = pool
		}
		tr.TLSClientConfig = conf
	}
	return &newsForwarder{base: u, client: &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
		// A redirect is the news service's answer to the console, not ours to follow.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// newsForwardPath: the requests the news service owns. OpenPak topics are openpak_*; the
// title topic lookup is forwarded for every title, since the service answers an unknown
// title with its own signed empty list.
func newsForwardPath(host, p string) bool {
	switch {
	case strings.HasPrefix(host, "bcat-list"):
		return strings.HasPrefix(p, "/api/nx/v1/list/openpak_")
	case strings.HasPrefix(host, "bcat-topics"):
		return strings.HasPrefix(p, "/api/nx/v1/titles/") && strings.HasSuffix(p, "/topics")
	}
	return false
}

// newsForwardHeaders are the request headers that travel on: the conditional and range
// headers the module sends, and what identifies the console to the service's logs.
var newsForwardHeaders = []string{
	"If-None-Match", "If-Modified-Since", "Range", "If-Range", "Accept", "Accept-Language",
	"User-Agent", "X-Nintendo-Serial-Number",
}

// hopHeaders never travel through a proxy.
var hopHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

func (f *newsForwarder) forward(w http.ResponseWriter, r *http.Request) {
	target := *f.base
	target.Path = f.base.Path + r.URL.Path
	target.RawPath = ""
	target.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		http.Error(w, "bad news request", http.StatusBadRequest)
		return
	}
	for _, h := range newsForwardHeaders {
		for _, v := range r.Header.Values(h) {
			req.Header.Add(h, v)
		}
	}
	req.Header.Set("X-Forwarded-Host", hostOf(r))
	resp, err := f.client.Do(req)
	if err != nil {
		log.Printf("[news] forward %s%s: %v", hostOf(r), r.URL.RequestURI(), err)
		http.Error(w, "news service unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if hopHeaders[k] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	log.Printf("[news] %s %s%s -> %d (%d bytes, etag %s)", r.Method, shortHost(hostOf(r)), r.URL.RequestURI(),
		resp.StatusCode, n, resp.Header.Get("ETag"))
}

// ---------- push ----------

// newsReceiverToken is the Penne Meta routing token a news message is addressed to: the
// bcat program id, by the friends module's precedent (it listens under its own program
// id). Unconfirmed; NX_PENNE_NEWS_RECEIVER overrides it without a rebuild.
var newsReceiverToken = func() string {
	if v := os.Getenv("NX_PENNE_NEWS_RECEIVER"); v != "" {
		return v
	}
	return "0x010000000000000c"
}()

// POST /internal/news/push {"topic_id":"openpak_news","revision":7[,"wait_range":600]
// [,"subscription":"<raw topic>"]}
//
// Delivers {"type":"news","topic_id","revision"[,"wait_range"]} to every live connection
// subscribed to the topic. "subscription" names the Penne topic string when it differs
// from the News topic id (the naming is what hardware still has to show); without it the
// topic id itself is matched. Live delivery only: a console that is offline refreshes on
// its next boot anyway, and a stale revision is worthless.
func (s *server) newsPush(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	if r.Method != http.MethodPost {
		apiErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var in struct {
		TopicID      string      `json:"topic_id"`
		Revision     json.Number `json:"revision"`
		WaitRange    json.Number `json:"wait_range"`
		Subscription string      `json:"subscription"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.UseNumber()
	if err := dec.Decode(&in); err != nil || in.TopicID == "" || in.Revision == "" {
		apiErr(w, http.StatusBadRequest, "topic_id and revision required")
		return
	}
	msg := map[string]any{"type": "news", "topic_id": in.TopicID, "revision": in.Revision}
	if in.WaitRange != "" {
		msg["wait_range"] = in.WaitRange
	}
	body, _ := json.Marshal(msg)
	topic := in.Subscription
	if topic == "" {
		topic = in.TopicID
	}
	subscribers, delivered := s.deliverToTopic(strings.ToLower(topic), "news", string(body))
	log.Printf("[news] push %s revision %s -> topic %q: %d subscriber(s), %d connection(s)", in.TopicID, in.Revision, topic, subscribers, delivered)
	writeJSON(w, 200, map[string]any{"topic": topic, "subscribers": subscribers, "delivered": delivered})
}

// deliverToTopic writes one message to every live connection of every account that
// subscribed the topic on that connection's device. It returns how many subscriptions
// matched and how many connections the message was queued on.
func (s *server) deliverToTopic(topic, name, body string) (subscribers, delivered int) {
	subs := s.notifStore().TopicSubscribers(topic)
	subscribers = len(subs)
	if subscribers == 0 {
		return 0, 0
	}
	now := uint64(time.Now().Unix())
	frame := penne.BuildMessage(penne.Message{Name: name, Type: 1, Receivers: newsReceiverToken, Body: body}, now, now+penneSyncTTL)
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
