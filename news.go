package main

// The News channel's half that stays in this adapter: pushing "this topic changed" to the
// consoles that follow it. The News fetches themselves are nx-bcat's (the bcat hosts).
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
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

// ---------- push ----------

// newsReceiverToken is the Penne Meta routing token a news message is addressed to. bcat
// registers its npns listen key with ListenToByName("bcat") (23.0.1 bcat, rodata 0x3119e7),
// not its program id like friends; confirmed on Harbor 2026-10-16 (the frame reaches
// nn.bcat.EventWatcher and the list is fetched). NX_PENNE_NEWS_RECEIVER overrides it.
var newsReceiverToken = func() string {
	if v := os.Getenv("NX_PENNE_NEWS_RECEIVER"); v != "" {
		return v
	}
	return "bcat"
}()

// POST /internal/news/push {"topic_id":"openpak_news","revision":7[,"wait_range":600]
// [,"subscription":"<raw topic>"]}
//
// Delivers {"type":"news","topic_id","revision"[,"wait_range"]} (revision as a JSON string) to every live connection
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
	// bcat reads "$.revision" with its string getter and hashes it; a bare number is ignored
	// and nothing is fetched (23.0.1 bcat FUN_00206f50, proven on Harbor 2026-10-16).
	msg := map[string]any{"type": "news", "topic_id": in.TopicID, "revision": in.Revision.String()}
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
// matched and how many connections the message was queued on. The delivery itself is
// penne_link.go's: here, or in nx-penne once Penne has moved.
func (s *server) deliverToTopic(topic, name, body string) (subscribers, delivered int) {
	return s.penneTopicMessage(topic, name, newsReceiverToken, body)
}
