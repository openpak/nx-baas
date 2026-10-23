// Surfaces the 22.5.0 modules reach that this adapter had no answer for.
//
// Every route here was found in a firmware module's own string table (NIM and
// the friends module; see internal research notes),
// which means a console can ask for it — an unanswered host is a TLS error and
// an unanswered path is our 404, and either can stall a native journey in a way
// that is hard to attribute afterwards. So each one is answered here with the
// smallest shape that is defensible, logged by name, and labelled with what it
// is for and what is still unknown about it.
//
// The rule these follow: an empty collection is a real answer ("you have none
// of these"), so it is given where the module asks "what do I have?". Where an
// answer would have to carry invented semantics — a licence, an entitlement, a
// signed anything — the request is recorded and refused instead, because a
// plausible lie is worse than a clear no.
//
// The eShop's own hosts (pearljam, idbe, bvc and the rest) are nx-shop's and never reach the
// handlers here (split.go). What stays is path-routed: the answers that need no catalog, and
// the two catalog questions (superfly's dv, acds search) and the friends module's app
// catalog, which are forwarded to nx-shop from whichever host asks them.
package main

import (
	"log"
	"net/http"
	"nx-baas/internal/httpx"
	"nx-baas/redact"
	"strings"
)

// nimUnserved answers the NIM routes that had no handler. They are grouped by
// what the module is asking, because that decides what an honest answer is.
//
// Returns false when the path is not one of them, so the caller can fall
// through to its own routing.
func (s *server) nimUnserved(w http.ResponseWriter, r *http.Request, body []byte) bool {
	p := r.URL.Path
	switch {
	// "Who in this family could lend me this title?" — the virtual-card
	// (vphym) lending surface [nim: /v1/accounts/vphyms,
	// /v1/accounts/vphym-borrowers/candidates, /v1/accounts/in-same-family].
	// OpenPak has no family groups, so nobody is in one and nobody can lend:
	// an empty candidate list is the true answer, not a placeholder.
	case p == "/v1/accounts/vphyms":
		log.Printf("[shop] nim %s %s -> no virtual cards (OpenPak has no family lending)", r.Method, redact.Path(p))
		httpx.WriteJSON(w, 200, map[string]any{"vphyms": []any{}})
		return true
	case p == "/v1/accounts/vphym-borrowers/candidates":
		log.Printf("[shop] nim %s %s -> no borrowers", r.Method, redact.Path(p))
		httpx.WriteJSON(w, 200, map[string]any{"candidates": []any{}})
		return true
	case strings.HasPrefix(p, "/v1/accounts/in-same-family"):
		log.Printf("[shop] nim %s %s -> not in a family", r.Method, redact.Path(p))
		httpx.WriteJSON(w, 200, map[string]any{"inSameFamily": false})
		return true

	// "Is another console of mine nearby?" — the local-transfer proximity
	// checks [nim: /v1/nearness-checks, /prune]. Nothing of ours brokers
	// device-to-device transfers, so there are no checks outstanding.
	case strings.HasPrefix(p, "/v1/nearness-checks"):
		log.Printf("[shop] nim %s %s -> no nearness checks", r.Method, redact.Path(p))
		httpx.WriteJSON(w, 200, map[string]any{"nearnessChecks": []any{}})
		return true

	// "Is there a system update?" [nim: /v1/system_update_meta?device_id=].
	// An empty list means "you are current", which is what we want a console
	// on OpenPak to believe: we serve no system images and must never point
	// one at an update it cannot get.
	case strings.HasPrefix(p, "/v1/system_update_meta"):
		log.Printf("[shop] nim %s %s -> no system update", r.Method, redact.Path(p))
		httpx.WriteJSON(w, 200, map[string]any{"system_update_metas": []any{}})
		return true
	// aqua: "which system version must I have before content delivery?"
	// [nim: aqua.hac.%.d4c.nintendo.net/required_system_update_meta?device_id=,
	// checker 0x218e40]. It is a gate, not a background check: NIM runs it first
	// in the download-task-list task (0x218a10, before pushmo), the version-list
	// task (tagaya) and the latest-version task (superfly), and any failure ends
	// the task. Any non-2xx fails it (a 404 left the console fetching nothing), so
	// does a body without both keys (0xa7889). NIM then looks the id up in the
	// console's BuiltInSystem content meta database: it must exist, be a
	// SystemUpdate meta, and its installed version must be >= the one sent, else
	// 0x2bc89. The SystemUpdate title at version 0 is therefore the "no
	// requirement, go ahead" answer on every console; we serve no system images,
	// so we never name a real floor.
	case strings.HasPrefix(p, "/required_system_update_meta"):
		log.Printf("[shop] nim aqua required system update device=%s -> none (0100000000000816 v0)", redact.Tag(r.URL.Query().Get("device_id")))
		httpx.WriteJSON(w, 200, map[string]any{
			"contents_delivery_required_title_id":      "0100000000000816",
			"contents_delivery_required_title_version": 0,
		})
		return true

	// Messages the shop would show the player [nim: /v1/direct-messages] and
	// the family/account notification fan-out [/v1/accounts/notify,
	// /v1/accounts/notify-to-family]. Nothing produces either yet.
	case strings.HasPrefix(p, "/v1/direct-messages"):
		log.Printf("[shop] nim %s %s -> no messages", r.Method, redact.Path(p))
		httpx.WriteJSON(w, 200, map[string]any{"messages": []any{}, "count": 0})
		return true
	case p == "/v1/accounts/notify", p == "/v1/accounts/notify-to-family":
		log.Printf("[shop] nim %s %s -> accepted, nothing to fan out", r.Method, redact.Path(p))
		w.WriteHeader(http.StatusOK)
		return true

	// "What versions of this application exist?" — NIM's update check on
	// superfly [nim: /v1/a/%016llx/dv, built at 0x1ecbe0; the reply is read by
	// the SAX handler at 0x3280e0]. Answered from the catalog in nx-shop.
	case strings.HasPrefix(p, "/v1/a/") && strings.HasSuffix(p, "/dv") && s.ShopFwd != nil:
		httpx.ForwardRead(s.ShopFwd, w, r, body) // the catalog lives in nx-shop (split.go)
		return true

	// The eShop's own catalogue search [nim: /v1/acds/search]. Answered from
	// the shop catalog in nx-shop rather than with an empty list: the console is
	// asking what this store has, and the store knows.
	case strings.HasPrefix(p, "/v1/acds/search") && s.ShopFwd != nil:
		httpx.ForwardRead(s.ShopFwd, w, r, body)
		return true
	}
	return false
}

// friendsAppCatalog answers the two routes the friends module fetches itself
// for a friend-request route or suggestion's external catalog id
// ("https://%s/v1/apps/%016llx%016llx/catalog.json" and ".../nx.jpg",
// host c-%.accounts.nintendo.com), matched here on the path before host
// routing claims it, so it answers on every host that reaches this server
// [friends-contract-22.5.0 §A.10]. The module only builds the nx.jpg URL and
// never downloads it. A catalog id this server does not carry renders as
// "unknown" instead of failing. The catalog is nx-shop's, so both are forwarded there.
func (s *server) friendsAppCatalog(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/v1/apps/") {
		return false
	}
	rest := strings.TrimPrefix(p, "/v1/apps/")
	appID, file, ok := strings.Cut(rest, "/")
	if !ok || appID == "" {
		return false
	}
	if s.ShopFwd != nil && (file == "catalog.json" || strings.HasSuffix(file, ".jpg") || strings.HasSuffix(file, ".png")) {
		s.ShopFwd.ServeHTTP(w, r) // the catalog lives in nx-shop (split.go)
		return true
	}
	return false
}
