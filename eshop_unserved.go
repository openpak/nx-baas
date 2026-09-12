// Surfaces the 22.5.0 modules reach that this adapter had no answer for.
//
// Every route here was found in a firmware module's own string table (NIM and
// the friends module; see docs/switch/firmware-22.5.0-followup-2026-09-12.md),
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
package main

import (
	"bytes"
	"image"
	"image/png"
	"log"
	"net/http"
	"strings"
)

// pearljam is the eShop host NIM names beside dragons and tigers
// [firmware, nim strings: "https://pearljam.hac.%.eshop.nintendo.net/civil"
// and "/sugar"]. What the two paths carry is not recovered: they are the only
// eShop endpoints in NIM whose request and response shapes we have never seen,
// and no console of ours has asked for one yet. Recording the full request is
// the point — the first console that does ask writes the specification for us.
func (s *server) pearljam(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	dump(r, body, "!! ESHOP pearljam (shape unrecovered; see docs/switch/firmware-22.5.0-followup-2026-09-12.md)")
	switch {
	case strings.HasPrefix(p, "/civil"), strings.HasPrefix(p, "/sugar"):
		// Answering 404 keeps the console's own error path intact rather than
		// feeding it an invented body it might act on.
		writeJSON(w, 404, map[string]any{"status": 404, "title": "not implemented",
			"detail": "pearljam " + p + " is recorded, not implemented: its contract is not recovered"})
	default:
		writeJSON(w, 404, map[string]any{"status": 404, "title": "not found"})
	}
}

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
		log.Printf("[shop] nim %s %s -> no virtual cards (OpenPak has no family lending)", r.Method, p)
		writeJSON(w, 200, map[string]any{"vphyms": []any{}})
		return true
	case p == "/v1/accounts/vphym-borrowers/candidates":
		log.Printf("[shop] nim %s %s -> no borrowers", r.Method, p)
		writeJSON(w, 200, map[string]any{"candidates": []any{}})
		return true
	case strings.HasPrefix(p, "/v1/accounts/in-same-family"):
		log.Printf("[shop] nim %s %s -> not in a family", r.Method, p)
		writeJSON(w, 200, map[string]any{"inSameFamily": false})
		return true

	// "Is another console of mine nearby?" — the local-transfer proximity
	// checks [nim: /v1/nearness-checks, /prune]. Nothing of ours brokers
	// device-to-device transfers, so there are no checks outstanding.
	case strings.HasPrefix(p, "/v1/nearness-checks"):
		log.Printf("[shop] nim %s %s -> no nearness checks", r.Method, p)
		writeJSON(w, 200, map[string]any{"nearnessChecks": []any{}})
		return true

	// "Has this device redeemed anything / which device am I targeting?"
	// [nim: /v1/devices/redeemed_status, /v1/devices/target/{set,clear}].
	case p == "/v1/devices/redeemed_status":
		log.Printf("[shop] nim %s %s -> nothing redeemed", r.Method, p)
		writeJSON(w, 200, map[string]any{"redeemed": false})
		return true
	case p == "/v1/devices/target/set", p == "/v1/devices/target/clear":
		log.Printf("[shop] nim %s %s -> accepted, no download targeting implemented", r.Method, p)
		w.WriteHeader(http.StatusOK)
		return true

	// "Is there a system update?" [nim: /v1/system_update_meta?device_id=].
	// An empty list means "you are current", which is what we want a console
	// on OpenPak to believe: we serve no system images and must never point
	// one at an update it cannot get.
	case strings.HasPrefix(p, "/v1/system_update_meta"):
		log.Printf("[shop] nim %s %s -> no system update", r.Method, p)
		writeJSON(w, 200, map[string]any{"system_update_metas": []any{}})
		return true

	// Messages the shop would show the player [nim: /v1/direct-messages] and
	// the family/account notification fan-out [/v1/accounts/notify,
	// /v1/accounts/notify-to-family]. Nothing produces either yet.
	case strings.HasPrefix(p, "/v1/direct-messages"):
		log.Printf("[shop] nim %s %s -> no messages", r.Method, p)
		writeJSON(w, 200, map[string]any{"messages": []any{}, "count": 0})
		return true
	case p == "/v1/accounts/notify", p == "/v1/accounts/notify-to-family":
		log.Printf("[shop] nim %s %s -> accepted, nothing to fan out", r.Method, p)
		w.WriteHeader(http.StatusOK)
		return true

	// The eShop's own catalogue search [nim: /v1/acds/search]. The response
	// shape is an ACD list whose fields we have not recovered; an empty result
	// is honest and lets the applet render "nothing found" instead of hanging.
	case strings.HasPrefix(p, "/v1/acds/search"):
		dump(r, body, "!! ESHOP acds/search (result shape unrecovered)")
		writeJSON(w, 200, map[string]any{"acds": []any{}, "count": 0, "original_count": 0})
		return true
	}
	return false
}

// friendsAppCatalog answers the two routes the friends module fetches itself
// for the title behind a friend's presence [firmware, friends strings:
// "https://%s/v1/apps/%016llx%016llx/catalog.json" and ".../<name>.jpg"].
// Without them a friend shown as PLAYING has no title name and no icon.
//
// The catalog document's fields are not recovered, so this serves the shape we
// can defend — the application id it was asked about and an empty localisation
// map — and a transparent 1x1 PNG for the art. Both are placeholders whose job
// is to keep the console's rendering path alive and say so in the log.
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
	switch {
	case file == "catalog.json":
		log.Printf("[nx-baas] friends app catalog for %s (placeholder: the document's fields are unrecovered)", appID)
		writeJSON(w, 200, map[string]any{
			"application_id":    appID,
			"application_names": map[string]any{},
		})
		return true
	case strings.HasSuffix(file, ".jpg"):
		log.Printf("[nx-baas] friends app art %s/%s (placeholder pixel)", appID, file)
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(placeholderPixel)
		return true
	}
	return false
}

// placeholderPixel is a 1x1 transparent PNG, encoded once at startup: the
// smallest thing that is a valid image, for art we do not have.
var placeholderPixel = func() []byte {
	var buf bytes.Buffer
	img := image.NewNRGBA(image.Rect(0, 0, 1, 1))
	if err := png.Encode(&buf, img); err != nil {
		return nil
	}
	return buf.Bytes()
}()
