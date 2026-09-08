package main

// The other console services, per kinnay's server list: news (BCAT) and online
// save storage (OLSC/SCSI). Both were reaching this server and being answered
// with a 404 and an empty object, which is what a console shows as an error
// rather than as "there is nothing here".
//
// Neither stores anything yet. An empty, correctly shaped answer is a true
// statement -- this network has no news and no cloud saves -- and it lets the
// console finish the screen instead of failing it. The saves PRD replaces the
// second one; the news PRD the first.

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// bcat serves the news service. The console asks per title and expects a
// content container; an empty topic list is "no news for this game".
func (s *server) bcat(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/topics"):
		writeJSON(w, 200, map[string]any{"topics": []any{}})
	case strings.HasSuffix(p, "/catalog"):
		writeJSON(w, 200, map[string]any{"topics": []any{}, "updatedAt": time.Now().Unix()})
	case strings.Contains(p, "/latest_news/"), strings.Contains(p, "/online_archives"):
		writeJSON(w, 200, map[string]any{"news": []any{}})
	default:
		dump(r, body, "!! UNHANDLED bcat")
		writeJSON(w, 200, map[string]any{})
	}
}

// olsc serves online save storage. Nothing is stored, so every list is empty
// and every upload is refused politely rather than 404'd: a console that gets
// a 404 here reports a save-data error, one that gets an empty list simply has
// no cloud saves.
func (s *server) olsc(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "notification_tokens"):
		// Echo the token back, which is what the documented reply carries.
		tok := bodyField(body, r.URL.Query(), "notification_token")
		writeJSON(w, 200, map[string]any{"notification_token": tok})
	case strings.HasSuffix(p, "/save_data_archives"):
		writeJSON(w, 200, map[string]any{"save_data_archives": []any{}})
	case strings.Contains(p, "/save_data_archives/"):
		// start_upload, finish_upload, generate_key_seed_package and the rest
		// of the upload dance. Cloud saves are the saves PRD's job; until then
		// the honest answer is that this archive does not exist.
		baasErr(w, r, 404, "resource_is_not_found", "Specified resource is not found", "Resource is not found")
	case strings.Contains(p, "/application_policy/"):
		// Whether a title may sync at all. "No" is the true answer today.
		writeJSON(w, 200, map[string]any{"application_policy": map[string]any{"save_data_backup": false}})
	default:
		dump(r, body, "!! UNHANDLED olsc")
		writeJSON(w, 200, map[string]any{})
	}
}

// serviceStatus is the "is this game's online service up" check. Saying yes for
// everything we serve is right; saying nothing at all reads as an outage.
func (s *server) serviceStatus(w http.ResponseWriter, r *http.Request, _ []byte) {
	log.Printf("[nx-baas] service status %s", r.URL.Path)
	writeJSON(w, 200, map[string]any{"status": "available", "type": "NORMAL"})
}
