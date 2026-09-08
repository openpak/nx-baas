package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// An avatar is an account fact, not an adapter one. The console uploads its
// profile picture here, but the website and the app read avatars from the
// website's media store, so a picture that stopped at this service would show
// on a console and nowhere else.
//
// Best effort on purpose: the console is mid-setup when this happens, and a
// website that is down or unconfigured must not turn a working link into a
// failed one. The picture is kept locally either way, so nothing is lost if
// this call does not land.
func (s *server) shareAvatar(subject, base64JPEG string) {
	url, key := getenv("WEBSITE_INTERNAL_URL", ""), getenv("WEBSITE_INTERNAL_KEY", "")
	if url == "" || key == "" {
		return // not configured: the console still gets its picture back from here
	}
	body, err := json.Marshal(map[string]string{
		"namespace":      getenv("SWITCH_NAMESPACE", "switch"),
		"subject":        subject,
		"content_base64": base64JPEG,
	})
	if err != nil {
		return
	}
	go func() {
		req, err := http.NewRequest(http.MethodPost, url+"/internal/avatar", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			log.Printf("[nx-baas] avatar: could not reach the website: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("[nx-baas] avatar: website answered %s", resp.Status)
			return
		}
		log.Printf("[nx-baas] avatar shared with the account for subject %s", subject)
	}()
}
