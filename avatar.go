package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"nx-baas/redact"
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
			log.Printf("[nx-baas] avatar: could not reach the website: %v", redact.Err(err))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("[nx-baas] avatar: website answered %s", resp.Status)
			return
		}
		log.Printf("[nx-baas] avatar shared with the account for subject %s", redact.Tag(subject))
	}()
}

// fetchAvatar pulls the account's picture from the website's media store.
// Short timeout on purpose: a console waiting on a thumbnail should get the
// default quickly rather than a spinner.
func fetchAvatar(url string) ([]byte, error) {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("avatar: %s said %d", url, resp.StatusCode)
	}
	img, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if len(img) < 2 || img[0] != 0xFF || img[1] != 0xD8 {
		return nil, fmt.Errorf("avatar: %s did not return a JPEG", url)
	}
	return img, nil
}

// newerPicture answers "does this user have a picture, and when did it last
// change" across the two places one can be set: the console's own upload and
// the account's avatar on the website. Zero means neither, which is the only
// case where a console should be sent to /1/default.
func newerPicture(u *User, id *Identity) int64 {
	at := u.AvatarAt
	if u.Avatar != "" && at == 0 {
		at = u.UpdatedAt // uploaded before this field existed
	}
	if u.Avatar == "" {
		at = 0
	}
	if id != nil && id.ImageUpdatedAt > at {
		return id.ImageUpdatedAt
	}
	return at
}

// websitePictureAt asks the website when the account's picture last changed.
// A HEAD, so nothing downloads an image to answer a question about a date,
// and short: if the website cannot say, the console keeps whatever it has.
func websitePictureAt(url string) int64 {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return 0
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	t, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		return 0
	}
	return t.Unix()
}
