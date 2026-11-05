package baas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"nx-baas/internal/httpx"
	"nx-baas/internal/identity"
	"nx-baas/internal/store"
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
// failed one. The picture is kept locally until the account has it (onShared
// then drops the local copy of a linked user), so nothing is lost if this call
// does not land.
func (s *Service) shareAvatar(subject, base64JPEG string, onShared func()) {
	url, key := httpx.Getenv("WEBSITE_INTERNAL_URL", ""), httpx.Getenv("WEBSITE_INTERNAL_KEY", "")
	if url == "" || key == "" {
		return // not configured: the console still gets its picture back from here
	}
	body, err := json.Marshal(map[string]string{
		"namespace":      httpx.Getenv("SWITCH_NAMESPACE", "switch"),
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
		if onShared != nil {
			onShared()
		}
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

// profileOps are the console's nickname and country edits out of one PATCH, empty when absent.
type profileOps struct{ nickname, country *string }

func ops2profile(ops []struct {
	Op, Path string
	Value    any
}) profileOps {
	var p profileOps
	for _, o := range ops {
		v, ok := o.Value.(string)
		if !ok || v == "" {
			continue
		}
		switch o.Path {
		case "/nickname":
			p.nickname = &v
		case "/country":
			p.country = &v
		}
	}
	return p
}

// shareProfile writes a linked user's nickname and country to the account core and
// reports which of them it took. A user with no core account, or a backend without
// one, shares nothing and the caller keeps the console's value locally.
func (s *Service) shareProfile(u *store.User, p profileOps) (nickOK, countryOK bool) {
	if u.PID == 0 || (p.nickname == nil && p.country == nil) {
		return false, false
	}
	w, ok := s.Acct.(identity.ProfileWriter)
	if !ok {
		return false, false
	}
	nickOK, countryOK, err := w.UpdateProfile(u.PID, p.nickname, p.country)
	if err != nil {
		log.Printf("[nx-baas] profile: the account refused part of a console edit (kept locally): %v", redact.Err(err))
	}
	if nickOK || countryOK {
		log.Printf("[nx-baas] profile edit shared with the account for %s", redact.Tag(u.ID))
	}
	return nickOK, countryOK
}
