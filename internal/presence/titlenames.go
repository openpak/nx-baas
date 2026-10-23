// SPDX-License-Identifier: AGPL-3.0-only
package presence

// Title names for friends who are playing on another platform.
//
// A Switch friend list draws a Switch friend's game from its own title id.
// For a friend on a Wii U or a 3DS it cannot, so the description line says
// what they are playing in words, and the words come from the website's
// catalogue (GET /internal/titles/name on WEBSITE_INTERNAL_URL), the same
// source the website and the app name titles from.
//
// A friend list must never wait on this: an unknown name starts one fetch in
// the background and the render says "a game" until it lands.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"nx-baas/internal/httpx"
	"strings"
	"sync"
	"time"
)

const (
	titleNameHitTTL  = 6 * time.Hour
	titleNameMissTTL = 10 * time.Minute
)

type TitleNameEntry struct {
	name string
	at   time.Time
	busy bool
}

type TitleNames struct {
	mu    sync.Mutex
	byKey map[string]*TitleNameEntry
	// fetch looks one name up; swapped in tests. ok=false means the website
	// could not answer (retry after the miss TTL), not that it has no name.
	fetch func(namespace, titleID string) (string, bool)
}

var SiteTitleNames = NewTitleNames(fetchTitleName)

// NewTitleNames is an empty name cache over fetch (tests pass their own).
func NewTitleNames(fetch func(namespace, titleID string) (string, bool)) *TitleNames {
	return &TitleNames{byKey: map[string]*TitleNameEntry{}, fetch: fetch}
}

// name answers from the cache and never blocks on the network.
func (t *TitleNames) Name(namespace, titleID string) string {
	if titleID == "" {
		return ""
	}
	key := strings.ToLower(namespace) + "/" + strings.ToUpper(titleID)
	t.mu.Lock()
	e := t.byKey[key]
	if e == nil {
		e = &TitleNameEntry{}
		t.byKey[key] = e
	}
	ttl := titleNameHitTTL
	if e.name == "" {
		ttl = titleNameMissTTL
	}
	stale := e.at.IsZero() || time.Since(e.at) > ttl
	name := e.name
	if stale && !e.busy {
		e.busy = true
		go func() {
			n, ok := t.fetch(namespace, titleID)
			t.mu.Lock()
			defer t.mu.Unlock()
			e.busy = false
			e.at = time.Now()
			if ok {
				e.name = n
			}
		}()
	}
	t.mu.Unlock()
	return name
}

func fetchTitleName(namespace, titleID string) (string, bool) {
	site, key := httpx.Getenv("WEBSITE_INTERNAL_URL", ""), httpx.Getenv("WEBSITE_INTERNAL_KEY", "")
	if site == "" || key == "" {
		return "", false
	}
	req, err := http.NewRequest(http.MethodGet, site+"/internal/titles/name?namespace="+
		url.QueryEscape(namespace)+"&title_id="+url.QueryEscape(titleID), nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var out struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return "", false
	}
	return out.Name, true
}
