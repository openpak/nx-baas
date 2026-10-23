package main

// Parental controls once they have moved to nx-pctl (split.go): the pctl hosts and the
// website's /internal/pctl routes are forwarded, and the records nx-baas kept before the move
// stay in baas.json byte for byte, because nx-pctl fingerprints them on import.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"nx-baas/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMovedPctlIsForwarded(t *testing.T) {
	type seen struct{ host, path string }
	got := make(chan seen, 8)
	pctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		got <- seen{r.Host, r.URL.Path}
		w.WriteHeader(299)
	}))
	defer pctl.Close()
	t.Setenv("NX_PCTL_URL", pctl.URL)
	t.Setenv("NX_INTERNAL_KEY", "test-internal-key")
	s := linkedServer(t)
	s.forwardersFromEnv()

	for _, c := range []seen{
		{"api-lp1.pctl.srv.nintendo.net", "/moon/v1/devices"},
		{"parentalcontrols-movie-lp1.cdn.nintendo.net", "/default/switchpc_en.mp4"},
	} {
		req := httptest.NewRequest("GET", "https://"+c.host+c.path, nil)
		req.Host = c.host
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != 299 {
			t.Fatalf("%s%s = %d, want it forwarded", c.host, c.path, rec.Code)
		}
		if g := <-got; g != c {
			t.Fatalf("reached nx-pctl as %+v", g)
		}
	}
	rec := identityDo(t, s, "POST", "/internal/pctl/pairing", `{"account_id":"a"}`)
	if rec.Code != 299 {
		t.Fatalf("/internal/pctl = %d, want it forwarded", rec.Code)
	}
	if g := <-got; g.path != "/internal/pctl/pairing" {
		t.Fatalf("reached nx-pctl as %+v", g)
	}
}

func TestPctlRecordsSurviveASaveVerbatim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baas.json")
	records := `{
  "0123456789abcdef": {
   "moonId": 81985529216486895,
   "dauthId": "cert-1",
   "unlockCode": "1234"
  }
 }`
	in := "{\n \"devices\": {},\n \"users\": {},\n \"naToPid\": {},\n \"pctlDevices\": " + records + "\n}"
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	st := store.Load(path)
	st.NewUser() // any write rewrites the whole file
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	if len(top["users"]) <= 2 {
		t.Fatalf("the store was not rewritten: %s", b)
	}
	if got := string(top["pctlDevices"]); got != records {
		t.Fatalf("pctlDevices after a save:\n%s\nwant:\n%s", got, records)
	}

	// A store that never had records does not grow the key.
	empty := filepath.Join(t.TempDir(), "baas.json")
	store.Load(empty).NewUser()
	b, _ = os.ReadFile(empty)
	if !strings.Contains(string(b), `"users"`) || strings.Contains(string(b), "pctlDevices") {
		t.Fatalf("a store without records wrote the key: %s", b)
	}
}
