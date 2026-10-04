package main

// Parental controls once they have moved to nx-pctl (split.go): the pctl hosts and the
// website's /internal/pctl routes are forwarded, and a rollback file hands the records back.

import (
	"io"
	"net/http"
	"net/http/httptest"
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
	s := shopServerFor(t)
	s.store = pctlStore(t)
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

func TestPctlRollbackHandsTheRecordsBack(t *testing.T) {
	dir := t.TempDir()
	st := &Store{path: filepath.Join(dir, "baas.json"), Users: map[string]*User{}, Devices: map[string]*DeviceAccount{}, NaToPID: map[string]uint64{}}
	stale := st.PctlNewPairing("acct-parent")

	// nx-pctl's file: the same key, a record paired after the cut-over.
	other := &Store{path: filepath.Join(dir, "pctl-rollback.json")}
	d := other.PctlNewPairing("acct-parent")
	other.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa")

	st.importPctlRollback(filepath.Join(dir, "pctl-rollback.json"))
	if got := st.PctlByMoonID(d.Hex()); got == nil || got.DauthID != "cert-aaaaaaaaaaaaaaaa" {
		t.Fatalf("rolled-back record = %+v", got)
	}
	if st.PctlByMoonID(stale.Hex()) != nil {
		t.Fatal("the pre-cut-over record survived the rollback")
	}
	if _, err := os.Stat(filepath.Join(dir, "pctl-rollback.json")); !os.IsNotExist(err) {
		t.Fatal("the rollback file was left to be applied again")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "baas.json"))
	if !strings.Contains(string(b), d.Hex()) {
		t.Fatal("the rollback was not saved to baas.json")
	}
	// No file: nothing happens.
	st.importPctlRollback(filepath.Join(dir, "pctl-rollback.json"))
	if st.PctlByMoonID(d.Hex()) == nil {
		t.Fatal("a missing rollback file changed the records")
	}
}
