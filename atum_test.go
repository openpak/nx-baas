package main

// Atum content-delivery tests (SHP-04): authorization gates, ranges, hash manifest and
// the missing-content failure path.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// contentServerFor builds a shop whose fixture title carries one real content file, the
// way a placed package would: bytes on disk, pinned by hash in the catalog.
func contentServerFor(t *testing.T) (*server, []byte) {
	t.Helper()
	s := shopServerFor(t)
	content := make([]byte, 4096)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	dir := s.shop.dir
	if err := os.MkdirAll(filepath.Join(dir, "content"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "content", "test.bin")
	if err := os.WriteFile(file, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256Hex(content)
	s.shop.mu.Lock()
	title := s.shop.Catalog[testTitleID]
	title.Content = []ShopContent{{
		ContentID: "aa" + strings.Repeat("0", 30), File: "content/test.bin",
		Size: int64(len(content)), SHA256: sum,
	}}
	title.ControlPath = "content/test.bin"
	title.CNMTPath = "content/test.bin"
	s.shop.mu.Unlock()
	return s, content
}

func atumReq(s *server, method, host, path, deneb string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://"+host+path, nil)
	req.Host = host
	req.Header.Set("User-Agent", consoleUA())
	if deneb != "" {
		req.Header.Set("X-Nintendo-DenebEdgeToken", deneb)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// The c2 gate: no token, a foreign token, a token for another title, and finally the right
// token. Only the last serves bytes.
func TestAtumC2GateRequiresATokenBoundToTheTitle(t *testing.T) {
	s, content := contentServerFor(t)
	linkConsole(t, s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", naIDTokenFor(s), "")

	host := "atum.hac.lp1.d4c.nintendo.net"
	path := "/c2/" + testTitleID + "/c/c/" + "aa" + strings.Repeat("0", 30)

	if rec := atumReq(s, "GET", host, path, ""); rec.Code != 403 {
		t.Errorf("no token = %d, want 403", rec.Code)
	}
	other := s.dragonsEdgeToken(testDevice, []string{"0f9f0c0ffee00999"})
	if rec := atumReq(s, "GET", host, path, "Bearer "+other); rec.Code != 403 {
		t.Errorf("token for another title = %d, want 403", rec.Code)
	}
	mine := s.dragonsEdgeToken(testDevice, []string{testTitleID})
	rec := atumReq(s, "GET", host, path, "Bearer "+mine)
	if rec.Code != 200 {
		t.Fatalf("owned title with its token = %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != len(content) {
		t.Errorf("served %d bytes, want %d", rec.Body.Len(), len(content))
	}
}

// The c1 gate accepts the dauth-style dtoken shape: live exp, device in data=sub=....
func TestAtumC1AcceptsADtokenShape(t *testing.T) {
	s, content := contentServerFor(t)
	host := "atum.hac.lp1.d4c.nintendo.net"
	path := "/c1/" + testTitleID + "/c/c/" + "aa" + strings.Repeat("0", 30)

	if rec := atumReq(s, "GET", host, path, ""); rec.Code != 403 {
		t.Errorf("no dtoken = %d, want 403", rec.Code)
	}
	live := edgeDToken(timeNowUnix()+3600, testDevice)
	rec := atumReq(s, "GET", host, path, live)
	if rec.Code != 200 || rec.Body.Len() != len(content) {
		t.Errorf("live dtoken = %d (%d bytes)", rec.Code, rec.Body.Len())
	}
	expired := edgeDToken(timeNowUnix()-3600, testDevice)
	if rec := atumReq(s, "GET", host, path, expired); rec.Code != 403 {
		t.Errorf("expired dtoken = %d, want 403", rec.Code)
	}
}

// Resumable download: a byte range returns exactly those bytes, so an interrupted NIM
// transfer resumes instead of restarting (SHP-04).
func TestAtumRangeResumption(t *testing.T) {
	s, content := contentServerFor(t)
	mine := s.dragonsEdgeToken(testDevice, []string{testTitleID})
	host := "atum.hac.lp1.d4c.nintendo.net"
	path := "/c2/" + testTitleID + "/c/c/" + "aa" + strings.Repeat("0", 30)

	req := httptest.NewRequest("GET", "https://"+host+path, nil)
	req.Host = host
	req.Header.Set("User-Agent", consoleUA())
	req.Header.Set("X-Nintendo-DenebEdgeToken", "Bearer "+mine)
	req.Header.Set("Range", "bytes=100-199")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 206 {
		t.Fatalf("range = %d, want 206", rec.Code)
	}
	if got := rec.Body.Bytes(); string(got) != string(content[100:200]) {
		t.Errorf("range bytes do not match the source")
	}
	if cr := rec.Header().Get("Content-Range"); cr != fmt.Sprintf("bytes 100-199/%d", len(content)) {
		t.Errorf("Content-Range = %q", cr)
	}

	// A range past the clamped end returns the tail.
	req.Header.Set("Range", "bytes=4000-9999")
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 206 || rec.Body.Len() != len(content)-4000 {
		t.Errorf("tail range = %d (%d bytes)", rec.Code, rec.Body.Len())
	}
}

// The /d manifest declares the hash the catalog pinned — the value a client checks content
// against after download (metadata/hash consistency, SHP-04).
func TestAtumHashManifestMatchesTheCatalog(t *testing.T) {
	s, content := contentServerFor(t)
	mine := s.dragonsEdgeToken(testDevice, []string{testTitleID})
	rec := atumReq(s, "GET", "atum.hac.lp1.d4c.nintendo.net",
		"/c2/"+testTitleID+"/c/c/"+"aa"+strings.Repeat("0", 30)+"/d", "Bearer "+mine)
	if rec.Code != 200 {
		t.Fatalf("manifest = %d", rec.Code)
	}
	var m struct {
		Hashes []string `json:"partitioned_content_hashes"`
		Size   int64    `json:"content_size"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("manifest is not JSON: %v", err)
	}
	if len(m.Hashes) != 1 || m.Hashes[0] != sha256Hex(content) {
		t.Errorf("partitioned_content_hashes %v, want the catalog's pin", m.Hashes)
	}
	if m.Size != int64(len(content)) {
		t.Errorf("manifest size %d, want %d", m.Size, len(content))
	}
}

// SHP-05: a catalog row whose file vanished is the missing-content case — the download
// request fails and every open task for the title is marked failed, not stuck downloading.
func TestAtumMissingContentFailsOpenTasks(t *testing.T) {
	s, _ := contentServerFor(t)
	tok := naIDTokenFor(s)
	linkConsole(t, s)
	shopReq(s, "POST", "/ashigaru/api/v1/catalog/"+testTitleID+"/acquire", tok, "")
	rec := shopReq(s, "POST", "/ashigaru/api/v1/tasks", tok, `{"title_id":"`+testTitleID+`"}`)
	taskID := decodeBody(t, rec)["id"].(string)
	s.shop.updateTask(taskID, testNAID, "downloading", "")

	// The file vanishes from under the catalog.
	os.Remove(filepath.Join(s.shop.dir, "content", "test.bin"))

	mine := s.dragonsEdgeToken(testDevice, []string{testTitleID})
	host := "atum.hac.lp1.d4c.nintendo.net"
	path := "/c2/" + testTitleID + "/c/c/" + "aa" + strings.Repeat("0", 30)
	if rec := atumReq(s, "GET", host, path, "Bearer "+mine); rec.Code != 404 {
		t.Errorf("missing content = %d, want 404", rec.Code)
	}
	task := s.shop.task(taskID, testNAID)
	if task.State != "failed" || task.FailReason != "missing_content" {
		t.Errorf("task = %s/%s, want failed/missing_content", task.State, task.FailReason)
	}
}

// Control and CNMT routes resolve the catalog's named files.
func TestAtumControlAndCNMTRoutes(t *testing.T) {
	s, content := contentServerFor(t)
	mine := s.dragonsEdgeToken(testDevice, []string{testTitleID})
	for _, p := range []string{"/c2/a/d/" + testTitleID, "/c2/a/d/" + testTitleID + "/65536", "/c2/t/a/" + testTitleID + "/65536"} {
		rec := atumReq(s, "GET", "atum.hac.lp1.d4c.nintendo.net", p, "Bearer "+mine)
		if rec.Code != 200 || rec.Body.Len() != len(content) {
			t.Errorf("%s = %d (%d bytes)", p, rec.Code, rec.Body.Len())
		}
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// NIM's ApplicationControlTask takes the control content's identity from headers and
// rejects the body without them (2137-1311 on hardware); the CNMT step reads the content id
// and fetches /c/a/<that id>, which must then resolve even for a hand-placed file.
func TestAtumNamedRoutesCarryNimContentHeaders(t *testing.T) {
	s, content := contentServerFor(t)
	mine := s.dragonsEdgeToken(testDevice, []string{testTitleID})
	host := "atum.hac.lp1.d4c.nintendo.net"
	sum := sha256Hex(content)

	rec := atumReq(s, "GET", host, "/c2/a/d/"+testTitleID, "Bearer "+mine)
	h := rec.Header()
	if rec.Code != 200 || h.Get("X-Nintendo-Content-Hash") != sum || h.Get("X-Nintendo-Content-Id") != sum[:32] ||
		h.Get("X-Nintendo-Title-Version") == "" || h.Get("Content-Length") != fmt.Sprint(len(content)) {
		t.Fatalf("control = %d, headers %v", rec.Code, h)
	}

	rec = atumReq(s, "HEAD", host, "/c2/t/a/"+testTitleID+"/65536", "Bearer "+mine)
	cid := rec.Header().Get("X-Nintendo-Content-Id")
	if rec.Code != 200 || len(cid) != 32 {
		t.Fatalf("cnmt = %d, content id %q", rec.Code, cid)
	}
	rec = atumReq(s, "GET", host, "/c2/"+testTitleID+"/c/a/"+cid, "Bearer "+mine)
	if rec.Code != 200 || rec.Body.Len() != len(content) {
		t.Errorf("cnmt by id = %d (%d bytes)", rec.Code, rec.Body.Len())
	}
}
