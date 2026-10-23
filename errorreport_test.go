package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"nx-baas/internal/core"
	"nx-baas/internal/msgpack"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// consoleReport is what eupld sends: multipart/mixed, a msgpack report part and a
// screenshot attachment.
func consoleReport(t *testing.T) ([]byte, string) {
	t.Helper()
	report := msgpack.Encode(map[string]any{
		"ErrorCode":           "2168-0002",
		"ApplicationID":       "01006f8002326000",
		"OsVersion":           "22.5.0",
		"PrivateOsVersion":    "22.5.0-1.0",
		"OccurrenceTimestamp": int64(1790000000),
		"ReportIdentifier":    "7f3c2a10-4b5d-4e6f-8a9b-0c1d2e3f4a5b",
		"EncryptionKey":       []byte{1, 2, 3, 4},
		"ProgramId":           "0100000000001000",
	})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", "application/x-msgpack")
	p, _ := mw.CreatePart(h)
	p.Write(report)
	h = textproto.MIMEHeader{}
	h.Set("Content-Type", "image/jpeg")
	h.Set("Content-Disposition", `attachment; filename="screenshot.jpg"`)
	p, _ = mw.CreatePart(h)
	p.Write([]byte("\xff\xd8\xff\xe0jpeg"))
	mw.Close()
	return buf.Bytes(), "multipart/mixed; boundary=" + mw.Boundary()
}

func postReport(s *server, body []byte, ct string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://receive.hac.lp1.er.srv.nintendo.net/", bytes.NewReader(body))
	r.Host = "receive.hac.lp1.er.srv.nintendo.net"
	r.Header.Set("Content-Type", ct)
	r.Header.Set("X-Nintendo-Error-Report-Share-Permission", "1")
	r.Header.Set("User-Agent", consoleUA())
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// fakeCrashIngest records what the website would receive and answers with status.
type fakeCrashIngest struct {
	mu     sync.Mutex
	status int
	got    []map[string]any
	keys   []string
}

func (f *fakeCrashIngest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/api/v1/internal/crash-reports" {
		w.WriteHeader(404)
		return
	}
	var m map[string]any
	b, _ := io.ReadAll(r.Body)
	json.Unmarshal(b, &m)
	f.keys = append(f.keys, r.Header.Get("X-Internal-Key"))
	if f.status == 0 {
		f.got = append(f.got, m)
		w.WriteHeader(201)
		return
	}
	w.WriteHeader(f.status)
}

func TestErrorReportIsDecodedKeptAndForwarded(t *testing.T) {
	ingest := &fakeCrashIngest{}
	site := httptest.NewServer(ingest)
	defer site.Close()
	t.Setenv("WEBSITE_INTERNAL_URL", site.URL)
	t.Setenv("WEBSITE_INTERNAL_KEY", "site-key")
	dir := t.TempDir()
	s := &server{Core: &core.Core{}, reports: newReportSpool(dir)}

	body, ct := consoleReport(t)
	if w := postReport(s, body, ct); w.Code != 200 {
		t.Fatalf("upload = %d", w.Code)
	}
	// Raw payload kept byte for byte, named by the report's own id.
	raw, err := os.ReadFile(filepath.Join(dir, "raw", "7f3c2a10-4b5d-4e6f-8a9b-0c1d2e3f4a5b.bin"))
	if err != nil || !bytes.Equal(raw, body) {
		t.Fatalf("raw payload: %v (equal=%v)", err, bytes.Equal(raw, body))
	}
	if n := s.reports.flush(); n != 1 {
		t.Fatalf("flushed %d, want 1", n)
	}
	if len(ingest.got) != 1 || ingest.keys[0] != "site-key" {
		t.Fatalf("website got %d report(s), key %v", len(ingest.got), ingest.keys)
	}
	m := ingest.got[0]
	want := map[string]any{"source": "console", "error_code": "2168-0002", "title_id": "01006f8002326000",
		"firmware": "22.5.0", "device_id": testDevice}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
	if _, ok := m["account_id"]; ok {
		t.Errorf("account_id sent with no account known: %v", m["account_id"])
	}
	fields := m["fields"].(map[string]any)
	if fields["OccurrenceTimestamp"].(float64) != 1790000000 || fields["EncryptionKey"] != base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4}) || fields["share_permission"] != "1" {
		t.Errorf("fields %v", fields)
	}
	if att, _ := base64.StdEncoding.DecodeString(m["attachment_b64"].(string)); string(att) != "\xff\xd8\xff\xe0jpeg" {
		t.Errorf("attachment %q", att)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "spool", "*.json")); len(left) != 0 {
		t.Errorf("forwarded reports still spooled: %v", left)
	}
}

// A website that is down keeps the report spooled; the next flush delivers it. A refusal
// (4xx) is permanent and parks the report instead of retrying forever.
func TestErrorReportSpoolRetriesAndParksRefusals(t *testing.T) {
	ingest := &fakeCrashIngest{status: 503}
	site := httptest.NewServer(ingest)
	defer site.Close()
	t.Setenv("WEBSITE_INTERNAL_URL", site.URL)
	t.Setenv("WEBSITE_INTERNAL_KEY", "k")
	dir := t.TempDir()
	s := &server{Core: &core.Core{}, reports: newReportSpool(dir)}
	body, ct := consoleReport(t)
	postReport(s, body, ct)

	if n := s.reports.flush(); n != 0 {
		t.Fatalf("sent %d to a website answering 503", n)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "spool", "*.json")); len(left) != 1 {
		t.Fatalf("report not kept for retry: %v", left)
	}
	ingest.mu.Lock()
	ingest.status = 0
	ingest.mu.Unlock()
	if n := s.reports.flush(); n != 1 || len(ingest.got) != 1 {
		t.Fatalf("retry sent %d", n)
	}

	ingest.mu.Lock()
	ingest.status = 400
	ingest.mu.Unlock()
	postReport(s, []byte{0x81, 0xa9, 'E', 'r', 'r', 'o', 'r', 'C', 'o', 'd', 'e', 0xa3, 'x', 'y', 'z'}, "application/x-msgpack")
	s.reports.flush()
	if parked, _ := filepath.Glob(filepath.Join(dir, "spool", "rejected", "*.json")); len(parked) != 1 {
		t.Fatalf("refused report not parked: %v", parked)
	}
}

// A shape nobody expected is still accepted, kept and forwarded with what was readable.
func TestErrorReportUnknownShapeIsKept(t *testing.T) {
	t.Setenv("WEBSITE_INTERNAL_URL", "")
	dir := t.TempDir()
	s := &server{Core: &core.Core{}, reports: newReportSpool(dir)}
	if w := postReport(s, []byte("<xml>what</xml>"), "text/xml"); w.Code != 200 {
		t.Fatalf("unknown shape = %d", w.Code)
	}
	spooled, _ := filepath.Glob(filepath.Join(dir, "spool", "*.json"))
	if len(spooled) != 1 {
		t.Fatalf("spool %v", spooled)
	}
	b, _ := os.ReadFile(spooled[0])
	if !strings.Contains(string(b), "decode_error") {
		t.Fatalf("forward does not say it could not decode: %s", b)
	}
	if raws, _ := filepath.Glob(filepath.Join(dir, "raw", "*.bin")); len(raws) != 1 {
		t.Fatalf("raw not kept: %v", raws)
	}
}

func TestTitleIDOfReadsEveryEncoding(t *testing.T) {
	for in, want := range map[any]string{
		"0x01006F8002326000": "01006f8002326000", "1006f8002326000": "01006f8002326000",
		uint64(0x01006f8002326000): "01006f8002326000", int64(0): "", "": "",
	} {
		if got := titleIDOf(in); got != want {
			t.Errorf("titleIDOf(%#v) = %q, want %q", in, got, want)
		}
	}
}
