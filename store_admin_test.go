package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const adminKey = "test-internal-key"
const adminTID = "0100abcd12340000"

// fakeNCA is random bytes and the content id the Switch derives from them: the first 16
// bytes of their SHA-256.
type fakeNCA struct {
	data []byte
	id   string
	sum  string
}

func newFakeNCA(t *testing.T, n int) fakeNCA {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return fakeNCA{data: b, id: hex.EncodeToString(h[:16]), sum: hex.EncodeToString(h[:])}
}

type pfsFile struct {
	name string
	data []byte
}

// buildPFS0 lays files out the way an NSP does.
func buildPFS0(files []pfsFile) []byte {
	var strs bytes.Buffer
	var entries bytes.Buffer
	var data bytes.Buffer
	for _, f := range files {
		binary.Write(&entries, binary.LittleEndian, uint64(data.Len()))
		binary.Write(&entries, binary.LittleEndian, uint64(len(f.data)))
		binary.Write(&entries, binary.LittleEndian, uint32(strs.Len()))
		binary.Write(&entries, binary.LittleEndian, uint32(0))
		strs.WriteString(f.name)
		strs.WriteByte(0)
		data.Write(f.data)
	}
	for strs.Len()%16 != 0 {
		strs.WriteByte(0)
	}
	var out bytes.Buffer
	out.WriteString("PFS0")
	binary.Write(&out, binary.LittleEndian, uint32(len(files)))
	binary.Write(&out, binary.LittleEndian, uint32(strs.Len()))
	binary.Write(&out, binary.LittleEndian, uint32(0))
	out.Write(entries.Bytes())
	out.Write(strs.Bytes())
	out.Write(data.Bytes())
	return out.Bytes()
}

func adminServer(t *testing.T) *server {
	t.Helper()
	t.Setenv("NX_INTERNAL_KEY", adminKey)
	return &server{shop: newShopState(t.TempDir())}
}

func adminDo(t *testing.T, s *server, method, path string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("X-Internal-Key", adminKey)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	s.gameAPI().ServeHTTP(rec, req)
	return rec
}

func adminJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return m
}

func createAdminTitle(t *testing.T, s *server) {
	t.Helper()
	body := `{"title_id":"` + adminTID + `","publisher":"Homebrew Dev","category":"tool",
	 "localized":{"en-US":{"name":"Brew","description":"A tool"}},"default_lang":"en-US",
	 "distribution":{"source":"https://example.org/brew","permission":"MIT, author's release"}}`
	rec := adminDo(t, s, "POST", "/internal/store/titles", []byte(body), "application/json")
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
}

// uploadBody builds the multipart request: metadata first, then the package.
func uploadBody(t *testing.T, meta any, nsp []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mp, _ := mw.CreateFormField("metadata")
	json.NewEncoder(mp).Encode(meta)
	fp, _ := mw.CreateFormFile("nsp", "title.nsp")
	fp.Write(nsp)
	mw.Close()
	return buf.Bytes(), mw.FormDataContentType()
}

func versionMetaFor(kind string, version uint32, label string, cnmt, program fakeNCA) map[string]any {
	return map[string]any{"kind": kind, "version": version, "version_label": label, "contents": []map[string]any{
		{"content_id": cnmt.id, "content_type": "meta", "size": len(cnmt.data), "sha256": cnmt.sum},
		{"content_id": program.id, "content_type": "program"},
	}}
}

func uploadVersion(t *testing.T, s *server, kind string, version uint32, label string) (cnmt, program fakeNCA, rec *httptest.ResponseRecorder) {
	t.Helper()
	cnmt, program = newFakeNCA(t, 700), newFakeNCA(t, 3000)
	nsp := buildPFS0([]pfsFile{{cnmt.id + ".cnmt.nca", cnmt.data}, {program.id + ".nca", program.data}, {cnmt.id + ".cnmt.xml", []byte("<xml/>")}})
	body, ct := uploadBody(t, versionMetaFor(kind, version, label, cnmt, program), nsp)
	return cnmt, program, adminDo(t, s, "POST", "/internal/store/titles/"+adminTID+"/versions", body, ct)
}

func TestStoreAdminRequiresTheInternalKey(t *testing.T) {
	s := &server{shop: newShopState(t.TempDir())}
	t.Setenv("NX_INTERNAL_KEY", "")
	t.Setenv("OPENPAK_INTERNAL_KEY", "")
	if rec := adminDo(t, s, "GET", "/internal/store/titles", nil, ""); rec.Code != 503 {
		t.Fatalf("no key configured = %d, want 503 (fail closed)", rec.Code)
	}
	t.Setenv("NX_INTERNAL_KEY", "other")
	if rec := adminDo(t, s, "GET", "/internal/store/titles", nil, ""); rec.Code != 401 {
		t.Fatalf("wrong key = %d, want 401", rec.Code)
	}
}

// The whole life of a title: created unpublished and invisible, a base uploaded and served
// out of the package at its offset, published, updated, stats counted, deleted.
func TestStoreAdminTitleLifecycle(t *testing.T) {
	s := adminServer(t)
	createAdminTitle(t, s)
	if rec := adminDo(t, s, "POST", "/internal/store/titles", []byte(`{"title_id":"`+adminTID+`","publisher":"x","localized":{"en":{"name":"x"}},"distribution":{"source":"a","permission":"b"}}`), ""); rec.Code != 409 {
		t.Fatalf("duplicate create = %d, want 409", rec.Code)
	}
	if s.shop.listed(adminTID) != nil {
		t.Fatal("a new title is listed before it is published")
	}
	if rec := adminDo(t, s, "POST", "/internal/store/titles/"+adminTID+"/publish", nil, ""); rec.Code != 409 || adminJSON(t, rec)["error"] != "no_base_version" {
		t.Fatalf("publish without a base = %d %s", rec.Code, rec.Body.String())
	}

	cnmt, program, rec := uploadVersion(t, s, "base", 0, "1.0.0")
	if rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body.String())
	}
	app := adminJSON(t, rec)["application"].(map[string]any)
	if got := len(app["content"].([]any)); got != 2 {
		t.Fatalf("registered %d contents, want 2 (the .cnmt.xml is not content)", got)
	}

	if rec := adminDo(t, s, "POST", "/internal/store/titles/"+adminTID+"/publish", nil, ""); rec.Code != 200 {
		t.Fatalf("publish = %d %s", rec.Code, rec.Body.String())
	}
	// atum serves the program NCA's exact bytes from inside the NSP, with ranges.
	live := edgeDToken(timeNowUnix()+3600, testDevice)
	host := "atum.hac.lp1.d4c.nintendo.net"
	got := atumReq(s, "GET", host, "/c1/"+adminTID+"/c/c/"+program.id, live)
	if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), program.data) {
		t.Fatalf("program NCA: %d, %d bytes, equal=%v", got.Code, got.Body.Len(), bytes.Equal(got.Body.Bytes(), program.data))
	}
	if cl := got.Header().Get("Content-Length"); cl != "3000" {
		t.Errorf("Content-Length %q, want 3000", cl)
	}
	req := httptest.NewRequest("GET", "https://"+host+"/c1/"+adminTID+"/c/c/"+program.id, nil)
	req.Host = host
	req.Header.Set("X-Nintendo-DenebEdgeToken", live)
	req.Header.Set("Range", "bytes=100-199")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != 206 || !bytes.Equal(rr.Body.Bytes(), program.data[100:200]) {
		t.Fatalf("range: %d %d bytes", rr.Code, rr.Body.Len())
	}
	// The CNMT route resolves to the meta content, and serving it counts a download.
	if got := atumReq(s, "GET", host, "/c1/t/a/"+adminTID+"/0", live); got.Code != 200 || !bytes.Equal(got.Body.Bytes(), cnmt.data) {
		t.Fatalf("cnmt route: %d", got.Code)
	}
	st := adminJSON(t, adminDo(t, s, "GET", "/internal/store/titles/"+adminTID+"/stats", nil, ""))
	if st["downloads"].(float64) != 1 || st["content_requests"].(float64) != 3 || st["bytes_served"].(float64) != 3000+100+700 {
		t.Fatalf("stats %v", st)
	}

	// An update: version list and superfly carry it; the same version again is refused.
	if _, _, rec := uploadVersion(t, s, "update", 65536, "1.0.1"); rec.Code != 201 {
		t.Fatalf("update = %d %s", rec.Code, rec.Body.String())
	}
	if _, _, rec := uploadVersion(t, s, "update", 65536, "1.0.1"); rec.Code != 409 {
		t.Fatalf("same update version again = %d, want 409", rec.Code)
	}
	tr := httptest.NewRequest("GET", "https://tagaya.hac.lp1.eshop.nintendo.net/tagaya/hac_versionlist", nil)
	tr.Host = "tagaya.hac.lp1.eshop.nintendo.net"
	tw := httptest.NewRecorder()
	s.ServeHTTP(tw, tr)
	if !strings.Contains(tw.Body.String(), `"id":"`+adminTID+`","required_version":0,"version":65536`) {
		t.Fatalf("version list: %s", tw.Body.String())
	}
	title := adminJSON(t, adminDo(t, s, "GET", "/internal/store/titles/"+adminTID, nil, ""))
	if title["version"].(float64) != 65536 || title["update"] == nil || title["base_version"].(float64) != 0 {
		t.Fatalf("title after update: %v", title)
	}

	// Everything survives a restart: state and catalog agree.
	again := newShopState(s.shop.dir)
	if tt := again.adminGet(adminTID); tt == nil || tt.Unpublished || tt.Patch == nil || len(tt.Content) != 2 {
		t.Fatalf("after restart: %+v", tt)
	}

	// Withdraw the update, unpublish, delete.
	if rec := adminDo(t, s, "DELETE", "/internal/store/titles/"+adminTID+"/versions/update", nil, ""); rec.Code != 200 || adminJSON(t, rec)["version"].(float64) != 0 {
		t.Fatalf("drop update = %d %s", rec.Code, rec.Body.String())
	}
	adminDo(t, s, "POST", "/internal/store/titles/"+adminTID+"/unpublish", nil, "")
	if got := atumReq(s, "GET", host, "/c1/"+adminTID+"/c/c/"+program.id, live); got.Code != 404 {
		t.Fatalf("unpublished content served: %d", got.Code)
	}
	if rec := adminDo(t, s, "DELETE", "/internal/store/titles/"+adminTID, nil, ""); rec.Code != 204 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(s.shop.dir, "content", adminTID)); !os.IsNotExist(err) {
		t.Fatalf("package directory survived the delete: %v", err)
	}
}

func TestStoreAdminPatchIsStrict(t *testing.T) {
	s := adminServer(t)
	createAdminTitle(t, s)
	rec := adminDo(t, s, "PATCH", "/internal/store/titles/"+adminTID, []byte(`{"publisher":"New Name","category":"game"}`), "")
	if rec.Code != 200 || adminJSON(t, rec)["publisher"] != "New Name" {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body.String())
	}
	if rec := adminDo(t, s, "PATCH", "/internal/store/titles/"+adminTID, []byte(`{"version":5}`), ""); rec.Code != 400 {
		t.Fatalf("patching a version field = %d, want 400", rec.Code)
	}
	if rec := adminDo(t, s, "PATCH", "/internal/store/titles/"+adminTID, []byte(`{"distribution":{"source":"x"}}`), ""); rec.Code != 400 {
		t.Fatalf("distribution without permission = %d, want 400", rec.Code)
	}
}

// Every verification the contract lists, each on its own package.
func TestStoreAdminUploadVerification(t *testing.T) {
	s := adminServer(t)
	createAdminTitle(t, s)
	cnmt, program := newFakeNCA(t, 500), newFakeNCA(t, 900)
	good := versionMetaFor("base", 0, "1.0.0", cnmt, program)
	wrongID := strings.Repeat("ab", 16)
	cases := []struct {
		name  string
		files []pfsFile
		meta  map[string]any
		code  string
	}{
		{"ticket", []pfsFile{{cnmt.id + ".cnmt.nca", cnmt.data}, {program.id + ".nca", program.data}, {"0100abcd123400000000000000000000.tik", []byte("t")}}, good, "rights_id_not_allowed"},
		{"id not the hash", []pfsFile{{cnmt.id + ".cnmt.nca", cnmt.data}, {wrongID + ".nca", program.data}}, good, "content_id_mismatch"},
		{"no cnmt", []pfsFile{{program.id + ".nca", program.data}}, good, "no_cnmt"},
		{"undeclared nca", []pfsFile{{cnmt.id + ".cnmt.nca", cnmt.data}, {program.id + ".nca", program.data}}, map[string]any{"kind": "base", "contents": []map[string]any{{"content_id": cnmt.id, "content_type": "meta"}}}, "content_mismatch"},
		{"declared size wrong", []pfsFile{{cnmt.id + ".cnmt.nca", cnmt.data}, {program.id + ".nca", program.data}}, map[string]any{"kind": "base", "contents": []map[string]any{{"content_id": cnmt.id, "content_type": "meta"}, {"content_id": program.id, "content_type": "program", "size": 1}}}, "size_mismatch"},
	}
	for _, c := range cases {
		body, ct := uploadBody(t, c.meta, buildPFS0(c.files))
		rec := adminDo(t, s, "POST", "/internal/store/titles/"+adminTID+"/versions", body, ct)
		if rec.Code != 422 || adminJSON(t, rec)["error"] != c.code {
			t.Errorf("%s: %d %s, want 422 %s", c.name, rec.Code, rec.Body.String(), c.code)
		}
	}
	body, ct := uploadBody(t, good, []byte("not a package at all"))
	if rec := adminDo(t, s, "POST", "/internal/store/titles/"+adminTID+"/versions", body, ct); adminJSON(t, rec)["error"] != "not_pfs0" {
		t.Errorf("garbage: %s", rec.Body.String())
	}
	// Nothing refused leaves a file behind.
	left, _ := filepath.Glob(filepath.Join(s.shop.dir, "content", adminTID, "*"))
	hidden, _ := filepath.Glob(filepath.Join(s.shop.dir, "content", adminTID, ".upload-*"))
	if len(left)+len(hidden) != 0 {
		t.Fatalf("refused uploads left files: %v %v", left, hidden)
	}
	// Metadata must come first.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fp, _ := mw.CreateFormFile("nsp", "x.nsp")
	fp.Write([]byte("PFS0"))
	mw.Close()
	if rec := adminDo(t, s, "POST", "/internal/store/titles/"+adminTID+"/versions", buf.Bytes(), mw.FormDataContentType()); rec.Code != 400 {
		t.Errorf("file before metadata = %d, want 400", rec.Code)
	}
}

func TestStoreAdminUploadSizeLimit(t *testing.T) {
	s := adminServer(t)
	createAdminTitle(t, s)
	t.Setenv("NX_SHOP_UPLOAD_MAX_BYTES", "2048")
	_, _, rec := uploadVersion(t, s, "base", 0, "1.0.0")
	if rec.Code != http.StatusRequestEntityTooLarge || adminJSON(t, rec)["error"] != "too_large" {
		t.Fatalf("oversized upload = %d %s", rec.Code, rec.Body.String())
	}
}

func TestStoreAdminAccountViews(t *testing.T) {
	s := adminServer(t)
	naID := "00112233aabbccdd"
	if _, _, err := s.shop.acquire(naID, "baas1", defaultFixtureID, "dev", 65536); err != nil {
		t.Fatal(err)
	}
	if _, err := s.shop.createTask(naID, defaultFixtureID); err != nil {
		t.Fatal(err)
	}
	ents := adminJSON(t, adminDo(t, s, "GET", "/internal/store/accounts/-/entitlements?na_id="+naID, nil, ""))
	if list := ents["entitlements"].([]any); len(list) != 1 || list[0].(map[string]any)["status"] != "active" {
		t.Fatalf("entitlements %v", ents)
	}
	tasks := adminJSON(t, adminDo(t, s, "GET", "/internal/store/accounts/-/tasks?na_id="+naID, nil, ""))
	if list := tasks["tasks"].([]any); len(list) != 1 || list[0].(map[string]any)["state"] != "queued" {
		t.Fatalf("tasks %v", tasks)
	}
	// Without the core backend an account id cannot be mapped: 404, not a guess.
	if rec := adminDo(t, s, "GET", "/internal/store/accounts/acc-1/entitlements", nil, ""); rec.Code != 404 {
		t.Fatalf("unmapped account = %d", rec.Code)
	}
	stats := adminJSON(t, adminDo(t, s, "GET", "/internal/store/stats", nil, ""))
	row := stats["titles"].([]any)[0].(map[string]any)
	if row["entitlements"].(float64) != 1 || row["tasks"].(map[string]any)["queued"].(float64) != 1 {
		t.Fatalf("stats %v", row)
	}
}

func TestStoreAdminIcon(t *testing.T) {
	s := adminServer(t)
	createAdminTitle(t, s)
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)
	rec := adminDo(t, s, "PUT", "/internal/store/titles/"+adminTID+"/icon", png, "image/png")
	if rec.Code != 200 || adminJSON(t, rec)["icon_path"] != "icons/"+adminTID+".png" {
		t.Fatalf("icon = %d %s", rec.Code, rec.Body.String())
	}
	if rec := adminDo(t, s, "PUT", "/internal/store/titles/"+adminTID+"/icon", []byte("hello"), "image/png"); rec.Code != 400 {
		t.Fatalf("non-image icon = %d", rec.Code)
	}
}

// A title's bundle is set through PATCH, validated, and written to catalog.json.
func TestStoreAdminBundle(t *testing.T) {
	s := adminServer(t)
	createAdminTitle(t, s)
	path := "/internal/store/titles/" + adminTID
	rec := adminDo(t, s, "PATCH", path, []byte(`{"bundle":[{"application_id":"0100AAAA00000000"},{"application_id":"0100bbbb00000000","is_upgrade_edition":true}]}`), "")
	if rec.Code != 200 {
		t.Fatalf("patch bundle = %d %s", rec.Code, rec.Body.String())
	}
	b, _ := adminJSON(t, rec)["bundle"].([]any)
	if len(b) != 2 || b[0].(map[string]any)["application_id"] != "0100aaaa00000000" || b[1].(map[string]any)["is_upgrade_edition"] != true {
		t.Errorf("bundle = %v", adminJSON(t, rec)["bundle"])
	}
	cat, _ := os.ReadFile(s.shop.dir + "/catalog.json")
	if !strings.Contains(string(cat), `"is_upgrade_edition": true`) {
		t.Errorf("catalog.json does not carry the bundle: %s", cat)
	}
	for _, bad := range []string{
		`{"bundle":[{"application_id":"` + adminTID + `"}]}`,
		`{"bundle":[{"application_id":"0100aaaa00000800"}]}`,
		`{"bundle":[{"application_id":"0100aaaa00000000"},{"application_id":"0100AAAA00000000"}]}`,
	} {
		if rec := adminDo(t, s, "PATCH", path, []byte(bad), ""); rec.Code != 400 {
			t.Errorf("patch %s = %d, want 400", bad, rec.Code)
		}
	}
	if rec := adminDo(t, s, "PATCH", path, []byte(`{"bundle":[]}`), ""); rec.Code != 200 || len(adminJSON(t, rec)["bundle"].([]any)) != 0 {
		t.Errorf("clearing the bundle = %d %s", rec.Code, rec.Body.String())
	}
}

// The bvc blocklist: replace, add, remove, validated, persisted, and served.
func TestStoreAdminFirmwareBlocklist(t *testing.T) {
	s := adminServer(t)
	const path = "/internal/store/firmware-blocklist"
	rec := adminDo(t, s, "PUT", path, []byte(`{"versions":[{"version":"14-0-0"},{"version":"13.0.0","note":"old"}]}`), "application/json")
	if rec.Code != 200 {
		t.Fatalf("put = %d %s", rec.Code, rec.Body.String())
	}
	if vs := adminJSON(t, rec)["versions"].([]any); len(vs) != 2 || vs[0].(map[string]any)["version"] != "13-0-0" {
		t.Errorf("versions = %v", vs)
	}
	if rec := adminDo(t, s, "PUT", path+"/22-1-0", nil, ""); rec.Code != 200 || len(adminJSON(t, rec)["versions"].([]any)) != 3 {
		t.Errorf("add = %d %s", rec.Code, rec.Body.String())
	}
	if rec := adminDo(t, s, "DELETE", path+"/14-0-0", nil, ""); rec.Code != 200 || len(adminJSON(t, rec)["versions"].([]any)) != 2 {
		t.Errorf("delete = %d %s", rec.Code, rec.Body.String())
	}
	if rec := adminDo(t, s, "DELETE", path+"/14-0-0", nil, ""); rec.Code != 404 {
		t.Errorf("delete missing = %d", rec.Code)
	}
	for _, bad := range []string{path + "/22-5", path + "/256-0-0", path + "/a-b-c"} {
		if rec := adminDo(t, s, "PUT", bad, nil, ""); rec.Code != 400 {
			t.Errorf("put %s = %d, want 400", bad, rec.Code)
		}
	}
	// Persisted, and bvc answers from it.
	s2 := &server{shop: newShopState(s.shop.dir)}
	if rec := adminDo(t, s2, "GET", path, nil, ""); len(adminJSON(t, rec)["versions"].([]any)) != 2 {
		t.Errorf("after restart = %s", rec.Body.String())
	}
	for v, want := range map[string]int{"/22-1-0": 200, "/13-0-0": 200, "/14-0-0": 404} {
		req := httptest.NewRequest("GET", "https://bvc-hac-lp1.cdn.nintendo.net"+v, nil)
		req.Host = "bvc-hac-lp1.cdn.nintendo.net"
		w := httptest.NewRecorder()
		s2.bvc(w, req)
		if w.Code != want {
			t.Errorf("bvc %s = %d, want %d", v, w.Code, want)
		}
	}
}
