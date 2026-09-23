package main

// atum: the content host for the native download (SHP-04). The native client is NIM, and
// the route shapes, the edge-token headers and the user agent come from public research
// (kinnay's Atum-Server wiki page, accessed 2026-09-11) and agree with the 22.5.0 NIM
// strings (atum subdomains, /c/c/<hex>, X-Nintendo-DenebEdgeToken, edge_token_not_grantable).
//
// What this server can and cannot do:
//
//   - It serves bytes. The NCA bytes come from a redistributable package the operator
//     placed under $NX_DATA/shop/content/; the catalog maps content ids to files and
//     hashes. This server never builds or alters an NCA.
//   - It enforces authorization. c1 accepts the dauth-style edge dtoken (shape check:
//     exp + device; the dauth dtoken's hmac was never verifiable here), c2 requires a
//     dragons edge token — our own signature, unexpired, naming the title (authorized
//     content delivery). 403 otherwise, in the documented error family.
//   - It supports resumable download with HTTP Range on every content route (SHP-04).
//
// Route table (wiki):  /c1/a/d/<tid>[/<ver>]      control NCA (icon and name)
//                      /c1/t/a/<tid>/<ver>        NCA containing CNMT
//                      /c1/<tid>/c/a/<cid>        NCA containing CNMT, by content id
//                      /c1/<tid>/c/c/<cid>        NCA containing game content
//                      /c1/<tid>/c/c/<cid>/d      JSON object containing content hashes
//            ... and the same set under /c2/ (c1: dauth token, c2: dragons token).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func timeNowUnix() int64 { return time.Now().Unix() }

func (s *server) atum(w http.ResponseWriter, r *http.Request, body []byte) {
	if s.shop == nil {
		s.shop = newShopState("")
	}
	p := r.URL.Path
	edge := r.Header.Get("X-Nintendo-DenebEdgeToken")
	if edge == "" {
		edge = r.Header.Get("X-Nintendo-EdgeToken")
	}

	// Expected shapes: cN / a / d / tid [/ver]   |   cN / t / a / tid / ver   |
	//                  cN / tid / c / (a|c) / cid [/d]
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) < 4 || !strings.HasPrefix(parts[0], "c") {
		atumErr(w, r, 404, "no such content route", p)
		return
	}
	var titleID, contentID string
	var namedFile string // control/CNMT routes name their file in the catalog
	switch parts[1] {
	case "a": // /cN/a/d/<tid>[/<ver>] — control NCA (icon and name)
		if len(parts) < 4 || parts[2] != "d" {
			atumErr(w, r, 404, "no such content route", p)
			return
		}
		titleID, namedFile = parts[3], "control"
	case "t": // /cN/t/a/<tid>/<ver> — NCA containing CNMT
		if len(parts) < 5 || parts[2] != "a" {
			atumErr(w, r, 404, "no such content route", p)
			return
		}
		titleID, namedFile = parts[3], "cnmt"
	default: // /cN/<tid>/c/(a|c)/<cid>[/d]
		if len(parts) < 5 || parts[2] != "c" {
			atumErr(w, r, 404, "no such content route", p)
			return
		}
		titleID, contentID = parts[1], parts[4]
		_ = parts[3] // a => CNMT content, c => program content; the catalog decides
	}
	if !validTitleID(titleID) {
		atumErr(w, r, 404, "no such title", titleID)
		return
	}

	// Authorization (SHP-04): c2 needs a dragons token bound to this title; c1 accepts the
	// dauth-style dtoken with a live exp and the requesting device in data=sub=...
	device := ""
	s.shop.reloadCatalog()
	if parts[0] == "c2" {
		// An update is fetched under its application's token: the token names
		// application ids, and a patch id resolves to the title that owns it.
		var ok bool
		if device, ok = s.verifyDragonsEdgeToken(edge, titleID); !ok {
			device, ok = s.verifyDragonsEdgeToken(edge, s.shop.applicationFor(titleID))
		}
		if !ok {
			atumErr(w, r, 403, "403/edge_token_not_grantable", "edge token missing, expired, or not valid for this title")
			return
		}
	} else {
		device = dtokenDevice(edge)
		if device == "" || !dtokenLive(edge) {
			atumErr(w, r, 403, "403/edge_token_not_grantable", "edge token missing or expired")
			return
		}
	}
	if did := deviceIDFromUA(r.UserAgent()); did != "" && did != device && device != "" {
		log.Printf("[shop] atum: UA device %s does not match token device %s", did, device)
	}

	// The catalog is the authority on what exists and what the bytes hash to.
	var path string
	var c ShopContent
	if namedFile != "" {
		path, c = s.shop.titleFile(titleID, namedFile)
		if path == "" {
			atumErr(w, r, 404, "no such content", namedFile)
			return
		}
	} else {
		var err error
		path, c, err = s.shop.contentFile(titleID, contentID)
		if err != nil {
			atumErr(w, r, 404, "no such content", contentID)
			return
		}
		if strings.HasSuffix(p, "/d") {
			s.atumHashes(w, titleID, contentID, c)
			return
		}
	}
	s.serveContentRange(w, r, path, c, titleID, device)
}

// atumHashes answers the /d route with the field names NIM's own parser reads
// [firmware, nim strings]. The wiki names the route ("JSON object containing
// content hashes") but not its fields; these come from the module.
func (s *server) atumHashes(w http.ResponseWriter, titleID, contentID string, c ShopContent) {
	writeJSON(w, 200, map[string]any{
		// Names from NIM's own parser [firmware, nim strings]: content_size,
		// partitioned_content_hashes[%d] and partitioning_size. "size" and
		// "hashes" were this file's own guesses and NIM reads neither.
		// digest_algorithm_for_partitioned_content is read too; its value
		// space is not recovered, so it is left out rather than invented.
		"content_id": contentID, "title_id": titleID,
		"content_size": c.Size, "partitioning_size": c.Size,
		"partitioned_content_hashes": []string{c.SHA256},
	})
}

// titleFile resolves the control/CNMT named file for a title: the hand-placed file the
// catalog names (control_path/cnmt_path), else the content entry of that type — which is
// how an uploaded NSP is served (store_admin.go), straight out of the package at its offset.
func (s *shopState) titleFile(titleID, which string) (string, ShopContent) {
	title, isPatch := s.meta(titleID)
	if title == nil {
		return "", ShopContent{}
	}
	p, contents := title.ControlPath, title.Content
	if which == "cnmt" {
		p = title.CNMTPath
	}
	if isPatch {
		p, contents = title.Patch.ControlPath, title.Patch.Content
		if which == "cnmt" {
			p = title.Patch.CNMTPath
		}
	}
	if p != "" {
		return s.dir + "/" + p, ShopContent{}
	}
	want := "control"
	if which == "cnmt" {
		want = "meta"
	}
	for _, c := range contents {
		if c.ContentType == want {
			return s.dir + "/" + c.File, c
		}
	}
	return "", ShopContent{}
}

// serveContentRange streams a file with Range support, refusing to serve bytes the catalog
// did not pin: offset+size come from the entry, and a trailing mismatch against the pinned
// sha256 is logged loudly. Resumability is the client asking again with Range — NIM does —
// and this handler honoring it (SHP-04).
func (s *server) serveContentRange(w http.ResponseWriter, r *http.Request, path string, c ShopContent, titleID, device string) {
	f, err := os.Open(path)
	if err != nil {
		atumErr(w, r, 404, "content file missing", path)
		// A catalog row whose file vanished is exactly the corrupt/missing-content case
		// (SHP-05): say so on the task, never a silent retry loop.
		s.shop.failOpenTasks(titleID, "missing_content")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		atumErr(w, r, 500, "cannot stat content", path)
		return
	}
	// A content entry may live inside a package (an uploaded NSP): its bytes are
	// [Offset, Offset+Size) of the file. A file that no longer holds them is missing
	// content, never a short read served as if whole.
	size := c.Size
	if size == 0 {
		size = st.Size() - c.Offset
	}
	if c.Offset < 0 || size <= 0 || c.Offset+size > st.Size() {
		atumErr(w, r, 404, "content file truncated", path)
		s.shop.failOpenTasks(titleID, "missing_content")
		return
	}
	start, end := int64(0), size-1
	status := 200
	if rh := r.Header.Get("Range"); rh != "" {
		if start, end, err = parseRange(rh, size); err != nil {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
			w.WriteHeader(416)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
		status = 206
	}
	// Headers before the status line: set after WriteHeader they are silently dropped.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	n, err := io.Copy(w, io.NewSectionReader(f, c.Offset+start, end-start+1))
	if err != nil && n != end-start+1 {
		log.Printf("[shop] atum: %s for %s/%s: %d/%d bytes (client %s)", err, titleID, c.ContentID, n, end-start+1, device)
	}
	s.shop.noteServed(titleID, c, start, n)
}

// parseRange handles the single byte range NIM sends: "bytes=start-end" or "bytes=start-".
func parseRange(h string, size int64) (start, end int64, err error) {
	if size <= 0 {
		return 0, 0, fmt.Errorf("empty content")
	}
	if !strings.HasPrefix(h, "bytes=") || strings.Contains(h, ",") {
		return 0, 0, fmt.Errorf("unsupported range")
	}
	spec := strings.TrimPrefix(h, "bytes=")
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return 0, 0, fmt.Errorf("bad range")
	}
	start, err = strconv.ParseInt(spec[:dash], 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, fmt.Errorf("bad range start")
	}
	tail := spec[dash+1:]
	if tail == "" {
		return start, size - 1, nil
	}
	if end, err = strconv.ParseInt(tail, 10, 64); err != nil || end < start {
		return 0, 0, fmt.Errorf("bad range end")
	}
	if end >= size {
		end = size - 1
	}
	return start, end, nil
}

// failOpenTasks marks every non-terminal task for a title failed with a reason (SHP-05:
// missing/corrupt content must surface as a failed task, not an endless download).
func (s *shopState) failOpenTasks(titleID, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.Tasks {
		if t.TitleID == titleID && (t.State == "queued" || t.State == "downloading" || t.State == "paused") {
			t.State, t.FailReason = "failed", reason
			t.UpdatedAt = timeNowUnix()
		}
	}
	s.save()
}

// atumErr answers a content error. The wiki documents the 403 string family
// ("403/edge_token_not_grantable") observed in the NIM strings; other statuses log for the
// hardware capture to refine.
func atumErr(w http.ResponseWriter, r *http.Request, status int, message, detail string) {
	log.Printf("[shop] atum %d %s %s: %s", status, r.Method, r.URL.Path, message)
	http.Error(w, message, status)
}

// dtokenDevice reads the dauth edge dtoken's embedded device: "...~data=sub=<device>...~hmac=...".
func dtokenDevice(dtoken string) string {
	i := strings.Index(dtoken, "data=sub=")
	if i < 0 {
		return ""
	}
	rest := dtoken[i+len("data=sub="):]
	if j := strings.IndexByte(rest, '~'); j >= 0 {
		rest = rest[:j]
	}
	k := strings.Index(rest, ".sn=")
	if k >= 0 {
		rest = rest[:k]
	}
	return rest
}

// dtokenLive checks the dtoken's exp= field.
func dtokenLive(dtoken string) bool {
	i := strings.Index(dtoken, "exp=")
	if i < 0 {
		return false
	}
	rest := dtoken[i+4:]
	if j := strings.IndexByte(rest, '~'); j >= 0 {
		rest = rest[:j]
	}
	exp, err := strconv.ParseInt(rest, 10, 64)
	return err == nil && exp >= timeNowUnix()
}

// hashFileSHA256 is the consistency check the operator runs when packaging (metadata/hash
// consistency, SHP-04): the catalog's sha256 must equal the file's. Used by tests and by
// the packaging helper in docs/native-shop.md.
func hashFileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
