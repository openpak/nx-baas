package main

// Console error reports: eupld, the Switch's error-report uploader, POSTs every report erpt
// collected to https://receive.hac.<env>.er.srv.nintendo.net/ [firmware, 22.5.0 eupld
// strings: that URL, "multipart/mixed", "Content-Type: application/x-msgpack",
// "Content-Disposition" with "attachment"/"filename", "Authorization: Bearer %s",
// "X-Nintendo-Error-Report-Share-Permission:%d"]. The report itself is a msgpack map whose
// keys are erpt's field names (ErrorCode, OsVersion, ApplicationID, OccurrenceTimestamp,
// ReportIdentifier, … [firmware, erpt 010000000000002b field-name table]). Fields erpt
// encrypts for Nintendo (EncryptionKey and the fields it covers) stay opaque bytes here.
//
// What happens to one:
//
//  1. The raw body is written to $NX_DATA/error-reports/raw/<id>.bin (with the request's
//     content type beside it) before anything is parsed, so nothing is ever lost to a
//     decoder bug.
//  2. What decodes is decoded: the msgpack parts become `fields`, the first non-msgpack part
//     (a screenshot or log) becomes the attachment. A shape this file does not expect is
//     logged with "!! ERROR REPORT" and forwarded with what could be read.
//  3. The website's crash ingest gets it: POST ${WEBSITE_INTERNAL_URL}/api/v1/internal/crash-reports
//     with X-Internal-Key: ${WEBSITE_INTERNAL_KEY}. The forward is spooled to
//     $NX_DATA/error-reports/spool/ first and retried until the website takes it; a 4xx
//     (other than 408/429) is a permanent refusal and moves the file to spool/rejected/.
//  4. The console gets a 200 as soon as step 1 succeeded: accepting the upload is what
//     clears its local queue (it retries a refused one forever).

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultErrorReportMax = 16 << 20 // a report plus a screenshot is well under this

type reportSpool struct {
	dir  string
	kick chan struct{}
	mu   sync.Mutex // one sender at a time
	http *http.Client
}

func newReportSpool(dir string) *reportSpool {
	return &reportSpool{dir: dir, kick: make(chan struct{}, 1), http: &http.Client{Timeout: 20 * time.Second}}
}

func (s *server) errorReports() *reportSpool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reports == nil {
		s.reports = newReportSpool(getenv("NX_DATA", "/data") + "/error-reports")
	}
	return s.reports
}

// errorReport serves the er host. Routed before the shared body read (main.go), which caps
// bodies at 1 MiB; a report with a screenshot can be larger.
func (s *server) errorReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		log.Printf("[error-report] UNMAPPED %s %s%s", r.Method, hostOf(r), r.URL.Path)
		http.Error(w, "no such route", 404)
		return
	}
	limit := int64(defaultErrorReportMax)
	if n, err := strconv.ParseInt(os.Getenv("NX_ERROR_REPORT_MAX_BYTES"), 10, 64); err == nil && n > 0 {
		limit = n
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		log.Printf("!! ERROR REPORT: reading upload: %v", err)
		http.Error(w, "report too large or truncated", http.StatusRequestEntityTooLarge)
		return
	}
	sp := s.errorReports()
	received := time.Now().UTC()
	rep := decodeErrorReport(r.Header.Get("Content-Type"), body)
	id := rep.id
	if id == "" {
		id = randHex(16)
	}
	if err := sp.keepRaw(id, r.Header.Get("Content-Type"), body); err != nil {
		// Not accepted if not kept: the console will upload it again.
		log.Printf("!! ERROR REPORT: keeping raw payload: %v", err)
		http.Error(w, "cannot store the report", 503)
		return
	}
	if v := r.Header.Get("X-Nintendo-Error-Report-Share-Permission"); v != "" {
		rep.fields["share_permission"] = v
	}
	device, account := s.reportIdentity(r)
	out := map[string]any{
		"source": "console", "received_at": received.Format(time.RFC3339),
		"device_id": device, "fields": rep.fields,
	}
	for k, v := range map[string]string{"account_id": account, "title_id": rep.titleID,
		"error_code": rep.errorCode, "firmware": rep.firmware, "message": rep.message} {
		if v != "" {
			out[k] = v
		}
	}
	if rep.attachment != nil {
		out["attachment_b64"] = base64.StdEncoding.EncodeToString(rep.attachment)
	}
	if err := sp.enqueue(id, out); err != nil {
		log.Printf("!! ERROR REPORT %s: spooling the forward: %v (raw payload kept)", id, err)
	}
	log.Printf("[error-report] %s: code=%s title=%s fw=%s device=%s account=%s, %d bytes, %d field(s)",
		id, rep.errorCode, rep.titleID, rep.firmware, device, account, len(body), len(rep.fields))
	w.WriteHeader(200)
}

// reportIdentity names the console and, when the bearer is one of our user tokens, the
// core account. The bearer eupld sends is not recovered: a device token names the device,
// a BAAS user token names the account; anything else leaves the User-Agent's did.
func (s *server) reportIdentity(r *http.Request) (device, account string) {
	if s.key != nil {
		if c := s.bearer(r); c != nil {
			sub := str(c, "sub")
			if n, ok := c["nintendo"].(map[string]any); ok {
				device = str(n, "di")
			}
			var u *User
			if s.store != nil {
				u = s.store.User(sub)
			}
			if u != nil {
				if src := s.banSrc(); src != nil {
					account = src.accountFor(u.PID)
				}
			} else if device == "" {
				device = sub
			}
		}
	}
	if device == "" {
		device = deviceIDFromUA(r.UserAgent())
	}
	if device == "" {
		device = "unknown"
	}
	return device, account
}

type decodedReport struct {
	fields                                    map[string]any
	id, titleID, errorCode, firmware, message string
	attachment                                []byte
}

// decodeErrorReport reads a multipart/mixed upload (or a bare msgpack body) into the
// forward's fields. It never fails: what it cannot read it says so about, loudly.
func decodeErrorReport(contentType string, body []byte) decodedReport {
	rep := decodedReport{fields: map[string]any{}}
	mt, params, err := mime.ParseMediaType(contentType)
	switch {
	case err == nil && strings.HasPrefix(mt, "multipart/"):
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		var attachments []map[string]any
		msgpacks := 0
		for i := 0; ; i++ {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Printf("!! ERROR REPORT: multipart part %d: %v", i, err)
				rep.fields["decode_error"] = err.Error()
				break
			}
			data, err := io.ReadAll(part)
			if err != nil {
				log.Printf("!! ERROR REPORT: multipart part %d body: %v", i, err)
				break
			}
			pct := part.Header.Get("Content-Type")
			if strings.Contains(pct, "msgpack") {
				m := decodeReportMsgpack(data)
				if msgpacks == 0 {
					for k, v := range m {
						rep.fields[k] = v
					}
				} else {
					rep.fields[fmt.Sprintf("part_%d", i)] = m
				}
				msgpacks++
				continue
			}
			attachments = append(attachments, map[string]any{
				"name": part.FileName(), "content_type": pct, "size": len(data)})
			if rep.attachment == nil {
				rep.attachment = data
			} else {
				log.Printf("[error-report] extra attachment %q (%s, %d bytes) kept in the raw payload only", part.FileName(), pct, len(data))
			}
		}
		if len(attachments) > 0 {
			rep.fields["attachments"] = attachments
		}
		if msgpacks == 0 {
			log.Printf("!! ERROR REPORT: multipart upload with no msgpack part (content type %q, %d bytes)", contentType, len(body))
		}
	case err == nil && strings.Contains(mt, "msgpack"):
		for k, v := range decodeReportMsgpack(body) {
			rep.fields[k] = v
		}
	default:
		log.Printf("!! ERROR REPORT: unknown upload shape: content type %q, %d bytes, starts %s",
			contentType, len(body), hex.EncodeToString(body[:min(len(body), 32)]))
		rep.fields["decode_error"] = "unrecognized content type " + contentType
	}
	rep.errorCode = fieldString(rep.fields["ErrorCode"])
	rep.firmware = fieldString(rep.fields["OsVersion"])
	rep.message = fieldString(rep.fields["ErrorDescription"])
	for _, k := range []string{"ApplicationID", "RunningApplicationId", "ProgramId"} {
		if t := titleIDOf(rep.fields[k]); t != "" {
			rep.titleID = t
			break
		}
	}
	if rid := fieldString(rep.fields["ReportIdentifier"]); rid != "" {
		// The report's own id makes a re-upload land on the same spool entry.
		clean := strings.Map(func(c rune) rune {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-' {
				return c
			}
			return -1
		}, rid)
		if len(clean) >= 16 && len(clean) <= 64 {
			rep.id = strings.ToLower(clean)
		}
	}
	return rep
}

// decodeReportMsgpack decodes one msgpack part to JSON-ready values (binary → base64).
func decodeReportMsgpack(b []byte) map[string]any {
	v, err := msgpackDecode(b)
	if err != nil {
		log.Printf("!! ERROR REPORT: msgpack part does not decode (%v); %d bytes starting %s",
			err, len(b), hex.EncodeToString(b[:min(len(b), 32)]))
		return map[string]any{"decode_error": err.Error()}
	}
	m, ok := v.(map[string]any)
	if !ok {
		log.Printf("!! ERROR REPORT: msgpack part is a %T, not a map", v)
		return map[string]any{"value": jsonReady(v)}
	}
	return jsonReady(m).(map[string]any)
}

func jsonReady(v any) any {
	switch t := v.(type) {
	case []byte:
		return base64.StdEncoding.EncodeToString(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = jsonReady(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = jsonReady(x)
		}
		return out
	}
	return v
}

func fieldString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimRight(t, "\x00")
	case int64, uint64:
		return fmt.Sprint(t)
	}
	return ""
}

// titleIDOf reads an application id however erpt stored it: a hex string (with or without
// 0x) or an integer.
func titleIDOf(v any) string {
	switch t := v.(type) {
	case string:
		s := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(strings.TrimRight(t, "\x00")), "0x"))
		if n, err := strconv.ParseUint(s, 16, 64); err == nil && n != 0 {
			return fmt.Sprintf("%016x", n)
		}
	case uint64:
		if t != 0 {
			return fmt.Sprintf("%016x", t)
		}
	case int64:
		if t > 0 {
			return fmt.Sprintf("%016x", t)
		}
	}
	return ""
}

// ---------- spool ----------

func (sp *reportSpool) keepRaw(id, contentType string, body []byte) error {
	dir := filepath.Join(sp.dir, "raw")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, id+".bin"), body, 0o600); err != nil {
		return err
	}
	meta, _ := json.Marshal(map[string]any{"content_type": contentType, "received_at": time.Now().UTC().Format(time.RFC3339)})
	return os.WriteFile(filepath.Join(dir, id+".meta.json"), meta, 0o600)
}

func (sp *reportSpool) enqueue(id string, payload map[string]any) error {
	dir := filepath.Join(sp.dir, "spool")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, id+".json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, id+".json")); err != nil {
		return err
	}
	select {
	case sp.kick <- struct{}{}:
	default:
	}
	return nil
}

// run forwards the spool now and then every minute, and prunes raw payloads past
// NX_ERROR_REPORT_KEEP_DAYS (default 30): a report can carry a serial number.
func (sp *reportSpool) run() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		sp.flush()
		sp.prune()
		select {
		case <-sp.kick:
		case <-t.C:
		}
	}
}

// flush sends every spooled report once. It returns how many went.
func (sp *reportSpool) flush() int {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	base, key := strings.TrimRight(getenv("WEBSITE_INTERNAL_URL", ""), "/"), getenv("WEBSITE_INTERNAL_KEY", "")
	dir := filepath.Join(sp.dir, "spool")
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) == 0 {
		return 0
	}
	if base == "" || key == "" {
		log.Printf("[error-report] %d report(s) spooled; WEBSITE_INTERNAL_URL/WEBSITE_INTERNAL_KEY unset, holding them", len(files))
		return 0
	}
	sent := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/internal/crash-reports", bytes.NewReader(b))
		if err != nil {
			log.Printf("!! ERROR REPORT forward: %v", err)
			return sent
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Internal-Key", key)
		resp, err := sp.http.Do(req)
		if err != nil {
			log.Printf("[error-report] forward failed (%v); %d still spooled, retrying later", err, len(files)-sent)
			return sent // the website is down: stop hammering it
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			os.Remove(f)
			sent++
		case resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 408 && resp.StatusCode != 429:
			// A refusal, not an outage: retrying cannot change the answer.
			rej := filepath.Join(dir, "rejected")
			os.MkdirAll(rej, 0o700)
			os.Rename(f, filepath.Join(rej, filepath.Base(f)))
			log.Printf("!! ERROR REPORT %s refused by the website: %s; moved to spool/rejected", filepath.Base(f), resp.Status)
		default:
			log.Printf("[error-report] website answered %s; retrying later", resp.Status)
			return sent
		}
	}
	if sent > 0 {
		log.Printf("[error-report] forwarded %d report(s) to the website", sent)
	}
	return sent
}

func (sp *reportSpool) prune() {
	days, err := strconv.Atoi(getenv("NX_ERROR_REPORT_KEEP_DAYS", "30"))
	if err != nil || days <= 0 {
		return
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	entries, _ := os.ReadDir(filepath.Join(sp.dir, "raw"))
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(sp.dir, "raw", e.Name()))
		}
	}
}
