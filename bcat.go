package main

// BCAT and the News channel, as the 22.5.0 `bcat` sysmodule (0x010000000000000c)
// actually speaks them. What was here before was a Wii-U-shaped guess: JSON
// objects with a `topics` array on any path ending in /topics. The module reads
// **msgpack**, from two fixed hosts, on two fixed routes, so that answer could
// only ever parse as garbage.
//
// The contract, recovered from the module (docs/firmware-22.5.0-followup-2026-09-12.md §21):
//
//	GET https://bcat-topics-<env>.cdn.nintendo.net/api/nx/v1/titles/<tid:016llx>/topics[?l=<lang>]
//	GET https://bcat-list-<env>.cdn.nintendo.net/api/nx/v1/list/nx_data_<tid:016llx>[?u=<uuid>&i=<sha1hex>]
//	GET https://<host>/api/nx/v1/list/<key>[?l=<lang>[&<news id>]]      (News channel)
//
// `<env>` is the environment identifier the firmware substitutes for `%` (lp1
// on retail). Both answers are msgpack documents; the module then downloads
// each file named by `$.directories[*].data_list[*].url` and checks it against
// the sibling `.digest`. Requests carry `X-Nintendo-Serial-Number`,
// `X-Nintendo-DenebEdgeToken` and `If-None-Match`/`Range`, and the user agent
// `libcurl (nnBcat; …; SDK 22.2.0.0)`.
//
// This network publishes no BCAT data and no news, and says so in the shape the
// module parses: in service, nothing to fetch. That is a true statement, not a
// placeholder — a title with no BCAT container and a News channel with no
// issues are exactly what an empty directories list means. When OpenPak starts
// publishing news, the documents grow entries here; the route table does not
// change.

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strings"
)

// bcat serves the two CDN hosts. Anything else on them is logged with its path
// rather than answered with a plausible-looking empty object: an unmapped BCAT
// route that returns 200 is indistinguishable from one that works.
func (s *server) bcat(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	switch {
	// Per-title topic document. Read fields (module FUN_00215590): $.topic_id,
	// $.na_required, $.test_distribution, $.service_status,
	// $.directories[0].data_list[].
	case strings.HasSuffix(p, "/topics"):
		tid := ""
		if seg := strings.Split(strings.Trim(p, "/"), "/"); len(seg) >= 2 {
			tid = seg[len(seg)-2]
		}
		log.Printf("[bcat] topics for title %s (%s)", tid, shortHost(hostOf(r)))
		s.bcatDoc(w, r, map[string]any{
			"service_status":    "in_service",
			"topic_id":          "",
			"na_required":       false,
			"test_distribution": false,
			"directories":       []any{},
		})
	// Data list, for a title (`nx_data_<tid>`) or for the News channel.
	// Read fields (module FUN_0019a010): $.required_application_version,
	// $.directories[*].{name,mode,digest}, and per entry
	// {filename,url,size,digest,data_id}.
	case strings.Contains(p, "/v1/list/"):
		key := p[strings.LastIndex(p, "/")+1:]
		log.Printf("[bcat] list %s l=%q (%s)", key, r.URL.Query().Get("l"), shortHost(hostOf(r)))
		s.bcatDoc(w, r, map[string]any{
			"required_application_version": 0,
			"directories":                  []any{},
		})
	default:
		dump(r, body, "!! UNHANDLED bcat route (docs/firmware-22.5.0-followup-2026-09-12.md §21)")
		http.Error(w, "no such bcat route", 404)
	}
}

// bcatDoc writes a msgpack document with the ETag the module's conditional GET
// wants: it stores the ETag in `<mount>:/etag.bin` and sends it back as
// If-None-Match, so an unchanged document costs one 304 instead of a download
// on every poll.
func (s *server) bcatDoc(w http.ResponseWriter, r *http.Request, doc map[string]any) {
	b := msgpack(doc)
	sum := sha1.Sum(b)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/x-msgpack")
	w.WriteHeader(200)
	w.Write(b)
}

// msgpack encodes the subset these documents use: string-keyed maps, strings,
// integers, booleans and arrays. ponytail: no dependency for four type tags —
// add one the day a document needs floats or binary.
func msgpack(v any) []byte {
	var out []byte
	switch t := v.(type) {
	case nil:
		out = append(out, 0xc0)
	case bool:
		if t {
			out = append(out, 0xc3)
		} else {
			out = append(out, 0xc2)
		}
	case string:
		out = append(out, msgpackLen(0xa0, 0xd9, 0xda, 0xdb, len(t))...)
		out = append(out, t...)
	case int:
		out = append(out, msgpackInt(int64(t))...)
	case int64:
		out = append(out, msgpackInt(t)...)
	case uint64:
		if t <= math.MaxInt64 {
			out = append(out, msgpackInt(int64(t))...)
			break
		}
		out = append(out, 0xcf)
		out = binary.BigEndian.AppendUint64(out, t)
	case []any:
		out = append(out, msgpackLen(0x90, 0, 0xdc, 0xdd, len(t))...)
		for _, e := range t {
			out = append(out, msgpack(e)...)
		}
	case map[string]any:
		out = append(out, msgpackLen(0x80, 0, 0xde, 0xdf, len(t))...)
		// Sorted so the ETag is a function of the document, not of Go's map order.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, msgpack(k)...)
			out = append(out, msgpack(t[k])...)
		}
	default:
		panic(fmt.Sprintf("msgpack: unsupported %T", v))
	}
	return out
}

// msgpackLen writes the fix/8/16/32 header for a length-prefixed type. `f8` is
// 0 for arrays and maps, which have no 8-bit form.
func msgpackLen(fix, f8, f16, f32 byte, n int) []byte {
	limit := 15
	if fix == 0xa0 {
		limit = 31
	}
	switch {
	case n <= limit:
		return []byte{fix | byte(n)}
	case f8 != 0 && n <= math.MaxUint8:
		return []byte{f8, byte(n)}
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16([]byte{f16}, uint16(n))
	default:
		return binary.BigEndian.AppendUint32([]byte{f32}, uint32(n))
	}
}

func msgpackInt(n int64) []byte {
	switch {
	case n >= 0 && n <= 127:
		return []byte{byte(n)}
	case n < 0 && n >= -32:
		return []byte{byte(n)}
	case n >= math.MinInt8 && n <= math.MaxInt8:
		return []byte{0xd0, byte(n)}
	case n >= math.MinInt16 && n <= math.MaxInt16:
		return binary.BigEndian.AppendUint16([]byte{0xd1}, uint16(n))
	case n >= math.MinInt32 && n <= math.MaxInt32:
		return binary.BigEndian.AppendUint32([]byte{0xd2}, uint32(n))
	default:
		return binary.BigEndian.AppendUint64([]byte{0xd3}, uint64(n))
	}
}
