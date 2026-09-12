package main

// The BCAT surface has one job the console can tell apart from a failure: hand
// back a msgpack document the module's parser accepts. These check the bytes
// against the spec's own encoding (the module is the consumer; nothing here can
// prove it parsed, only that what we write is msgpack and says what we mean).

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMsgpackEncodesTheDocumentTypesBCATUses(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{nil, "c0"},
		{true, "c3"},
		{false, "c2"},
		{"", "a0"},
		{"in_service", "aa" + hex.EncodeToString([]byte("in_service"))},
		{0, "00"},
		{127, "7f"},
		{128, "d100 80"},
		{-1, "ff"},
		{-33, "d0df"},
		{[]any{}, "90"},
		{[]any{1, "a"}, "9201a161"},
		{map[string]any{}, "80"},
		// Keys sorted, so the ETag is a function of the document.
		{map[string]any{"b": 1, "a": 2}, "82" + "a161" + "02" + "a162" + "01"},
	} {
		want, err := hex.DecodeString(stripSpaces(tc.want))
		if err != nil {
			t.Fatalf("bad fixture %q: %v", tc.want, err)
		}
		if got := msgpack(tc.in); !bytes.Equal(got, want) {
			t.Errorf("msgpack(%#v) = %x, want %x", tc.in, got, want)
		}
	}
}

func stripSpaces(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// A 33-character string crosses out of fixstr into str8, which is the only
// length boundary these documents can realistically hit (URLs and digests).
func TestMsgpackStringsCrossTheFixstrBoundary(t *testing.T) {
	long := string(bytes.Repeat([]byte("x"), 33))
	got := msgpack(long)
	if got[0] != 0xd9 || got[1] != 33 || string(got[2:]) != long {
		t.Fatalf("str8 encoding wrong: %x", got[:4])
	}
}

// The two routes the module actually asks for must answer as msgpack, and the
// ETag must let the second poll be a 304 -- the module stores it in etag.bin
// and sends it back, and a server that ignores it re-sends the document on
// every wake.
func TestBcatRoutesAnswerMsgpackAndHonorIfNoneMatch(t *testing.T) {
	s := &server{}
	for _, path := range []string{
		"/api/nx/v1/titles/0100000000010000/topics",
		"/api/nx/v1/list/nx_data_0100000000010000",
	} {
		r := httptest.NewRequest("GET", "https://bcat-list-lp1.cdn.nintendo.net"+path, nil)
		w := httptest.NewRecorder()
		s.bcat(w, r, nil)
		if w.Code != 200 {
			t.Fatalf("%s: status %d", path, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/x-msgpack" {
			t.Errorf("%s: content-type %q", path, ct)
		}
		body := w.Body.Bytes()
		if len(body) == 0 || body[0]&0xf0 != 0x80 {
			t.Fatalf("%s: body is not a msgpack fixmap: %x", path, body)
		}
		etag := w.Header().Get("ETag")
		if etag == "" {
			t.Fatalf("%s: no ETag, so every poll re-downloads", path)
		}

		r2 := httptest.NewRequest("GET", "https://bcat-list-lp1.cdn.nintendo.net"+path, nil)
		r2.Header.Set("If-None-Match", etag)
		w2 := httptest.NewRecorder()
		s.bcat(w2, r2, nil)
		if w2.Code != http.StatusNotModified {
			t.Errorf("%s: unchanged document answered %d, want 304", path, w2.Code)
		}
	}
}

// An unmapped route on these hosts is a 404 that names itself in the log, not a
// 200 that reads as a working feature.
func TestUnknownBcatRouteIs404(t *testing.T) {
	s := &server{}
	w := httptest.NewRecorder()
	s.bcat(w, httptest.NewRequest("GET", "https://bcat-list-lp1.cdn.nintendo.net/api/nx/v1/whatever", nil), nil)
	if w.Code != 404 {
		t.Fatalf("status %d, want 404", w.Code)
	}
}
