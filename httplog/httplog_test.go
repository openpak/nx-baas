package httplog

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func capture(t *testing.T) *bytes.Buffer {
	var b bytes.Buffer
	log.SetOutput(&b)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(nil) })
	return &b
}

func TestLineHasStatusDurationNoQuery(t *testing.T) {
	b := capture(t)
	h := Wrap("[x]", Options{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(404)
	}))
	r := httptest.NewRequest("GET", "http://h.example/oauth/token?access_token=SECRET&code=abc", nil)
	r.Header.Set("Authorization", "Bearer SECRETHDR")
	r.AddCookie(&http.Cookie{Name: "s", Value: "SECRETCOOKIE"})
	h.ServeHTTP(httptest.NewRecorder(), r)
	out := b.String()
	if !strings.HasPrefix(out, "[x] http GET h.example /oauth/token -> 404 ") || !strings.Contains(out, "ms") {
		t.Fatalf("line: %q", out)
	}
	for _, s := range []string{"SECRET", "access_token", "code=", "?"} {
		if strings.Contains(out, s) {
			t.Fatalf("%q leaked in %q", s, out)
		}
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("want one line: %q", out)
	}
}

func TestDefaultStatus200AndSkipHealthz(t *testing.T) {
	b := capture(t)
	h := Wrap("", Options{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/healthz", nil))
	if b.Len() != 0 {
		t.Fatalf("healthz logged: %q", b)
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/a", nil))
	if !strings.Contains(b.String(), "http POST example.com /a -> 200 ") {
		t.Fatalf("line: %q", b)
	}
}

func TestPathAndUAHooks(t *testing.T) {
	b := capture(t)
	h := Wrap("", Options{
		Path:      func(p string) string { return strings.ReplaceAll(p, "deadbeef", "~id") },
		UserAgent: func(string) string { return "nintendo" },
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/u/deadbeef/x?t=1", nil))
	if !strings.Contains(b.String(), "/u/~id/x -> 200") || !strings.HasSuffix(strings.TrimSpace(b.String()), `ua="nintendo"`) {
		t.Fatalf("line: %q", b)
	}
}

func TestFlusherAndUnwrapPreserved(t *testing.T) {
	capture(t)
	flushed := false
	h := Wrap("", Options{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("Flusher lost")
			return
		}
		f.Flush()
		flushed = true
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("ResponseController: %v", err)
		}
		if _, ok := w.(http.Hijacker); !ok {
			t.Error("Hijacker lost")
		}
		if _, ok := w.(http.Pusher); !ok {
			t.Error("Pusher lost")
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/s", nil))
	if !flushed || !rec.Flushed {
		t.Fatal("flush did not reach the underlying writer")
	}
}

func TestInformationalDoesNotSetStatus(t *testing.T) {
	b := capture(t)
	h := Wrap("", Options{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(103)
		w.WriteHeader(201)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/a", nil))
	if !strings.Contains(b.String(), "-> 201 ") {
		t.Fatalf("line: %q", b)
	}
}
