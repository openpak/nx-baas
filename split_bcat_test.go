package main

// The BCAT hosts once they have moved to nx-bcat (split.go): forwarded with the console's Host
// kept, and never to an /internal route.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMovedBcatIsForwarded(t *testing.T) {
	got := make(chan [2]string, 4)
	bcat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		got <- [2]string{r.Host, r.URL.Path}
		w.WriteHeader(299)
	}))
	defer bcat.Close()
	t.Setenv("NX_BCAT_URL", bcat.URL)
	s := shopServerFor(t)
	s.forwardersFromEnv()
	for _, c := range [][2]string{
		{"bcat-list-lp1.cdn.nintendo.net", "/api/nx/v1/list/openpak_news"},
		{"bcat-topics-lp1.cdn.nintendo.net", "/api/nx/v1/titles/0100000000001000/topics"},
		{"bcat-data-lp1.cdn.nintendo.net", "/bcat/0100000000000001/aa/d/f"},
	} {
		req := httptest.NewRequest("GET", "https://"+c[0]+c[1], nil)
		req.Host = c[0]
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != 299 || <-got != c {
			t.Fatalf("%s%s = %d, want it forwarded unchanged", c[0], c[1], rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "https://bcat-list-lp1.cdn.nintendo.net/internal/news/push", nil)
	req.Host = "bcat-list-lp1.cdn.nintendo.net"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("/internal on a bcat host = %d, want 404", rec.Code)
	}
}
