package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeBCATRelayKeepsContainersAndConditionalHeaders(t *testing.T) {
	body := []byte{'b', 'c', 'a', 't', 0, 255, 1}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != `"dataset"` || r.Header.Get("Range") != "bytes=0-6" {
			t.Errorf("lost conditional headers")
		}
		w.Header().Set("ETag", `"dataset"`)
		w.Header().Set("Content-Range", "bytes 0-6/7")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(body)
	}))
	defer upstream.Close()
	f, err := newNewsForwarder(upstream.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{bcatFiles: f}
	for _, url := range []string{
		"https://bcat-list-lp1.cdn.nintendo.net/api/nx/v1/list/nx_data_0100f8f0000a2000",
		"https://bcat-data-lp1.cdn.nintendo.net/bcat/0100f8f0000a2000/revision/vsdata/VSSetting_0.byaml",
	} {
		r := httptest.NewRequest("GET", url, nil)
		r.Header.Set("If-None-Match", `"dataset"`)
		r.Header.Set("Range", "bytes=0-6")
		w := httptest.NewRecorder()
		s.bcat(w, r, nil)
		if w.Code != 206 || w.Body.String() != string(body) || w.Header().Get("ETag") != `"dataset"` || w.Header().Get("Content-Range") != "bytes 0-6/7" {
			t.Fatalf("relay: %d %v %q", w.Code, w.Header(), w.Body.Bytes())
		}
	}
	for _, path := range []string{"/api/nx/v1/list/openpak_news", "/api/nx/v1/list/nx_data_invalid", "/api/nx/v1/list/nx_data_0100f8f0000a2000/extra"} {
		if nativeBCATForwardPath("bcat-list-lp1.cdn.nintendo.net", path) {
			t.Errorf("forwarded unrelated path %s", path)
		}
	}
}
