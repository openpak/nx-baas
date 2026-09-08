package main

import (
	"net/http/httptest"
	"os"
	"testing"
)

// TestDumpLinkPages writes the console-link pages to disk so they can be
// opened in a browser at a phone's width. These are the pages a person meets
// while their console waits, and they are easy to leave unlooked-at because
// nothing here renders them otherwise.
//
//	PREVIEW_DIR=/tmp/link go test -count=1 -run DumpLinkPages .
func TestDumpLinkPages(t *testing.T) {
	dir := os.Getenv("PREVIEW_DIR")
	if dir == "" {
		t.Skip("set PREVIEW_DIR")
	}
	_ = os.MkdirAll(dir, 0o755)
	s := &server{}
	for name, render := range map[string]func(*httptest.ResponseRecorder){
		"confirm": func(w *httptest.ResponseRecorder) { s.phoneConfirmPage(w, "hansolo", "pair-1", "") },
		"done":    func(w *httptest.ResponseRecorder) { s.phoneDonePage(w, "hansolo") },
		"signin":  func(w *httptest.ResponseRecorder) { s.phoneLoginPage(w, "pair-1", "") },
	} {
		w := httptest.NewRecorder()
		render(w)
		if err := os.WriteFile(dir+"/link-"+name+".html", w.Body.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
