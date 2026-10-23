package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"nx-baas/internal/core"
	"nx-baas/internal/identity"
	"nx-baas/internal/store"
	"testing"
)

// The friend-code search asks for /1/<id>?width=128&height=128 and shows "?"
// unless it gets that size; the answer must be a baseline JPEG (a progressive
// one is 2206-1017 on a console). No size asked: the stored bytes, unchanged.
func TestThumbnailIsServedAtTheRequestedSize(t *testing.T) {
	t.Setenv("NX_DATA", t.TempDir())
	s := dauthServer(t)
	s.Store = store.Load(t.TempDir() + "/baas.json")
	u, _ := s.Store.NewUser()

	src := image.NewRGBA(image.Rect(0, 0, 256, 256))
	for y := 0; y < 256; y++ {
		for x := 0; x < 256; x++ {
			src.Set(x, y, color.RGBA{uint8(x), uint8(y), 128, 255})
		}
	}
	var stored bytes.Buffer
	if err := jpeg.Encode(&stored, src, nil); err != nil {
		t.Fatal(err)
	}
	s.Store.Update(u, func(u *store.User) { u.PID = 1 })
	s.Acct = fakeBackend{id: &identity.Identity{PID: 1, Avatar: base64.StdEncoding.EncodeToString(stored.Bytes())}}

	get := func(path string) []byte {
		t.Helper()
		r := httptest.NewRequest("GET", "https://cdn-image-"+core.BaasHost+path, nil)
		r.Host = "cdn-image-" + core.BaasHost
		w := httptest.NewRecorder()
		s.baas(w, r, nil)
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/jpeg" {
			t.Fatalf("%s = %d %q", path, w.Code, w.Header().Get("Content-Type"))
		}
		return w.Body.Bytes()
	}

	if got := get("/1/" + u.ID); !bytes.Equal(got, stored.Bytes()) {
		t.Errorf("no size asked: the stored picture changed (%d bytes, want %d)", len(got), stored.Len())
	}
	for _, path := range []string{"/1/" + u.ID + "?width=128&height=128", "/1/default?width=64&height=64"} {
		got := get(path)
		cfg, err := jpeg.DecodeConfig(bytes.NewReader(got))
		if err != nil {
			t.Fatalf("%s: not a JPEG: %v", path, err)
		}
		want := 128
		if path[3:10] == "default" {
			want = 64
		}
		if cfg.Width != want || cfg.Height != want {
			t.Errorf("%s: %dx%d, want %dx%d", path, cfg.Width, cfg.Height, want, want)
		}
		if !baselineJPEG(got) {
			t.Errorf("%s: not a baseline JPEG", path)
		}
	}
	// Same size twice is the cached bytes.
	if a, b := get("/1/"+u.ID+"?width=128&height=128"), get("/1/"+u.ID+"?width=128&height=128"); !bytes.Equal(a, b) {
		t.Error("the same size came back different")
	}
}

// baselineJPEG: the frame header is SOF0 (baseline), not SOF2 (progressive).
func baselineJPEG(b []byte) bool {
	for i := 2; i+3 < len(b); {
		if b[i] != 0xFF {
			return false
		}
		switch m := b[i+1]; m {
		case 0xC0:
			return true
		case 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF:
			return false
		}
		i += 2 + int(b[i+2])<<8 | int(b[i+3])
	}
	return false
}
