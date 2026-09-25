package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
)

// The one way this spike can go badly wrong is proxying to ourselves: the console's name is
// redirected to this box, so a Director that keeps the request pointed at the listener would
// loop. It must target the same name over public TLS, which only resolves to Team17 because
// the box is not redirected.
func TestT17DirectorTargetsTheRealService(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/get-token", nil)
	r.Host = "directory.t17service.com"
	t17Proxy().(*httputil.ReverseProxy).Director(r)
	if r.URL.Scheme != "https" || r.URL.Host != "directory.t17service.com" {
		t.Fatalf("director sent the request to %s://%s", r.URL.Scheme, r.URL.Host)
	}
}

// The directory is the only address the game is given, so getting its shape wrong costs a whole
// test run. This is the reply Team17's own service sends, with our hosts in place of the empty
// `game.url` it actually returns.
func TestT17DirectoryHandsBackOurOwnHosts(t *testing.T) {
	t.Setenv("T17_SELF_HOST", "t17service.com")
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "directory.t17service.com"
	w := httptest.NewRecorder()
	if !t17Directory(w, r) {
		t.Fatal("the directory root was not answered")
	}
	var got struct {
		Game       struct{ URL string }
		XPlayURL   string `json:"xplayurl"`
		AllowXPlay string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unparseable: %v (%s)", err, w.Body)
	}
	if got.Game.URL != "https://game.t17service.com/" || got.XPlayURL != "https://xplay.t17service.com/prod/" ||
		got.AllowXPlay != "1" {
		t.Fatalf("wrong addressing: %s", w.Body)
	}
	// Anything but the root is still the capture path, or the game backend would never be read.
	if t17Directory(httptest.NewRecorder(), httptest.NewRequest("GET", "/something", nil)) {
		t.Fatal("a non-root path was answered as the directory")
	}
}

// A client frame is always masked and its length is encoded three different ways depending on
// size — the one place in the socket code where a wrong byte silently corrupts every message.
func TestT17ReadFrameUnmasksEverySizeClass(t *testing.T) {
	for _, n := range []int{5, 200, 70000} {
		payload := bytes.Repeat([]byte("t17."), n/4+1)[:n]
		mask := [4]byte{0xa1, 0xb2, 0xc3, 0xd4}
		var f bytes.Buffer
		f.WriteByte(0x81) // FIN + text
		switch {
		case n < 126:
			f.WriteByte(byte(0x80 | n))
		case n < 65536:
			f.WriteByte(0x80 | 126)
			_ = binary.Write(&f, binary.BigEndian, uint16(n))
		default:
			f.WriteByte(0x80 | 127)
			_ = binary.Write(&f, binary.BigEndian, uint64(n))
		}
		f.Write(mask[:])
		for i, b := range payload {
			f.WriteByte(b ^ mask[i%4])
		}

		op, got, err := readFrame(&f)
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		if op != 1 || !bytes.Equal(got, payload) {
			t.Fatalf("len %d: op=%d, payload round-trip failed", n, op)
		}
	}
}

// PreInitialise names every field it demands in its own error strings; answering with a subset
// leaves the game authenticated and silent, which is exactly what happened with six of them.
func TestT17GetTokenCarriesEveryRequiredField(t *testing.T) {
	t.Setenv("T17_SELF_HOST", "t17service.com")
	s := testServer(t)
	// testServer has no signing key; get-token verifies the console's id_token against ours.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.key = key
	claims := map[string]any{"sub": "aaaaaaaaaaaa0001", "typ": "id_token"}
	tok := signJWT(map[string]any{"alg": "RS256", "kid": "openpak-baas-key-1", "typ": "JWT"}, claims, s.key)
	body := []byte(`{"platformId":"nintendo","deviceId":"nintendo-switch","gameId":"ProjectJourney",` +
		`"displayName":"hansolo","nintendoSwitchAccessToken":"` + tok + `"}`)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/prod/auth/get-token", bytes.NewReader(body))
	if !s.t17GetToken(w, r, body) || w.Code != 200 {
		t.Fatalf("get-token not answered: %d %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// The order PreInitialise looks them up in, including the `version` its fill pass reads
	// without ever naming it in an error.
	for _, field := range []string{"websocketUrl", "token", "exp", "ttl", "displayName",
		"globalPlayerId", "role", "blockList", "deviceId", "platformId", "version",
		"killSwitchActive"} {
		if _, ok := got[field]; !ok {
			t.Errorf("missing required field %q", field)
		}
	}
	if got["globalPlayerId"] != "aaaaaaaaaaaa0001" || got["role"] != "client" {
		t.Errorf("wrong identity or role: %s", w.Body)
	}
	// The C# class has exactly twelve fields and JSON that carries anything else is a different
	// shape than the one it models; `apiVersion` in particular belongs to another class.
	if len(got) != 12 {
		t.Errorf("reply has %d fields, the C# response class has 12: %s", len(got), w.Body)
	}
}
