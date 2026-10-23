package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"nx-baas/internal/core"
	"nx-baas/internal/services"
	"strings"
	"testing"
)

func TestPlayFabAnswersServiceUnavailable(t *testing.T) {
	s := &server{Core: &core.Core{}}
	for _, host := range []string{"3f284.playfabapi.com", "playfabapi.com", "3F284.PlayFabAPI.com:443"} {
		r := httptest.NewRequest("POST", "https://"+host+"/Client/LoginWithNintendoSwitchDeviceId?sdk=UnitySDK-2.0",
			strings.NewReader(`{"TitleId":"3F284","IdentityToken":"secret"}`))
		r.Host = host
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 503 {
			t.Fatalf("%s: status %d, want 503", host, w.Code)
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: body %q: %v", host, w.Body.String(), err)
		}
		if got["status"] != "ServiceUnavailable" || got["errorCode"] != float64(1123) || got["code"] != float64(503) {
			t.Fatalf("%s: body %v is not a PlayFab ServiceUnavailable error", host, got)
		}
	}
}

func TestPlayFabCoreKeeperForwardBeforeDebugBodyLogger(t *testing.T) {
	var logs bytes.Buffer
	oldWriter, oldDebug := log.Writer(), debug
	log.SetOutput(&logs)
	debug = true
	t.Cleanup(func() { log.SetOutput(oldWriter); debug = oldDebug })
	body := `{"TitleId":"94845","IdentityToken":"private-nintendo-token","CreateAccount":true}`
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		got, _ := io.ReadAll(r.Body)
		if string(got) != body || r.Host != "94845.playfabapi.com:443" || r.URL.Path != "/Client/LoginWithNintendoServiceAccount" {
			t.Errorf("proxy changed the host, path or body")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"status":"OK","data":{"SessionTicket":"private-ticket"}}`))
	}))
	defer upstream.Close()
	t.Setenv("NX_PLAYFAB_URL", upstream.URL)
	s := &server{Core: &core.Core{}}
	s.forwardersFromEnv()
	r := httptest.NewRequest("POST", "https://94845.playfabapi.com:443/Client/LoginWithNintendoServiceAccount", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || calls != 1 || !strings.Contains(w.Body.String(), `"SessionTicket":"private-ticket"`) {
		t.Fatalf("Core Keeper did not reach its separate service: %d", w.Code)
	}
	for _, host := range []string{"3f284.playfabapi.com", "94845.playfabapi.com.evil.playfabapi.com"} {
		r := httptest.NewRequest("POST", "https://"+host+"/Client/LoginWithNintendoServiceAccount", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 503 || calls != 1 {
			t.Fatal("unsupported title reached the service")
		}
	}
	if strings.Contains(logs.String(), "private-nintendo-token") || strings.Contains(logs.String(), "private-ticket") {
		t.Fatal("debug logger recorded a PlayFab credential")
	}
	upstream.Close()
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"errorCode":1123`) {
		t.Fatal("unreachable service did not return the SDK error envelope")
	}
}

func TestIsPlayFabStaysInItsFamily(t *testing.T) {
	for host, want := range map[string]bool{
		"3f284.playfabapi.com":      true,
		"playfabapi.com":            true,
		"notplayfabapi.com":         false,
		"playfabapi.com.example.io": false,
		"accounts.nintendo.com":     false,
	} {
		if got := services.IsPlayFab(host); got != want {
			t.Errorf("isPlayFab(%q) = %v, want %v", host, got, want)
		}
	}
}
