package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlayFabAnswersServiceUnavailable(t *testing.T) {
	s := &server{}
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

func TestIsPlayFabStaysInItsFamily(t *testing.T) {
	for host, want := range map[string]bool{
		"3f284.playfabapi.com":      true,
		"playfabapi.com":            true,
		"notplayfabapi.com":         false,
		"playfabapi.com.example.io": false,
		"accounts.nintendo.com":     false,
	} {
		if got := isPlayFab(host); got != want {
			t.Errorf("isPlayFab(%q) = %v, want %v", host, got, want)
		}
	}
}
