package main

import (
	"log"
	"net/http"
	"strings"
)

// Microsoft's PlayFab (`<titleid>.playfabapi.com`): We Were Here and Minecraft Dungeons log in
// there. The family is redirected so a console never reaches Microsoft, and Traefik's
// catch-all sends the connection here with an on-demand OpenPak-CA certificate. OpenPak runs
// no PlayFab service yet, so every call gets PlayFab's own error envelope with
// ServiceUnavailable (errorCode 1123 in the SDKs' PlayFabErrorCode): the game's SDK reads it
// as an ordinary outage instead of failing to parse the generic catch-all's `{}`.
//
// Answered before the body is read and never dumped: the login calls carry the console's
// identity token.
func isPlayFab(host string) bool {
	host = strings.ToLower(host)
	return host == "playfabapi.com" || strings.HasSuffix(host, ".playfabapi.com")
}

func playfabUnavailable(w http.ResponseWriter, r *http.Request) {
	log.Printf("[nx-baas] playfab is not served by OpenPak yet: %s %s%s -> 503", r.Method, hostOf(r), r.URL.Path)
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"code":         http.StatusServiceUnavailable,
		"status":       "ServiceUnavailable",
		"error":        "ServiceUnavailable",
		"errorCode":    1123,
		"errorMessage": "This game's online service (PlayFab) is not available on OpenPak yet.",
	})
}
