package services

import (
	"log"
	"net/http"
	"nx-baas/internal/httpx"
	"nx-baas/redact"
	"strings"
)

// Microsoft's PlayFab (`<titleid>.playfabapi.com`): We Were Here and Minecraft Dungeons log in
// there. The family is redirected so a console never reaches Microsoft, and Traefik's
// catch-all sends the connection here with an on-demand OpenPak-CA certificate. OpenPak runs
// a service for Core Keeper when NX_PLAYFAB_URL is set. Other titles get an error with
// ServiceUnavailable (errorCode 1123 in the SDKs' PlayFabErrorCode): the game's SDK reads it
// as an ordinary outage instead of failing to parse the generic catch-all's `{}`.
//
// Answered before the body is read and never dumped: the login calls carry the console's
// identity token.
func IsPlayFab(host string) bool {
	host = strings.ToLower(host)
	return host == "playfabapi.com" || strings.HasSuffix(host, ".playfabapi.com")
}

func PlayfabUnavailable(w http.ResponseWriter, r *http.Request) {
	log.Printf("[nx-baas] playfab unavailable: %s %s%s -> 503", r.Method, httpx.HostOf(r), redact.Path(r.URL.Path))
	httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{
		"code":         http.StatusServiceUnavailable,
		"status":       "ServiceUnavailable",
		"error":        "ServiceUnavailable",
		"errorCode":    1123,
		"errorMessage": "This game's online service (PlayFab) is not available on OpenPak yet.",
	})
}
