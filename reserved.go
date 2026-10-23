package main

// Platform pseudo-titles: what a friend on another platform, or at HOME, is listed as playing.
//
// The Switch friend list draws a state ("Online") or the name of a title, and names a title only
// from what the viewer has -- or, when it has not got it, from the control NCA it asks atum for.
// So the platform is carried as a title of its own: 01fe00fe<n>000, named "Pier", "Harbor",
// "PS3"... by nx-shop (reserved.go there, built by hbstore-tools/reserved.py). The order of
// reservedKeys is the id and is shared with reserved.py's PLATFORMS: only ever append.

import (
	"fmt"
	"nx-baas/internal/httpx"
	"strings"
)

// reservedGeneration is the id's first eight digits. A console keeps the control data of every id
// it has fetched and never asks again, so a changed name or picture is a new generation (shared
// with reserved.py's GENERATION and nx-shop's accepted prefix): 01fe00ff was the first.
const reservedGeneration = "01fe00fe"

var reservedKeys = []string{
	"switch", "harbor", "ryujinx", "eden", "citron", "pier", "ps3", "wharf", "xbox360", "wii", "wiiu",
	"3ds", "nds", "dolphin", "cemu", "azahar", "melonds", "xemu", "xenia", "pcsx2", "rpcs3", "ppsspp",
	"vita3k", "ps4", "ps5", "psp", "vita", "xbox", "xboxone",
}

// reservedNamespace maps a presence namespace to the platform it is, for a real console.
var reservedNamespace = map[string]string{
	"switch": "switch", "np": "ps3", "ps3": "ps3", "xbox360": "xbox360", "xbox-360": "xbox360",
	"xbl": "xbox360", "wii": "wii", "wiiu": "wiiu", "3ds": "3ds", "nds": "nds", "ds": "nds",
	"ps4": "ps4", "ps5": "ps5", "psp": "psp", "vita": "vita", "psvita": "vita", "xbox": "xbox",
	"xboxone": "xboxone", "xbox-one": "xboxone",
}

// reservedID is the title id naming where somebody is: the emulator when the client is one, the
// console's platform otherwise. "" for a platform with no reserved title.
func reservedID(namespace, client string) string {
	key := strings.ToLower(strings.TrimSpace(client))
	if key == "" {
		key = reservedNamespace[strings.ToLower(strings.TrimSpace(namespace))]
	}
	for i, k := range reservedKeys {
		if k == key {
			return fmt.Sprintf("%s%05x000", reservedGeneration, i+1)
		}
	}
	if p, ok := reservedNamespace[key]; ok && p != key { // a console reporting its own name as the client
		return reservedID("", p)
	}
	return ""
}

// platformTitle reports whether the pseudo-titles are served (NX_PLATFORM_TITLE=1).
func platformTitle() bool { return httpx.Getenv("NX_PLATFORM_TITLE", "") == "1" }
