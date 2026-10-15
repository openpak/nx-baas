// SPDX-License-Identifier: AGPL-3.0-only
package main

// Which client a person is on, and how every surface names it.
//
// Emulators send `X-OpenPak-Client: <client>/<version> (<os>)` (ryujinx, eden,
// citron; os one of windows, macos, linux, android, ios) on their BAAS
// requests. Older builds leave the "(os)" part off. A real console sends nothing over REST and
// is recognised by speaking Penne instead. The client rides with the device
// claim into the core session, so the website, the app, a Wii U and a 3DS can
// all say "Playing Kirby on Ryujinx" rather than only "online".

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"
)

// clientHeader is the header emulators identify themselves with.
const clientHeader = "X-OpenPak-Client"

// requestClient reads the client name from X-OpenPak-Client, dropping the
// version. Anything that is not a short lower-case token is treated as no
// answer rather than stored: it ends up in the core and on other people's
// screens.
func requestClient(r *http.Request) string {
	return parseClient(r.Header.Get(clientHeader))
}

// requestClientOS reads the OS from X-OpenPak-Client (see parseClientOS).
func requestClientOS(r *http.Request) string {
	return parseClientOS(r.Header.Get(clientHeader))
}

// parseClientOS returns the OS in the header's trailing "(<os>)", lower case,
// when it is one the core knows; "" otherwise (a real console, an older
// emulator, or anything unrecognised).
func parseClientOS(v string) string {
	_, rest, ok := strings.Cut(v, "(")
	if !ok {
		return ""
	}
	os, _, ok := strings.Cut(rest, ")")
	if !ok {
		return ""
	}
	switch os = strings.ToLower(strings.TrimSpace(os)); os {
	case "windows", "macos", "linux", "android", "ios":
		return os
	}
	return ""
}

func parseClient(v string) string {
	name, _, _ := strings.Cut(strings.TrimSpace(v), "/")
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || len(name) > 32 {
		return ""
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return ""
		}
	}
	return name
}

// platformLabels is what a real console's network is called, by presence namespace.
var platformLabels = map[string]string{
	"switch": "Switch", "wiiu": "Wii U", "wii": "Wii", "3ds": "3DS", "nds": "NDS", "ds": "NDS",
	"np": "PS3", "ps3": "PS3", "xbox360": "Xbox 360", "xbox-360": "Xbox 360", "xbl": "Xbox 360",
}

// emulatorLabels is what an emulator calls itself, by the client it reports.
var emulatorLabels = map[string]string{
	"harbor": "Harbor", "ryujinx": "Ryujinx", "eden": "Eden", "citron": "Citron",
	"pier": "Pier", "wharf": "Wharf", "cemu": "Cemu", "azahar": "Azahar", "dolphin": "Dolphin",
	"melonds": "melonDS", "xemu": "xemu", "xenia": "Xenia", "pcsx2": "PCSX2", "rpcs3": "RPCS3",
	"ppsspp": "PPSSPP", "vita3k": "Vita3K",
}

// clientLabel names what somebody is on: the emulator when the client is one, the console's
// platform when it is real hardware (no client, or the console's own), so "PS3" is a PS3 and
// "Pier" is somebody on the emulator. The same table lives in nx-baas, the website, nn-friends
// and np-account.
func clientLabel(namespace, client string) string {
	c := strings.ToLower(strings.TrimSpace(client))
	if e, ok := emulatorLabels[c]; ok {
		return e
	}
	if p, ok := platformLabels[c]; ok {
		return p
	}
	if c != "" {
		return strings.ToUpper(c[:1]) + c[1:] // an emulator this table has not heard of yet
	}
	ns := strings.ToLower(strings.TrimSpace(namespace))
	if p, ok := platformLabels[ns]; ok {
		return p
	}
	if ns == "" {
		return ""
	}
	return strings.ToUpper(ns[:1]) + ns[1:]
}

// presenceDescription is the line shown for a friend who is somewhere this
// console cannot draw: "Playing Kirby on Wii U", "Playing a game on 3DS",
// "Online on Cemu".
func presenceDescription(label, titleID, titleName string) string {
	if label == "" {
		label = "another console"
	}
	switch {
	case titleID == "":
		return "Online on " + label
	case titleName != "":
		return "Playing " + titleName + " on " + label
	default:
		return "Playing a game on " + label
	}
}

// maxDescriptionBytes keeps the description inside the console's 0xC0-byte
// key/value blob: "sys_description\0" and the value's own NUL take 17 of it.
const maxDescriptionBytes = 160

// descriptionAppField renders the description as the appField a console
// publishes for SetDescription: a JSON object string with one key,
// sys_description [docs/switch/friends-presence-firmware-2026-09-19.md §1.2,
// §2.2]. The friend-list parser reads it back into the key/value blob that
// FriendPresence::GetDescription searches.
func descriptionAppField(desc string) string {
	for len(desc) > maxDescriptionBytes {
		_, size := utf8.DecodeLastRuneInString(desc)
		desc = desc[:len(desc)-size]
	}
	// No HTML escaping: "Mario & Luigi" goes to a console as written, not as
	// \u0026, which nothing proves its parser decodes.
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]string{"sys_description": desc})
	return strings.TrimSuffix(b.String(), "\n")
}
