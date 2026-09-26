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

// platformName is how a person reads a presence namespace.
func platformName(namespace string) string {
	switch strings.ToLower(namespace) {
	case "switch":
		return "Switch"
	case "wiiu":
		return "Wii U"
	case "3ds":
		return "3DS"
	case "":
		return ""
	default:
		return strings.ToUpper(namespace[:1]) + namespace[1:]
	}
}

// clientLabel names what somebody is on: the client when one is known, the
// platform otherwise. The same table lives in the website and nn-friends.
func clientLabel(namespace, client string) string {
	switch strings.ToLower(client) {
	case "":
		return platformName(namespace)
	case "switch":
		return "Switch"
	case "ryujinx":
		return "Ryujinx"
	case "eden":
		return "Eden"
	case "citron":
		return "Citron"
	case "wiiu":
		return "Wii U"
	case "3ds":
		return "3DS"
	case "cemu":
		return "Cemu"
	case "azahar":
		return "Azahar"
	default:
		return strings.ToUpper(client[:1]) + client[1:]
	}
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
