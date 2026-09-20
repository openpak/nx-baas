package main

import (
	"strings"
	"testing"
)

// The account module checks all forty characters of a device-account password
// are hex digits before writing the profile's local record, and that record is
// create-only: a profile that links with anything else can never publish
// presence or take a notification again.
func TestDeviceAccountPasswordIsFortyHexDigits(t *testing.T) {
	for i := 0; i < 32; i++ {
		p := randPassword()
		if len(p) != 40 {
			t.Fatalf("password %q is %d characters, want 40", p, len(p))
		}
		for _, c := range p {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				t.Fatalf("password %q carries %q, which is not a hex digit", p, c)
			}
		}
	}
}
