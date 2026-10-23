package msgpack

// The msgpack encoder's bytes, checked against the spec's own encoding.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestMsgpackEncodesTheDocumentTypesBCATUses(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{nil, "c0"},
		{true, "c3"},
		{false, "c2"},
		{"", "a0"},
		{"in_service", "aa" + hex.EncodeToString([]byte("in_service"))},
		{0, "00"},
		{127, "7f"},
		{128, "d100 80"},
		{-1, "ff"},
		{-33, "d0df"},
		{[]any{}, "90"},
		{[]any{1, "a"}, "9201a161"},
		{map[string]any{}, "80"},
		// Keys sorted, so the ETag is a function of the document.
		{map[string]any{"b": 1, "a": 2}, "82" + "a161" + "02" + "a162" + "01"},
	} {
		want, err := hex.DecodeString(stripSpaces(tc.want))
		if err != nil {
			t.Fatalf("bad fixture %q: %v", tc.want, err)
		}
		if got := Encode(tc.in); !bytes.Equal(got, want) {
			t.Errorf("msgpack(%#v) = %x, want %x", tc.in, got, want)
		}
	}
}

func stripSpaces(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// A 33-character string crosses out of fixstr into str8, which is the only
// length boundary these documents can realistically hit (URLs and digests).
func TestMsgpackStringsCrossTheFixstrBoundary(t *testing.T) {
	long := string(bytes.Repeat([]byte("x"), 33))
	got := Encode(long)
	if got[0] != 0xd9 || got[1] != 33 || string(got[2:]) != long {
		t.Fatalf("str8 encoding wrong: %x", got[:4])
	}
}
