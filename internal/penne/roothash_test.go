package penne

import (
	"bytes"
	"testing"
)

// Round-trip against the shape the console actually sent.
func TestRootHashRoundTrip(t *testing.T) {
	in := []RootEntry{
		{Name: "c-appearance", Digest: bytes.Repeat([]byte{0xa1}, 20)},
		{Name: "c-friends", Digest: bytes.Repeat([]byte{0xb2}, 20)},
	}
	frame := BuildRootHash(in, 20, 1789204471, 1789208071)
	env, err := DecodeEnvelope(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Type() != TypeRootHash {
		t.Fatalf("type = %s", env.TypeName())
	}
	pay, ok := env.Payload()
	if !ok {
		t.Fatal("no payload")
	}
	got := ParseRootHash(pay)
	if len(got) != len(in) {
		t.Fatalf("entries = %d, want %d", len(got), len(in))
	}
	for i := range in {
		if got[i].Name != in[i].Name || !bytes.Equal(got[i].Digest, in[i].Digest) {
			t.Errorf("entry %d = %q/%x", i, got[i].Name, got[i].Digest)
		}
	}
}
