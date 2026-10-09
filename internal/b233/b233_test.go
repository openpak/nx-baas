package b233

import (
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// testdata holds throwaway keys made by OpenSSL for these tests only (openssl ecparam -name
// sect233r1 -genkey; openssl genpkey ... ec_paramgen_curve:sect233r1) and a signature OpenSSL
// made with the first over msg.bin (openssl dgst -sha256 -sign).

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Parsing checks the file's public point against our scalar multiplication: a wrong field or
// curve formula fails here.
func TestOpenSSLKeysParse(t *testing.T) {
	for _, name := range []string{"key.pem", "key8.pem"} {
		if _, err := ParsePrivateKeyPEM(load(t, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVerifiesOpenSSLSignature(t *testing.T) {
	key, err := ParsePrivateKeyPEM(load(t, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	msg, sig := load(t, "msg.bin"), load(t, "sig.der")
	if !VerifyASN1(&key.PublicKey, msg, sig) {
		t.Fatal("OpenSSL's signature does not verify")
	}
	if VerifyASN1(&key.PublicKey, append(msg, '!'), sig) {
		t.Fatal("a signature verified over another message")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(rand.Reader, key, []byte("certificate body"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(&key.PublicKey, []byte("certificate body"), sig) {
		t.Fatal("own signature does not verify")
	}
	sig[5] ^= 1
	if Verify(&key.PublicKey, []byte("certificate body"), sig) {
		t.Fatal("a damaged signature verified")
	}
	pub, err := ParsePublicKey(key.PublicKey.Bytes())
	if err != nil || pub.X.Cmp(key.X) != 0 {
		t.Fatalf("public key round trip: %v", err)
	}
	bad := key.PublicKey.Bytes()
	bad[59] ^= 1
	if _, err := ParsePublicKey(bad); err == nil {
		t.Fatal("a point off the curve parsed")
	}
}

// Our signatures verify in OpenSSL, when it is installed.
func TestOpenSSLVerifiesOurSignature(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl")
	}
	key, err := ParsePrivateKeyPEM(load(t, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("signed in Go")
	raw, err := Sign(rand.Reader, key, msg)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:Size]), new(big.Int).SetBytes(raw[Size:])})
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keyPath := write("k.pem", key.MarshalPEM())
	out, err := exec.Command(openssl, "dgst", "-sha256", "-prverify", keyPath, "-signature", write("s.der", der), write("m.bin", msg)).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl: %v: %s", err, out)
	}
}
