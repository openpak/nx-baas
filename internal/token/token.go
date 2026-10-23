// Package token mints and checks the tokens nx-baas signs (RS256 JWTs, the JWKS that
// publishes their key) and the random ids and passwords it hands out.
package token

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

func B64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func RandHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func UUID4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// 40 alphanumerics, like a real BAAS device-account password.
// RandPassword mints a device-account password. The account module checks all
// forty characters are hex digits before it writes the profile's local record,
// and writes nothing at all otherwise -- and that record is create-only, so a
// profile that links with a non-hex password can never publish presence or
// receive notifications until it is unlinked (2026-09-20,
// docs/switch/presence-publish-gate-2026-09-20.md). Alphanumeric passwords
// passed that check with probability about 1e-18.
func RandPassword() string {
	return RandHex(20)
}

func LoadRSAKey(path string) *rsa.PrivateKey {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[nx-baas] read signing key %s: %v", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Fatalf("[nx-baas] no PEM block in %s", path)
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k
	}
	log.Fatalf("[nx-baas] cannot parse RSA private key in %s", path)
	return nil
}

func JWKSFor(pub *rsa.PublicKey, kids ...string) []byte {
	n, e := B64URL(pub.N.Bytes()), B64URL(big.NewInt(int64(pub.E)).Bytes())
	keys := []map[string]any{}
	for _, kid := range kids {
		keys = append(keys, map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e})
	}
	out, _ := json.Marshal(map[string]any{"keys": keys})
	return out
}

func SignJWT(header, claims map[string]any, key *rsa.PrivateKey) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := B64URL(h) + "." + B64URL(c)
	sum := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return input + "." + B64URL(sig)
}

// ParseJWT returns the claims of a compact JWT. With key != nil the RS256 signature must verify
// (our own tokens); with nil it only decodes (a dauth device token we did not issue).
func ParseJWT(tok string, key *rsa.PublicKey) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a jwt")
	}
	if key != nil {
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
			return nil, err
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(raw, &claims)
}

func RandB64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
