// Package b233 is ECDSA on sect233r1 (SEC 2 "B-233"), the binary curve of a Switch's device
// certificate and of OpenPak's Harbor device CA (HD00000001). Go's crypto/ecdsa has prime
// curves only, so the field (GF(2^233), f = x^233 + x^74 + 1) and the curve arithmetic are
// here, on math/big used as a bit container. Affine coordinates: it signs a few certificates
// per enrolment and is far from any hot path. Not constant-time; the only secret it handles is
// the CA key, on the server, and enrolment is rate-limited.
//
// Signatures are plain ECDSA with SHA-256 truncated to the order's 233 bits, as OpenSSL signs on
// this curve (and as Harbor's proof of possession is made); b233_test.go checks both directions
// against OpenSSL's output.
package b233

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
)

// Size is the byte length of a coordinate, a scalar and each half of a raw signature.
const Size = 30

var (
	poly = func() *big.Int { // x^233 + x^74 + 1
		p := new(big.Int).SetBit(new(big.Int), 233, 1)
		p.SetBit(p, 74, 1)
		return p.SetBit(p, 0, 1)
	}()
	curveB = hexInt("0066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad")
	gx     = hexInt("00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b")
	gy     = hexInt("01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052")
	// N is the order of the base point (the curve has cofactor 2).
	N = hexInt("01000000000000000000000000000013e974e72f8a6922031d2603cfe0d7")
)

// OID is sect233r1's object identifier (SEC 2: 1.3.132.0.27).
var OID = asn1.ObjectIdentifier{1, 3, 132, 0, 27}

func hexInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("b233: bad constant")
	}
	return n
}

// ---- GF(2^233) ----

func fAdd(a, b *big.Int) *big.Int { return new(big.Int).Xor(a, b) }

// fReduce brings a polynomial of any degree below 233.
func fReduce(a *big.Int) *big.Int {
	r := new(big.Int).Set(a)
	for r.BitLen() > 233 {
		shift := uint(r.BitLen() - 234)
		r.Xor(r, new(big.Int).Lsh(poly, shift))
	}
	return r
}

func fMul(a, b *big.Int) *big.Int {
	r := new(big.Int)
	for i := b.BitLen() - 1; i >= 0; i-- {
		r.Lsh(r, 1)
		if b.Bit(i) == 1 {
			r.Xor(r, a)
		}
	}
	return fReduce(r)
}

func fSqr(a *big.Int) *big.Int { return fMul(a, a) }

// fInv is the inverse by the extended Euclidean algorithm on polynomials; a must not be zero.
func fInv(a *big.Int) *big.Int {
	u, v := fReduce(a), new(big.Int).Set(poly)
	g1, g2 := big.NewInt(1), new(big.Int)
	for u.Cmp(big.NewInt(1)) != 0 {
		j := u.BitLen() - v.BitLen()
		if j < 0 {
			u, v = v, u
			g1, g2 = g2, g1
			j = -j
		}
		u = new(big.Int).Xor(u, new(big.Int).Lsh(v, uint(j)))
		g1 = new(big.Int).Xor(g1, new(big.Int).Lsh(g2, uint(j)))
	}
	return fReduce(g1)
}

// ---- the curve: y^2 + xy = x^3 + x^2 + b ----

type point struct {
	x, y *big.Int
	inf  bool
}

func onCurve(p point) bool {
	if p.inf {
		return false
	}
	if p.x.BitLen() > 233 || p.y.BitLen() > 233 || p.x.Sign() < 0 || p.y.Sign() < 0 {
		return false
	}
	lhs := fAdd(fSqr(p.y), fMul(p.x, p.y))
	x2 := fSqr(p.x)
	rhs := fAdd(fAdd(fMul(x2, p.x), x2), curveB)
	return lhs.Cmp(rhs) == 0
}

func add(p, q point) point {
	if p.inf {
		return q
	}
	if q.inf {
		return p
	}
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) == 0 {
			return double(p)
		}
		return point{inf: true} // q = -p
	}
	l := fMul(fAdd(p.y, q.y), fInv(fAdd(p.x, q.x)))
	x3 := fAdd(fAdd(fAdd(fAdd(fSqr(l), l), p.x), q.x), big.NewInt(1))
	y3 := fAdd(fAdd(fMul(l, fAdd(p.x, x3)), x3), p.y)
	return point{x: x3, y: y3}
}

func double(p point) point {
	if p.inf || p.x.Sign() == 0 {
		return point{inf: true}
	}
	l := fAdd(p.x, fMul(p.y, fInv(p.x)))
	x3 := fAdd(fAdd(fSqr(l), l), big.NewInt(1))
	y3 := fAdd(fSqr(p.x), fMul(fAdd(l, big.NewInt(1)), x3))
	return point{x: x3, y: y3}
}

func mul(k *big.Int, p point) point {
	r := point{inf: true}
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = double(r)
		if k.Bit(i) == 1 {
			r = add(r, p)
		}
	}
	return r
}

var base = point{x: gx, y: gy}

// ---- keys ----

// PublicKey is a point of the curve's prime-order subgroup.
type PublicKey struct{ X, Y *big.Int }

// PrivateKey is a scalar in [1, N-1] and its public key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// ParsePublicKey reads a point as Nintendo's certificates store it: x then y, 30 bytes each,
// big-endian. It refuses anything that is not a point of order N.
func ParsePublicKey(xy []byte) (*PublicKey, error) {
	if len(xy) != 2*Size {
		return nil, errors.New("b233: a public key is 60 bytes")
	}
	p := point{x: new(big.Int).SetBytes(xy[:Size]), y: new(big.Int).SetBytes(xy[Size:])}
	if !onCurve(p) {
		return nil, errors.New("b233: not a point of the curve")
	}
	if !mul(N, p).inf {
		return nil, errors.New("b233: not in the prime-order subgroup")
	}
	return &PublicKey{X: p.x, Y: p.y}, nil
}

// Bytes is x then y, 30 bytes each.
func (k *PublicKey) Bytes() []byte {
	out := make([]byte, 2*Size)
	k.X.FillBytes(out[:Size])
	k.Y.FillBytes(out[Size:])
	return out
}

// NewPrivateKey makes a key from a scalar.
func NewPrivateKey(d *big.Int) (*PrivateKey, error) {
	if d.Sign() <= 0 || d.Cmp(N) >= 0 {
		return nil, errors.New("b233: scalar out of range")
	}
	q := mul(d, base)
	return &PrivateKey{PublicKey: PublicKey{X: q.x, Y: q.y}, D: new(big.Int).Set(d)}, nil
}

// GenerateKey makes a new key from rand (tests and the throwaway test CA only: the real CA key
// is made by its owner).
func GenerateKey(r io.Reader) (*PrivateKey, error) {
	d, err := randScalar(r)
	if err != nil {
		return nil, err
	}
	return NewPrivateKey(d)
}

func randScalar(r io.Reader) (*big.Int, error) {
	for {
		k, err := rand.Int(r, N)
		if err != nil {
			return nil, err
		}
		if k.Sign() > 0 {
			return k, nil
		}
	}
}

// ParsePrivateKeyPEM reads the CA key file: an "EC PRIVATE KEY" (SEC 1, what `openssl ecparam
// -name sect233r1 -genkey -noout` writes) or a "PRIVATE KEY" (PKCS#8, what `openssl genpkey`
// writes), on sect233r1.
func ParsePrivateKeyPEM(data []byte) (*PrivateKey, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("b233: no EC PRIVATE KEY or PRIVATE KEY block")
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			return parseSEC1(block.Bytes, nil)
		case "PRIVATE KEY":
			var p8 struct {
				Version int
				Algo    struct {
					Algorithm  asn1.ObjectIdentifier
					Parameters asn1.ObjectIdentifier
				}
				Key []byte
			}
			if _, err := asn1.Unmarshal(block.Bytes, &p8); err != nil {
				return nil, err
			}
			if !p8.Algo.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}) {
				return nil, errors.New("b233: PKCS#8 key is not an EC key")
			}
			return parseSEC1(p8.Key, p8.Algo.Parameters)
		}
	}
}

func parseSEC1(der []byte, curve asn1.ObjectIdentifier) (*PrivateKey, error) {
	var k struct {
		Version    int
		PrivateKey []byte
		Curve      asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	if _, err := asn1.Unmarshal(der, &k); err != nil {
		return nil, err
	}
	if len(k.Curve) > 0 {
		curve = k.Curve
	}
	if !curve.Equal(OID) {
		return nil, errors.New("b233: the key is not on sect233r1")
	}
	key, err := NewPrivateKey(new(big.Int).SetBytes(k.PrivateKey))
	if err != nil {
		return nil, err
	}
	if pub := k.PublicKey.Bytes; len(pub) == 1+2*Size && pub[0] == 4 {
		if new(big.Int).SetBytes(pub[1:1+Size]).Cmp(key.X) != 0 || new(big.Int).SetBytes(pub[1+Size:]).Cmp(key.Y) != 0 {
			return nil, errors.New("b233: the key's public part does not match its scalar")
		}
	}
	return key, nil
}

// MarshalPEM writes the key as SEC 1 "EC PRIVATE KEY", as OpenSSL does (test keys).
func (k *PrivateKey) MarshalPEM() []byte {
	d := make([]byte, Size)
	k.D.FillBytes(d)
	der, _ := asn1.Marshal(struct {
		Version    int
		PrivateKey []byte
		Curve      asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}{1, d, OID, asn1.BitString{Bytes: append([]byte{4}, k.PublicKey.Bytes()...), BitLength: 8 * (1 + 2*Size)}})
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// ---- ECDSA-SHA256 ----

func hashInt(msg []byte) *big.Int {
	h := sha256.Sum256(msg)
	e := new(big.Int).SetBytes(h[:])
	return e.Rsh(e, uint(256-N.BitLen())) // the leftmost bits, as many as the order has
}

// Sign returns r and s, 30 bytes each (Nintendo's signature layout), over SHA-256(msg).
func Sign(r io.Reader, k *PrivateKey, msg []byte) ([]byte, error) {
	e := hashInt(msg)
	for {
		nonce, err := randScalar(r)
		if err != nil {
			return nil, err
		}
		p := mul(nonce, base)
		rr := new(big.Int).Mod(p.x, N)
		if rr.Sign() == 0 {
			continue
		}
		s := new(big.Int).Mul(rr, k.D)
		s.Add(s, e)
		s.Mul(s, new(big.Int).ModInverse(nonce, N))
		s.Mod(s, N)
		if s.Sign() == 0 {
			continue
		}
		out := make([]byte, 2*Size)
		rr.FillBytes(out[:Size])
		s.FillBytes(out[Size:])
		return out, nil
	}
}

// Verify checks a raw r||s signature over SHA-256(msg).
func Verify(k *PublicKey, msg, sig []byte) bool {
	if len(sig) != 2*Size {
		return false
	}
	return verify(k, msg, new(big.Int).SetBytes(sig[:Size]), new(big.Int).SetBytes(sig[Size:]))
}

// VerifyASN1 checks a DER ECDSA-Sig-Value (what OpenSSL's EVP_DigestSign writes).
func VerifyASN1(k *PublicKey, msg, der []byte) bool {
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		return false
	}
	return verify(k, msg, sig.R, sig.S)
}

func verify(k *PublicKey, msg []byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	q := point{x: k.X, y: k.Y}
	if !onCurve(q) {
		return false
	}
	w := new(big.Int).ModInverse(s, N)
	u1 := new(big.Int).Mul(hashInt(msg), w)
	u1.Mod(u1, N)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, N)
	p := add(mul(u1, base), mul(u2, q))
	if p.inf {
		return false
	}
	return new(big.Int).Mod(p.x, N).Cmp(r) == 0
}
