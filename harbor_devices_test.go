package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nx-baas/internal/b233"
)

// A throwaway device CA, made per test: the real keys are the owner's.
func testDeviceCA(t *testing.T) *harborDeviceCA {
	t.Helper()
	ecc, err := b233.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Harbor Device CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(30, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &harborDeviceCA{ecc: ecc, tlsCert: cert, tlsKey: key, pool: pool}
}

// testConsole is a Harbor calibration's identity, as cal0.cpp makes it.
type testConsole struct {
	id                   uint64
	serial               string
	ecc                  *b233.PrivateKey
	eticket, device, tls *rsa.PrivateKey
	eccCert, etCert      []byte
	devCert, tlsCert     []byte
}

func serialWithCheck(digits string) string {
	sum := 0
	for i := 0; i < 10; i++ {
		d := int(digits[i] - '0')
		if i%2 == 0 {
			sum += d
		} else {
			sum += 3 * d
		}
	}
	return "HBW" + digits + fmt.Sprint((10-sum%10)%10)
}

func nintendoCert(size int, keyType uint32, id uint64, pub []byte) []byte {
	c := make([]byte, size)
	binary.BigEndian.PutUint32(c, sigTypeEcdsaSha256)
	copy(c[certSigned:], harborIssuer)
	binary.BigEndian.PutUint32(c[certKeyType:], keyType)
	copy(c[certName:], certificateName(id))
	copy(c[certPublicKey:], pub)
	return c
}

func rsaPub(k *rsa.PrivateKey) []byte {
	out := make([]byte, 0x104)
	k.N.FillBytes(out[:0x100])
	binary.BigEndian.PutUint32(out[0x100:], uint32(k.E))
	return out
}

func newTestConsole(t *testing.T, id uint64, digits string) *testConsole {
	t.Helper()
	c := &testConsole{id: id, serial: serialWithCheck(digits)}
	var err error
	if c.ecc, err = b233.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	for _, k := range []**rsa.PrivateKey{&c.eticket, &c.device, &c.tls} {
		if *k, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			t.Fatal(err)
		}
	}
	c.eccCert = nintendoCert(eccCertSize, keyTypeEccB233, id, c.ecc.PublicKey.Bytes())
	c.etCert = nintendoCert(rsaCertSize, keyTypeRsa2048, id, rsaPub(c.eticket))
	c.devCert = nintendoCert(rsaCertSize, keyTypeRsa2048, id, rsaPub(c.device))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "OpenPak Harbor device"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(25, 0, 0)}
	c.tlsCert, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &c.tls.PublicKey, c.tls)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *testConsole) request(t *testing.T, nonce string) *enrolRequest {
	t.Helper()
	raw, _ := base64Std(nonce)
	msg := enrolProofMessage(raw, c.id)
	h := sha256.Sum256(msg)
	rsaSign := func(k *rsa.PrivateKey) []byte {
		s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	eccRaw, err := b233.Sign(rand.Reader, c.ecc, msg)
	if err != nil {
		t.Fatal(err)
	}
	eccDER, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(eccRaw[:30]), new(big.Int).SetBytes(eccRaw[30:])})
	req := &enrolRequest{Nonce: nonce, DeviceID: fmt.Sprintf("%016x", c.id), Serial: c.serial,
		ECCCert: c.eccCert, ETicketCert: c.etCert, DeviceCert: c.devCert, TLSCertificate: c.tlsCert}
	req.Proofs.ECC, req.Proofs.ETicket, req.Proofs.Device, req.Proofs.TLS = eccDER, rsaSign(c.eticket), rsaSign(c.device), rsaSign(c.tls)
	return req
}

func base64Std(s string) ([]byte, error) {
	var out []byte
	err := json.Unmarshal([]byte(`"`+s+`"`), &out)
	return out, err
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func enrolServer(t *testing.T) (*server, *fakeClock) {
	t.Helper()
	s := dauthServer(t)
	s.store = &Store{path: filepath.Join(t.TempDir(), "baas.json"), Users: map[string]*User{}, Devices: map[string]*DeviceAccount{}}
	s.harbor = newHarborDevices(testDeviceCA(t), filepath.Join(t.TempDir(), "harbor-devices.json"))
	clock := &fakeClock{t: time.Now()}
	s.harbor.now = clock.now
	return s, clock
}

// post sends a request to the dauth host, presenting `cert` as the TLS client certificate.
func post(s *server, path string, body any, cert []byte, session string) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	r.Host = "dauth-lp1.ndas.srv.nintendo.net"
	if cert != nil {
		c, err := x509.ParseCertificate(cert)
		if err != nil {
			panic(err)
		}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
	}
	if session != "" {
		r.Header.Set(consoleSessionHeader, session)
	}
	w := httptest.NewRecorder()
	s.dauth(w, r, raw)
	return w
}

func challenge(t *testing.T, s *server) string {
	t.Helper()
	w := post(s, "/harbor/v1/devices/challenge", nil, nil, "")
	var out struct{ Nonce string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Nonce == "" {
		t.Fatalf("challenge = %d %s", w.Code, w.Body.String())
	}
	return out.Nonce
}

type enrolled struct {
	ECC     []byte `json:"ecc_certificate"`
	ETicket []byte `json:"eticket_certificate"`
	Device  []byte `json:"device_certificate"`
	TLS     []byte `json:"tls_certificate"`
}

func enrolOK(t *testing.T, s *server, c *testConsole, presented []byte) enrolled {
	t.Helper()
	w := post(s, "/harbor/v1/devices", c.request(t, challenge(t, s)), presented, "")
	var out enrolled
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("enrol = %d %s", w.Code, w.Body.String())
	}
	return out
}

func tokenSub(t *testing.T, w *httptest.ResponseRecorder) (sub, sn string) {
	t.Helper()
	var out struct {
		Results []struct {
			Token string `json:"device_auth_token"`
		} `json:"results"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Results) == 0 {
		t.Fatalf("device_auth_tokens = %d %s", w.Code, w.Body.String())
	}
	claims, _ := parseJWT(out.Results[0].Token, nil)
	n, _ := claims["nintendo"].(map[string]any)
	return str(claims, "sub"), str(n, "sn")
}

var tokenBody = map[string]any{"token_requests": []any{map[string]any{"client_id": "8f849b5d34778d8e"}}}

func wantInUse(t *testing.T, what string, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusConflict || strings.TrimSpace(w.Body.String()) != `{"action":"make_new_console","error":"device_id_in_use"}` {
		t.Fatalf("%s = %d %s, want 409 device_id_in_use", what, w.Code, w.Body.String())
	}
}

// Without CA keys nothing changes: the enrolment says it is unavailable and dauth names a
// console by its certificate exactly as before.
func TestHarborEnrolmentInertWithoutKeys(t *testing.T) {
	s := dauthServer(t)
	for _, p := range []string{"/harbor/v1/devices/challenge", "/harbor/v1/devices", "/harbor/v1/devices/live"} {
		if w := post(s, p, nil, nil, ""); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "enrolment_unavailable") {
			t.Fatalf("%s = %d %s", p, w.Code, w.Body.String())
		}
	}
	c := newTestConsole(t, 0x7E00112233445566, "1234567890")
	cert, _ := x509.ParseCertificate(c.tlsCert)
	sub, sn := tokenSub(t, post(s, "/v8/device_auth_tokens", tokenBody, c.tlsCert, "a"))
	if sub != legacyDauthID(cert) || sn != consoleSerial(sub) {
		t.Fatalf("sub/sn = %q %q, want the certificate's id as before", sub, sn)
	}
	if !s.bindDeviceAccount("any", sub) {
		t.Fatal("a login was refused without a device CA")
	}
}

func TestHarborEnrolSignsAndBinds(t *testing.T) {
	s, _ := enrolServer(t)
	c := newTestConsole(t, 0x7E00112233445566, "1234567890")
	before, _ := x509.ParseCertificate(c.tlsCert)
	out := enrolOK(t, s, c, c.tlsCert)

	// Nintendo-format certificates: the same bodies, now with HD00000001's signature.
	for _, pair := range [][2][]byte{{c.eccCert, out.ECC}, {c.etCert, out.ETicket}, {c.devCert, out.Device}} {
		sent, got := pair[0], pair[1]
		if !bytes.Equal(sent[certSigned:], got[certSigned:]) || !bytes.Equal(sent[:4], got[:4]) {
			t.Fatal("a certificate body changed")
		}
		if !b233.Verify(&s.harbor.ca.ecc.PublicKey, got[certSigned:], got[certSignature:certSignature+60]) {
			t.Fatal("a certificate's signature does not verify against HD00000001")
		}
	}
	// The TLS certificate: the console's key, chained to the device CA, for client auth.
	tlsCert, err := x509.ParseCertificate(out.TLS)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeysEqual(tlsCert.PublicKey, &c.tls.PublicKey) {
		t.Fatal("the TLS certificate carries another key")
	}
	if _, err := tlsCert.Verify(x509.VerifyOptions{Roots: s.harbor.ca.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("the TLS certificate does not chain: %v", err)
	}

	// dauth knows it by its new certificate, under the id it had before, with its own serial.
	sub, sn := tokenSub(t, post(s, "/v8/device_auth_tokens", tokenBody, out.TLS, "session-a"))
	if sub != legacyDauthID(before) || sn != c.serial {
		t.Fatalf("enrolled dauth sub/sn wrong (sub kept: %v, serial: %v)", sub == legacyDauthID(before), sn == c.serial)
	}

	// BaaS: the device account belongs to this console from its first login.
	s.store.Devices["acct1"] = &DeviceAccount{ID: "acct1", Password: "p"}
	if !s.bindDeviceAccount("acct1", sub) || s.store.Devices["acct1"].BoundDevice != sub {
		t.Fatal("the device account was not bound")
	}
	if s.bindDeviceAccount("acct1", "cert-0000000000000000") {
		t.Fatal("another device used a bound device account")
	}
	// An account first used by a console that is not enrolled stays unbound.
	s.store.Devices["acct2"] = &DeviceAccount{ID: "acct2", Password: "p"}
	if !s.bindDeviceAccount("acct2", "cert-1111111111111111") || s.store.Devices["acct2"].BoundDevice != "" {
		t.Fatal("an unenrolled device bound an account")
	}

	// The store survives a restart.
	again := newHarborDevices(s.harbor.ca, s.harbor.path)
	if len(again.Devices) != 1 || !again.enrolledDauthID(sub) {
		t.Fatal("the enrolment was not kept")
	}
}

// A copied NAND that made new keys under the same id is another console: refused while the first
// is live. The restored console (same id, same keys) gets its certificates again.
func TestHarborDuplicateRefusedRestoreAccepted(t *testing.T) {
	s, clock := enrolServer(t)
	c := newTestConsole(t, 0x7E00AABBCCDDEEFF, "5550001112")
	first := enrolOK(t, s, c, c.tlsCert)

	copyWithNewKeys := newTestConsole(t, c.id, "5550001112")
	wantInUse(t, "second console, same id", post(s, "/harbor/v1/devices", copyWithNewKeys.request(t, challenge(t, s)), copyWithNewKeys.tlsCert, ""))

	// The same id and serial under another id is refused too.
	sameSerial := newTestConsole(t, 0x7E00000000000001, "5550001112")
	wantInUse(t, "same serial, other id", post(s, "/harbor/v1/devices", sameSerial.request(t, challenge(t, s)), sameSerial.tlsCert, ""))

	restored := enrolOK(t, s, c, first.TLS)
	if !bytes.Equal(restored.TLS, first.TLS) || !bytes.Equal(restored.ECC, first.ECC) {
		t.Fatal("the restored console got other certificates")
	}

	// Once the first console has been silent for the whole window, the id may take other keys,
	// and the old certificate is then refused at dauth.
	clock.t = clock.t.Add(enrolLiveWindow + time.Hour)
	enrolOK(t, s, copyWithNewKeys, copyWithNewKeys.tlsCert)
	wantInUse(t, "dauth with the old certificate", post(s, "/v8/device_auth_tokens", tokenBody, first.TLS, "s1"))
}

// One console's identity, two running copies: the second session is refused while the first
// says it is alive, and admitted once it has gone quiet or released.
func TestHarborConcurrentSessions(t *testing.T) {
	s, clock := enrolServer(t)
	c := newTestConsole(t, 0x7E0102030405060A, "9876543210")
	out := enrolOK(t, s, c, c.tlsCert)

	tokenSub(t, post(s, "/v8/device_auth_tokens", tokenBody, out.TLS, "first"))
	wantInUse(t, "second session at dauth", post(s, "/v8/device_auth_tokens", tokenBody, out.TLS, "second"))
	wantInUse(t, "second session's live ping", post(s, "/harbor/v1/devices/live", nil, out.TLS, "second"))
	wantInUse(t, "second session's edge token", post(s, "/v8/edge_tokens", map[string]any{"token_requests": []any{map[string]any{"client_id": "x", "vendor_id": "akamai"}}}, out.TLS, "second"))

	// Harbor pings every 30 s: a console that keeps pinging keeps its claim, and one more beat
	// than that (a late one) does not lose it.
	clock.t = clock.t.Add(30 * time.Second)
	if w := post(s, "/harbor/v1/devices/live", nil, out.TLS, "first"); w.Code != http.StatusNoContent {
		t.Fatalf("first session's ping = %d", w.Code)
	}
	clock.t = clock.t.Add(30 * time.Second)
	wantInUse(t, "second session while the first pings", post(s, "/harbor/v1/devices/live", nil, out.TLS, "second"))

	// A killed process releases nothing: the next one takes over once its beat is missed, well
	// inside the 90 s the claim used to last.
	if sessionLiveWindow > 60*time.Second {
		t.Fatalf("sessionLiveWindow = %v, a killed Harbor would wait too long", sessionLiveWindow)
	}
	clock.t = clock.t.Add(sessionLiveWindow + time.Second)
	tokenSub(t, post(s, "/v8/device_auth_tokens", tokenBody, out.TLS, "second"))
	// ...and the one it replaced is the stranger now.
	wantInUse(t, "the replaced session", post(s, "/harbor/v1/devices/live", nil, out.TLS, "first"))

	// A release frees the id at once.
	if w := post(s, "/harbor/v1/devices/release", nil, out.TLS, "second"); w.Code != http.StatusNoContent {
		t.Fatalf("release = %d", w.Code)
	}
	tokenSub(t, post(s, "/v8/device_auth_tokens", tokenBody, out.TLS, "third"))
}

func TestHarborEnrolmentRefusals(t *testing.T) {
	s, _ := enrolServer(t)
	c := newTestConsole(t, 0x7E00112233445566, "1234567890")
	try := func(what string, mutate func(*enrolRequest), wantCode string) {
		t.Helper()
		req := c.request(t, challenge(t, s))
		mutate(req)
		w := post(s, "/harbor/v1/devices", req, c.tlsCert, "")
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), wantCode) {
			t.Fatalf("%s = %d %s, want 400 %s", what, w.Code, w.Body.String(), wantCode)
		}
	}
	try("a console's id (no 7e prefix)", func(r *enrolRequest) { r.DeviceID = "0000112233445566" }, "invalid_device")
	try("a wrong check digit", func(r *enrolRequest) {
		last := r.Serial[13]
		r.Serial = r.Serial[:13] + string('0'+(last-'0'+1)%10)
	}, "invalid_device")
	try("a console serial", func(r *enrolRequest) { r.Serial = "XAW" + r.Serial[3:] }, "invalid_device")
	try("a certificate for another id", func(r *enrolRequest) { r.DeviceID = "7e00112233445567" }, "invalid_device")
	try("a proof by another key", func(r *enrolRequest) {
		other := newTestConsole(t, c.id, "1234567890").request(t, r.Nonce)
		r.Proofs.Device = other.Proofs.Device
	}, "invalid_proof")
	try("a proof for another nonce", func(r *enrolRequest) {
		r.Proofs.ECC = c.request(t, challenge(t, s)).Proofs.ECC
	}, "invalid_proof")
	try("an unknown nonce", func(r *enrolRequest) { r.Nonce = "AAAA" }, "invalid_nonce")

	// A nonce is single-use.
	req := c.request(t, challenge(t, s))
	if w := post(s, "/harbor/v1/devices", req, c.tlsCert, ""); w.Code != 200 {
		t.Fatalf("enrol = %d %s", w.Code, w.Body.String())
	}
	if w := post(s, "/harbor/v1/devices", req, c.tlsCert, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("replayed enrolment = %d", w.Code)
	}
}

// The CA as the box loads it: three PEM files.
func TestLoadHarborDeviceCAFiles(t *testing.T) {
	ca := testDeviceCA(t)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		return p
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(ca.tlsKey)
	eccPath := write("hd.pem", ca.ecc.MarshalPEM())
	certPath := write("tls-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.tlsCert.Raw}))
	keyPath := write("tls-ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	got, err := loadHarborDeviceCAFiles(eccPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.ecc.D.Cmp(ca.ecc.D) != 0 {
		t.Fatal("ECC key differs")
	}
	other := testDeviceCA(t)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other.tlsKey)
	if _, err := loadHarborDeviceCAFiles(eccPath, certPath, write("wrong.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}))); err == nil {
		t.Fatal("a key that is not the certificate's loaded")
	}
	t.Setenv("NX_DEVICE_CA_ECC_KEY_FILE", eccPath)
	t.Setenv("NX_DEVICE_CA_TLS_CERT_FILE", "")
	t.Setenv("NX_DEVICE_CA_TLS_KEY_FILE", "")
	if _, err := loadHarborDeviceCA(); err == nil {
		t.Fatal("a partial configuration was accepted")
	}
}
