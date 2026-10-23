// Package devices is Harbor device enrolment: OpenPak's device CA signs a Harbor console's device certificates, the
// way Nintendo's signs a Switch's at the factory (design: harbor-eden docs/harbor/calibration.md,
// "Certificates", owner decisions 2026-10-08).
//
// A Harbor console makes its own calibration (CAL0) with an ECC B233 device certificate, eTicket
// and device RSA-2048 certificates in Nintendo's format, and an X.509 TLS client certificate,
// all unsigned. Once, after its first OpenPak sign-in, it enrols on the dauth host (where it
// presents its TLS client certificate):
//
//	POST /harbor/v1/devices/challenge -> {"nonce": b64(32), "expires_in": 300}
//	POST /harbor/v1/devices           -> the four certificates, signed
//	POST /harbor/v1/devices/live      -> 204, every 30 s while the console runs
//	POST /harbor/v1/devices/release   -> 204, when it stops
//
// The enrolment carries proof of possession: each of the four private keys signs
// enrolProofMessage (ECDSA-SHA256 on B233 for the ECC key, RSASSA-PKCS1-v1_5-SHA256 for the
// three RSA keys).
//
// One live console per device id: an id enrolled with other keys that was seen within
// enrolLiveWindow, a device CA certificate that is no longer its id's, and a second console
// session (X-OpenPak-Console-Session) while another was heard from within SessionLiveWindow all
// answer 409 {"error":"device_id_in_use","action":"make_new_console"}, which Harbor answers by
// offering "Make this a new console". The same id with the same keys is the same console (a
// restore): it gets its certificates again.
//
// The CA keys are files named by NX_DEVICE_CA_ECC_KEY_FILE, NX_DEVICE_CA_TLS_CERT_FILE and
// NX_DEVICE_CA_TLS_KEY_FILE, mounted read-only. Without all three this file is inert: the
// enrolment answers 503 {"error":"enrolment_unavailable"} and dauth and BaaS behave exactly as
// before. The files:
//
//	NX_DEVICE_CA_ECC_KEY_FILE   HD00000001: a sect233r1 private key, PEM, SEC 1 "EC PRIVATE KEY"
//	                            (openssl ecparam -name sect233r1 -genkey -noout) or PKCS#8
//	                            "PRIVATE KEY" (openssl genpkey ... ec_paramgen_curve:sect233r1).
//	NX_DEVICE_CA_TLS_CERT_FILE  the OpenPak Harbor Device CA: an X.509 CA certificate, PEM
//	                            (basicConstraints CA:TRUE, keyUsage keyCertSign).
//	NX_DEVICE_CA_TLS_KEY_FILE   its private key, PEM: PKCS#8, PKCS#1 RSA or SEC 1 EC (RSA >= 2048
//	                            or ECDSA P-256/P-384).
//
// Changing either key re-keys every enrolled console's certificates: keep them for good.
//
// Privacy: device ids, serials and session ids are never logged.
package devices

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"nx-baas/redact"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"nx-baas/internal/b233"
	"nx-baas/internal/httpx"
	"nx-baas/internal/store"
)

const (
	// The issuer every Harbor device certificate names: HD00000001 (the B233 key below) under the
	// root Root-OP00000001.
	HarborIssuer = "Root-OP00000001-HD00000001"

	SigTypeEcdsaSha256 = 0x00010005
	KeyTypeRsa2048     = 1
	KeyTypeEccB233     = 2

	EccCertSize = 0x180
	RsaCertSize = 0x240

	CertSignature = 0x004
	CertSigned    = 0x080 // the signature covers the certificate from the issuer to its end
	CertKeyType   = 0x0C0
	CertName      = 0x0C4
	CertPublicKey = 0x108

	enrolProofLabel   = "OpenPak Harbor device enrolment v1\x00"
	nonceLifetime     = 5 * time.Minute
	maxNonces         = 10000
	enrolPerHour      = 10
	EnrolLiveWindow   = 30 * 24 * time.Hour // an enrolment with other keys waits this long
	SessionLiveWindow = 45 * time.Second    // Harbor says it is alive every 30 s; a process that was killed (nothing released its claim) is replaced after this
	lastSeenSaveEvery = time.Hour

	ConsoleSessionHeader = "X-OpenPak-Console-Session"
)

// harborDeviceCA is the OpenPak device CA: a B233 key for Nintendo-format certificates and an
// X.509 CA for the TLS client certificate.
type CA struct {
	ECC     *b233.PrivateKey
	TLSCert *x509.Certificate
	TLSKey  crypto.Signer
	Pool    *x509.CertPool
}

// loadHarborDeviceCA reads the CA from the files the environment names. None set: nil, nil (the
// enrolment is off). Some set, or a file that does not parse: an error, and the caller keeps the
// enrolment off.
func LoadCA() (*CA, error) {
	eccFile, certFile, keyFile := os.Getenv("NX_DEVICE_CA_ECC_KEY_FILE"), os.Getenv("NX_DEVICE_CA_TLS_CERT_FILE"), os.Getenv("NX_DEVICE_CA_TLS_KEY_FILE")
	if eccFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}
	if eccFile == "" || certFile == "" || keyFile == "" {
		return nil, errors.New("NX_DEVICE_CA_ECC_KEY_FILE, NX_DEVICE_CA_TLS_CERT_FILE and NX_DEVICE_CA_TLS_KEY_FILE must all be set")
	}
	return LoadCAFiles(eccFile, certFile, keyFile)
}

func LoadCAFiles(eccFile, certFile, keyFile string) (*CA, error) {
	eccPEM, err := os.ReadFile(eccFile)
	if err != nil {
		return nil, err
	}
	ecc, err := b233.ParsePrivateKeyPEM(eccPEM)
	if err != nil {
		return nil, fmt.Errorf("ECC key: %w", err)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("TLS CA certificate: no CERTIFICATE block")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("TLS CA certificate: %w", err)
	}
	if !caCert.IsCA || caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("TLS CA certificate: not a CA (basicConstraints CA:TRUE and keyUsage keyCertSign are required)")
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	signer, err := parseSignerPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("TLS CA key: %w", err)
	}
	if !PublicKeysEqual(signer.Public(), caCert.PublicKey) {
		return nil, errors.New("TLS CA key does not match the CA certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &CA{ECC: ecc, TLSCert: caCert, TLSKey: signer, Pool: pool}, nil
}

func parseSignerPEM(data []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("no private key block")
		}
		switch block.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			if s, ok := k.(crypto.Signer); ok {
				return s, nil
			}
			return nil, errors.New("unsupported key type")
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		}
	}
}

func PublicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// harborDevice is one enrolled console.
type Device struct {
	DeviceID      string `json:"deviceId"` // 16 lowercase hex digits, top byte 7e
	Serial        string `json:"serial"`
	KeysSHA256    string `json:"keysSha256"` // the four public keys: same keys, same console
	ECCCert       []byte `json:"eccCertificate"`
	ETicketCert   []byte `json:"eticketCertificate"`
	DeviceCert    []byte `json:"deviceCertificate"`
	TLSCert       []byte `json:"tlsCertificate"`
	TLSCertSHA256 string `json:"tlsCertificateSha256"`
	// DauthID is the device id dauth issues this console: the one it had before it enrolled
	// ("cert-<8 bytes>" of the certificate it presented then), so pctl pairings, shop links and
	// device accounts made before the enrolment carry on.
	DauthID    string `json:"dauthId"`
	EnrolledAt int64  `json:"enrolledAt"`
	LastSeen   int64  `json:"lastSeen"`
}

type liveConsole struct {
	session string
	seen    time.Time
}

// harborDevices is the enrolment store (NX_DATA/harbor-devices.json) and its in-memory state.
type Registry struct {
	// CA signs enrolments; FilePath is harbor-devices.json; Now is the clock (tests set it).
	// None is persisted.
	CA       *CA              `json:"-"`
	FilePath string           `json:"-"`
	Now      func() time.Time `json:"-"`

	mu       sync.Mutex
	Devices  map[string]*Device `json:"devices"` // by device id
	byTLS    map[string]*Device
	byDauth  map[string]*Device
	nonces   map[string]time.Time
	attempts map[string][]time.Time
	live     map[string]liveConsole
	savedAt  time.Time
}

func NewRegistry(ca *CA, path string) *Registry {
	d := &Registry{CA: ca, FilePath: path, Now: time.Now, Devices: map[string]*Device{},
		nonces: map[string]time.Time{}, attempts: map[string][]time.Time{}, live: map[string]liveConsole{}}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(b, d); err != nil {
				log.Printf("[harbor-devices] %s does not parse (%v); starting empty and keeping the file aside", path, redact.Err(err))
				os.Rename(path, path+".invalid")
				d.Devices = map[string]*Device{}
			}
		}
	}
	if d.Devices == nil {
		d.Devices = map[string]*Device{}
	}
	d.index()
	return d
}

// index rebuilds the lookups. Called with mu held (or before the store is shared).
func (d *Registry) index() {
	d.byTLS, d.byDauth = map[string]*Device{}, map[string]*Device{}
	for _, dev := range d.Devices {
		d.byTLS[dev.TLSCertSHA256] = dev
		if dev.DauthID != "" {
			d.byDauth[dev.DauthID] = dev
		}
	}
}

// save is called with mu held.
func (d *Registry) save() {
	d.savedAt = d.Now()
	if d.FilePath == "" {
		return
	}
	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		return
	}
	if err := os.WriteFile(d.FilePath+".tmp", b, 0o600); err != nil {
		log.Printf("[harbor-devices] could not write the store: %v", redact.Err(err))
		return
	}
	os.Rename(d.FilePath+".tmp", d.FilePath)
}

// ---- the console's identity at dauth ----

// CertDauthID is how dauth has always named a console: a hash of the certificate it presents.
func CertDauthID(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "cert-" + hex.EncodeToString(sum[:8])
}

// errDeviceInUse is the one-live-console refusal.
var ErrDeviceInUse = errors.New("device_id_in_use")

// forCertificate finds the enrolled console a TLS client certificate belongs to and records that
// it is alive. nil, nil: not an enrolled console (a Switch, or a Harbor that has not enrolled).
func (d *Registry) ForCertificate(c *x509.Certificate, session string) (*Device, error) {
	sum := sha256.Sum256(c.Raw)
	_, chainErr := c.Verify(x509.VerifyOptions{Roots: d.CA.Pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: d.Now()})
	d.mu.Lock()
	defer d.mu.Unlock()
	dev := d.byTLS[hex.EncodeToString(sum[:])]
	if dev == nil {
		dev = d.byDauth[CertDauthID(c)] // the certificate it enrolled with
	}
	if dev == nil {
		if chainErr == nil {
			// Signed by the device CA, and not the certificate its id is enrolled with now: its id
			// went to other keys.
			return nil, ErrDeviceInUse
		}
		return nil, nil
	}
	if !d.touchLocked(dev, session) {
		return nil, ErrDeviceInUse
	}
	return dev, nil
}

// touchLocked records that a console session is alive; false when another session of the same
// console was heard from within the window. An empty session claims nothing.
func (d *Registry) touchLocked(dev *Device, session string) bool {
	now := d.Now()
	if session != "" {
		cur, ok := d.live[dev.DeviceID]
		if ok && cur.session != session && now.Sub(cur.seen) < SessionLiveWindow {
			return false
		}
		d.live[dev.DeviceID] = liveConsole{session: session, seen: now}
	}
	dev.LastSeen = now.Unix()
	if now.Sub(d.savedAt) > lastSeenSaveEvery {
		d.save()
	}
	return true
}

func (d *Registry) Release(dev *Device, session string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if cur, ok := d.live[dev.DeviceID]; ok && cur.session == session {
		delete(d.live, dev.DeviceID)
	}
}

// enrolledDauthID says whether a dauth device id is an enrolled console's.
func (d *Registry) EnrolledDauthID(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.byDauth[id] != nil
}

func WriteDeviceInUse(w http.ResponseWriter) {
	httpx.WriteJSON(w, http.StatusConflict, map[string]any{"error": "device_id_in_use", "action": "make_new_console"})
}

// ---- the enrolment ----

type EnrolRequest struct {
	Nonce          string `json:"nonce"`
	DeviceID       string `json:"device_id"`
	Serial         string `json:"serial"`
	ECCCert        []byte `json:"ecc_certificate"`
	ETicketCert    []byte `json:"eticket_certificate"`
	DeviceCert     []byte `json:"device_certificate"`
	TLSCertificate []byte `json:"tls_certificate"`
	Proofs         struct {
		ECC     []byte `json:"ecc"`
		ETicket []byte `json:"eticket"`
		Device  []byte `json:"device"`
		TLS     []byte `json:"tls"`
	} `json:"proofs"`
}

// enrolProofMessage is what each of the console's keys signs: a label, the server's nonce and
// the device id (8 bytes, big-endian).
func EnrolProofMessage(nonce []byte, deviceID uint64) []byte {
	msg := append([]byte(enrolProofLabel), nonce...)
	return binary.BigEndian.AppendUint64(msg, deviceID)
}

// harborSerialValid: "HBW", ten digits and the console check digit (weights 1 and 3).
func harborSerialValid(serial string) bool {
	if len(serial) != 14 || !strings.HasPrefix(serial, "HBW") {
		return false
	}
	sum := 0
	for i := 0; i < 11; i++ {
		c := serial[3+i]
		if c < '0' || c > '9' {
			return false
		}
		if i < 10 {
			if i%2 == 0 {
				sum += int(c - '0')
			} else {
				sum += 3 * int(c-'0')
			}
		}
	}
	return int(serial[13]-'0') == (10-sum%10)%10
}

func CertificateName(deviceID uint64) string {
	return fmt.Sprintf("NX%016X-0", deviceID)
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// checkNintendoCertificate checks an unsigned certificate's shape: ECDSA-SHA256 signature type,
// the HD00000001 issuer, the key type, and the console's name.
func checkNintendoCertificate(cert []byte, size int, keyType uint32, name string) error {
	if len(cert) != size {
		return fmt.Errorf("size %d", len(cert))
	}
	if binary.BigEndian.Uint32(cert) != SigTypeEcdsaSha256 {
		return errors.New("signature type")
	}
	if cString(cert[CertSigned:CertSigned+0x40]) != HarborIssuer {
		return errors.New("issuer")
	}
	if binary.BigEndian.Uint32(cert[CertKeyType:]) != keyType {
		return errors.New("key type")
	}
	if cString(cert[CertName:CertName+0x40]) != name {
		return errors.New("name")
	}
	return nil
}

func nintendoRSAKey(cert []byte) (*rsa.PublicKey, error) {
	n := new(big.Int).SetBytes(cert[CertPublicKey : CertPublicKey+0x100])
	e := binary.BigEndian.Uint32(cert[CertPublicKey+0x100:])
	if n.BitLen() != 2048 || e < 3 || e%2 == 0 {
		return nil, errors.New("not an RSA-2048 key")
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

func verifyRSAProof(pub crypto.PublicKey, msg, sig []byte) bool {
	k, ok := pub.(*rsa.PublicKey)
	if !ok || k.N.BitLen() < 2048 {
		return false
	}
	h := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
}

func verifyTLSProof(pub crypto.PublicKey, msg, sig []byte) bool {
	if k, ok := pub.(*ecdsa.PublicKey); ok {
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, h[:], sig)
	}
	return verifyRSAProof(pub, msg, sig)
}

// signNintendo fills a certificate's signature with HD00000001's.
func (ca *CA) signNintendo(cert []byte) ([]byte, error) {
	out := bytes.Clone(cert)
	sig, err := b233.Sign(rand.Reader, ca.ECC, out[CertSigned:])
	if err != nil {
		return nil, err
	}
	clear(out[CertSignature:CertSigned])
	copy(out[CertSignature:], sig)
	return out, nil
}

// issueTLS makes the console's TLS client certificate: its key, its name, the device CA's
// signature.
func (ca *CA) issueTLS(pub crypto.PublicKey, deviceID uint64, now time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	notAfter := now.AddDate(25, 0, 0)
	if notAfter.After(ca.TLSCert.NotAfter) {
		notAfter = ca.TLSCert.NotAfter
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if _, ok := pub.(*rsa.PublicKey); ok {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: CertificateName(deviceID), Organization: []string{"OpenPak Harbor"}},
		NotBefore:    now.Add(-24 * time.Hour), NotAfter: notAfter,
		KeyUsage:    keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.TLSCert, pub, ca.TLSKey)
}

func keysFingerprint(eccPub []byte, eticket, device *rsa.PublicKey, tlsPub crypto.PublicKey) string {
	spki, _ := x509.MarshalPKIXPublicKey(tlsPub)
	h := sha256.New()
	h.Write(eccPub)
	h.Write(eticket.N.Bytes())
	h.Write(device.N.Bytes())
	h.Write(spki)
	return hex.EncodeToString(h.Sum(nil))
}

type enrolError struct {
	status int
	code   string
	reason string
}

func (e *enrolError) Error() string { return e.code + ": " + e.reason }

func badDevice(reason string) error {
	return &enrolError{http.StatusBadRequest, "invalid_device", reason}
}

// issueNonce hands out a challenge.
func (d *Registry) issueNonce() (string, error) {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.Now()
	for n, exp := range d.nonces {
		if now.After(exp) {
			delete(d.nonces, n)
		}
	}
	if len(d.nonces) >= maxNonces {
		return "", &enrolError{http.StatusTooManyRequests, "rate_limited", "too many open challenges"}
	}
	key := base64.StdEncoding.EncodeToString(nonce)
	d.nonces[key] = now.Add(nonceLifetime)
	return key, nil
}

// enrol checks a request and answers the console's signed certificates. presented is the TLS
// client certificate of the request (the dauth id the console has had so far), or nil.
func (d *Registry) enrol(req *EnrolRequest, presented *x509.Certificate) (*Device, bool, error) {
	// The challenge is single-use whatever happens next.
	d.mu.Lock()
	exp, ok := d.nonces[req.Nonce]
	delete(d.nonces, req.Nonce)
	d.mu.Unlock()
	if !ok || d.Now().After(exp) {
		return nil, false, &enrolError{http.StatusBadRequest, "invalid_nonce", "unknown or expired challenge"}
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return nil, false, &enrolError{http.StatusBadRequest, "invalid_nonce", "not base64"}
	}

	// Identity: a Harbor device id and serial.
	if len(req.DeviceID) != 16 {
		return nil, false, badDevice("device id")
	}
	id, err := strconv.ParseUint(req.DeviceID, 16, 64)
	if err != nil || id>>56 != 0x7E {
		return nil, false, badDevice("device id")
	}
	deviceID := fmt.Sprintf("%016x", id)
	if !harborSerialValid(req.Serial) {
		return nil, false, badDevice("serial")
	}

	if !d.allowAttempt(deviceID) {
		return nil, false, &enrolError{http.StatusTooManyRequests, "rate_limited", "too many enrolments for this device"}
	}

	// The certificates, unsigned, and their keys.
	name := CertificateName(id)
	if err := checkNintendoCertificate(req.ECCCert, EccCertSize, KeyTypeEccB233, name); err != nil {
		return nil, false, badDevice("ECC certificate: " + err.Error())
	}
	eccPub, err := b233.ParsePublicKey(req.ECCCert[CertPublicKey : CertPublicKey+2*b233.Size])
	if err != nil {
		return nil, false, badDevice("ECC certificate: " + err.Error())
	}
	if err := checkNintendoCertificate(req.ETicketCert, RsaCertSize, KeyTypeRsa2048, name); err != nil {
		return nil, false, badDevice("eTicket certificate: " + err.Error())
	}
	eticketPub, err := nintendoRSAKey(req.ETicketCert)
	if err != nil {
		return nil, false, badDevice("eTicket certificate: " + err.Error())
	}
	if err := checkNintendoCertificate(req.DeviceCert, RsaCertSize, KeyTypeRsa2048, name); err != nil {
		return nil, false, badDevice("device certificate: " + err.Error())
	}
	devicePub, err := nintendoRSAKey(req.DeviceCert)
	if err != nil {
		return nil, false, badDevice("device certificate: " + err.Error())
	}
	tlsCert, err := x509.ParseCertificate(req.TLSCertificate)
	if err != nil {
		return nil, false, badDevice("TLS certificate")
	}

	// Proof of possession: every key signed this nonce for this id.
	msg := EnrolProofMessage(nonce, id)
	if !b233.VerifyASN1(eccPub, msg, req.Proofs.ECC) ||
		!verifyRSAProof(eticketPub, msg, req.Proofs.ETicket) ||
		!verifyRSAProof(devicePub, msg, req.Proofs.Device) ||
		!verifyTLSProof(tlsCert.PublicKey, msg, req.Proofs.TLS) {
		return nil, false, &enrolError{http.StatusBadRequest, "invalid_proof", "a key did not sign the challenge"}
	}
	keys := keysFingerprint(eccPub.Bytes(), eticketPub, devicePub, tlsCert.PublicKey)

	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.Now()
	if dev := d.Devices[deviceID]; dev != nil {
		if dev.KeysSHA256 == keys {
			// The same console (a restore with its device key): its certificates again.
			if dev.Serial != req.Serial {
				return nil, false, badDevice("serial")
			}
			dev.LastSeen = now.Unix()
			d.save()
			return dev, false, nil
		}
		if now.Sub(time.Unix(dev.LastSeen, 0)) < EnrolLiveWindow {
			return nil, false, ErrDeviceInUse
		}
		// Other keys, and the console that had them is gone: the id is free again.
	}
	for _, other := range d.Devices {
		if other.Serial == req.Serial && other.DeviceID != deviceID {
			return nil, false, ErrDeviceInUse
		}
	}

	dev := &Device{DeviceID: deviceID, Serial: req.Serial, KeysSHA256: keys, EnrolledAt: now.Unix(), LastSeen: now.Unix()}
	if dev.ECCCert, err = d.CA.signNintendo(req.ECCCert); err == nil {
		if dev.ETicketCert, err = d.CA.signNintendo(req.ETicketCert); err == nil {
			if dev.DeviceCert, err = d.CA.signNintendo(req.DeviceCert); err == nil {
				dev.TLSCert, err = d.CA.issueTLS(tlsCert.PublicKey, id, now)
			}
		}
	}
	if err != nil {
		return nil, false, &enrolError{http.StatusInternalServerError, "signing_failed", err.Error()}
	}
	sum := sha256.Sum256(dev.TLSCert)
	dev.TLSCertSHA256 = hex.EncodeToString(sum[:])
	if presented != nil {
		dev.DauthID = CertDauthID(presented)
	} else {
		dev.DauthID = deviceID
	}
	if old := d.Devices[deviceID]; old != nil {
		delete(d.byTLS, old.TLSCertSHA256)
		delete(d.byDauth, old.DauthID)
		delete(d.live, deviceID)
	}
	d.Devices[deviceID] = dev
	d.index()
	d.save()
	return dev, true, nil
}

func (d *Registry) allowAttempt(deviceID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.Now()
	kept := d.attempts[deviceID][:0]
	for _, t := range d.attempts[deviceID] {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	if len(kept) >= enrolPerHour {
		d.attempts[deviceID] = kept
		return false
	}
	d.attempts[deviceID] = append(kept, now)
	return true
}

// Handler answers /harbor/v1/devices* on the dauth host. A nil Registry (no device CA) says
// the enrolment is unavailable.
func (d *Registry) Handler(w http.ResponseWriter, r *http.Request, body []byte) {
	if d == nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "enrolment_unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var presented *x509.Certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		presented = r.TLS.PeerCertificates[0]
	}
	session := r.Header.Get(ConsoleSessionHeader)

	switch r.URL.Path {
	case "/harbor/v1/devices/challenge":
		nonce, err := d.issueNonce()
		if err != nil {
			writeEnrolError(w, err)
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{"nonce": nonce, "expires_in": int(nonceLifetime.Seconds())})

	case "/harbor/v1/devices":
		var req EnrolRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeEnrolError(w, badDevice("not JSON"))
			return
		}
		dev, fresh, err := d.enrol(&req, presented)
		if err != nil {
			log.Printf("[harbor-devices] enrolment refused: %v", redact.Err(err))
			writeEnrolError(w, err)
			return
		}
		if fresh {
			log.Printf("[harbor-devices] a console enrolled")
		} else {
			log.Printf("[harbor-devices] an enrolled console asked again (same keys)")
		}
		httpx.WriteJSON(w, 200, map[string]any{
			"ecc_certificate":     dev.ECCCert,
			"eticket_certificate": dev.ETicketCert,
			"device_certificate":  dev.DeviceCert,
			"tls_certificate":     dev.TLSCert,
			"tls_ca_certificate":  d.CA.TLSCert.Raw,
		})

	case "/harbor/v1/devices/live", "/harbor/v1/devices/release":
		if presented == nil {
			writeEnrolError(w, &enrolError{http.StatusUnauthorized, "no_certificate", "present the console's certificate"})
			return
		}
		if r.URL.Path == "/harbor/v1/devices/release" {
			if dev := d.Lookup(presented); dev != nil && session != "" {
				d.Release(dev, session)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		dev, err := d.ForCertificate(presented, session)
		if err != nil {
			writeEnrolError(w, err)
			return
		}
		if dev == nil {
			writeEnrolError(w, &enrolError{http.StatusNotFound, "not_enrolled", "this certificate is not an enrolled console's"})
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.NotFound(w, r)
	}
}

// lookup finds the enrolled console of a certificate without touching its liveness.
func (d *Registry) Lookup(c *x509.Certificate) *Device {
	sum := sha256.Sum256(c.Raw)
	d.mu.Lock()
	defer d.mu.Unlock()
	if dev := d.byTLS[hex.EncodeToString(sum[:])]; dev != nil {
		return dev
	}
	return d.byDauth[CertDauthID(c)]
}

func writeEnrolError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrDeviceInUse) {
		WriteDeviceInUse(w)
		return
	}
	var e *enrolError
	if errors.As(err, &e) {
		httpx.WriteJSON(w, e.status, map[string]any{"error": e.code, "reason": e.reason})
		return
	}
	httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal"})
}

// ---- BaaS: a device account belongs to the enrolled console that first used it ----

// BindDeviceAccount ties a device account to the enrolled console logging in with it (dauth id
// di), the first time one does; after that only that console may use it. False refuses the login.
// Device accounts used by anything that is not an enrolled console are never bound.
func (d *Registry) BindDeviceAccount(st *store.Store, accountID, di string) bool {
	if d == nil || accountID == "" {
		return true
	}
	enrolled := di != "" && d.EnrolledDauthID(di)
	return st.BindDevice(accountID, di, enrolled)
}

// FromEnv turns the enrolment on when the CA files are configured; nil leaves it off.
func FromEnv() *Registry {
	ca, err := LoadCA()
	if err != nil {
		log.Printf("[harbor-devices] enrolment OFF: %v", redact.Err(err))
		return nil
	}
	if ca == nil {
		log.Printf("[harbor-devices] enrolment off (no NX_DEVICE_CA_* key files): enrolment answers 503, dauth unchanged")
		return nil
	}
	d := NewRegistry(ca, httpx.Getenv("NX_DATA", "/data")+"/harbor-devices.json")
	log.Printf("[harbor-devices] enrolment on (%d console(s) enrolled)", len(d.Devices))
	return d
}
