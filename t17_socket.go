package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"strings"
)

// The T17BE websocket: everything after getToken — /player/*, /sessions/*, /friends/*,
// /storage/*, /live/* — is JSON over this one socket, each message carrying a `headers` object
// the SDK matches back to its original request. Nothing is answered yet; this accepts the
// upgrade and logs both directions so the envelope can be read off a real client.
//
// ponytail: RFC 6455 by hand rather than a dependency — a server that only reads frames is the
// handshake, a length, and an unmask. Add a library when this has to speak the protocol back
// (fragmentation, compression), not before.
func (s *server) t17Socket(w http.ResponseWriter, r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return false
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[t17] socket: connection cannot be hijacked")
		return false
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		log.Printf("[t17] socket: hijack: %v", err)
		return false
	}
	defer conn.Close()

	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // RFC 6455 §4.2.2
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
	_ = rw.Flush()
	log.Printf("[t17] socket: open %s%s from %s", hostOf(r), r.URL.Path, r.RemoteAddr)

	for {
		op, payload, err := readFrame(rw)
		if err != nil {
			log.Printf("[t17] socket: closed (%v)", err)
			return true
		}
		switch op {
		case 0x8: // close
			log.Printf("[t17] socket: client closed")
			return true
		case 0x9: // ping -> pong, or the client gives up on us
			_, _ = rw.Write([]byte{0x8a, byte(len(payload))})
			_, _ = rw.Write(payload)
			_ = rw.Flush()
		default:
			log.Printf("[t17] socket <<< op=%d len=%d %s", op, len(payload), payload)
		}
	}
}

// readFrame returns one frame's opcode and unmasked payload. Client frames are always masked.
func readFrame(r io.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	op, masked, n := h[0]&0x0f, h[1]&0x80 != 0, uint64(h[1]&0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return op, payload, nil
}
