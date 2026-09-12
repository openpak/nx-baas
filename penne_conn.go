package main

// penne_conn.go: the Penne "frontline" persistent connection (NTF-02, NTF-03).
//
// Lifecycle the 22.5.0 client drives, per the recovered protocol specification
// (docs/penne-protocol.md): a POST to https://<frontline>/ with a bearer login
// ticket, X-Protocol-Version 4 and friends; the connection is held open and
// carries length-prefixed FlatBuffers envelopes in both directions. The
// client's outgoing framing is firmware-confirmed (u32 LE length + buffer);
// server-to-client framing is treated as symmetric pending a capture.
//
// What changed versus the old handler: authentication (the ticket is real and
// revocable), frames instead of a newline heartbeat (a newline byte would
// desync any length-prefixed decoder -- the keepalive below flushes without
// writing content), subscriptions that persist, and a delivery pump with
// reconnect reconciliation (NTF-05).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nx-baas/internal/penne"
)

// frontlineKeepalive is how often the held-open connection is flushed. A Flush
// with nothing written keeps intermediaries from timing the connection out
// without inventing frame content the protocol has not shown us.
var frontlineKeepalive = 30 * time.Second

// isPenneFrontline names the hosts the persistent connection lands on
// (fro-N.hac.lp1.penne.srv.nintendo.net).
func isPenneFrontline(host string) bool { return strings.HasPrefix(host, "fro-") }

// frontline answers the Penne persistent POST. Two shapes exist:
//
//   - A streaming request body (chunked, no length): the NPNS shape -- the
//     client keeps writing frames while it reads pushes. Go's net/http server
//     cannot serve this: its first response flush drains up to 256 KiB of the
//     request body into io.discard (server.go writeHeader -> body.Close),
//     destroying the frame stream. The connection is hijacked instead and the
//     HTTP/1.1 chunked exchange is carried by hand.
//   - A finite request body: the older frontline shape (register a room, hold
//     the response open). The ordinary held-open response below serves it.
func (s *server) frontline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"status": 405, "title": "method not allowed"})
		return
	}
	now := time.Now()
	ticket := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	ticket = strings.TrimSpace(ticket)
	if ticket == "" {
		writeJSON(w, 401, map[string]any{"status": 401, "errorCode": "credentials_required",
			"title": "Credentials required", "detail": "The frontline connection requires a login ticket",
			"type": "https://penne.nintendo.net/errors/1.0.0/401/credentials_required"})
		return
	}
	rec, err := s.notifStore().ValidateTicket(ticket, deviceIDFromUA(r.UserAgent()), now)
	if err != nil {
		// Expired, revoked, unknown or wrong-device: a denial is a denial, and
		// the console re-registers rather than retrying forever.
		log.Printf("[nx-baas] penne frontline: denied (%v)", err)
		writeJSON(w, 401, map[string]any{"status": 401, "errorCode": "invalid_credentials",
			"title": "Invalid credentials", "detail": "The login ticket is not usable",
			"type": "https://penne.nintendo.net/errors/1.0.0/401/invalid_credentials"})
		return
	}
	if !isPenneFrontline(hostOf(r)) {
		writeJSON(w, 404, map[string]any{})
		return
	}
	if len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == "chunked" {
		s.frontlineStream(w, r, rec)
		return
	}
	s.frontlineHeldOpen(w, r, rec)
}

// frontlineHeldOpen serves the finite-body shape: 200, chunked, held open,
// flushing the writer so the client sees acceptance, delivering frames as they
// are submitted. A keepalive ticker flushes the writer without content: the
// newline heartbeat this replaces was unvalidated and would desync any
// length-prefixed decoder; a zero-byte flush desyncs nothing.
func (s *server) frontlineHeldOpen(w http.ResponseWriter, r *http.Request, rec *penneTicketRec) {
	fl, ok := w.(http.Flusher)
	if !ok {
		// Without Flusher there is no streaming; answering and closing is the
		// documented failure class, so refuse loudly instead.
		writeJSON(w, 500, map[string]any{"status": "no-stream"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(200)
	fl.Flush() // let the client see the connection accepted before anything else

	ctx, cancel := context.WithCancel(r.Context())
	sess := &penneSession{
		user: s.sessionUser(rec), device: rec.DeviceID, penneID: rec.PenneID,
		ctx: ctx, cancel: cancel, send: make(chan penneOutbound, penneSendQueue),
		done: make(chan struct{}),
	}
	s.penneHub.attach(sess)
	defer s.penneHub.detach(sess)
	defer cancel()
	log.Printf("[nx-baas] penne frontline: open user=%s device=%s", rec.UserID, rec.DeviceID)

	// The console reads exactly one message here, with a 70-second deadline,
	// and accepts only HandoverResult or Reset (RVA 0xd9730): everything else
	// is "HandoverResult expected, but ...received" and the connection fails.
	// A zero result continues to normal operation, where it sends its
	// subscription list. This is why a connection held open in silence closed
	// itself after ~65 seconds having sent nothing [firmware, 2026-09-12].
	if err := penne.WriteFrame(w, penne.BuildHandoverResult(0)); err != nil {
		return
	}
	fl.Flush()
	s.notifStore().framesOut.Add(1)

	// Reader: the request body carries the client's frames.
	go s.penneRead(sess, r.Body)

	// Finite-body connections need the same offline replay as stream connections.
	s.penneWake(sess.user)

	ticker := time.NewTicker(frontlineKeepalive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): // console hung up
			close(sess.done)
			return
		case out := <-sess.send:
			s.notifStore().framesOut.Add(1)
			if err := penne.WriteFrame(w, out.frame); err != nil {
				if out.id != "" {
					s.notifStore().MarkFailed(sess.user, out.id, err.Error(), time.Now())
				}
				cancel()
				continue
			}
			if out.id != "" {
				s.notifStore().MarkDelivered(sess.user, out.id, time.Now())
			}
			fl.Flush()
		case <-ticker.C:
			// Keepalive: flush without content. The newline heartbeat this
			// replaces was unvalidated and would desync a length-prefixed
			// decoder; a zero-byte flush desyncs nothing.
			fl.Flush()
		}
	}
}

// frontlineStream serves the NPNS bidirectional shape over a hijacked
// connection: HTTP/1.1 chunked frames in both directions, carried by hand.
func (s *server) frontlineStream(w http.ResponseWriter, r *http.Request, rec *penneTicketRec) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[nx-baas] penne frontline: no hijacker available; refusing")
		writeJSON(w, 500, map[string]any{"status": "no-stream"})
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		log.Printf("[nx-baas] penne frontline: hijack: %v", err)
		return
	}
	defer conn.Close()
	if k, ok := conn.(interface{ NetConn() net.Conn }); ok { // *tls.Conn: keepalive on the TCP beneath
		if tc, ok := k.NetConn().(*net.TCPConn); ok {
			tc.SetKeepAlive(true) // no HTTP-level keepalive exists in this shape
		}
	}
	// The response head, written directly: chunked octet-stream, held open.
	if _, err := brw.Writer.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"); err != nil {
		return
	}
	if err := brw.Writer.Flush(); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	sess := &penneSession{
		user: s.sessionUser(rec), device: rec.DeviceID, penneID: rec.PenneID,
		ctx: ctx, cancel: cancel, send: make(chan penneOutbound, penneSendQueue),
		done: make(chan struct{}),
	}
	s.penneHub.attach(sess)
	defer s.penneHub.detach(sess)
	log.Printf("[nx-baas] penne frontline: open (stream) user=%s device=%s", rec.UserID, rec.DeviceID)

	// Reader: the client's frames arrive as chunked request-body bytes.
	body := newChunkReader(brw.Reader)
	go s.penneRead(sess, body)

	// Reconciliation first: anything the outbox owes this account goes out
	// before new work (NTF-05 reconnect behavior).
	s.penneWake(sess.user)

	writeChunk := func(frame []byte) error {
		if _, err := fmt.Fprintf(brw.Writer, "%x\r\n", len(frame)); err != nil {
			return err
		}
		if _, err := brw.Writer.Write(frame); err != nil {
			return err
		}
		_, err := brw.Writer.WriteString("\r\n")
		if err != nil {
			return err
		}
		return brw.Writer.Flush()
	}
	// Same handover as the finite-body path.
	if err := writeChunk(penne.AppendFrame(nil, penne.BuildHandoverResult(0))); err != nil {
		return
	}
	s.notifStore().framesOut.Add(1)

	for {
		select {
		case <-ctx.Done():
			close(sess.done)
			// Terminate the chunked response so a well-behaved client sees EOF.
			brw.Writer.WriteString("0\r\n\r\n") //nolint:errcheck // closing anyway
			brw.Writer.Flush()
			return
		case out := <-sess.send:
			s.notifStore().framesOut.Add(1)
			// The chunk carries a framed message: the protocol's own
			// length prefix rides inside the HTTP chunk, as in the
			// held-open path.
			if err := writeChunk(penne.AppendFrame(nil, out.frame)); err != nil {
				if out.id != "" {
					s.notifStore().MarkFailed(sess.user, out.id, err.Error(), time.Now())
				}
				cancel()
				continue
			}
			if out.id != "" {
				s.notifStore().MarkDelivered(sess.user, out.id, time.Now())
			}
		}
	}
}

// chunkReader de-chunks a request body we took over with Hijack (the server's
// own decoder belongs to the r.Body we may no longer touch). Chunk-size lines
// are bounded by the bufio buffer: one longer than that is a protocol error,
// not an allocation opportunity.
type chunkReader struct {
	br   *bufio.Reader
	n    int  // bytes left in the current chunk
	done bool // terminating chunk seen
}

func newChunkReader(br *bufio.Reader) *chunkReader { return &chunkReader{br: br} }

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	if c.n == 0 {
		line, err := c.br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, ';'); i >= 0 { // chunk extensions
			line = line[:i]
		}
		n, err := strconv.ParseInt(line, 16, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad chunk size %q", line)
		}
		if n == 0 {
			c.done = true
			return 0, io.EOF
		}
		if n > penne.MaxFrameSize*4 {
			return 0, penne.ErrFrameTooLarge
		}
		c.n = int(n)
	}
	if len(p) == 0 {
		return 0, nil
	}
	want := c.n
	if want > len(p) {
		want = len(p)
	}
	r, err := io.ReadFull(c.br, p[:want])
	c.n -= r
	if c.n == 0 && err == nil {
		if _, err := c.br.Discard(2); err != nil { // the CRLF after each chunk
			return r, err
		}
	}
	return r, err
}

// penneSendQueue bounds a session's outbound queue. When full, the work stays
// in the persistent outbox (bounded there too) instead of growing here.
const penneSendQueue = 64

// penneOutbound is one queued write: the encoded frame plus the delivery id it
// settles on success ("" for control frames like Pong, which settle nothing).
type penneOutbound struct {
	id    string
	frame []byte
}

// penneSession is one live frontline connection.
type penneSession struct {
	user    string
	device  string
	penneID string
	ctx     context.Context
	cancel  context.CancelFunc
	send    chan penneOutbound
	done    chan struct{}
}

// offer queues a frame without ever blocking the caller; if this connection is
// slow, the persistent outbox keeps the work.
func (sess *penneSession) offer(id string, frame []byte) {
	select {
	case sess.send <- penneOutbound{id: id, frame: frame}:
	default:
	}
}

// sessionUser is the account a live connection delivers for. A ticket minted
// before its console signed in to BAAS carries the device certificate as its
// subject, and the outbox is keyed by accounts — so the certificate is resolved
// through what the login recorded. Without this a console reconnecting on an
// old ticket is told there is nothing for it while its events expire.
func (s *server) sessionUser(rec *penneTicketRec) string {
	if rec == nil {
		return ""
	}
	if u := s.notifStore().ResolveUser(rec.UserID); u != "" && u != rec.UserID {
		log.Printf("[nx-baas] penne frontline: ticket names console %s; delivering for account %s", rec.UserID, u)
		return u
	}
	return rec.UserID
}

// penneRead decodes the client's frames until the connection ends. A malformed
// or oversized stream terminates the session: never a panic, never unbounded
// allocation.
func (s *server) penneRead(sess *penneSession, body io.Reader) {
	fr := penne.NewFrameReader(body, penne.MaxFrameSize)
	for {
		frame, err := fr.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) && sess.ctx.Err() == nil {
				s.notifStore().malformed.Add(1)
				log.Printf("[nx-baas] penne frontline: read ended (%v); closing", err)
				sess.cancel()
			}
			return
		}
		s.notifStore().framesIn.Add(1)
		s.penneDispatch(sess, frame)
	}
}

// penneDispatch handles one inbound envelope. Only firmware-identified
// messages get firmware-identified answers; everything else is counted and
// logged for the protocol capture, never answered with invented schemas.
func (s *server) penneDispatch(sess *penneSession, frame []byte) {
	env, err := penne.DecodeEnvelope(frame)
	if err != nil {
		s.notifStore().malformed.Add(1)
		log.Printf("[nx-baas] penne frontline: malformed frame (%v); closing", err)
		sess.cancel()
		return
	}
	store := s.notifStore()
	switch env.Type() {
	case penne.TypeSubscribeTopic: // 0x17, firmware-confirmed
		payload, hasPayload := env.Payload()
		var topic string
		var flags [2]bool
		var have [2]bool
		if hasPayload {
			flags[0], have[0] = payload.Bool(0)
			flags[1], have[1] = payload.Bool(4)
			// The recovered builder formats the topic as %016llx of a u64
			// (16 lowercase hex); field 3 is the best-evidence topic slot.
			for _, f := range []int{3, 2, 1} {
				if v, ok := payload.String(f); ok && v != "" {
					topic = v
					break
				}
			}
		}
		if topic == "" {
			store.unknownType.Add(1)
			log.Printf("[nx-baas] penne: SubscribeTopic without a readable topic (flags %v/%v); counted, not guessed", have[0], have[1])
			return
		}
		store.SetSubscriptions(sess.user, sess.device, []string{strings.ToLower(topic)}, time.Now())
		log.Printf("[nx-baas] penne: subscribed user=%s device=%s topic=%s", sess.user, sess.device, topic)
		// Confirmation: SubscriptionUpdated carries one u64 (recovered shape);
		// the value's meaning is not recovered -- we send the unix second as
		// the least-surprising candidate, flagged in the protocol spec.
		sess.offer("", penne.BuildSubscriptionUpdated(uint64(time.Now().Unix())))
	case penne.TypePing: // 16: three u64s recovered; echo field 0
		var ping uint64
		if payload, ok := env.Payload(); ok {
			ping, _ = payload.U64(0)
		}
		sess.offer("", penne.BuildPong(ping))
	case penne.TypeAck: // 9: the module sends one field; correlation target not yet recovered
		if payload, ok := env.Payload(); ok {
			if v, ok := payload.U64(0); ok {
				log.Printf("[nx-baas] penne: ack=%d user=%s", v, sess.user)
			} else if id, ok := payload.String(0); ok {
				// Best-effort replay ack: a message id naming one of our
				// queued events settles that delivery.
				store.AckDelivery(sess.user, id, time.Now())
			}
		}
	case penne.TypeResendRequest: // 26: one string field; treat it as replay-by-id
		if payload, ok := env.Payload(); ok {
			if id, ok := payload.String(0); ok {
				log.Printf("[nx-baas] penne: resend requested for %s", id)
				s.penneWake(sess.user)
			}
		}
	case penne.TypeHi, penne.TypeIdle, penne.TypePowerState, penne.TypeSubscriptionListRequest:
		// Recovered empty/near-empty client messages: noted, no answer defined
		// by evidence. Logged by name because the first one the console ever
		// sends is what settles the opening handshake.
		log.Printf("[nx-baas] penne: %s from user=%s device=%s", env.TypeName(), sess.user, sess.device)
	default:
		store.unknownType.Add(1)
		log.Printf("[nx-baas] penne: frame type %s counted, no evidence-backed answer", env.TypeName())
	}
}

// penneSweep retries due deliveries, expires stale work and prunes retention.
// Started once from main(); every tick logs the sanitized snapshot.
func (s *server) penneSweep() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	var lastLog int64
	for now := range t.C {
		for _, uid := range s.notifStore().Sweep(now) {
			s.penneWake(uid)
		}
		if now.Unix()-lastLog >= 600 {
			lastLog = now.Unix()
			snap := s.notifStore().Snapshot()
			if snap["outbox_pending"] != 0 || snap["malformed"] != uint64(0) {
				log.Printf("[nx-baas] penne: %v", snap)
			}
		}
	}
}
