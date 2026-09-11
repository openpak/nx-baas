// Package penne implements the Penne (NPNS) frontline wire protocol: the
// length-prefixed binary frames and the FlatBuffers-compatible message
// envelopes the persistent notification connection carries.
//
// Provenance of every recovered constant lives in docs/penne-protocol.md
// (nx-baas). In short: the union slot table and envelope layout were recovered
// from the Horizon 22.5.0 NPNS module (static analysis, private working
// directory), the outbound framing from the same module's send path, and the
// FlatBuffers table layout from the public wire-format specification. Anything
// not yet confirmed is marked hypothesis at its definition and must not be
// presented as interoperable until a runtime capture proves it.
//
// This is an independent implementation: it follows the documented wire format
// and the recovered constants, and carries no third-party code.
package penne

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ---------- framing ----------
//
// A frame is a four-byte little-endian length followed by that many bytes of
// buffer. The 22.5.0 NPNS send path passes exactly this shape (a body reader of
// "four-byte length followed by the binary buffer") to its HTTP transport;
// server-to-client framing is not yet runtime-confirmed and is treated as the
// symmetric case, per docs/penne-protocol.md.

const (
	// LengthPrefixSize is the size of a frame's length prefix.
	LengthPrefixSize = 4
	// MaxFrameSize bounds a single frame. A malformed or hostile stream must
	// fail this bound instead of growing memory without limit.
	MaxFrameSize = 1 << 20
)

// ErrFrameTooLarge is returned for a frame whose declared length exceeds the
// reader's bound.
var ErrFrameTooLarge = errors.New("penne: frame length exceeds the maximum frame size")

// AppendFrame appends one length-prefixed frame to dst.
func AppendFrame(dst, payload []byte) []byte {
	var head [LengthPrefixSize]byte
	binary.LittleEndian.PutUint32(head[:], uint32(len(payload)))
	dst = append(dst, head[:]...)
	return append(dst, payload...)
}

// WriteFrame writes one length-prefixed frame to w.
func WriteFrame(w io.Writer, payload []byte) error {
	var head [LengthPrefixSize]byte
	binary.LittleEndian.PutUint32(head[:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// FrameReader reads length-prefixed frames off a stream. Frames larger than max
// fail with ErrFrameTooLarge; a stream that ends mid-frame fails with
// io.ErrUnexpectedEOF; a clean end of stream is io.EOF.
type FrameReader struct {
	r    io.Reader
	max  int
	head [LengthPrefixSize]byte
	buf  []byte
}

// NewFrameReader reads frames of at most max bytes (MaxFrameSize when 0).
func NewFrameReader(r io.Reader, max int) *FrameReader {
	if max <= 0 {
		max = MaxFrameSize
	}
	return &FrameReader{r: r, max: max}
}

// Next returns the next frame payload. The returned slice aliases an internal
// buffer and stays valid only until the following call.
func (fr *FrameReader) Next() ([]byte, error) {
	if _, err := io.ReadFull(fr.r, fr.head[:]); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("penne: reading frame length: %w", err)
	}
	n := binary.LittleEndian.Uint32(fr.head[:])
	if int(n) > fr.max {
		return nil, ErrFrameTooLarge
	}
	if cap(fr.buf) < int(n) {
		fr.buf = make([]byte, n)
	}
	buf := fr.buf[:n]
	if _, err := io.ReadFull(fr.r, buf); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("penne: frame truncated after length prefix: %w", io.ErrUnexpectedEOF)
		}
		return nil, fmt.Errorf("penne: reading frame body: %w", err)
	}
	return buf, nil
}

// ---------- message slots ----------
//
// The union discriminator of an envelope names its payload type. Slot numbers
// below were recovered from the 22.5.0 NPNS module's message-name table
// (module-relative RVA 0x168968; slot value == discriminator byte). The slot
// the findings had already pinned independently (SubscribeTopic = 0x17 = 23)
// matches this table, which is what makes the rest of the ordering usable.

const (
	TypeNONE                    = 0x00
	TypeMessageRequest          = 0x01
	TypePublishRequest          = 0x02
	TypeKickRequest             = 0x03
	TypePutRecord               = 0x04
	TypeDeleteRecord            = 0x05
	TypeRootHash                = 0x06
	TypeLeafHash                = 0x07
	TypeSyncComplete            = 0x08
	TypeAck                     = 0x09
	TypeHandoverRequest         = 0x0a
	TypeHandoverResponse        = 0x0b
	TypeHandoverResult          = 0x0c
	TypeReset                   = 0x0d
	TypePowerState              = 0x0e
	TypeDebugDisconnect         = 0x0f
	TypePing                    = 0x10
	TypePong                    = 0x11
	TypeDebugUpdateRecord       = 0x12
	TypeDebugDeleteRecord       = 0x13
	TypeIdle                    = 0x14
	TypePutRequest              = 0x15
	TypeDeleteRequest           = 0x16
	TypeSubscribeTopic          = 0x17
	TypeNack                    = 0x18
	TypeSubscriptionList        = 0x19
	TypeResendRequest           = 0x1a
	TypeDAPresence              = 0x1b
	TypeSubscriptionListRequest = 0x1c
	TypeMyAccountMessageRequest = 0x1d
	TypeReloadLink              = 0x1e
	TypeSubscriptionUpdated     = 0x1f
	TypeHi                      = 0x20
	TypeOnset                   = 0x21
	TypePresenceNotifyRequest   = 0x22
	TypeDenySubscribe           = 0x23
	TypeTopicRead               = 0x24
	TypeCrewNotifyRequest       = 0x25
)

// typeName maps every recovered slot to its recovered name.
var typeName = [38]string{
	"NONE", "MessageRequest", "PublishRequest", "KickRequest",
	"PutRecord", "DeleteRecord", "RootHash", "LeafHash",
	"SyncComplete", "Ack", "HandoverRequest", "HandoverResponse",
	"HandoverResult", "Reset", "PowerState", "DebugDisconnect",
	"Ping", "Pong", "DebugUpdateRecord", "DebugDeleteRecord",
	"Idle", "PutRequest", "DeleteRequest", "SubscribeTopic",
	"Nack", "SubscriptionList", "ResendRequest", "DAPresence",
	"SubscriptionListRequest", "MyAccountMessageRequest", "ReloadLink", "SubscriptionUpdated",
	"Hi", "Onset", "PresenceNotifyRequest", "DenySubscribe",
	"TopicRead", "CrewNotifyRequest",
}

// TypeName names a slot; unknown slots read as "Unknown(n)".
func TypeName(t byte) string {
	if int(t) < len(typeName) {
		return typeName[t]
	}
	return fmt.Sprintf("Unknown(%d)", t)
}

// ---------- envelope reading ----------
//
// The envelope is a FlatBuffers-compatible table with a union pair: field 0 is
// the one-byte discriminator, field 1 the payload table (recovered from the
// 22.5.0 NPNS send path, which switches on vtable slot 0 as a byte and
// dereferences slot 1 as an indirect table). Table/vtable layout follows the
// public wire format. Every read is bounds-checked: a malformed buffer yields
// an error or absent fields, never a panic.

// Buffer is a received wire buffer.
type Buffer []byte

// Table is a table position inside a Buffer.
type Table struct {
	buf Buffer
	pos int
}

// ErrMalformed reports a buffer that does not decode as an envelope.
var ErrMalformed = errors.New("penne: malformed envelope")

// Envelope is a decoded message: a union slot plus its payload table.
type Envelope struct {
	root Table
}

// DecodeEnvelope parses a wire buffer into its envelope.
func DecodeEnvelope(buf Buffer) (Envelope, error) {
	if len(buf) < 4 {
		return Envelope{}, fmt.Errorf("%w: shorter than a root offset", ErrMalformed)
	}
	root := int(binary.LittleEndian.Uint32(buf))
	if root < 0 || root+4 > len(buf) {
		return Envelope{}, fmt.Errorf("%w: root offset %d out of range (len %d)", ErrMalformed, root, len(buf))
	}
	return Envelope{root: Table{buf: buf, pos: root}}, nil
}

// Type is the union discriminator (envelope field 0). Zero (NONE) when absent.
func (e Envelope) Type() byte {
	v, _ := e.root.u8(0)
	return v
}

// TypeName names the envelope's slot.
func (e Envelope) TypeName() string { return TypeName(e.Type()) }

// Payload returns the union payload table; ok is false for NONE or an absent
// field.
func (e Envelope) Payload() (Table, bool) { return e.root.table(1) }

// Table exposes the root table itself for field access beyond the union pair
// (root fields >= 2 are not yet recovered; nothing may assume them).
func (e Envelope) Root() Table { return e.root }

// Type reads the table's field id as a byte (union discriminators are bytes).
func (t Table) Type(id int) (byte, bool) { return t.u8(id) }

// U8 reads field id as a uint8.
func (t Table) U8(id int) (uint8, bool) { return t.u8(id) }

// U16 reads field id as a uint16.
func (t Table) U16(id int) (uint16, bool) { return t.u16(id) }

// U32 reads field id as a uint32.
func (t Table) U32(id int) (uint32, bool) { return t.u32(id) }

// U64 reads field id as a uint64.
func (t Table) U64(id int) (uint64, bool) { return t.u64(id) }

// Bool reads field id as a boolean.
func (t Table) Bool(id int) (bool, bool) {
	v, ok := t.u8(id)
	return v != 0, ok
}

// String reads field id as a string.
func (t Table) String(id int) (string, bool) {
	pos, ok := t.uoffset(id)
	if !ok {
		return "", false
	}
	if pos+4 > len(t.buf) {
		return "", false
	}
	n := int(binary.LittleEndian.Uint32(t.buf[pos:]))
	if n < 0 || pos+4+n > len(t.buf) {
		return "", false
	}
	return string(t.buf[pos+4 : pos+4+n]), true
}

// Table reads field id as an indirect table reference.
func (t Table) Table(id int) (Table, bool) { return t.table(id) }

// VectorLen reads field id as a vector and returns its element count.
func (t Table) VectorLen(id int) (int, bool) {
	pos, ok := t.uoffset(id)
	if !ok || pos+4 > len(t.buf) {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(t.buf[pos:]))
	if n < 0 || pos+4+4*n > len(t.buf) {
		return 0, false
	}
	return n, true
}

// VectorTable reads element i of the vector at field id as a table.
func (t Table) VectorTable(id, i int) (Table, bool) {
	pos, ok := t.uoffset(id)
	if !ok || pos+4 > len(t.buf) {
		return Table{}, false
	}
	n := int(binary.LittleEndian.Uint32(t.buf[pos:]))
	if i < 0 || i >= n {
		return Table{}, false
	}
	elem := pos + 4 + 4*i
	if elem+4 > len(t.buf) {
		return Table{}, false
	}
	next := elem + int(binary.LittleEndian.Uint32(t.buf[elem:]))
	if next < 0 || next+4 > len(t.buf) {
		return Table{}, false
	}
	return Table{buf: t.buf, pos: next}, true
}

// fieldOff returns the field data's offset from the table start.
func (t Table) fieldOff(id int) (int, bool) {
	if t.pos < 0 || t.pos+4 > len(t.buf) {
		return 0, false
	}
	vtRel := int(int32(binary.LittleEndian.Uint32(t.buf[t.pos:])))
	vpos := t.pos - vtRel
	if vpos < 0 || vpos+4 > len(t.buf) {
		return 0, false
	}
	vsize := int(binary.LittleEndian.Uint16(t.buf[vpos:]))
	if vsize < 4 || vpos+vsize > len(t.buf) {
		return 0, false
	}
	foffIdx := 4 + 2*id
	if foffIdx+2 > vsize {
		return 0, false
	}
	off := int(binary.LittleEndian.Uint16(t.buf[vpos+foffIdx:]))
	if off == 0 || t.pos+off >= len(t.buf) {
		return 0, false // absent field (FlatBuffers omits defaults) or out of range
	}
	return off, true
}

func (t Table) u8(id int) (uint8, bool) {
	off, ok := t.fieldOff(id)
	if !ok || t.pos+off >= len(t.buf) {
		return 0, false
	}
	return t.buf[t.pos+off], true
}

func (t Table) u16(id int) (uint16, bool) {
	off, ok := t.fieldOff(id)
	if !ok || t.pos+off+2 > len(t.buf) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(t.buf[t.pos+off:]), true
}

func (t Table) u32(id int) (uint32, bool) {
	off, ok := t.fieldOff(id)
	if !ok || t.pos+off+4 > len(t.buf) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(t.buf[t.pos+off:]), true
}

func (t Table) u64(id int) (uint64, bool) {
	off, ok := t.fieldOff(id)
	if !ok || t.pos+off+8 > len(t.buf) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(t.buf[t.pos+off:]), true
}

func (t Table) uoffset(id int) (int, bool) {
	off, ok := t.fieldOff(id)
	if !ok {
		return 0, false
	}
	fieldPos := t.pos + off
	if fieldPos+4 > len(t.buf) {
		return 0, false
	}
	next := fieldPos + int(binary.LittleEndian.Uint32(t.buf[fieldPos:]))
	if next < 0 || next+4 > len(t.buf) {
		return 0, false
	}
	return next, true
}

func (t Table) table(id int) (Table, bool) {
	pos, ok := t.uoffset(id)
	if !ok {
		return Table{}, false
	}
	return Table{buf: t.buf, pos: pos}, true
}

// ---------- envelope building ----------
//
// A builder for the same wire format, used for the server-to-client direction.
// It writes back to front as the format requires. Vtable deduplication is
// deliberately omitted: it is an optimisation, not a correctness requirement.

// Builder assembles a wire buffer.
type Builder struct {
	buf       []byte
	head      int
	minalign  int
	vtable    []int
	fieldLow  int
	objectEnd int
}

// NewBuilder creates a builder whose initial buffer holds size bytes.
func NewBuilder(size int) *Builder {
	if size < 16 {
		size = 16
	}
	buf := make([]byte, size)
	return &Builder{buf: buf, head: size, minalign: 1}
}

// Offset is the distance from the buffer end to the write head.
func (b *Builder) Offset() int { return len(b.buf) - b.head }

// Bytes returns the finished buffer.
func (b *Builder) Bytes() []byte { return b.buf[b.head:] }

func (b *Builder) grow(need int) {
	if b.head >= need {
		return
	}
	size := len(b.buf) * 2
	for size-b.head < need {
		size *= 2
	}
	base := size - (len(b.buf) - b.head)
	nbuf := make([]byte, size)
	copy(nbuf[base:], b.buf[b.head:])
	b.buf, b.head = nbuf, base
}

func (b *Builder) place(v byte) {
	b.grow(1)
	b.head--
	b.buf[b.head] = v
}

// prep aligns the head so that, after additional more bytes, a field of the
// given size lands size-aligned from the buffer end.
func (b *Builder) prep(size, additional int) {
	if size > b.minalign {
		b.minalign = size
	}
	// align so that, after `additional` further bytes, a field of `size`
	// bytes lands size-aligned from the buffer end. (-v)&(size-1) is v's
	// complement to the next multiple of size; ^v would be off by one.
	align := (-(len(b.buf) - b.head + additional)) & (size - 1)
	for i := 0; i < align; i++ {
		b.place(0)
	}
}

func (b *Builder) placeU16(v uint16) {
	b.grow(2)
	b.head -= 2
	binary.LittleEndian.PutUint16(b.buf[b.head:], v)
}

func (b *Builder) placeU32(v uint32) {
	b.grow(4)
	b.head -= 4
	binary.LittleEndian.PutUint32(b.buf[b.head:], v)
}

func (b *Builder) placeU64(v uint64) {
	b.grow(8)
	b.head -= 8
	binary.LittleEndian.PutUint64(b.buf[b.head:], v)
}

// CreateString writes a string and returns its offset.
func (b *Builder) CreateString(s string) int {
	b.prep(4, len(s)+1)
	b.place(0) // NUL terminator as the format prescribes
	for i := len(s) - 1; i >= 0; i-- {
		b.place(s[i])
	}
	b.placeU32(uint32(len(s)))
	return b.Offset()
}

// StartTable begins a table; slot ids run 0..fields-1.
func (b *Builder) StartTable(fields int) {
	b.vtable = make([]int, fields)
	b.fieldLow = -1
	b.objectEnd = b.Offset()
}

func (b *Builder) addSlot(slot, size int) {
	if slot < 0 || slot >= len(b.vtable) {
		panic(fmt.Sprintf("penne: builder slot %d outside table of %d fields", slot, len(b.vtable)))
	}
	b.vtable[slot] = b.Offset()
	// Track the lowest field start (in end-distance coordinates) for the
	// table-size computation in EndTable; -1 marks a table with no fields.
	if low := b.Offset() - size; b.fieldLow < 0 || low < b.fieldLow {
		b.fieldLow = low
	}
}

// PrependU8Slot writes a byte field.
func (b *Builder) PrependU8Slot(slot int, v uint8) {
	b.prep(1, 0)
	b.place(v)
	b.addSlot(slot, 1)
}

// PrependU16Slot writes a uint16 field.
func (b *Builder) PrependU16Slot(slot int, v uint16) {
	b.prep(2, 0)
	b.placeU16(v)
	b.addSlot(slot, 2)
}

// PrependU32Slot writes a uint32 field.
func (b *Builder) PrependU32Slot(slot int, v uint32) {
	b.prep(4, 0)
	b.placeU32(v)
	b.addSlot(slot, 4)
}

// PrependU64Slot writes a uint64 field.
func (b *Builder) PrependU64Slot(slot int, v uint64) {
	b.prep(8, 0)
	b.placeU64(v)
	b.addSlot(slot, 8)
}

// PrependBoolSlot writes a boolean field.
func (b *Builder) PrependBoolSlot(slot int, v bool) {
	n := uint8(0)
	if v {
		n = 1
	}
	b.PrependU8Slot(slot, n)
}

// PrependUOffsetSlot writes a forward reference (string, table, vector).
func (b *Builder) PrependUOffsetSlot(slot, off int) {
	b.prep(4, 0)
	b.placeU32(uint32(b.Offset() + 4 - off))
	b.addSlot(slot, 4)
}

// EndTable finishes the table and returns its offset.
//
// The formulas below are derived in end-distance coordinates (doff = bytes
// written from the buffer end; a field recorded at doff F occupies final
// positions [L-F, L-F+size)) and were checked byte-for-byte against the
// hand-assembled fixture in protocol_test.go:
//
//	vtable entry_i = S - F_i        (field offset from the table start)
//	tsize          = S - fieldLow   (table bytes from its soffset on)
//	soffset        = W - S          (table start minus vtable start; negative,
//	                                 because back-to-front building puts the
//	                                 vtable above the table's soffset)
func (b *Builder) EndTable() int {
	// Trim trailing absent slots: the vtable only covers used fields.
	used := len(b.vtable)
	for used > 0 && b.vtable[used-1] == 0 {
		used--
	}
	D := b.Offset()
	aligned := (D + 1) & ^1
	vsize := 4 + 2*used
	pad := (-(aligned + vsize)) & 3
	S := aligned + vsize + pad + 4 // doff the soffset (table start) will sit at
	for i := used - 1; i >= 0; i-- {
		b.prep(2, 0)
		off := uint16(0)
		if b.vtable[i] != 0 {
			off = uint16(S - b.vtable[i])
		}
		b.placeU16(off)
	}
	b.prep(2, 0)
	tsize := 4
	if b.fieldLow >= 0 {
		tsize = S - b.fieldLow
	}
	b.placeU16(uint16(tsize)) // table size
	b.prep(2, 0)
	b.placeU16(uint16(vsize)) // vtable size
	vOff := b.Offset()        // doff of the vtable structure's first byte
	b.prep(4, 0)
	b.placeU32(uint32(int32(vOff - S))) // soffset: table - vtable
	b.vtable, b.fieldLow = nil, -1
	return b.Offset()
}

// FinishEnvelope writes the root envelope table (union slot + payload) and the
// root offset, returning the finished buffer.
func (b *Builder) FinishEnvelope(slot byte, payload int) []byte {
	b.StartTable(2)
	b.PrependUOffsetSlot(1, payload)
	b.PrependU8Slot(0, slot)
	root := b.EndTable()
	b.prep(b.minalign, 4)
	b.placeU32(uint32(b.Offset() + 4 - root))
	return b.Bytes()
}

// EmptyPayload builds the offset of a table with no fields (the payload of
// messages recovered with empty payloads, e.g. Hi, SyncComplete,
// SubscriptionListRequest).
func (b *Builder) EmptyPayload() int {
	b.StartTable(0)
	return b.EndTable()
}

// ---------- recovered payload helpers ----------
//
// Only shapes the 22.5.0 module demonstrably reads or writes are provided.
// Field semantics beyond what the module's own logging showed remain unknown
// and are named for their position, not guessed meanings.

// BuildPong encodes a Pong envelope echoing value back on field 0. The 22.5.0
// module reads Pong as a single uint64 field; echoing the Ping's first field is
// the minimum-behaviour hypothesis (docs/penne-protocol.md).
func BuildPong(echo uint64) []byte {
	b := NewBuilder(64)
	b.StartTable(1)
	b.PrependU64Slot(0, echo)
	payload := b.EndTable()
	return b.FinishEnvelope(TypePong, payload)
}

// BuildPing encodes a Ping envelope with its three recovered uint64 fields
// (semantics not yet recovered; the caller supplies what it can defend).
func BuildPing(f0, f1, f2 uint64) []byte {
	b := NewBuilder(64)
	b.StartTable(3)
	b.PrependU64Slot(2, f2)
	b.PrependU64Slot(1, f1)
	b.PrependU64Slot(0, f0)
	payload := b.EndTable()
	return b.FinishEnvelope(TypePing, payload)
}

// BuildSubscriptionUpdated encodes a SubscriptionUpdated envelope with a single
// uint64 field (the shape the module logs). The meaning of the value is not
// recovered; callers pass what they can defend.
func BuildSubscriptionUpdated(v uint64) []byte {
	b := NewBuilder(64)
	b.StartTable(1)
	b.PrependU64Slot(0, v)
	payload := b.EndTable()
	return b.FinishEnvelope(TypeSubscriptionUpdated, payload)
}

// BuildEvent encodes a delivered event: carrier slot MessageRequest with a
// single string field holding the event's JSON body. Both the carrier slot and
// the payload field are hypotheses pending a runtime capture -- they are the
// best-evidence candidates, not confirmed interoperability, and everything
// downstream must treat them as such (docs/penne-protocol.md).
func BuildEvent(jsonBody string) []byte {
	b := NewBuilder(64 + len(jsonBody))
	str := b.CreateString(jsonBody)
	b.StartTable(1)
	b.PrependUOffsetSlot(0, str)
	payload := b.EndTable()
	return b.FinishEnvelope(TypeMessageRequest, payload)
}
