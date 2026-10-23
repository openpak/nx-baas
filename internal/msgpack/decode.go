package msgpack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// Ordered encodes a string-keyed map with caller-chosen key order,
// unlike Encode, which sorts. Takes an even list of key, value.
func Ordered(pairs ...any) []byte {
	if len(pairs)%2 != 0 {
		panic("msgpackOrdered: odd pair count")
	}
	out := Len(0x80, 0, 0xde, 0xdf, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		k, ok := pairs[i].(string)
		if !ok {
			panic("msgpackOrdered: non-string key")
		}
		out = append(out, Encode(k)...)
		out = append(out, Encode(pairs[i+1])...)
	}
	return out
}

// IntOf reads the small integers the game sends (posfixint through
// int64) as int64. Anything else is 0 — the caller logs the raw map on the
// error paths that matter, so a mistyped field reads as zero, not a refusal.
func IntOf(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case uint64:
		if t <= math.MaxInt64 {
			return int64(t)
		}
	}
	return 0
}

// UintOf is the unsigned sibling, for ids that may one day set the top
// bit. Today in_app_id fits either way; the response encodes it unsigned.
func UintOf(v any) uint64 {
	switch t := v.(type) {
	case uint64:
		return t
	case int64:
		if t >= 0 {
			return uint64(t)
		}
	}
	return 0
}

// Decode reads the subset of msgpack the game and these documents use:
// nil, booleans, integers through 64 bits, floats (kept whole), strings,
// binary, arrays and string-keyed maps. It is the mirror of Encode, which
// only encodes. Unknown type tags are an error, not a guess:
// silently skipping a field would register a different island than the game
// posted.
func Decode(b []byte) (any, error) {
	v, rest, err := value(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("msgpack: %d trailing bytes", len(rest))
	}
	return v, nil
}

func value(b []byte) (any, []byte, error) {
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("msgpack: empty")
	}
	c := b[0]
	switch {
	case c <= 0x7f: // posfixint
		return int64(c), b[1:], nil
	case c >= 0xe0: // negfixint
		return int64(int8(c)), b[1:], nil
	case c >= 0xa0 && c <= 0xbf: // fixstr
		return bytesOf(b, 1, int(c&0x1f), true)
	case c >= 0x90 && c <= 0x9f: // fixarray
		return array(b, 1, int(c&0x0f))
	case c >= 0x80 && c <= 0x8f: // fixmap
		return mapOf(b, 1, int(c&0x0f))
	}
	switch c {
	case 0xc0:
		return nil, b[1:], nil
	case 0xc2:
		return false, b[1:], nil
	case 0xc3:
		return true, b[1:], nil
	case 0xca: // float32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: float32 truncated")
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b[1:]))), b[5:], nil
	case 0xcb: // float64
		if len(b) < 9 {
			return nil, nil, fmt.Errorf("msgpack: float64 truncated")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b[1:])), b[9:], nil
	case 0xcc:
		return readUint(b, 2)
	case 0xcd:
		return readUint(b, 3)
	case 0xce:
		return readUint(b, 5)
	case 0xcf:
		return readUint(b, 9)
	case 0xd0:
		return readInt(b, 2)
	case 0xd1:
		return readInt(b, 3)
	case 0xd2:
		return readInt(b, 5)
	case 0xd3:
		return readInt(b, 9)
	case 0xd9: // str8
		if len(b) < 2 {
			return nil, nil, fmt.Errorf("msgpack: str8 truncated")
		}
		return bytesOf(b, 2, int(b[1]), true)
	case 0xda: // str16
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: str16 truncated")
		}
		return bytesOf(b, 3, int(binary.BigEndian.Uint16(b[1:])), true)
	case 0xdb: // str32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: str32 truncated")
		}
		n := binary.BigEndian.Uint32(b[1:])
		if n > math.MaxInt32 {
			return nil, nil, fmt.Errorf("msgpack: str32 absurd length %d", n)
		}
		return bytesOf(b, 5, int(n), true)
	case 0xc4: // bin8
		if len(b) < 2 {
			return nil, nil, fmt.Errorf("msgpack: bin8 truncated")
		}
		return bytesOf(b, 2, int(b[1]), false)
	case 0xc5: // bin16
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: bin16 truncated")
		}
		return bytesOf(b, 3, int(binary.BigEndian.Uint16(b[1:])), false)
	case 0xc6: // bin32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: bin32 truncated")
		}
		n := binary.BigEndian.Uint32(b[1:])
		if n > math.MaxInt32 {
			return nil, nil, fmt.Errorf("msgpack: bin32 absurd length %d", n)
		}
		return bytesOf(b, 5, int(n), false)
	case 0xdc: // array16
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: array16 truncated")
		}
		return array(b, 3, int(binary.BigEndian.Uint16(b[1:])))
	case 0xdd: // array32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: array32 truncated")
		}
		n := binary.BigEndian.Uint32(b[1:])
		if n > 1<<20 {
			return nil, nil, fmt.Errorf("msgpack: array32 absurd length %d", n)
		}
		return array(b, 5, int(n))
	case 0xde: // map16
		if len(b) < 3 {
			return nil, nil, fmt.Errorf("msgpack: map16 truncated")
		}
		return mapOf(b, 3, int(binary.BigEndian.Uint16(b[1:])))
	case 0xdf: // map32
		if len(b) < 5 {
			return nil, nil, fmt.Errorf("msgpack: map32 truncated")
		}
		n := binary.BigEndian.Uint32(b[1:])
		if n > 1<<20 {
			return nil, nil, fmt.Errorf("msgpack: map32 absurd length %d", n)
		}
		return mapOf(b, 5, int(n))
	}
	return nil, nil, fmt.Errorf("msgpack: unknown tag 0x%02x", c)
}

// readUint reads an unsigned integer whose tag plus width is n bytes.
func readUint(b []byte, n int) (any, []byte, error) {
	if len(b) < n {
		return nil, nil, fmt.Errorf("msgpack: uint truncated")
	}
	switch n {
	case 2:
		return int64(b[1]), b[2:], nil
	case 3:
		return int64(binary.BigEndian.Uint16(b[1:])), b[3:], nil
	case 5:
		return int64(binary.BigEndian.Uint32(b[1:])), b[5:], nil
	default:
		return binary.BigEndian.Uint64(b[1:]), b[9:], nil
	}
}

// readInt reads a signed integer whose tag plus width is n bytes.
func readInt(b []byte, n int) (any, []byte, error) {
	if len(b) < n {
		return nil, nil, fmt.Errorf("msgpack: int truncated")
	}
	switch n {
	case 2:
		return int64(int8(b[1])), b[2:], nil
	case 3:
		return int64(int16(binary.BigEndian.Uint16(b[1:]))), b[3:], nil
	case 5:
		return int64(int32(binary.BigEndian.Uint32(b[1:]))), b[5:], nil
	default:
		return int64(binary.BigEndian.Uint64(b[1:])), b[9:], nil
	}
}

// bytesOf reads n content bytes at offset off. str is whether the bytes
// must be valid UTF-8 (msgpack str) as opposed to opaque binary.
func bytesOf(b []byte, off, n int, str bool) (any, []byte, error) {
	if n < 0 || len(b)-off < n {
		return nil, nil, fmt.Errorf("msgpack: string/binary truncated")
	}
	raw := bytes.Clone(b[off : off+n])
	if str {
		return string(raw), b[off+n:], nil
	}
	return raw, b[off+n:], nil
}

// array reads n elements.
func array(b []byte, off, n int) (any, []byte, error) {
	if n < 0 || n > 1<<20 {
		return nil, nil, fmt.Errorf("msgpack: absurd array length %d", n)
	}
	rest := b[off:]
	out := make([]any, 0, n)
	for range n {
		var v any
		var err error
		v, rest, err = value(rest)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, v)
	}
	return out, rest, nil
}

// mapOf reads n string-keyed pairs. A non-string key is an error: every
// document on this host is a JSON-shaped record, and a positional map would
// decode into the wrong island.
func mapOf(b []byte, off, n int) (any, []byte, error) {
	if n < 0 || n > 1<<20 {
		return nil, nil, fmt.Errorf("msgpack: absurd map length %d", n)
	}
	rest := b[off:]
	out := make(map[string]any, n)
	for range n {
		var k any
		var err error
		k, rest, err = value(rest)
		if err != nil {
			return nil, nil, err
		}
		ks, ok := k.(string)
		if !ok {
			return nil, nil, fmt.Errorf("msgpack: non-string map key %T", k)
		}
		var v any
		v, rest, err = value(rest)
		if err != nil {
			return nil, nil, err
		}
		out[ks] = v
	}
	return out, rest, nil
}
