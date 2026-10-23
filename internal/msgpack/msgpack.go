// Package msgpack is a small msgpack encoder and decoder: Animal Crossing's web API speaks
// msgpack (acbaa.go), as do the console's error reports.
package msgpack

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

// Encode encodes the subset these documents use: string-keyed maps, strings,
// integers, booleans and arrays. ponytail: no dependency for four type tags —
// add one the day a document needs floats or binary.
// Raw is msgpack already encoded, for embedding an ordered map in a
// list the game reads positionally.
type Raw []byte

func Encode(v any) []byte {
	var out []byte
	switch t := v.(type) {
	case nil:
		out = append(out, 0xc0)
	case bool:
		if t {
			out = append(out, 0xc3)
		} else {
			out = append(out, 0xc2)
		}
	case Raw: // already encoded, embedded as-is (ordered maps inside lists)
		out = append(out, t...)
	case []byte:
		switch {
		case len(t) < 256:
			out = append(out, 0xc4, byte(len(t)))
		default:
			out = append(out, 0xc5, byte(len(t)>>8), byte(len(t)))
		}
		out = append(out, t...)
	case string:
		out = append(out, Len(0xa0, 0xd9, 0xda, 0xdb, len(t))...)
		out = append(out, t...)
	case int:
		out = append(out, Int(int64(t))...)
	case int64:
		out = append(out, Int(t)...)
	case uint64:
		if t <= math.MaxInt64 {
			out = append(out, Int(int64(t))...)
			break
		}
		out = append(out, 0xcf)
		out = binary.BigEndian.AppendUint64(out, t)
	case []any:
		out = append(out, Len(0x90, 0, 0xdc, 0xdd, len(t))...)
		for _, e := range t {
			out = append(out, Encode(e)...)
		}
	case map[string]any:
		out = append(out, Len(0x80, 0, 0xde, 0xdf, len(t))...)
		// Sorted so the ETag is a function of the document, not of Go's map order.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, Encode(k)...)
			out = append(out, Encode(t[k])...)
		}
	default:
		panic(fmt.Sprintf("msgpack: unsupported %T", v))
	}
	return out
}

// Len writes the fix/8/16/32 header for a length-prefixed type. `f8` is
// 0 for arrays and maps, which have no 8-bit form.
func Len(fix, f8, f16, f32 byte, n int) []byte {
	limit := 15
	if fix == 0xa0 {
		limit = 31
	}
	switch {
	case n <= limit:
		return []byte{fix | byte(n)}
	case f8 != 0 && n <= math.MaxUint8:
		return []byte{f8, byte(n)}
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16([]byte{f16}, uint16(n))
	default:
		return binary.BigEndian.AppendUint32([]byte{f32}, uint32(n))
	}
}

func Int(n int64) []byte {
	switch {
	case n >= 0 && n <= 127:
		return []byte{byte(n)}
	case n < 0 && n >= -32:
		return []byte{byte(n)}
	case n >= math.MinInt8 && n <= math.MaxInt8:
		return []byte{0xd0, byte(n)}
	case n >= math.MinInt16 && n <= math.MaxInt16:
		return binary.BigEndian.AppendUint16([]byte{0xd1}, uint16(n))
	case n >= math.MinInt32 && n <= math.MaxInt32:
		return binary.BigEndian.AppendUint32([]byte{0xd2}, uint32(n))
	default:
		return binary.BigEndian.AppendUint64([]byte{0xd3}, uint64(n))
	}
}
