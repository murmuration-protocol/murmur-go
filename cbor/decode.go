package cbor

import (
	"bytes"
	"math/big"
)

// Decode parses one canonical CBOR artifact and returns its value. It rejects,
// rather than re-encodes, any well-formed CBOR that is not in canonical form:
// a non-minimal head, an indefinite length, a tag, a float, null, a map with
// mixed or duplicate or out-of-order keys, or a trailing byte. The whole input
// MUST be exactly one data item.
func Decode(data []byte) (Value, error) {
	d := &decoder{data: data}
	v, err := d.item(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(data) {
		return nil, &DecodeError{Reason: ReasonTrailingBytes, Pos: d.pos}
	}
	return v, nil
}

type decoder struct {
	data  []byte
	pos   int
	items int
}

func (d *decoder) item(depth int) (Value, error) {
	if depth > MaxDepth {
		return nil, &DecodeError{Reason: ReasonDepthExceeded, Pos: d.pos}
	}
	d.items++
	if d.items > MaxItems {
		return nil, &DecodeError{Reason: ReasonSizeExceeded, Pos: d.pos}
	}
	if d.pos >= len(d.data) {
		return nil, &DecodeError{Reason: ReasonTruncated, Pos: d.pos}
	}
	b := d.data[d.pos]
	major := b >> 5
	ai := b & 0x1f

	switch major {
	case 7:
		return d.simple(ai)
	case 6:
		return nil, &DecodeError{Reason: ReasonTag, Pos: d.pos}
	}

	at := d.pos
	d.pos++
	arg, err := d.readArg(ai, at)
	if err != nil {
		return nil, err
	}

	switch major {
	case 0:
		return Int{V: new(big.Int).SetUint64(arg)}, nil
	case 1:
		// -1-arg, computed in big.Int so arg = 2^64-1 (value -2^64) is exact.
		n := new(big.Int).SetUint64(arg)
		n.Add(n, bigOne)
		n.Neg(n)
		return Int{V: n}, nil
	case 2:
		raw, err := d.bytes(arg, at)
		if err != nil {
			return nil, err
		}
		return Bytes{V: raw}, nil
	case 3:
		raw, err := d.bytes(arg, at)
		if err != nil {
			return nil, err
		}
		s := string(raw)
		if err := validateText(s); err != nil {
			return nil, &DecodeError{Reason: textReason(err), Pos: at, Msg: err.Error()}
		}
		return Text{V: s}, nil
	case 4:
		return d.array(arg, depth)
	case 5:
		return d.mapValue(arg, at, depth)
	}
	return nil, &DecodeError{Reason: ReasonReservedAdditional, Pos: at}
}

// readArg reads the argument that follows a head, enforcing minimal encoding:
// the shortest form that holds the value. A longer form than the value needs is
// reported as ReasonNonMinimal, the one minimal-encoding rule that covers an
// integer value, a string length, and an element count alike.
func (d *decoder) readArg(ai byte, headPos int) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		v, err := d.takeUint(1, headPos)
		if err != nil {
			return 0, err
		}
		if v < 24 {
			return 0, &DecodeError{Reason: ReasonNonMinimal, Pos: headPos}
		}
		return v, nil
	case ai == 25:
		v, err := d.takeUint(2, headPos)
		if err != nil {
			return 0, err
		}
		if v < 1<<8 {
			return 0, &DecodeError{Reason: ReasonNonMinimal, Pos: headPos}
		}
		return v, nil
	case ai == 26:
		v, err := d.takeUint(4, headPos)
		if err != nil {
			return 0, err
		}
		if v < 1<<16 {
			return 0, &DecodeError{Reason: ReasonNonMinimal, Pos: headPos}
		}
		return v, nil
	case ai == 27:
		v, err := d.takeUint(8, headPos)
		if err != nil {
			return 0, err
		}
		if v < 1<<32 {
			return 0, &DecodeError{Reason: ReasonNonMinimal, Pos: headPos}
		}
		return v, nil
	case ai == 31:
		return 0, &DecodeError{Reason: ReasonIndefiniteLength, Pos: headPos}
	default: // 28, 29, 30
		return 0, &DecodeError{Reason: ReasonReservedAdditional, Pos: headPos}
	}
}

func (d *decoder) takeUint(n, headPos int) (uint64, error) {
	if d.pos+n > len(d.data) {
		return 0, &DecodeError{Reason: ReasonTruncated, Pos: headPos}
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(d.data[d.pos+i])
	}
	d.pos += n
	return v, nil
}

func (d *decoder) bytes(arg uint64, headPos int) ([]byte, error) {
	n := int(arg)
	if uint64(n) != arg || d.pos+n > len(d.data) {
		return nil, &DecodeError{Reason: ReasonTruncated, Pos: headPos}
	}
	out := make([]byte, n)
	copy(out, d.data[d.pos:d.pos+n])
	d.pos += n
	return out, nil
}

func (d *decoder) array(arg uint64, depth int) (Value, error) {
	n := int(arg)
	if uint64(n) != arg {
		return nil, &DecodeError{Reason: ReasonSizeExceeded, Pos: d.pos}
	}
	items := make([]Value, 0, min(n, 1024))
	for i := 0; i < n; i++ {
		v, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return Array{Items: items}, nil
}

func (d *decoder) mapValue(arg uint64, headPos, depth int) (Value, error) {
	n := int(arg)
	if uint64(n) != arg {
		return nil, &DecodeError{Reason: ReasonSizeExceeded, Pos: headPos}
	}
	entries := make([]MapEntry, 0, min(n, 1024))
	var keysAreText bool
	var prevKey []byte
	for i := 0; i < n; i++ {
		keyStart := d.pos
		key, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		keyBytes := d.data[keyStart:d.pos]

		switch key.(type) {
		case Int:
			if i == 0 {
				keysAreText = false
			} else if keysAreText {
				return nil, &DecodeError{Reason: ReasonMixedMapKeys, Pos: keyStart}
			}
		case Text:
			if i == 0 {
				keysAreText = true
			} else if !keysAreText {
				return nil, &DecodeError{Reason: ReasonMixedMapKeys, Pos: keyStart}
			}
		default:
			return nil, &DecodeError{Reason: ReasonBadMapKeyType, Pos: keyStart}
		}

		// Order is taken on the encoded key bytes, which the minimal-head rule
		// above already guarantees are themselves canonical. Strictly ascending
		// catches both an out-of-order map and a duplicate key.
		if i > 0 {
			switch bytes.Compare(prevKey, keyBytes) {
			case 0:
				return nil, &DecodeError{Reason: ReasonDuplicateMapKey, Pos: keyStart}
			case 1:
				return nil, &DecodeError{Reason: ReasonUnsortedMapKeys, Pos: keyStart}
			}
		}
		prevKey = keyBytes

		val, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		entries = append(entries, MapEntry{Key: key, Value: val})
	}
	return Map{Entries: entries}, nil
}

// simple decodes a major-type-7 value, restricted to the booleans. Floats,
// null, undefined, and every other simple value are refused.
func (d *decoder) simple(ai byte) (Value, error) {
	at := d.pos
	switch ai {
	case 20:
		d.pos++
		return Bool{V: false}, nil
	case 21:
		d.pos++
		return Bool{V: true}, nil
	case 22, 23:
		return nil, &DecodeError{Reason: ReasonNull, Pos: at}
	case 25, 26, 27:
		return nil, &DecodeError{Reason: ReasonFloat, Pos: at}
	case 31:
		return nil, &DecodeError{Reason: ReasonIndefiniteLength, Pos: at}
	default:
		return nil, &DecodeError{Reason: ReasonSimpleValue, Pos: at}
	}
}

func textReason(err error) Reason {
	if e, ok := err.(*EncodeError); ok {
		switch e.Msg {
		case "text string is not valid UTF-8":
			return ReasonInvalidUTF8
		case "text string carries a byte-order mark":
			return ReasonByteOrderMark
		case "text string is not in Normalization Form C":
			return ReasonNonNFC
		}
	}
	return ReasonInvalidUTF8
}
