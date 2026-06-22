package cbor

import (
	"bytes"
	"math/big"
	"sort"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Limits bound decoding (and, cheaply, encoding) so adversarial nesting fails
// to the safe state rather than exhausting the decoder. They are the declared
// limit the canonical-encoding rules require; the values are generous for
// authored control-plane artifacts and far below what would exhaust a host.
const (
	MaxDepth = 64      // maximum nesting of arrays and maps
	MaxItems = 1 << 20 // maximum total data items in one artifact
)

var (
	maxUint64Plus1 = new(big.Int).Lsh(big.NewInt(1), 64) // 2^64, the first out-of-range argument
	bigTen         = big.NewInt(10)
	bigOne         = big.NewInt(1)
)

// Encode returns the single canonical byte form of v, or an error if v has no
// canonical form (an out-of-range integer, a non-reduced rational, a mixed-key
// map, a duplicate key, invalid text).
func Encode(v Value) ([]byte, error) {
	e := &encoder{}
	if err := e.value(v, 0); err != nil {
		return nil, err
	}
	return e.buf, nil
}

type encoder struct {
	buf []byte
}

func (e *encoder) value(v Value, depth int) error {
	if depth > MaxDepth {
		return &EncodeError{Msg: "nesting exceeds MaxDepth"}
	}
	switch t := v.(type) {
	case Int:
		return e.integer(t.V)
	case Bytes:
		e.head(2, uint64(len(t.V)))
		e.buf = append(e.buf, t.V...)
		return nil
	case Text:
		if err := validateText(t.V); err != nil {
			return err
		}
		e.head(3, uint64(len(t.V)))
		e.buf = append(e.buf, t.V...)
		return nil
	case Bool:
		if t.V {
			e.buf = append(e.buf, 0xf5)
		} else {
			e.buf = append(e.buf, 0xf4)
		}
		return nil
	case Array:
		e.head(4, uint64(len(t.Items)))
		for _, item := range t.Items {
			if err := e.value(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case Map:
		return e.mapValue(t, depth)
	case Decimal:
		return e.decimal(t, depth)
	case Rational:
		return e.rational(t, depth)
	default:
		return &EncodeError{Msg: "unknown value type"}
	}
}

// head writes the minimal CBOR head for a major type and argument: the
// shortest of the immediate, 1, 2, 4, and 8 byte argument forms that holds it.
// This one routine serves integers, lengths, and element counts alike.
func (e *encoder) head(major byte, arg uint64) {
	m := major << 5
	switch {
	case arg < 24:
		e.buf = append(e.buf, m|byte(arg))
	case arg < 1<<8:
		e.buf = append(e.buf, m|24, byte(arg))
	case arg < 1<<16:
		e.buf = append(e.buf, m|25, byte(arg>>8), byte(arg))
	case arg < 1<<32:
		e.buf = append(e.buf, m|26, byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	default:
		e.buf = append(e.buf, m|27,
			byte(arg>>56), byte(arg>>48), byte(arg>>40), byte(arg>>32),
			byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	}
}

func (e *encoder) integer(n *big.Int) error {
	if n.Sign() >= 0 {
		if n.Cmp(maxUint64Plus1) >= 0 {
			return &EncodeError{Msg: "integer above 2^64-1 has no canonical form (no bignum tag)"}
		}
		e.head(0, n.Uint64())
		return nil
	}
	// Major type 1 encodes -1-arg, so arg = -n-1. The range -1..-2^64 maps to
	// arg 0..2^64-1; anything more negative is out of range.
	arg := new(big.Int).Neg(n)
	arg.Sub(arg, bigOne)
	if arg.Cmp(maxUint64Plus1) >= 0 {
		return &EncodeError{Msg: "integer below -2^64 has no canonical form (no bignum tag)"}
	}
	e.head(1, arg.Uint64())
	return nil
}

func (e *encoder) decimal(d Decimal, depth int) error {
	if err := CheckDecimal(d.Scale, d.Mantissa); err != nil {
		return err
	}
	return e.intPair(d.Scale, d.Mantissa, depth)
}

func (e *encoder) rational(r Rational, depth int) error {
	if err := CheckRational(r.Num, r.Den); err != nil {
		return err
	}
	return e.intPair(r.Num, r.Den, depth)
}

// intPair emits a two-element array of two integers, the shared wire shape of
// the decimal and the rational.
func (e *encoder) intPair(a, b *big.Int, depth int) error {
	if depth+1 > MaxDepth {
		return &EncodeError{Msg: "nesting exceeds MaxDepth"}
	}
	e.head(4, 2)
	if err := e.integer(a); err != nil {
		return err
	}
	return e.integer(b)
}

func (e *encoder) mapValue(m Map, depth int) error {
	type encoded struct {
		key, val []byte
	}
	pairs := make([]encoded, 0, len(m.Entries))
	var keysAreText bool
	for i, ent := range m.Entries {
		switch ent.Key.(type) {
		case Int:
			if i == 0 {
				keysAreText = false
			} else if keysAreText {
				return &EncodeError{Msg: "map mixes integer and text keys"}
			}
		case Text:
			if i == 0 {
				keysAreText = true
			} else if !keysAreText {
				return &EncodeError{Msg: "map mixes integer and text keys"}
			}
		default:
			return &EncodeError{Msg: "map key must be an integer or a text string"}
		}
		kb, err := encodeSub(ent.Key, depth+1)
		if err != nil {
			return err
		}
		vb, err := encodeSub(ent.Value, depth+1)
		if err != nil {
			return err
		}
		pairs = append(pairs, encoded{kb, vb})
	}
	// Canonical order: ascending bytewise on the encoded key.
	sort.SliceStable(pairs, func(i, j int) bool {
		return bytes.Compare(pairs[i].key, pairs[j].key) < 0
	})
	for i := 1; i < len(pairs); i++ {
		if bytes.Equal(pairs[i-1].key, pairs[i].key) {
			return &EncodeError{Msg: "map carries a duplicate key"}
		}
	}
	e.head(5, uint64(len(pairs)))
	for _, p := range pairs {
		e.buf = append(e.buf, p.key...)
		e.buf = append(e.buf, p.val...)
	}
	return nil
}

func encodeSub(v Value, depth int) ([]byte, error) {
	sub := &encoder{}
	if err := sub.value(v, depth); err != nil {
		return nil, err
	}
	return sub.buf, nil
}

// validateText enforces the canonical text rules: valid UTF-8, no byte-order
// mark, and Unicode Normalization Form C. NFC is checked with
// golang.org/x/text/unicode/norm, the one sanctioned dependency outside the
// standard library: NFC needs the Unicode tables, the module is Go-team owned
// in the golang.org/x extended-stdlib namespace, and shipping our own tables
// would be the larger risk (see doc.go).
func validateText(s string) error {
	if !utf8.ValidString(s) {
		return &EncodeError{Msg: "text string is not valid UTF-8"}
	}
	if len(s) >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF {
		return &EncodeError{Msg: "text string carries a byte-order mark"}
	}
	if !norm.NFC.IsNormalString(s) {
		return &EncodeError{Msg: "text string is not in Normalization Form C"}
	}
	return nil
}
