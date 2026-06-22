// Package cbor is the owned canonical CBOR codec: the deterministic CBOR
// subset Murmur uses, with encoding, decoding, and canonical enforcement.
//
// There is no third-party CBOR library here on purpose. A canonical encoding
// proven by a single implementation is unfalsifiable, so the oracle owns its
// codec and agrees with the Rust reference by running the same vectors, not by
// sharing code. The canonical-encoding rules in the spec repo
// (canonical-encoding.md) are authoritative; this package is their executable
// form. The same encoder is reused later by the authoring compiler, so it
// carries no oracle-specific coupling.
package cbor

import "math/big"

// Value is one decoded or to-be-encoded canonical value. The set is closed:
// the variants below are the only canonical types, mirroring the permitted
// CBOR major types plus the two magnitude constructs.
type Value interface {
	isValue()
}

// Int is a CBOR integer (major type 0 or 1). It is held in a big.Int so the
// full canonical range, 0 to 2^64-1 and -1 to -2^64, round-trips exactly;
// int64 cannot hold 2^64-1 or -2^64. The wire form has no bignum tag, so the
// encoder rejects a value outside that range.
type Int struct{ V *big.Int }

// Bytes is a CBOR byte string (major type 2): opaque bytes, no transform.
type Bytes struct{ V []byte }

// Text is a CBOR text string (major type 3): UTF-8, no BOM, in NFC.
type Text struct{ V string }

// Bool is a CBOR boolean (major type 7, the simple values true and false).
type Bool struct{ V bool }

// Array is a CBOR array (major type 4).
type Array struct{ Items []Value }

// MapEntry is one key-value pair of a Map. The key is an Int or a Text; no
// other type names a field.
type MapEntry struct {
	Key   Value
	Value Value
}

// Map is a CBOR map (major type 5). Every key is the same type, either Int or
// Text. Entries are held in whatever order they were built or decoded; the
// encoder is what imposes the canonical bytewise key order and rejects
// duplicates, and the decoder is what rejects an out-of-order or duplicated
// map on receipt.
type Map struct{ Entries []MapEntry }

// Decimal is a base-10 decimal magnitude, mantissa times ten to the scale. It
// shares the two-element integer-array wire shape [scale, mantissa] with
// Rational; which one a given array is comes from the schema position, not the
// bytes, so the decoder never produces a Decimal. The encoder emits it and
// enforces its canonical form: mantissa not divisible by ten, sign on the
// mantissa, zero is [0, 0].
type Decimal struct {
	Scale    *big.Int
	Mantissa *big.Int
}

// Rational is an exact ratio, numerator over denominator, on the wire as
// [numerator, denominator]. Canonical form: denominator positive and non-zero,
// numerator and denominator coprime, sign on the numerator, zero is [0, 1].
type Rational struct {
	Num *big.Int
	Den *big.Int
}

func (Int) isValue()      {}
func (Bytes) isValue()    {}
func (Text) isValue()     {}
func (Bool) isValue()     {}
func (Array) isValue()    {}
func (Map) isValue()      {}
func (Decimal) isValue()  {}
func (Rational) isValue() {}

// NewInt is a convenience constructor for an Int from a native int64.
func NewInt(v int64) Int { return Int{V: big.NewInt(v)} }
