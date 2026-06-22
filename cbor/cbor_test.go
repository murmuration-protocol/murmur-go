package cbor_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/murmuration-protocol/murmur-go/cbor"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func bigStr(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

// roundTrip asserts a value encodes to exactly want and decodes (then
// re-encodes) back to the same bytes.
func roundTrip(t *testing.T, v cbor.Value, want string) {
	t.Helper()
	got, err := cbor.Encode(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("encode: got %s, want %s", hex.EncodeToString(got), want)
	}
	dec, err := cbor.Decode(mustHex(t, want))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	re, err := cbor.Encode(dec)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if hex.EncodeToString(re) != want {
		t.Fatalf("round-trip: got %s, want %s", hex.EncodeToString(re), want)
	}
}

// TestIntegerRange covers the boundaries int64 cannot, which is the whole
// reason the value model is math/big.
func TestIntegerRange(t *testing.T) {
	cases := []struct {
		n    *big.Int
		want string
	}{
		{big.NewInt(0), "00"},
		{big.NewInt(23), "17"},
		{big.NewInt(24), "1818"},
		{big.NewInt(-1), "20"},
		{big.NewInt(-24), "37"},
		{bigStr("18446744073709551615"), "1bffffffffffffffff"},  // 2^64-1, max uint64
		{bigStr("-18446744073709551616"), "3bffffffffffffffff"}, // -2^64, min negative
	}
	for _, c := range cases {
		roundTrip(t, cbor.Int{V: c.n}, c.want)
	}
}

func TestIntegerOutOfRange(t *testing.T) {
	for _, n := range []*big.Int{
		bigStr("18446744073709551616"),  // 2^64, one past max uint64
		bigStr("-18446744073709551617"), // -2^64-1, one past min
	} {
		if _, err := cbor.Encode(cbor.Int{V: n}); err == nil {
			t.Errorf("%v: expected an out-of-range error", n)
		}
	}
}

func TestDecimalCanonical(t *testing.T) {
	// 150ms in a seconds field is [-2, 15]: array(2), -2 (0x21), 15 (0x0f).
	roundTrip(t, cbor.Decimal{Scale: big.NewInt(-2), Mantissa: big.NewInt(15)}, "82210f")
	// zero is [0, 0].
	roundTrip(t, cbor.Decimal{Scale: big.NewInt(0), Mantissa: big.NewInt(0)}, "820000")
}

func TestDecimalRejectsNonCanonical(t *testing.T) {
	// mantissa divisible by ten is the non-canonical [-3, 150] form.
	if _, err := cbor.Encode(cbor.Decimal{Scale: big.NewInt(-3), Mantissa: big.NewInt(150)}); err == nil {
		t.Error("expected rejection of mantissa divisible by ten")
	}
	// a non-zero scale on a zero mantissa is not the canonical zero.
	if _, err := cbor.Encode(cbor.Decimal{Scale: big.NewInt(-2), Mantissa: big.NewInt(0)}); err == nil {
		t.Error("expected rejection of [-2, 0]")
	}
}

func TestRationalCanonical(t *testing.T) {
	// one third is [1, 3]: array(2), 1, 3.
	roundTrip(t, cbor.Rational{Num: big.NewInt(1), Den: big.NewInt(3)}, "820103")
	// zero is [0, 1].
	roundTrip(t, cbor.Rational{Num: big.NewInt(0), Den: big.NewInt(1)}, "820001")
}

func TestRationalRejectsNonCanonical(t *testing.T) {
	cases := []cbor.Rational{
		{Num: big.NewInt(2), Den: big.NewInt(4)},  // not reduced
		{Num: big.NewInt(1), Den: big.NewInt(-3)}, // sign on the denominator
		{Num: big.NewInt(1), Den: big.NewInt(0)},  // zero denominator
		{Num: big.NewInt(0), Den: big.NewInt(2)},  // zero is [0, 1] only
	}
	for _, r := range cases {
		if _, err := cbor.Encode(r); err == nil {
			t.Errorf("%v/%v: expected rejection", r.Num, r.Den)
		}
	}
}

func TestMapSortsAndDedups(t *testing.T) {
	// Authored out of order; the encoder must emit ascending key order.
	m := cbor.Map{Entries: []cbor.MapEntry{
		{Key: cbor.NewInt(2), Value: cbor.NewInt(0)},
		{Key: cbor.NewInt(1), Value: cbor.NewInt(0)},
	}}
	roundTrip(t, m, "a201000200")

	dup := cbor.Map{Entries: []cbor.MapEntry{
		{Key: cbor.NewInt(1), Value: cbor.NewInt(0)},
		{Key: cbor.NewInt(1), Value: cbor.NewInt(1)},
	}}
	if _, err := cbor.Encode(dup); err == nil {
		t.Error("expected duplicate-key rejection on encode")
	}

	mixed := cbor.Map{Entries: []cbor.MapEntry{
		{Key: cbor.NewInt(1), Value: cbor.NewInt(0)},
		{Key: cbor.Text{V: "a"}, Value: cbor.NewInt(0)},
	}}
	if _, err := cbor.Encode(mixed); err == nil {
		t.Error("expected mixed-key rejection on encode")
	}
}

// TestRejectReasons pins each canonical violation to its reason string,
// including the ones the spec describes but the vector corpus does not yet
// carry as fixtures.
func TestRejectReasons(t *testing.T) {
	cases := []struct {
		hexBytes string
		reason   cbor.Reason
	}{
		{"1800", cbor.ReasonNonMinimal},             // 0 in two bytes
		{"190000", cbor.ReasonNonMinimal},           // 0 in three bytes
		{"9f0102ff", cbor.ReasonIndefiniteLength},   // indefinite-length array
		{"0000", cbor.ReasonTrailingBytes},          // a second data item
		{"a201000101", cbor.ReasonDuplicateMapKey},  // key 1 twice
		{"a202000100", cbor.ReasonUnsortedMapKeys},  // keys 2 then 1
		{"a100", cbor.ReasonTruncated},              // map(1), key 0, value missing
		{"c000", cbor.ReasonTag},                    // tag 0
		{"f6", cbor.ReasonNull},                     // null
		{"fa3f800000", cbor.ReasonFloat},            // float32 1.0
		{"a2010061610200", cbor.ReasonMixedMapKeys}, // int key then text key
		{"a1810000", cbor.ReasonBadMapKeyType},      // an array as a key
	}
	for _, c := range cases {
		_, err := cbor.Decode(mustHex(t, c.hexBytes))
		de, ok := err.(*cbor.DecodeError)
		if !ok {
			t.Errorf("%s: expected *cbor.DecodeError, got %v", c.hexBytes, err)
			continue
		}
		if de.Reason != c.reason {
			t.Errorf("%s: got reason %q, want %q", c.hexBytes, de.Reason, c.reason)
		}
	}
}

func TestTextRejectsNonNFC(t *testing.T) {
	// Built from code points so the source bytes are unambiguous. The
	// decomposed form is U+0065 (e) then U+0301 (combining acute); NFC composes
	// it to the single code point U+00E9, so the decomposed bytes are not
	// canonical.
	decomposed := "e" + string(rune(0x0301))
	composed := string(rune(0x00e9))

	if _, err := cbor.Encode(cbor.Text{V: decomposed}); err == nil {
		t.Error("expected NFC rejection on encode")
	}
	// Build the CBOR by hand: major 3, len 3, then the three UTF-8 bytes.
	b := append([]byte{0x63}, []byte(decomposed)...)
	_, err := cbor.Decode(b)
	de, ok := err.(*cbor.DecodeError)
	if !ok || de.Reason != cbor.ReasonNonNFC {
		t.Errorf("expected non-nfc rejection on decode, got %v", err)
	}
	// The composed form is canonical and round-trips (major 3, len 2, then c3a9).
	roundTrip(t, cbor.Text{V: composed}, "62"+hex.EncodeToString([]byte(composed)))
}

func TestDepthBound(t *testing.T) {
	// MaxDepth+1 nested single-element arrays must be refused, not recursed into.
	var b []byte
	for i := 0; i <= cbor.MaxDepth; i++ {
		b = append(b, 0x81) // array(1)
	}
	b = append(b, 0x00) // the innermost element
	_, err := cbor.Decode(b)
	de, ok := err.(*cbor.DecodeError)
	if !ok || de.Reason != cbor.ReasonDepthExceeded {
		t.Errorf("expected depth-exceeded, got %v", err)
	}
}
