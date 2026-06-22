package schema_test

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"

	"github.com/murmuration-protocol/murmur-go/cbor"
	"github.com/murmuration-protocol/murmur-go/schema"
)

// The pinned closure artifacts, the canonical CBOR of the three floor tables.
// These are the same bytes the spec's content-id vectors carry, and the
// conformance package independently checks they hash to their content
// addresses. Here they prove the fixed point one level up: interpreting each as
// a field table must reproduce the hardcoded floor grammar.
const (
	metaTableHex      = "a3000001010283a40000016964657363726962657302a100000301a40001016776657273696f6e02a100000301a400020167656e747269657302a2000601a2000702010301"
	entryHex          = "a3000101010284a4000001636b657902a100000301a4000101646e616d6502a100020301a4000201647479706502a2000702020301a40003016870726573656e636502a100000301"
	typeDescriptorHex = "a3000201010284a4000001646b696e6402a100000301a4000101626f6602a2000702020300a40002016372656602a100000300a400030164756e697402a100000300"
)

func decode(t *testing.T, h string) cbor.Value {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	v, err := cbor.Decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

// TestFixedPoint is the load-bearing test: each floor table, parsed from its own
// canonical artifact through the meta-table grammar, reproduces exactly the
// hardcoded floor. The closure decodes itself, in Go, byte-authored bytes to
// the same grammar the bytes are encoded in.
func TestFixedPoint(t *testing.T) {
	reg := schema.DefaultRegistry()
	cases := []struct {
		name string
		hex  string
		want schema.FieldTable
	}{
		{"meta-table", metaTableHex, schema.MetaTable},
		{"entry", entryHex, schema.EntryTable},
		{"type-descriptor", typeDescriptorHex, schema.TypeDescriptorTable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := schema.ParseFieldTable(decode(t, c.hex), reg)
			if err != nil {
				t.Fatalf("ParseFieldTable: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parsed table does not match the hardcoded floor:\n got  %+v\n want %+v", got, c.want)
			}
		})
	}
}

// intMap builds an integer-keyed cbor.Map from key/value pairs, for ad-hoc test
// artifacts.
func intMap(pairs ...struct {
	k int
	v cbor.Value
}) cbor.Map {
	m := cbor.Map{}
	for _, p := range pairs {
		m.Entries = append(m.Entries, cbor.MapEntry{Key: cbor.NewInt(int64(p.k)), Value: p.v})
	}
	return m
}

func kv(k int, v cbor.Value) struct {
	k int
	v cbor.Value
} {
	return struct {
		k int
		v cbor.Value
	}{k, v}
}

// testTable is a small fixed schema for the interpreter unit tests: an integer,
// a text, a decimal, and an optional boolean.
var testTable = schema.FieldTable{
	Describes: schema.PrivateRangeStart,
	Version:   1,
	Entries: []schema.Entry{
		{Key: 0, Name: "count", Type: schema.TypeDescriptor{Kind: schema.KindInt}, Presence: schema.PresenceRequired},
		{Key: 1, Name: "label", Type: schema.TypeDescriptor{Kind: schema.KindText}, Presence: schema.PresenceRequired},
		{Key: 2, Name: "deadline", Type: schema.TypeDescriptor{Kind: schema.KindDecimal, Unit: 1}, Presence: schema.PresenceOptional},
		{Key: 3, Name: "armed", Type: schema.TypeDescriptor{Kind: schema.KindBool}, Presence: schema.PresenceOptional},
	},
}

func TestInterpretScalars(t *testing.T) {
	v := intMap(
		kv(0, cbor.NewInt(7)),
		kv(1, cbor.Text{V: "all-notes-off"}),
		kv(3, cbor.Bool{V: true}),
	)
	in, err := schema.Interpret(testTable, v, schema.DefaultRegistry())
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	if n, ok := in.Int(0); !ok || n.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("count: got %v, %v", n, ok)
	}
	if s, ok := in.Text(1); !ok || s != "all-notes-off" {
		t.Errorf("label: got %q, %v", s, ok)
	}
	if b, ok := in.Bool(3); !ok || !b {
		t.Errorf("armed: got %v, %v", b, ok)
	}
	if in.Has(2) {
		t.Error("deadline should be absent")
	}
}

func TestInterpretDecimal(t *testing.T) {
	// 150ms as [-2, 15] in a decimal field interprets and validates.
	v := intMap(
		kv(0, cbor.NewInt(1)),
		kv(1, cbor.Text{V: "x"}),
		kv(2, cbor.Array{Items: []cbor.Value{cbor.NewInt(-2), cbor.NewInt(15)}}),
	)
	in, err := schema.Interpret(testTable, v, schema.DefaultRegistry())
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	d, ok := in.Decimal(2)
	if !ok || d.Scale.Cmp(big.NewInt(-2)) != 0 || d.Mantissa.Cmp(big.NewInt(15)) != 0 {
		t.Errorf("deadline: got %+v, %v", d, ok)
	}
}

func TestInterpretRejectsNonCanonicalDecimal(t *testing.T) {
	// [-3, 150] is a non-canonical decimal (mantissa divisible by ten), though
	// it is a perfectly canonical plain integer array. The schema position is
	// what makes it a decimal and the violation visible.
	v := intMap(
		kv(0, cbor.NewInt(1)),
		kv(1, cbor.Text{V: "x"}),
		kv(2, cbor.Array{Items: []cbor.Value{cbor.NewInt(-3), cbor.NewInt(150)}}),
	)
	_, err := schema.Interpret(testTable, v, schema.DefaultRegistry())
	assertReason(t, err, schema.ReasonNonCanonicalDecimal)
}

func TestInterpretRejectsUnknownKey(t *testing.T) {
	v := intMap(
		kv(0, cbor.NewInt(1)),
		kv(1, cbor.Text{V: "x"}),
		kv(9, cbor.NewInt(0)), // not in the table
	)
	_, err := schema.Interpret(testTable, v, schema.DefaultRegistry())
	assertReason(t, err, schema.ReasonUnknownField)
}

func TestInterpretRejectsTypeMismatch(t *testing.T) {
	v := intMap(
		kv(0, cbor.Text{V: "not an int"}),
		kv(1, cbor.Text{V: "x"}),
	)
	_, err := schema.Interpret(testTable, v, schema.DefaultRegistry())
	assertReason(t, err, schema.ReasonTypeMismatch)
}

// TestPresenceNotEnforcedByInterpret confirms the decode/validate split: a map
// missing a declared-required field still interprets, and the gate is the
// actor's separate Require.
func TestPresenceNotEnforcedByInterpret(t *testing.T) {
	v := intMap(kv(0, cbor.NewInt(1))) // missing required "label" (key 1)
	in, err := schema.Interpret(testTable, v, schema.DefaultRegistry())
	if err != nil {
		t.Fatalf("Interpret should not enforce presence: %v", err)
	}
	if err := in.Require(0); err != nil {
		t.Errorf("Require(0) should pass: %v", err)
	}
	if err := in.Require(1); err == nil {
		t.Error("Require(1) should fail on the absent required field")
	} else {
		assertReason(t, err, schema.ReasonMissingField)
	}
}

func TestUnresolvedRef(t *testing.T) {
	// A table with a ref to an artifact type the registry does not hold.
	refTable := schema.FieldTable{
		Describes: schema.PrivateRangeStart,
		Version:   1,
		Entries:   []schema.Entry{{Key: 0, Name: "nested", Type: schema.TypeDescriptor{Kind: schema.KindRef, Ref: schema.ArtifactGrant}, Presence: schema.PresenceRequired}},
	}
	v := intMap(kv(0, intMap(kv(0, cbor.NewInt(1)))))
	_, err := schema.Interpret(refTable, v, schema.DefaultRegistry())
	assertReason(t, err, schema.ReasonUnresolvedRef)
}

func assertReason(t *testing.T, err error, want schema.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with reason %q, got nil", want)
	}
	se, ok := err.(*schema.Error)
	if !ok {
		t.Fatalf("expected *schema.Error, got %T: %v", err, err)
	}
	if se.Reason != want {
		t.Errorf("got reason %q, want %q", se.Reason, want)
	}
}

// Builders for field-table artifacts, used by the malformed-floor tests. They
// produce the same shapes ParseFieldTable interprets: a field-table map, an
// entry map, and a scalar type-descriptor map.

func scalarTD(kind int) cbor.Map { return intMap(kv(0, cbor.NewInt(int64(kind)))) }

func entryArtifact(key int, name string, td cbor.Value, presence int) cbor.Map {
	return intMap(
		kv(0, cbor.NewInt(int64(key))),
		kv(1, cbor.Text{V: name}),
		kv(2, td),
		kv(3, cbor.NewInt(int64(presence))),
	)
}

func ftArtifact(describes, version int, entries ...cbor.Value) cbor.Map {
	return intMap(
		kv(0, cbor.NewInt(int64(describes))),
		kv(1, cbor.NewInt(int64(version))),
		kv(2, cbor.Array{Items: entries}),
	)
}

// TestParseFieldTableRejectsNonDenseKeys exercises malformed-field-table: a key
// sequence with a gap is not the dense, ascending sequence a table requires,
// though each entry decodes and type-checks cleanly against the entry table.
func TestParseFieldTableRejectsNonDenseKeys(t *testing.T) {
	td := scalarTD(int(schema.KindInt))
	ft := ftArtifact(int(schema.PrivateRangeStart), 1,
		entryArtifact(0, "a", td, int(schema.PresenceRequired)),
		entryArtifact(2, "b", td, int(schema.PresenceRequired)), // gap: 0 then 2
	)
	_, err := schema.ParseFieldTable(ft, schema.DefaultRegistry())
	assertReason(t, err, schema.ReasonMalformedFieldTable)
}

func TestParseFieldTableRejectsDuplicateKeys(t *testing.T) {
	td := scalarTD(int(schema.KindInt))
	ft := ftArtifact(int(schema.PrivateRangeStart), 1,
		entryArtifact(0, "a", td, int(schema.PresenceRequired)),
		entryArtifact(0, "b", td, int(schema.PresenceRequired)), // key 0 twice
	)
	_, err := schema.ParseFieldTable(ft, schema.DefaultRegistry())
	assertReason(t, err, schema.ReasonMalformedFieldTable)
}

// TestParseFieldTableRejectsMalformedTypeDescriptor exercises
// malformed-type-descriptor: an array kind that omits its element type. The
// descriptor decodes and matches the type-descriptor table field by field; only
// its conditional-by-kind rule catches it.
func TestParseFieldTableRejectsMalformedTypeDescriptor(t *testing.T) {
	arrayNoOf := scalarTD(int(schema.KindArray)) // kind = array, no `of`
	ft := ftArtifact(int(schema.PrivateRangeStart), 1,
		entryArtifact(0, "a", arrayNoOf, int(schema.PresenceRequired)),
	)
	_, err := schema.ParseFieldTable(ft, schema.DefaultRegistry())
	assertReason(t, err, schema.ReasonMalformedDescriptor)
}

// TestUnknownKindIsResolutionFamily confirms an unknown type-kind is the
// resolution family, not a malformed reason: a newer node may define the kind.
func TestUnknownKindIsResolutionFamily(t *testing.T) {
	tbl := schema.FieldTable{
		Describes: schema.PrivateRangeStart,
		Version:   1,
		Entries:   []schema.Entry{{Key: 0, Name: "x", Type: schema.TypeDescriptor{Kind: schema.Kind(99)}, Presence: schema.PresenceRequired}},
	}
	v := intMap(kv(0, cbor.NewInt(1)))
	_, err := schema.Interpret(tbl, v, schema.DefaultRegistry())
	assertReason(t, err, schema.ReasonUnresolvedRef)
}
