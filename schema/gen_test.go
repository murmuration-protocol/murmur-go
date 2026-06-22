package schema_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/murmur-protocol/murmur-go/cbor"
	"github.com/murmur-protocol/murmur-go/schema"
)

// genVectors guards the schema-reject vector generator. It writes real,
// self-checking fixtures into the spec repo, so it runs only when explicitly
// asked: `go test ./schema/ -run TestGenerateSchemaRejectVectors -genvectors`.
var genVectors = flag.Bool("genvectors", false, "write schema-reject vectors to ../../spec/vectors/schema-reject")

// genVector is one schema-reject fixture, in the authored field order the corpus
// pins: kind, description, spec, cbor, interpret_as, reason. interpret_as is the
// artifact-type code of the field table to interpret the bytes against; every
// fixture here is a field-table artifact (code 0), interpreted by ParseFieldTable.
type genVector struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Spec        string `json:"spec"`
	Cbor        string `json:"cbor"`
	InterpretAs int    `json:"interpret_as"`
	Reason      string `json:"reason"`
}

// fixture pairs a malformed floor artifact with the refusal it must provoke.
type fixture struct {
	name   string
	desc   string
	reason schema.Reason
	art    cbor.Value
}

func tkv(k string, v cbor.Value) cbor.MapEntry { return cbor.MapEntry{Key: cbor.Text{V: k}, Value: v} }

func textMap(entries ...cbor.MapEntry) cbor.Map { return cbor.Map{Entries: entries} }

// TestGenerateSchemaRejectVectors builds each malformed field-table artifact,
// encodes it canonically, self-checks it twice (the bytes round-trip
// byte-identically, so it is canonical and belongs in schema-reject not reject;
// and ParseFieldTable refuses it with the intended reason), then writes the
// vector file. A reason the generator does not expect fails the test loudly,
// which is how a surprise surfaces.
func TestGenerateSchemaRejectVectors(t *testing.T) {
	if !*genVectors {
		t.Skip("set -genvectors to (re)write the schema-reject corpus")
	}

	validTD := scalarTD(int(schema.KindInt))
	validEntry := func(k int) cbor.Value {
		return entryArtifact(k, fmt.Sprintf("f%d", k), validTD, int(schema.PresenceRequired))
	}
	ft := func(entries ...cbor.Value) cbor.Value {
		return ftArtifact(int(schema.PrivateRangeStart), 1, entries...)
	}
	// entriesArr is a valid one-entry entries array, for fixtures whose violation
	// is elsewhere and whose entries must be well-formed up to the violation.
	entriesArr := cbor.Array{Items: []cbor.Value{validEntry(0)}}
	// ftWith builds a field-table map from explicit key/value pairs, for the
	// fixtures that drop or add a top-level field.
	type pair = struct {
		k int
		v cbor.Value
	}
	ftWith := func(pairs ...pair) cbor.Value { return intMap(pairs...) }
	// entryMissing builds a field-table entry omitting one of its four fields.
	entryMissing := func(omit int) cbor.Value {
		var es []pair
		if omit != 0 {
			es = append(es, kv(0, cbor.NewInt(0)))
		}
		if omit != 1 {
			es = append(es, kv(1, cbor.Text{V: "a"}))
		}
		if omit != 2 {
			es = append(es, kv(2, validTD))
		}
		if omit != 3 {
			es = append(es, kv(3, cbor.NewInt(1)))
		}
		return intMap(es...)
	}
	// td builds a type-descriptor map from explicit key/value pairs.
	td := func(pairs ...pair) cbor.Value { return intMap(pairs...) }
	// entryWithTD wraps a (possibly malformed) type-descriptor in a valid entry
	// and a valid field table, so the descriptor is reached and judged.
	entryWithTD := func(t cbor.Value) cbor.Value {
		return ft(entryArtifact(0, "a", t, int(schema.PresenceRequired)))
	}

	kInt := cbor.NewInt(int64(schema.KindInt))
	kArr := cbor.NewInt(int64(schema.KindArray))
	kRef := cbor.NewInt(int64(schema.KindRef))
	kDec := cbor.NewInt(int64(schema.KindDecimal))
	kRat := cbor.NewInt(int64(schema.KindRational))

	fixtures := []fixture{
		// malformed-field-table: the entry keys are not a dense ascending
		// duplicate-free sequence, or the table carries no entries, or a
		// meta-table-required field is absent.
		{"malformed-field-table-keys-0-2", "field table whose entry keys are {0, 2}, a gap, not a dense ascending sequence", schema.ReasonMalformedFieldTable, ft(validEntry(0), validEntry(2))},
		{"malformed-field-table-keys-1", "field table whose single entry key is 1, not the 0 a dense sequence starts at", schema.ReasonMalformedFieldTable, ft(validEntry(1))},
		{"malformed-field-table-keys-1-2", "field table whose entry keys are {1, 2}, ascending but not starting at 0", schema.ReasonMalformedFieldTable, ft(validEntry(1), validEntry(2))},
		{"malformed-field-table-keys-0-1-3", "field table whose entry keys are {0, 1, 3}, a gap at the third entry", schema.ReasonMalformedFieldTable, ft(validEntry(0), validEntry(1), validEntry(3))},
		{"malformed-field-table-keys-0-0", "field table whose entry keys are {0, 0}, a duplicate of key 0", schema.ReasonMalformedFieldTable, ft(validEntry(0), validEntry(0))},
		{"malformed-field-table-keys-0-1-1", "field table whose entry keys are {0, 1, 1}, a duplicate of key 1", schema.ReasonMalformedFieldTable, ft(validEntry(0), validEntry(1), validEntry(1))},
		{"malformed-field-table-keys-1-0", "field table whose entry keys are {1, 0}, descending, not ascending", schema.ReasonMalformedFieldTable, ft(validEntry(1), validEntry(0))},
		{"malformed-field-table-keys-0-2-1", "field table whose entry keys are {0, 2, 1}, out of ascending order", schema.ReasonMalformedFieldTable, ft(validEntry(0), validEntry(2), validEntry(1))},
		{"malformed-field-table-keys-2-1-0", "field table whose entry keys are {2, 1, 0}, fully reversed", schema.ReasonMalformedFieldTable, ft(validEntry(2), validEntry(1), validEntry(0))},
		{"malformed-field-table-keys-neg-1", "field table whose single entry key is -1, below the 0 a sequence starts at", schema.ReasonMalformedFieldTable, ft(validEntry(-1))},
		{"malformed-field-table-empty-entries", "field table that carries no entries at all", schema.ReasonMalformedFieldTable, ft()},
		{"malformed-field-table-missing-describes", "field table missing the describes field the meta-table requires", schema.ReasonMalformedFieldTable, ftWith(kv(1, cbor.NewInt(1)), kv(2, entriesArr))},
		{"malformed-field-table-missing-version", "field table missing the version field the meta-table requires", schema.ReasonMalformedFieldTable, ftWith(kv(0, cbor.NewInt(int64(schema.PrivateRangeStart))), kv(2, entriesArr))},
		{"malformed-field-table-missing-entries", "field table missing the entries field the meta-table requires", schema.ReasonMalformedFieldTable, ftWith(kv(0, cbor.NewInt(int64(schema.PrivateRangeStart))), kv(1, cbor.NewInt(1)))},

		// malformed-entry: a field-table entry missing one of its four fields.
		{"malformed-entry-missing-key", "field-table entry missing its key field", schema.ReasonMalformedEntry, ft(entryMissing(0))},
		{"malformed-entry-missing-name", "field-table entry missing its name field", schema.ReasonMalformedEntry, ft(entryMissing(1))},
		{"malformed-entry-missing-type", "field-table entry missing its type field", schema.ReasonMalformedEntry, ft(entryMissing(2))},
		{"malformed-entry-missing-presence", "field-table entry missing its presence field", schema.ReasonMalformedEntry, ft(entryMissing(3))},

		// malformed-type-descriptor, omission: a kind without the field it requires.
		{"malformed-type-descriptor-array-without-of", "type-descriptor of kind array with no element type (of)", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kArr)))},
		{"malformed-type-descriptor-ref-without-ref", "type-descriptor of kind ref with no ref code", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kRef)))},
		{"malformed-type-descriptor-decimal-without-unit", "type-descriptor of kind decimal with no unit code", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kDec)))},
		{"malformed-type-descriptor-rational-without-unit", "type-descriptor of kind rational with no unit code", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kRat)))},
		{"malformed-type-descriptor-missing-kind", "type-descriptor with no kind at all", schema.ReasonMalformedDescriptor, entryWithTD(td())},

		// malformed-type-descriptor, commission: a kind carrying a field another
		// kind owns.
		{"malformed-type-descriptor-int-with-of", "scalar (int) type-descriptor carrying an of, which only array owns", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kInt), kv(1, validTD)))},
		{"malformed-type-descriptor-int-with-unit", "scalar (int) type-descriptor carrying a unit, which only a magnitude owns", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kInt), kv(3, cbor.NewInt(1))))},
		{"malformed-type-descriptor-array-with-unit", "array type-descriptor carrying a unit, which only a magnitude owns", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kArr), kv(1, validTD), kv(3, cbor.NewInt(1))))},

		// malformed-type-descriptor, nested: the violation is one or two levels
		// down an array's element type.
		{"malformed-type-descriptor-nested-array-without-of", "array of an array that itself has no element type", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kArr), kv(1, td(kv(0, kArr)))))},
		{"malformed-type-descriptor-nested-ref-without-ref", "array of a ref that has no ref code", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kArr), kv(1, td(kv(0, kRef)))))},
		{"malformed-type-descriptor-nested-decimal-without-unit", "array of an array of a decimal that has no unit code", schema.ReasonMalformedDescriptor, entryWithTD(td(kv(0, kArr), kv(1, td(kv(0, kArr), kv(1, td(kv(0, kDec)))))))},

		// type-mismatch: a value whose structure is not the type its field declares.
		{"type-mismatch-root-array", "field-table artifact that is an array, not a map", schema.ReasonTypeMismatch, cbor.Array{Items: []cbor.Value{cbor.NewInt(1)}}},
		{"type-mismatch-root-int", "field-table artifact that is an integer, not a map", schema.ReasonTypeMismatch, cbor.NewInt(0)},
		{"type-mismatch-describes-text", "field table whose describes is a text string, not an integer", schema.ReasonTypeMismatch, ftWith(kv(0, cbor.Text{V: "x"}), kv(1, cbor.NewInt(1)), kv(2, entriesArr))},
		{"type-mismatch-describes-bytes", "field table whose describes is a byte string, not an integer", schema.ReasonTypeMismatch, ftWith(kv(0, cbor.Bytes{V: []byte{0x01}}), kv(1, cbor.NewInt(1)), kv(2, entriesArr))},
		{"type-mismatch-version-text", "field table whose version is a text string, not an integer", schema.ReasonTypeMismatch, ftWith(kv(0, cbor.NewInt(int64(schema.PrivateRangeStart))), kv(1, cbor.Text{V: "x"}), kv(2, entriesArr))},
		{"type-mismatch-version-array", "field table whose version is an array, not an integer", schema.ReasonTypeMismatch, ftWith(kv(0, cbor.NewInt(int64(schema.PrivateRangeStart))), kv(1, cbor.Array{Items: []cbor.Value{cbor.NewInt(1)}}), kv(2, entriesArr))},
		{"type-mismatch-entries-int", "field table whose entries is an integer, not an array", schema.ReasonTypeMismatch, ftWith(kv(0, cbor.NewInt(int64(schema.PrivateRangeStart))), kv(1, cbor.NewInt(1)), kv(2, cbor.NewInt(0)))},
		{"type-mismatch-entries-map", "field table whose entries is a map, not an array", schema.ReasonTypeMismatch, ftWith(kv(0, cbor.NewInt(int64(schema.PrivateRangeStart))), kv(1, cbor.NewInt(1)), kv(2, intMap(kv(0, cbor.NewInt(0)))))},
		{"type-mismatch-entries-element-int", "field table whose entries element is an integer, not an entry map", schema.ReasonTypeMismatch, ft(cbor.NewInt(0))},
		{"type-mismatch-entries-element-text", "field table whose entries element is a text string, not an entry map", schema.ReasonTypeMismatch, ft(cbor.Text{V: "x"})},
		{"type-mismatch-entries-element-array", "field table whose entries element is an array, not an entry map", schema.ReasonTypeMismatch, ft(cbor.Array{Items: []cbor.Value{cbor.NewInt(1)}})},
		{"type-mismatch-entries-element-bool", "field table whose entries element is a boolean, not an entry map", schema.ReasonTypeMismatch, ft(cbor.Bool{V: true})},
		{"type-mismatch-entry-key-text", "field-table entry whose key is a text string, not an integer", schema.ReasonTypeMismatch, ft(intMap(kv(0, cbor.Text{V: "x"}), kv(1, cbor.Text{V: "a"}), kv(2, validTD), kv(3, cbor.NewInt(1))))},
		{"type-mismatch-entry-name-int", "field-table entry whose name is an integer, not a text string", schema.ReasonTypeMismatch, ft(intMap(kv(0, cbor.NewInt(0)), kv(1, cbor.NewInt(5)), kv(2, validTD), kv(3, cbor.NewInt(1))))},
		{"type-mismatch-entry-name-bytes", "field-table entry whose name is a byte string, not a text string", schema.ReasonTypeMismatch, ft(intMap(kv(0, cbor.NewInt(0)), kv(1, cbor.Bytes{V: []byte{0x01}}), kv(2, validTD), kv(3, cbor.NewInt(1))))},
		{"type-mismatch-entry-presence-text", "field-table entry whose presence is a text string, not an integer", schema.ReasonTypeMismatch, ft(intMap(kv(0, cbor.NewInt(0)), kv(1, cbor.Text{V: "a"}), kv(2, validTD), kv(3, cbor.Text{V: "x"})))},
		{"type-mismatch-entry-type-int", "field-table entry whose type is an integer, not a type-descriptor map", schema.ReasonTypeMismatch, ft(intMap(kv(0, cbor.NewInt(0)), kv(1, cbor.Text{V: "a"}), kv(2, cbor.NewInt(0)), kv(3, cbor.NewInt(1))))},
		{"type-mismatch-entry-type-array", "field-table entry whose type is an array, not a type-descriptor map", schema.ReasonTypeMismatch, ft(intMap(kv(0, cbor.NewInt(0)), kv(1, cbor.Text{V: "a"}), kv(2, cbor.Array{Items: []cbor.Value{cbor.NewInt(1)}}), kv(3, cbor.NewInt(1))))},
		{"type-mismatch-type-descriptor-kind-text", "type-descriptor whose kind is a text string, not an integer", schema.ReasonTypeMismatch, entryWithTD(td(kv(0, cbor.Text{V: "x"})))},
		{"type-mismatch-type-descriptor-of-int", "type-descriptor whose of is an integer, not a nested type-descriptor map", schema.ReasonTypeMismatch, entryWithTD(td(kv(0, kArr), kv(1, cbor.NewInt(0))))},
		{"type-mismatch-type-descriptor-ref-text", "type-descriptor whose ref is a text string, not an integer", schema.ReasonTypeMismatch, entryWithTD(td(kv(0, kRef), kv(2, cbor.Text{V: "x"})))},
		{"type-mismatch-type-descriptor-unit-text", "type-descriptor whose unit is a text string, not an integer", schema.ReasonTypeMismatch, entryWithTD(td(kv(0, kDec), kv(3, cbor.Text{V: "x"})))},

		// unknown-field-key: a wire key the version-closed table does not define.
		{"unknown-field-key-field-table-key-3", "field table carrying key 3, which the meta-table does not define", schema.ReasonUnknownField, ftWith(kv(0, cbor.NewInt(int64(schema.PrivateRangeStart))), kv(1, cbor.NewInt(1)), kv(2, entriesArr), kv(3, cbor.NewInt(0)))},
		{"unknown-field-key-field-table-key-99", "field table carrying key 99, far outside the meta-table", schema.ReasonUnknownField, ftWith(kv(0, cbor.NewInt(int64(schema.PrivateRangeStart))), kv(1, cbor.NewInt(1)), kv(2, entriesArr), kv(99, cbor.NewInt(0)))},
		{"unknown-field-key-entry-key-4", "field-table entry carrying key 4, which the entry table does not define", schema.ReasonUnknownField, ft(intMap(kv(0, cbor.NewInt(0)), kv(1, cbor.Text{V: "a"}), kv(2, validTD), kv(3, cbor.NewInt(1)), kv(4, cbor.NewInt(0))))},
		{"unknown-field-key-type-descriptor-key-4", "type-descriptor carrying key 4, which the type-descriptor table does not define", schema.ReasonUnknownField, entryWithTD(td(kv(0, kInt), kv(4, cbor.NewInt(0))))},

		// bad-field-key: a wholly text-keyed map where the table declares a fixed,
		// integer-keyed schema.
		{"bad-field-key-field-table", "field table written as a wholly text-keyed map", schema.ReasonBadFieldKey, textMap(tkv("describes", cbor.NewInt(0)), tkv("entries", cbor.NewInt(0)), tkv("version", cbor.NewInt(1)))},
		{"bad-field-key-entry", "field-table entry written as a wholly text-keyed map", schema.ReasonBadFieldKey, ft(textMap(tkv("key", cbor.NewInt(0)), tkv("name", cbor.Text{V: "a"}), tkv("presence", cbor.NewInt(1)), tkv("type", cbor.NewInt(0))))},
		{"bad-field-key-type-descriptor", "type-descriptor written as a wholly text-keyed map", schema.ReasonBadFieldKey, entryWithTD(textMap(tkv("kind", cbor.NewInt(0))))},
	}

	outDir := schemaRejectDir(t)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", outDir, err)
	}

	seen := map[string]bool{}
	for _, f := range fixtures {
		if seen[f.name] {
			t.Fatalf("duplicate fixture name %q", f.name)
		}
		seen[f.name] = true

		// Encode, and self-check (a): the bytes round-trip byte-identically, so
		// they are canonical, a schema-reject and not a byte reject.
		b, err := cbor.Encode(f.art)
		if err != nil {
			t.Fatalf("%s: encoding artifact: %v", f.name, err)
		}
		dec, err := cbor.Decode(b)
		if err != nil {
			t.Fatalf("%s: bytes do not decode (would belong in reject/): %v", f.name, err)
		}
		re, err := cbor.Encode(dec)
		if err != nil {
			t.Fatalf("%s: re-encoding: %v", f.name, err)
		}
		if !bytes.Equal(b, re) {
			t.Fatalf("%s: bytes are not canonical: %x != %x", f.name, b, re)
		}

		// Self-check (b): ParseFieldTable refuses it with exactly the intended
		// reason. A surprise fails here.
		_, perr := schema.ParseFieldTable(dec, schema.DefaultRegistry())
		if perr == nil {
			t.Fatalf("%s: expected refusal %q, but ParseFieldTable accepted it", f.name, f.reason)
		}
		se, ok := perr.(*schema.Error)
		if !ok {
			t.Fatalf("%s: expected *schema.Error, got %T: %v", f.name, perr, perr)
		}
		if se.Reason != f.reason {
			t.Fatalf("%s: SURPRISE: intended reason %q, got %q (%v)", f.name, f.reason, se.Reason, se)
		}

		gv := genVector{
			Kind:        "schema-reject",
			Description: f.desc,
			Spec:        "7.1",
			Cbor:        hex.EncodeToString(b),
			InterpretAs: int(schema.ArtifactFieldTable),
			Reason:      string(f.reason),
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(gv); err != nil {
			t.Fatalf("%s: marshalling: %v", f.name, err)
		}
		path := filepath.Join(outDir, f.name+".json")
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("%s: writing %s: %v", f.name, path, err)
		}
	}
	t.Logf("wrote %d schema-reject vectors to %s", len(fixtures), outDir)
}

// schemaRejectDir resolves the spec repo's schema-reject vector directory,
// ../../spec/vectors/schema-reject relative to this source file.
func schemaRejectDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the generator source path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "spec", "vectors", "schema-reject")
}
