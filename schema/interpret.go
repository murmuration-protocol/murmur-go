package schema

import (
	"fmt"
	"math/big"

	"github.com/murmur-protocol/murmur-go/cbor"
)

// Reason names why interpretation or a presence check failed. It is the schema
// layer's own vocabulary, kept distinct from cbor.Reason (the byte layer): the
// two layers refuse for different reasons and must not share one list (the
// separation law). The strings are the interpretation-refusal vocabulary of the
// spec repo's canonical-encoding.md ("Interpretation refusals"), grouped below
// into the same three classes that section defines. A reason is a local
// diagnostic, never a wire field. Schema reject vectors land with the field
// tables they exercise; until then these are aligned to the spec by name.
type Reason string

// Artifact-determined reasons are a function of the artifact bytes and the
// version-closed field table, which is itself normative, so two conformant
// interpreters reach the same reason and a schema vector can pin it.
// non-canonical-decimal and non-canonical-rational carry the content-addressing
// weight: a magnitude with a second accepted form forks its address, the byte
// subset's argument one layer up. The three malformed-* reasons share this
// class: each names a floor artifact that decodes cleanly and matches the
// meta-table field by field, yet breaks a structural rule of its floor type the
// flat field-table model cannot state. On the floor presence collapses into
// malformedness (the degenerate-case law): a floor artifact missing a field the
// meta-table requires is malformed-*, not missing-required-field, which is
// reserved for the protocol artifacts whose presence is action-relative. They
// are reserved for exactly those rules; an unresolvable code or enum value is
// the resolution family below, not malformed.
const (
	ReasonUnknownField Reason = "unknown-field-key" // a wire key the version-closed table does not define
	// bad-field-key is distinct from cbor.ReasonBadMapKeyType: a wholly
	// text-keyed map is well-formed CBOR, so the byte decoder passes it, and
	// only the table says this map should have been integer-keyed.
	ReasonBadFieldKey          Reason = "bad-field-key"             // a text key where a fixed, integer-keyed schema is declared
	ReasonTypeMismatch         Reason = "type-mismatch"             // a value whose structure is not the field's type
	ReasonBadMagnitude         Reason = "bad-magnitude"             // a decimal or rational field whose value is not a two-integer array
	ReasonNonCanonicalDecimal  Reason = "non-canonical-decimal"     // a decimal value outside its canonical form
	ReasonNonCanonicalRational Reason = "non-canonical-rational"    // a rational value outside its canonical form
	ReasonMalformedDescriptor  Reason = "malformed-type-descriptor" // a type-descriptor whose fields do not match its kind (a required field absent, or a field another kind owns present)
	ReasonMalformedFieldTable  Reason = "malformed-field-table"     // a field table whose entry keys are not a dense, ascending, duplicate-free sequence, that carries no entries, or that is missing a meta-table-required field
	ReasonMalformedEntry       Reason = "malformed-entry"           // a field-table entry missing a field the meta-table requires (key, name, type, presence)
)

// Capability-relative reasons depend on which tables and vocabularies this
// interpreter ships, not on the artifact alone, so two conformant nodes may
// disagree. Not pinned for cross-implementation reason-equality. This is the
// resolution family: besides an unresolved ref, it covers a code or enum value
// a floor field cannot resolve, an unknown type-kind, a presence or unit code
// outside the version's enum, an out-of-range code, since a newer node may know
// a value an older one does not.
const (
	ReasonUnresolvedRef Reason = "unresolved-ref" // a ref, or other code/enum value, the interpreter cannot resolve at the artifact's version
)

// Action-relative reasons depend on the action and role of the acting party,
// not on the artifact: a verifier requires a grant's signature, a relay
// requires none of it. Raised only by a presence gate, never by interpretation,
// so a vector states the actor's required keys, never the artifact alone.
const (
	ReasonMissingField Reason = "missing-required-field" // a presence gate found a field the action needs absent
)

// Error is a refusal at the interpretation or validation layer, distinct from
// cbor.DecodeError, which is the byte layer. Path locates the field in the
// artifact for diagnostics; it is local, never a wire field.
type Error struct {
	Reason Reason
	Path   string
	Msg    string
}

func (e *Error) Error() string {
	where := e.Path
	if where == "" {
		where = "(root)"
	}
	if e.Msg != "" {
		return fmt.Sprintf("schema: %s at %s: %s", e.Reason, where, e.Msg)
	}
	return fmt.Sprintf("schema: %s at %s", e.Reason, where)
}

// Instance is an interpreted artifact: the named, typed view of a structural
// cbor value under a field table. Fields holds only the keys present in the
// artifact; an absent field is simply not in the map (presence is not enforced
// here). The dynamic type of each field value follows its type-descriptor:
// cbor.Int, cbor.Bytes, cbor.Text, cbor.Bool for scalars; cbor.Decimal or
// cbor.Rational for magnitudes; *Instance for a ref; and []any (elements of the
// element type) for an array.
type Instance struct {
	Table   FieldTable
	Version int
	Fields  map[int]any
}

// Interpret binds a structural cbor value to the named, typed fields of a field
// table, resolving ref fields against the registry. It rejects an unknown wire
// key, a value whose structure does not match its field's type, an unresolved
// ref, and a decimal or rational outside its canonical form. It does not
// enforce presence.
func Interpret(table FieldTable, v cbor.Value, reg *Registry) (*Instance, error) {
	return interpretMap(table, v, reg, table.Version, "")
}

func interpretMap(table FieldTable, v cbor.Value, reg *Registry, version int, path string) (*Instance, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, &Error{Reason: ReasonTypeMismatch, Path: path, Msg: fmt.Sprintf("expected a map for %d, got %T", table.Describes, v)}
	}
	fields := make(map[int]any, len(m.Entries))
	for _, ent := range m.Entries {
		ki, ok := ent.Key.(cbor.Int)
		if !ok {
			return nil, &Error{Reason: ReasonBadFieldKey, Path: path, Msg: "fixed-schema map requires integer keys"}
		}
		if !ki.V.IsInt64() {
			return nil, &Error{Reason: ReasonUnknownField, Path: path, Msg: "key out of range"}
		}
		key := int(ki.V.Int64())
		field, ok := table.entryByKey(key)
		if !ok {
			return nil, &Error{Reason: ReasonUnknownField, Path: path, Msg: fmt.Sprintf("table for %d has no field with key %d", table.Describes, key)}
		}
		val, err := interpretValue(field.Type, ent.Value, reg, version, fieldPath(path, field.Name))
		if err != nil {
			return nil, err
		}
		fields[key] = val
	}
	return &Instance{Table: table, Version: version, Fields: fields}, nil
}

func interpretValue(td TypeDescriptor, v cbor.Value, reg *Registry, version int, path string) (any, error) {
	switch td.Kind {
	case KindInt:
		x, ok := v.(cbor.Int)
		if !ok {
			return nil, mismatch(path, "int", v)
		}
		return x, nil
	case KindBytes:
		x, ok := v.(cbor.Bytes)
		if !ok {
			return nil, mismatch(path, "bytes", v)
		}
		return x, nil
	case KindText:
		x, ok := v.(cbor.Text)
		if !ok {
			return nil, mismatch(path, "text", v)
		}
		return x, nil
	case KindBool:
		x, ok := v.(cbor.Bool)
		if !ok {
			return nil, mismatch(path, "bool", v)
		}
		return x, nil
	case KindDecimal:
		scale, mantissa, err := twoInts(v, path)
		if err != nil {
			return nil, err
		}
		if err := cbor.CheckDecimal(scale, mantissa); err != nil {
			return nil, &Error{Reason: ReasonNonCanonicalDecimal, Path: path, Msg: err.Error()}
		}
		return cbor.Decimal{Scale: scale, Mantissa: mantissa}, nil
	case KindRational:
		num, den, err := twoInts(v, path)
		if err != nil {
			return nil, err
		}
		if err := cbor.CheckRational(num, den); err != nil {
			return nil, &Error{Reason: ReasonNonCanonicalRational, Path: path, Msg: err.Error()}
		}
		return cbor.Rational{Num: num, Den: den}, nil
	case KindArray:
		arr, ok := v.(cbor.Array)
		if !ok {
			return nil, mismatch(path, "array", v)
		}
		if td.Of == nil {
			return nil, &Error{Reason: ReasonMalformedDescriptor, Path: path, Msg: "array type-descriptor has no element type"}
		}
		out := make([]any, 0, len(arr.Items))
		for i, item := range arr.Items {
			el, err := interpretValue(*td.Of, item, reg, version, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			out = append(out, el)
		}
		return out, nil
	case KindRef:
		child, ok := reg.Lookup(td.Ref, version)
		if !ok {
			return nil, &Error{Reason: ReasonUnresolvedRef, Path: path, Msg: fmt.Sprintf("no table for artifact type %d at version %d", td.Ref, version)}
		}
		return interpretMap(child, v, reg, version, path)
	default:
		// An unknown type-kind is a value the node cannot resolve, not a
		// structural malformation: the resolution family, since a newer node
		// may define the kind.
		return nil, &Error{Reason: ReasonUnresolvedRef, Path: path, Msg: fmt.Sprintf("unknown type-kind code %d", td.Kind)}
	}
}

// twoInts reads the [a, b] integer pair shared by the decimal and rational wire
// shapes, returning the two big.Int values or a bad-magnitude error.
func twoInts(v cbor.Value, path string) (*big.Int, *big.Int, error) {
	arr, ok := v.(cbor.Array)
	if !ok || len(arr.Items) != 2 {
		return nil, nil, &Error{Reason: ReasonBadMagnitude, Path: path, Msg: "expected a two-element array"}
	}
	a, aok := arr.Items[0].(cbor.Int)
	b, bok := arr.Items[1].(cbor.Int)
	if !aok || !bok {
		return nil, nil, &Error{Reason: ReasonBadMagnitude, Path: path, Msg: "both elements must be integers"}
	}
	return a.V, b.V, nil
}

func mismatch(path, want string, got cbor.Value) error {
	return &Error{Reason: ReasonTypeMismatch, Path: path, Msg: fmt.Sprintf("expected %s, got %T", want, got)}
}

func fieldPath(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "." + name
}

// Has reports whether the field with the given wire key is present.
func (in *Instance) Has(key int) bool {
	_, ok := in.Fields[key]
	return ok
}

// Require is the acting party's presence gate. It returns a missing-field error
// for the first key absent from the instance. Presence is scoped to an action
// and a role, so an actor passes the keys its own action needs, which may be a
// subset of, or distinct from, the table's declared required fields.
func (in *Instance) Require(keys ...int) error {
	for _, k := range keys {
		if !in.Has(k) {
			name := fmt.Sprintf("key %d", k)
			if e, ok := in.Table.entryByKey(k); ok {
				name = fmt.Sprintf("%q (key %d)", e.Name, k)
			}
			return &Error{Reason: ReasonMissingField, Msg: fmt.Sprintf("field %s is required to act but absent", name)}
		}
	}
	return nil
}

// Int returns the integer value of a field, or false if it is absent or not an
// integer.
func (in *Instance) Int(key int) (*big.Int, bool) {
	if x, ok := in.Fields[key].(cbor.Int); ok {
		return x.V, true
	}
	return nil, false
}

// Text returns the text value of a field, or false if it is absent or not text.
func (in *Instance) Text(key int) (string, bool) {
	if x, ok := in.Fields[key].(cbor.Text); ok {
		return x.V, true
	}
	return "", false
}

// Bool returns the boolean value of a field, or false if it is absent or not a
// boolean. The second result distinguishes absent from present-and-false.
func (in *Instance) Bool(key int) (val, ok bool) {
	if x, ok := in.Fields[key].(cbor.Bool); ok {
		return x.V, true
	}
	return false, false
}

// Bytes returns the byte-string value of a field, or false if it is absent or
// not a byte string.
func (in *Instance) Bytes(key int) ([]byte, bool) {
	if x, ok := in.Fields[key].(cbor.Bytes); ok {
		return x.V, true
	}
	return nil, false
}

// Decimal returns the decimal value of a field, or false if it is absent or not
// a decimal.
func (in *Instance) Decimal(key int) (cbor.Decimal, bool) {
	if x, ok := in.Fields[key].(cbor.Decimal); ok {
		return x, true
	}
	return cbor.Decimal{}, false
}

// Rational returns the rational value of a field, or false if it is absent or
// not a rational.
func (in *Instance) Rational(key int) (cbor.Rational, bool) {
	if x, ok := in.Fields[key].(cbor.Rational); ok {
		return x, true
	}
	return cbor.Rational{}, false
}

// Ref returns the nested instance of a ref field, or false if it is absent or
// not a ref.
func (in *Instance) Ref(key int) (*Instance, bool) {
	if x, ok := in.Fields[key].(*Instance); ok {
		return x, true
	}
	return nil, false
}

// Array returns the elements of an array field, or false if it is absent or not
// an array. Each element's dynamic type follows the array's element type.
func (in *Instance) Array(key int) ([]any, bool) {
	if x, ok := in.Fields[key].([]any); ok {
		return x, true
	}
	return nil, false
}
