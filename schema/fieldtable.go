package schema

import (
	"fmt"
	"math/big"

	"github.com/murmuration-protocol/murmur-go/cbor"
)

// ParseFieldTable interprets a field-table artifact, the canonical CBOR a table
// is authored and content-addressed as, and projects it into a FieldTable. This
// is how a node loads a protocol artifact table (envelope, grant, and the rest)
// from its authored bytes rather than transcribing it by hand, the single
// authored source the spec keeps every implementation reading from. The floor
// closure is its own input: parsing the meta-table artifact reproduces the
// meta-table grammar, which is the fixed point.
//
// It interprets against the held meta-table closure, so the registry must hold
// the floor (use DefaultRegistry).
func ParseFieldTable(v cbor.Value, reg *Registry) (FieldTable, error) {
	in, err := Interpret(MetaTable, v, reg)
	if err != nil {
		return FieldTable{}, err
	}
	if err := in.Require(0, 1, 2); err != nil {
		return FieldTable{}, err
	}
	describes, _ := in.Int(0)
	version, _ := in.Int(1)
	dCode, err := toInt(describes, "describes")
	if err != nil {
		return FieldTable{}, err
	}
	ver, err := toInt(version, "version")
	if err != nil {
		return FieldTable{}, err
	}

	rawEntries, _ := in.Array(2)
	entries := make([]Entry, 0, len(rawEntries))
	for i, raw := range rawEntries {
		ei, ok := raw.(*Instance)
		if !ok {
			return FieldTable{}, &Error{Reason: ReasonTypeMismatch, Path: fmt.Sprintf("entries[%d]", i), Msg: "entry is not a nested instance"}
		}
		ent, err := parseEntry(ei, i)
		if err != nil {
			return FieldTable{}, err
		}
		entries = append(entries, ent)
	}
	return FieldTable{Describes: ArtifactType(dCode), Version: ver, Entries: entries}, nil
}

func parseEntry(ei *Instance, idx int) (Entry, error) {
	if err := ei.Require(0, 1, 2, 3); err != nil {
		return Entry{}, err
	}
	keyN, _ := ei.Int(0)
	name, _ := ei.Text(1)
	presN, _ := ei.Int(3)

	key, err := toInt(keyN, "entry key")
	if err != nil {
		return Entry{}, err
	}
	pres, err := toInt(presN, "presence")
	if err != nil {
		return Entry{}, err
	}
	tdInst, ok := ei.Ref(2)
	if !ok {
		return Entry{}, &Error{Reason: ReasonTypeMismatch, Path: fmt.Sprintf("entries[%d].type", idx), Msg: "type is not a type-descriptor instance"}
	}
	td, err := parseTypeDescriptor(tdInst)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Key: key, Name: name, Type: td, Presence: Presence(pres)}, nil
}

func parseTypeDescriptor(ti *Instance) (TypeDescriptor, error) {
	if err := ti.Require(0); err != nil {
		return TypeDescriptor{}, err
	}
	kindN, _ := ti.Int(0)
	kindCode, err := toInt(kindN, "kind")
	if err != nil {
		return TypeDescriptor{}, err
	}
	td := TypeDescriptor{Kind: Kind(kindCode)}

	if ti.Has(1) {
		ofInst, ok := ti.Ref(1)
		if !ok {
			return TypeDescriptor{}, &Error{Reason: ReasonTypeMismatch, Path: "type-descriptor.of", Msg: "of is not a type-descriptor instance"}
		}
		of, err := parseTypeDescriptor(ofInst)
		if err != nil {
			return TypeDescriptor{}, err
		}
		td.Of = &of
	}
	if ti.Has(2) {
		refN, _ := ti.Int(2)
		refCode, err := toInt(refN, "ref")
		if err != nil {
			return TypeDescriptor{}, err
		}
		td.Ref = ArtifactType(refCode)
	}
	if ti.Has(3) {
		unitN, _ := ti.Int(3)
		unit, err := toInt(unitN, "unit")
		if err != nil {
			return TypeDescriptor{}, err
		}
		td.Unit = unit
	}
	return td, nil
}

// toInt narrows a wire integer to a native int for a code or key, refusing one
// that does not fit. Codes and keys are small by construction; an out-of-range
// value is malformed, not merely large.
func toInt(n *big.Int, what string) (int, error) {
	if n == nil || !n.IsInt64() {
		return 0, &Error{Reason: ReasonMalformedDescriptor, Msg: fmt.Sprintf("%s is out of range", what)}
	}
	v := n.Int64()
	if int64(int(v)) != v {
		return 0, &Error{Reason: ReasonMalformedDescriptor, Msg: fmt.Sprintf("%s is out of range", what)}
	}
	return int(v), nil
}
