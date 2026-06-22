// Package schema is the interpretation layer above cbor. The cbor codec turns
// bytes into a structural Value with no meaning; this package gives those bytes
// meaning by applying a field table, the wire schema of an artifact type.
//
// It follows the spec's "decode, then validate" split (canonical-encoding.md).
// Interpret binds integer wire keys to named fields, type-checks each value
// against its type-descriptor, resolves ref fields by artifact-type code
// against the held tables, and reads a two-element integer array as a decimal
// or rational where the schema says so. It does NOT enforce presence: a missing
// field is not a malformed encoding, and required-ness is scoped to an action
// and a role, so an actor enforces it with Instance.Require for what its own
// action needs.
//
// The floor closure (field-table, entry, type-descriptor) is the grammar a node
// is born knowing, so it is held here as Go values rather than fetched. The
// protocol artifact tables (envelope, grant, and the rest) are loaded from their
// canonical artifacts with ParseFieldTable once the spec pins them.
package schema

import "fmt"

// Kind is a type-descriptor's kind code (canonical-encoding.md, "Pinned
// codes"). The codes are append-only.
type Kind int

const (
	KindInt      Kind = 0
	KindBytes    Kind = 1
	KindText     Kind = 2
	KindBool     Kind = 3
	KindDecimal  Kind = 4
	KindRational Kind = 5
	KindArray    Kind = 6
	KindRef      Kind = 7
)

// Presence is a field's declared presence code. It is boolean-aligned (required
// is the truthy value) but an extensible enum, with room for codes such as
// required-to-act. It is a declared property of the field; enforcement is the
// acting party's, via Instance.Require.
type Presence int

const (
	PresenceOptional Presence = 0
	PresenceRequired Presence = 1
)

// ArtifactType is the code a field table is the grammar for, and the code a ref
// names. The floor closure occupies 0 to 2; the protocol artifact types run
// from 3; 1024 and above is the reserved private range.
type ArtifactType int

const (
	ArtifactFieldTable           ArtifactType = 0
	ArtifactEntry                ArtifactType = 1
	ArtifactTypeDescriptor       ArtifactType = 2
	ArtifactEnvelope             ArtifactType = 3
	ArtifactIdentifier           ArtifactType = 4
	ArtifactGrant                ArtifactType = 5
	ArtifactDelegation           ArtifactType = 6
	ArtifactCapabilityDefinition ArtifactType = 7
	ArtifactSafeStateDefinition  ArtifactType = 8
	ArtifactStewardSchema        ArtifactType = 9
	ArtifactDiscoveryRecord      ArtifactType = 10

	// PrivateRangeStart is the first code reserved for a custom protocol.
	PrivateRangeStart ArtifactType = 1024
)

// TypeDescriptor is a field's type: a kind, plus the extra a kind needs. Of is
// the element type when Kind is KindArray; Ref is the artifact-type code of the
// nested table when Kind is KindRef; Unit is the unit-vocabulary code when Kind
// is KindDecimal or KindRational. The unused fields are nil or zero.
type TypeDescriptor struct {
	Kind Kind
	Of   *TypeDescriptor // element type, when Kind == KindArray
	Ref  ArtifactType    // nested artifact type, when Kind == KindRef
	Unit int             // unit code, when Kind == KindDecimal or KindRational
}

// Entry is one field of a field table: its wire key, its authoring-surface
// name (never on the wire), its type, and its declared presence.
type Entry struct {
	Key      int
	Name     string
	Type     TypeDescriptor
	Presence Presence
}

// FieldTable is the wire schema of one artifact type at one format version: a
// flat list of entries. Describes is the artifact-type code it is the grammar
// for, Version is the format version it belongs to.
type FieldTable struct {
	Describes ArtifactType
	Version   int
	Entries   []Entry
}

// entryByKey returns the entry with the given wire key, or false if the table
// has no such field.
func (t FieldTable) entryByKey(key int) (Entry, bool) {
	for _, e := range t.Entries {
		if e.Key == key {
			return e, true
		}
	}
	return Entry{}, false
}

// RequiredKeys lists the wire keys the table declares required. It is the
// declared presence, a default an actor may tighten or relax for its own
// action; it is not enforced by Interpret.
func (t FieldTable) RequiredKeys() []int {
	var out []int
	for _, e := range t.Entries {
		if e.Presence == PresenceRequired {
			out = append(out, e.Key)
		}
	}
	return out
}

// Registry holds the field tables a node ships, keyed by artifact type and
// format version. A ref resolves against it by code at the artifact's version.
// Tables are held, never fetched to decide authority.
type Registry struct {
	tables map[regKey]FieldTable
}

type regKey struct {
	typ     ArtifactType
	version int
}

// NewRegistry returns an empty registry. Most callers want DefaultRegistry,
// which is seeded with the floor closure.
func NewRegistry() *Registry {
	return &Registry{tables: make(map[regKey]FieldTable)}
}

// Add registers a table under its own Describes code and Version. It panics on
// a duplicate, since a node holds exactly one table per (type, version).
func (r *Registry) Add(t FieldTable) {
	k := regKey{t.Describes, t.Version}
	if _, ok := r.tables[k]; ok {
		panic(fmt.Sprintf("schema: duplicate table for type %d version %d", t.Describes, t.Version))
	}
	r.tables[k] = t
}

// Lookup returns the table for an artifact type at a format version.
func (r *Registry) Lookup(typ ArtifactType, version int) (FieldTable, bool) {
	t, ok := r.tables[regKey{typ, version}]
	return t, ok
}
