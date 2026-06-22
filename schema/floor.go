package schema

// The floor closure: the three field tables a node is born knowing, held as Go
// values rather than fetched (canonical-encoding.md, "The floor is shipped, not
// fetched"). The meta-table describes a field table, the entry table describes
// one entry, and the type-descriptor table describes a field's type. The three
// reference one another, and themselves, by artifact-type code, so the set
// decodes itself and nothing outside it is needed.
//
// These transcriptions are checked against their canonical artifacts by the
// fixed-point test: ParseFieldTable applied to the pinned closure bytes must
// reproduce exactly these values. A transcription error is caught there.

// scalar is a type-descriptor that is a kind alone.
func scalar(k Kind) TypeDescriptor { return TypeDescriptor{Kind: k} }

// ref is a type-descriptor naming a nested table by artifact-type code.
func ref(t ArtifactType) TypeDescriptor { return TypeDescriptor{Kind: KindRef, Ref: t} }

// arrayOf is a type-descriptor for an array with the given element type.
func arrayOf(elem TypeDescriptor) TypeDescriptor {
	return TypeDescriptor{Kind: KindArray, Of: &elem}
}

// MetaTable is the field table that describes a field table (artifact type 0).
// A field table is a map of three fields: describes, version, and entries.
var MetaTable = FieldTable{
	Describes: ArtifactFieldTable,
	Version:   1,
	Entries: []Entry{
		{Key: 0, Name: "describes", Type: scalar(KindInt), Presence: PresenceRequired},
		{Key: 1, Name: "version", Type: scalar(KindInt), Presence: PresenceRequired},
		{Key: 2, Name: "entries", Type: arrayOf(ref(ArtifactEntry)), Presence: PresenceRequired},
	},
}

// EntryTable is the field table for one field-table entry (artifact type 1). An
// entry is a map of four: key, name, type, and presence.
var EntryTable = FieldTable{
	Describes: ArtifactEntry,
	Version:   1,
	Entries: []Entry{
		{Key: 0, Name: "key", Type: scalar(KindInt), Presence: PresenceRequired},
		{Key: 1, Name: "name", Type: scalar(KindText), Presence: PresenceRequired},
		{Key: 2, Name: "type", Type: ref(ArtifactTypeDescriptor), Presence: PresenceRequired},
		{Key: 3, Name: "presence", Type: scalar(KindInt), Presence: PresenceRequired},
	},
}

// TypeDescriptorTable is the field table for a field's type (artifact type 2).
// It is a small recursive descriptor: kind always, then of (the element type)
// when kind is array, ref (the nested artifact type) when kind is ref, and unit
// when kind is decimal or rational. The three trailing fields are optional and
// used by kind.
var TypeDescriptorTable = FieldTable{
	Describes: ArtifactTypeDescriptor,
	Version:   1,
	Entries: []Entry{
		{Key: 0, Name: "kind", Type: scalar(KindInt), Presence: PresenceRequired},
		{Key: 1, Name: "of", Type: ref(ArtifactTypeDescriptor), Presence: PresenceOptional},
		{Key: 2, Name: "ref", Type: scalar(KindInt), Presence: PresenceOptional},
		{Key: 3, Name: "unit", Type: scalar(KindInt), Presence: PresenceOptional},
	},
}

// DefaultRegistry returns a registry seeded with the floor closure. A protocol
// artifact table, once pinned in the spec, is added on top with Add or loaded
// from its canonical artifact with ParseFieldTable.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Add(MetaTable)
	r.Add(EntryTable)
	r.Add(TypeDescriptorTable)
	return r
}
