// Package conformance loads the shared vectors from the spec repo and runs
// them against the oracle's codec, content-addressing, and envelope primitive.
// The vectors are the language-neutral contract; this package is one party to
// it. The dispatch is by the vector's own `kind`, with no manifest: a runner
// globs the tree.
package conformance

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/murmuration-protocol/murmur-go/cbor"
	"github.com/murmuration-protocol/murmur-go/contentid"
	"github.com/murmuration-protocol/murmur-go/envelope"
	"github.com/murmuration-protocol/murmur-go/schema"
)

// Vector is one self-describing fixture. The header fields come first; the
// kind-specific fields below are populated only for their kind.
type Vector struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Spec        string `json:"spec"`

	// encode
	Value json.RawMessage `json:"value"`
	Cbor  string          `json:"cbor"`

	// content-id
	Sha256 string `json:"sha256"`

	// envelope
	Seed       string `json:"seed"`
	ClaimsCbor string `json:"claims_cbor"`
	PublicKey  string `json:"public_key"`
	Signature  string `json:"signature"`
	Valid      *bool  `json:"valid"`

	// reject
	Bytes  string `json:"bytes"`
	Reason string `json:"reason"`

	// schema-reject
	InterpretAs *int `json:"interpret_as"` // pointer so artifact-type code 0 is distinct from absent
}

// Load reads and parses one vector file.
func Load(path string) (*Vector, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Vector
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &v, nil
}

// Files globs the vector tree for every *.json fixture.
func Files(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".json" {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// Check runs one vector and returns nil on conformance or an error describing
// the disagreement.
func (v *Vector) Check() error {
	switch v.Kind {
	case "encode":
		return v.checkEncode()
	case "content-id":
		return v.checkContentID()
	case "envelope-sign":
		return v.checkEnvelopeSign()
	case "envelope-verify":
		return v.checkEnvelopeVerify()
	case "reject":
		return v.checkReject()
	case "schema-reject":
		return v.checkSchemaReject()
	default:
		return fmt.Errorf("unknown kind %q", v.Kind)
	}
}

func (v *Vector) checkEncode() error {
	want, err := hex.DecodeString(v.Cbor)
	if err != nil {
		return fmt.Errorf("bad cbor hex: %w", err)
	}
	// value to bytes: the parsed logical value encodes to exactly the pinned bytes.
	val, err := parseValue(v.Value)
	if err != nil {
		return fmt.Errorf("parsing value: %w", err)
	}
	got, err := cbor.Encode(val)
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if hex.EncodeToString(got) != v.Cbor {
		return fmt.Errorf("encode mismatch: got %s, want %s", hex.EncodeToString(got), v.Cbor)
	}
	// bytes to value: the pinned bytes decode, and re-encode to the same bytes,
	// so decoding is the exact inverse on a canonical artifact.
	dec, err := cbor.Decode(want)
	if err != nil {
		return fmt.Errorf("decoding pinned cbor: %w", err)
	}
	re, err := cbor.Encode(dec)
	if err != nil {
		return fmt.Errorf("re-encoding decoded value: %w", err)
	}
	if hex.EncodeToString(re) != v.Cbor {
		return fmt.Errorf("round-trip mismatch: got %s, want %s", hex.EncodeToString(re), v.Cbor)
	}
	return nil
}

func (v *Vector) checkContentID() error {
	b, err := hex.DecodeString(v.Cbor)
	if err != nil {
		return fmt.Errorf("bad cbor hex: %w", err)
	}
	// The bytes must be canonical, and must reproduce byte-identically through
	// a decode/encode cycle. This is the meta-table fixed point for the closure
	// vectors: a Go decoder agreeing with those bytes is the second-language proof.
	dec, err := cbor.Decode(b)
	if err != nil {
		return fmt.Errorf("decoding cbor: %w", err)
	}
	re, err := cbor.Encode(dec)
	if err != nil {
		return fmt.Errorf("re-encoding: %w", err)
	}
	if hex.EncodeToString(re) != v.Cbor {
		return fmt.Errorf("not canonical: re-encoded to %s, want %s", hex.EncodeToString(re), v.Cbor)
	}
	sum := contentid.Sum(b)
	if hex.EncodeToString(sum[:]) != v.Sha256 {
		return fmt.Errorf("content-id mismatch: got %s, want %s", hex.EncodeToString(sum[:]), v.Sha256)
	}
	return nil
}

func (v *Vector) checkEnvelopeSign() error {
	seed, err := hex.DecodeString(v.Seed)
	if err != nil {
		return fmt.Errorf("bad seed hex: %w", err)
	}
	claims, err := hex.DecodeString(v.ClaimsCbor)
	if err != nil {
		return fmt.Errorf("bad claims hex: %w", err)
	}
	pub, sig, err := envelope.Sign(seed, claims)
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}
	if hex.EncodeToString(pub) != v.PublicKey {
		return fmt.Errorf("public key mismatch: got %s, want %s", hex.EncodeToString(pub), v.PublicKey)
	}
	if hex.EncodeToString(sig) != v.Signature {
		return fmt.Errorf("signature mismatch: got %s, want %s", hex.EncodeToString(sig), v.Signature)
	}
	return nil
}

func (v *Vector) checkEnvelopeVerify() error {
	if v.Valid == nil {
		return fmt.Errorf("envelope-verify vector missing `valid`")
	}
	pub, err := hex.DecodeString(v.PublicKey)
	if err != nil {
		return fmt.Errorf("bad public key hex: %w", err)
	}
	claims, err := hex.DecodeString(v.ClaimsCbor)
	if err != nil {
		return fmt.Errorf("bad claims hex: %w", err)
	}
	sig, err := hex.DecodeString(v.Signature)
	if err != nil {
		return fmt.Errorf("bad signature hex: %w", err)
	}
	ok, err := envelope.Verify(pub, claims, sig)
	if *v.Valid {
		if err != nil {
			return fmt.Errorf("expected valid, got error: %w", err)
		}
		if !ok {
			return fmt.Errorf("expected valid, signature did not verify")
		}
		return nil
	}
	// A negative case must not verify; a non-canonical-claims error also counts
	// as a refusal.
	if ok {
		return fmt.Errorf("expected invalid, but signature verified")
	}
	return nil
}

func (v *Vector) checkReject() error {
	b, err := hex.DecodeString(v.Bytes)
	if err != nil {
		return fmt.Errorf("bad bytes hex: %w", err)
	}
	_, err = cbor.Decode(b)
	if err == nil {
		return fmt.Errorf("expected rejection (%s), but decode succeeded", v.Reason)
	}
	de, ok := err.(*cbor.DecodeError)
	if !ok {
		return fmt.Errorf("expected a *cbor.DecodeError, got %T: %v", err, err)
	}
	if string(de.Reason) != v.Reason {
		return fmt.Errorf("reason mismatch: got %q, want %q", de.Reason, v.Reason)
	}
	return nil
}

// checkSchemaReject runs a schema-reject vector: canonical CBOR that decodes
// clean but does not match the field table its type declares. The byte decoder
// MUST accept it (a decode failure means the fixture belongs in reject/, so
// that is a loud failure, not a pass), and interpretation against the table
// MUST refuse it with the named artifact-determined reason.
func (v *Vector) checkSchemaReject() error {
	if v.InterpretAs == nil {
		return fmt.Errorf("schema-reject vector missing `interpret_as`")
	}
	// The harness routes interpret_as 0 (the field-table type) through
	// ParseFieldTable, the floor's own interpreter. The pinned schema-reject
	// vectors all exercise the floor, so a different code has no table to route
	// to yet and is a fixture error.
	if *v.InterpretAs != int(schema.ArtifactFieldTable) {
		return fmt.Errorf("interpret_as %d is not yet routable; only the field-table type (0) is pinned", *v.InterpretAs)
	}
	b, err := hex.DecodeString(v.Cbor)
	if err != nil {
		return fmt.Errorf("bad cbor hex: %w", err)
	}
	decoded, err := cbor.Decode(b)
	if err != nil {
		return fmt.Errorf("schema-reject bytes must decode (a byte refusal belongs in reject/): %w", err)
	}
	_, err = schema.ParseFieldTable(decoded, schema.DefaultRegistry())
	if err == nil {
		return fmt.Errorf("expected interpretation to refuse (%s), but it succeeded", v.Reason)
	}
	se, ok := err.(*schema.Error)
	if !ok {
		return fmt.Errorf("expected a *schema.Error, got %T: %v", err, err)
	}
	if string(se.Reason) != v.Reason {
		return fmt.Errorf("reason mismatch: got %q, want %q", se.Reason, v.Reason)
	}
	return nil
}
