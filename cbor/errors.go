package cbor

import "fmt"

// Reason names why a decoder refused an artifact. The strings are the refusal
// vocabulary defined in the spec repo's canonical-encoding.md ("Refusal
// reasons"); the byte-determined ones match the `reason` field of the reject
// vectors, so a refusal is checkable against the fixture that pins it.
type Reason string

// Byte-determined reasons are a function of the bytes alone, so the same input
// yields the same reason on every conformant decoder, and a vector pins it.
const (
	ReasonNonMinimal         Reason = "non-minimal"         // a head longer than the shortest that holds its argument (value, length, or count)
	ReasonIndefiniteLength   Reason = "indefinite-length"   // indefinite length or break stop
	ReasonTrailingBytes      Reason = "trailing-bytes"      // a second data item rides behind the first
	ReasonDuplicateMapKey    Reason = "duplicate-map-key"   // the same key encoded twice
	ReasonUnsortedMapKeys    Reason = "unsorted-map-keys"   // keys not in ascending bytewise order
	ReasonMixedMapKeys       Reason = "mixed-map-keys"      // a map mixing integer and text keys
	ReasonBadMapKeyType      Reason = "bad-map-key-type"    // a key that is not an integer or text
	ReasonTag                Reason = "tag"                 // a CBOR tag (major type 6)
	ReasonFloat              Reason = "float"               // a floating-point value
	ReasonNull               Reason = "null"                // null or undefined
	ReasonSimpleValue        Reason = "simple-value"        // a major-type-7 value other than true or false
	ReasonReservedAdditional Reason = "reserved-additional" // additional info 28, 29, or 30
	ReasonTruncated          Reason = "truncated"           // the input ended mid-item
	ReasonInvalidUTF8        Reason = "invalid-utf8"        // a text string that is not valid UTF-8
	ReasonByteOrderMark      Reason = "byte-order-mark"     // a text string carrying a BOM
	ReasonNonNFC             Reason = "non-nfc"             // a text string not in Normalization Form C
)

// Limit-relative reasons are triggered by a bound this decoder declares, not by
// the bytes alone, so two conformant decoders with different bounds may
// disagree. They are not pinned for cross-implementation reason-equality.
const (
	ReasonDepthExceeded Reason = "depth-exceeded" // nesting past the declared bound
	ReasonSizeExceeded  Reason = "size-exceeded"  // more items or bytes than the declared bound
)

// DecodeError is a refusal to decode a non-canonical or malformed artifact. A
// decoder rejects rather than re-encoding to compare; Reason says why and Pos
// is the byte offset where the violation was found.
type DecodeError struct {
	Reason Reason
	Pos    int
	Msg    string
}

func (e *DecodeError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("cbor: %s at byte %d: %s", e.Reason, e.Pos, e.Msg)
	}
	return fmt.Sprintf("cbor: %s at byte %d", e.Reason, e.Pos)
}

// EncodeError is a refusal to encode a value that has no canonical form, such
// as an integer outside the wire range or a non-reduced rational.
type EncodeError struct{ Msg string }

func (e *EncodeError) Error() string { return "cbor: " + e.Msg }
