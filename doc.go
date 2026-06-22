// Package murmur is the root of the Murmur conformance oracle.
//
// The oracle is the independent second implementation of the Murmur wire
// contract. A canonical encoding proven by a single implementation is
// unfalsifiable, so murmur-go exists to run the shared conformance vectors and
// cross-check them against the Rust reference implementation.
//
// Its scope is narrow and deliberate: canonical CBOR encode and decode,
// SHA-256 content-addressing, the Ed25519 signing primitive over canonical
// claims, and rejection of non-canonical encodings on receipt. Full-envelope
// and identifier verify wait on their spec field tables; the cross-test waits
// on murmur-rs. Zenoh, MIDI, discovery, the daemon, and the bridge are out of
// scope and live in murmur-rs.
//
// Dependencies are the standard library plus one sanctioned exception,
// golang.org/x/text/unicode/norm, for Normalization Form C enforcement on text
// strings. NFC needs the Unicode tables; the module is Go-team owned in the
// golang.org/x extended-standard-library namespace; shipping our own tables
// would be the larger risk. Anything beyond that is a design error.
//
// The conformance vectors are normative spec artifacts. They live in the spec
// repository, not here.
package murmur
