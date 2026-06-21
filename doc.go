// Package murmur is the root of the Murmur conformance oracle.
//
// The oracle is the independent second implementation of the Murmur wire
// contract. A canonical encoding proven by a single implementation is
// unfalsifiable, so murmur-go exists to run the shared conformance vectors and
// cross-check them against the Rust reference implementation.
//
// Its scope is narrow and deliberate: canonical CBOR encode and decode,
// SHA-256 content-addressing, signed-envelope verification, and rejection of
// non-canonical encodings on receipt. Zenoh, MIDI, discovery, the daemon, and
// the bridge are out of scope and live in murmur-rs.
//
// The conformance vectors are normative spec artifacts. They live in the spec
// repository, not here.
package murmur
