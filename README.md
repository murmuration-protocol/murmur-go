# murmur-go

The conformance oracle for the Murmur protocol. It is not a daemon.

A canonical encoding proven by a single implementation is unfalsifiable: it only ever agrees with itself. `murmur-go` is the independent second implementation. It runs the shared conformance vectors and cross-checks them against the Rust reference (`murmur-rs`), so the wire contract is established by agreement between two codebases rather than asserted by one.

## Scope

In scope:

- Canonical CBOR encode and decode, against the deterministic profile the spec pins.
- SHA-256 content-addressing of the definition artifacts.
- Verification of the signed envelope: canonical CBOR claims, an Ed25519 signature, a minimal header.
- Rejection of non-canonical encodings on receipt. Exactly one byte form is valid.
- Running the shared conformance vectors, plus the cross-test in both directions (Rust signs and Go verifies, then the reverse), byte-identical.

Out of scope, and staying that way: Zenoh, MIDI, discovery, the daemon, the bridge. Those live in `murmur-rs`.

## Dependencies

Standard library, with one sanctioned exception. Ed25519 comes from `crypto/ed25519` and SHA-256 from `crypto/sha256`. The canonical CBOR codec is a small owned module, not a third-party dependency. That keeps the oracle an independent witness rather than a wrapper around someone else's encoder.

The one exception is `golang.org/x/text/unicode/norm`, used to enforce that text strings are in Normalization Form C. NFC needs the Unicode tables, the module is Go-team owned in the `golang.org/x` extended-standard-library namespace, and shipping our own normalization tables would be the larger risk. Any dependency beyond that is treated as a design error.

## Relationship to the other repos

- `spec` holds the normative contract and the conformance vectors. Vectors are data, not code, so they ship with the spec, not here.
- `murmur-rs` is the Rust reference implementation: the daemon (`murmurd`) and the bridge. The two implementations run the same vectors and verify each other.

## Status

v1. The oracle runs the full conformance corpus: canonical CBOR encode and decode with rejection of non-canonical forms, SHA-256 content-addressing (including the meta-table closure fixed point), and the Ed25519 signing primitive over canonical claims.

Deferred until their spec field tables or their counterpart implementation land:

- Full-envelope and identifier verify, which wait on the envelope-header and identifier field tables.
- The cross-test against `murmur-rs` (rust signs, go verifies, and the reverse), which waits on `murmur-rs`.

## Layout

- `cbor` is the owned canonical CBOR codec: the value model, encode, decode, and canonical enforcement. It is reused by the later authoring compiler, so it carries no oracle-specific coupling.
- `contentid` is SHA-256 over canonical bytes.
- `envelope` is the Ed25519 verify of the signing primitive, with a canonicality gate ahead of the signature check.
- `conformance` is the vector types, the tagged-JSON value parser, and the runner; `conformance_test.go` runs the corpus.

## Build and test

```
go vet ./...
go test ./...
```

The vectors live in the sibling `spec` repo. `go test` defaults to `../../spec/vectors`, relative to the `conformance` package, and honours `MURMUR_VECTORS` to point elsewhere (CI checks out `spec` separately and sets it). The module targets the Go 1.26 series.

## Licence

Apache-2.0. See `LICENSE`. Contributions are sign-off only (DCO): commit with `git commit -s`.
