// Package contentid is content-addressing: the SHA-256 of an artifact's
// canonical bytes is its identity (spec Section 7.2). The hash is always taken
// over the canonical byte form, never over a logical value, so two
// implementations name the same artifact the same way.
package contentid

import "crypto/sha256"

// Sum returns the SHA-256 content address of already-canonical CBOR bytes. The
// caller is responsible for having produced or verified the canonical form;
// content-addressing does not re-encode.
func Sum(canonical []byte) [32]byte {
	return sha256.Sum256(canonical)
}
