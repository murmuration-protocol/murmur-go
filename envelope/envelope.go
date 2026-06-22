// Package envelope is the signed-envelope signing primitive: an Ed25519
// signature over canonical CBOR claims. This is the verifiable core of the
// signed envelope (spec Section 7.2); the full header-plus-claims envelope and
// the algorithm-tagged identifier wait on their field tables and land here
// when those are pinned.
//
// Two rules from spec Section 7.1 and 7.2 are load-bearing here. A signature
// is verified over the exact bytes received, never over a re-encoding of them.
// And canonicality is a separate gate that runs first: a non-canonical
// artifact is refused outright and never reaches the signature check.
package envelope

import (
	"crypto/ed25519"
	"errors"

	"github.com/murmuration-protocol/murmur-go/cbor"
)

// ErrNonCanonicalClaims is returned when the claims bytes are not canonical
// CBOR. They are rejected before any signature is produced or checked.
var ErrNonCanonicalClaims = errors.New("envelope: claims are not canonical CBOR")

// Sign produces the deterministic Ed25519 signature over canonical claims and
// returns the public key derived from the seed. Ed25519 signing is
// deterministic (RFC 8032), so the signature bytes are reproducible across
// implementations and can be pinned. seed is the 32-byte private seed.
func Sign(seed, claims []byte) (pub, sig []byte, err error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, errors.New("envelope: seed must be 32 bytes")
	}
	if err := gate(claims); err != nil {
		return nil, nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig = ed25519.Sign(priv, claims)
	pub = make([]byte, ed25519.PublicKeySize)
	copy(pub, priv.Public().(ed25519.PublicKey))
	return pub, sig, nil
}

// Verify checks an Ed25519 signature over the exact claims bytes received. The
// canonicality gate runs first: non-canonical claims return
// ErrNonCanonicalClaims and are never verified. A well-formed but wrong
// signature returns (false, nil).
func Verify(pub, claims, sig []byte) (bool, error) {
	if len(pub) != ed25519.PublicKeySize {
		return false, errors.New("envelope: public key must be 32 bytes")
	}
	if err := gate(claims); err != nil {
		return false, err
	}
	return ed25519.Verify(pub, claims, sig), nil
}

// gate is the canonicality check: the claims MUST decode as one canonical CBOR
// map. Anything non-canonical is refused here, before the signature is touched.
func gate(claims []byte) error {
	v, err := cbor.Decode(claims)
	if err != nil {
		return ErrNonCanonicalClaims
	}
	if _, ok := v.(cbor.Map); !ok {
		return errors.New("envelope: claims must be a CBOR map")
	}
	return nil
}
