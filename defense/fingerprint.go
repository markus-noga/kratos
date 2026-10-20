// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package defense

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net/netip"
	"strings"

	"golang.org/x/crypto/hkdf"

	// One normalization for the identity lookup and the defense, so that they agree on what is one account.
	"github.com/ory/kratos/x"
)

// Fingerprinter derives the digests carried by Attempt. Identifier, scope and
// credential digests use separate HKDF subkeys, so they can never be confused
// or correlated.
type Fingerprinter struct {
	identifierKey, scopeKey, credentialKey []byte
}

// NewFingerprinter derives the subkeys from secret.
func NewFingerprinter(secret []byte) *Fingerprinter {
	derive := func(info string) []byte {
		k := make([]byte, sha256.Size)
		// HKDF-SHA256 yields up to 255*32 bytes, so reading 32 cannot fail.
		_, _ = io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte(info)), k)
		return k
	}
	return &Fingerprinter{
		identifierKey: derive("ory/kratos/defense/identifier"),
		scopeKey:      derive("ory/kratos/defense/scope"),
		credentialKey: derive("ory/kratos/defense/credential"),
	}
}

// Identifier returns the digest of the canonicalized identifier.
func (f *Fingerprinter) Identifier(identifier string) Digest {
	return f.CanonicalIdentifier(Canonicalize(identifier))
}

// CanonicalIdentifier returns the digest of an identifier in canonical form, as
// Canonicalize returns it: for a caller that needs that form too, so that the
// costliest step is done once.
func (f *Fingerprinter) CanonicalIdentifier(canonical string) Digest {
	return mac(f.identifierKey, canonical)
}

// Scope returns the digest of the name of something that is not an account, such
// as an identity provider. It lives in its own digest space: whatever a client
// types as an identifier, it can never collide with, and so never count against,
// a scope.
func (f *Fingerprinter) Scope(name string) Digest {
	return mac(f.scopeKey, name)
}

// Credential returns the digest of a submitted secret, byte for byte.
func (f *Fingerprinter) Credential(secret string) Digest {
	return mac(f.credentialKey, secret)
}

func mac(key []byte, s string) (d Digest) {
	h := hmac.New(sha256.New, key)
	_, _ = io.WriteString(h, s)
	h.Sum(d[:0])
	return d
}

// MaxIdentifierLength is the longest identifier, in bytes, that Canonicalize
// normalizes. Normalizing runs before the defense decides and costs far more
// than the rest of a check, so its cost must not be the client's choice.
// Identifiers of identities are far shorter.
const MaxIdentifierLength = 4 << 10

// oversized is the canonical form of every longer identifier, so that they all
// share one digest. Canonicalization drops control characters, so no identifier
// within the bound has it.
const oversized = "\x00oversized"

// Canonicalize normalizes an identifier as Kratos does before it looks an
// identity up (x.GracefulNormalization: invisible and bidi characters dropped,
// NFKC, width folded, lowercased, phone numbers in E.164), so that every variant
// that finds one identity shares its counters. A weaker normalization would give
// each variant, e.g. one zero-width space more, a fresh failure budget.
//
// An identifier over MaxIdentifierLength is neither normalized nor truncated, as
// a run of dropped runes could hide any identifier behind the cut: all of them
// have one canonical form, and with it one failure budget.
func Canonicalize(identifier string) string {
	if len(identifier) > MaxIdentifierLength {
		return oversized
	}
	return x.GracefulNormalization(identifier)
}

// ParseIP parses a client address, with or without port, and unmaps
// IPv4-mapped IPv6 addresses. It returns the zero Addr if s is not an address.
func ParseIP(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}
