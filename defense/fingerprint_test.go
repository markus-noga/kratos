// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package defense_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/identity"
	sqlidentity "github.com/ory/kratos/persistence/sql/identity"
)

func TestFingerprinter(t *testing.T) {
	t.Parallel()

	f := defense.NewFingerprinter([]byte("secret-secret-secret"))

	t.Run("case=identifier is canonicalized", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, f.Identifier("alice@example.com"), f.Identifier("  Alice@Example.COM "))
		assert.Equal(t, f.Identifier("ﬁle@example.com"), f.Identifier("file@example.com"), "NFKC")
		assert.NotEqual(t, f.Identifier("alice@example.com"), f.Identifier("bob@example.com"))
	})

	t.Run("case=every variant that finds the same identity shares its digest", func(t *testing.T) {
		t.Parallel()
		// The oracle is the lookup's own normalization, for each credential type
		// whose identifier the client types. A variant it maps to the same identity
		// but the defense to another digest would get a fresh failure budget for
		// that identity: one per invisible rune inserted anywhere. (The lookup also
		// matches the raw identifier, for identifiers stored before normalization.)
		var variants []string
		for _, base := range []string{"victim@example.com", "+49 170 1234567", "some.user"} {
			variants = append(variants, base, strings.ToUpper(base), " "+base+"\t")
			for _, r := range []rune{'\u200b', '\u00ad', '\u200d', '\u2060', '\ufeff', '\u202e', '\u2066'} {
				for i := range base {
					variants = append(variants, base[:i]+string(r)+base[i:])
				}
			}
		}
		variants = append(variants, "ｖｉｃｔｉｍ＠ｅｘａｍｐｌｅ．ｃｏｍ", "+491701234567", "+49-170-123 4567", "+49 (170) 1234567")
		digests := make([]defense.Digest, len(variants))
		for i, v := range variants {
			digests[i] = f.Identifier(v)
		}

		for _, ct := range []identity.CredentialsType{identity.CredentialsTypePassword, identity.CredentialsTypeCodeAuth, identity.CredentialsTypeWebAuthn} {
			lookup := make([]string, len(variants))
			for i, v := range variants {
				lookup[i] = sqlidentity.NormalizeIdentifier(ct, v)
			}
			var split []string
			for i := range variants {
				for j := i + 1; j < len(variants); j++ {
					if lookup[i] == lookup[j] && digests[i] != digests[j] {
						split = append(split, fmt.Sprintf("%+q and %+q", variants[i], variants[j]))
					}
				}
			}
			if len(split) > 0 {
				t.Errorf("%s: %d pairs of variants find the same identity but have different digests, e.g. %s",
					ct, len(split), strings.Join(split[:min(3, len(split))], "; "))
			}
		}
	})

	t.Run("case=an identifier over the bound is neither normalized nor truncated", func(t *testing.T) {
		t.Parallel()
		// Normalizing runs before the defense decides: its cost must not be the client's choice.
		const victim = "victim@example.com"
		atBound := victim + strings.Repeat(" ", defense.MaxIdentifierLength-len(victim))
		assert.Equal(t, victim, defense.Canonicalize(atBound))

		// Truncated, a run of dropped runes could hide any identifier behind it, or make it one.
		over := []string{
			atBound + " ",
			strings.Repeat("\u200b", defense.MaxIdentifierLength) + victim,
			victim + strings.Repeat("\u200b", defense.MaxIdentifierLength),
			strings.Repeat("a", 1<<20),
		}
		oversized := defense.Canonicalize(over[0])
		assert.NotEqual(t, victim, oversized)
		for _, id := range over {
			assert.Equal(t, oversized, defense.Canonicalize(id), "one canonical form for all")
			assert.Equal(t, f.Identifier(over[0]), f.Identifier(id), "one digest for all")
		}
		assert.NotEqual(t, f.Identifier(victim), f.Identifier(over[0]))
		assert.NotEqual(t, oversized, defense.Canonicalize(oversized), "no identifier within the bound has it")
	})

	t.Run("case=credential is not canonicalized", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, f.Credential("Password"), f.Credential("password"))
		assert.NotEqual(t, f.Credential(" password"), f.Credential("password"))
	})

	t.Run("case=subkeys are separate", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, f.Identifier("same"), f.Credential("same"))
	})

	t.Run("case=a scope never collides with an identifier", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, f.Identifier("google"), f.Scope("google"), "whatever a client types as an identifier")
		assert.NotEqual(t, f.Credential("google"), f.Scope("google"))
		assert.Equal(t, f.Scope("google"), f.Scope("google"))
		assert.NotEqual(t, f.Scope("google"), f.Scope("Google"), "provider ids are exact, not canonicalized")
		assert.False(t, f.Scope("google").IsZero())
	})

	t.Run("case=key matters", func(t *testing.T) {
		t.Parallel()
		other := defense.NewFingerprinter([]byte("another-secret-key"))
		assert.NotEqual(t, f.Identifier("alice"), other.Identifier("alice"))
		assert.False(t, f.Identifier("alice").IsZero())
	})
}

func TestParseIP(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]netip.Addr{
		"192.0.2.1":          netip.MustParseAddr("192.0.2.1"),
		"192.0.2.1:4711":     netip.MustParseAddr("192.0.2.1"),
		"[2001:db8::1]:443":  netip.MustParseAddr("2001:db8::1"),
		"2001:db8::1":        netip.MustParseAddr("2001:db8::1"),
		"::ffff:192.0.2.1":   netip.MustParseAddr("192.0.2.1"),
		"fe80::1%eth0":       netip.MustParseAddr("fe80::1"),
		" 192.0.2.1 ":        netip.MustParseAddr("192.0.2.1"),
		"":                   {},
		"not-an-ip":          {},
		"192.0.2.1, 1.1.1.1": {},
	} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, defense.ParseIP(in))
		})
	}
}

func TestMethodID(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "password", defense.MethodPassword.String())
	assert.Equal(t, "app_password", defense.MethodAppPassword.String())
	assert.Equal(t, "unknown", defense.MethodID(200).String())
	names := map[string]defense.MethodID{}
	for m := defense.MethodUnknown; m < defense.NumMethods; m++ {
		assert.NotEmpty(t, m.String())
		other, dup := names[m.String()]
		assert.False(t, dup, "%d and %d are both %q", m, other, m.String())
		names[m.String()] = m
	}
}

func TestDeviceState(t *testing.T) {
	t.Parallel()
	assert.Equal(t, defense.DeviceNone, defense.Attempt{}.Device, "absent cookie is the zero value")
	assert.Equal(t, "none", defense.DeviceNone.String())
	assert.Equal(t, "invalid", defense.DeviceInvalid.String())
	assert.Equal(t, "known", defense.DeviceKnown.String())
	assert.Equal(t, "invalid", defense.DeviceState(99).String())
}
