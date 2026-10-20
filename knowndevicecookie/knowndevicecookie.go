// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package knowndevicecookie issues and validates the KnownDeviceCookie: a
// long-lived cookie, set after a successful login, that tells the attack
// defense a request comes from a device which has logged in to this account
// before.
//
// The cookie is signed, not encrypted, and holds no address. It has up to
// MaxEntries independent entries, one per account used on the device. Each
// carries a pseudonym of the canonicalized identifier, next to its issue time
// and an HMAC over both. The pseudonym is a keyed hash: whoever reads the
// cookie, on the device or in a proxy's log, learns no address from it, and
// cannot test a guess against it without the secret. Validation needs a few
// HMACs and no database access, and can run before defense.Defense.BeforeAttempt.
// An entry is bound to the identifier it was issued for and to the cookie name.
//
// Verification cost and cookie size are bounded whatever a client sends: a
// value over MaxValueLength or with more than MaxEntries entries is rejected
// before any crypto, and Verify computes at most MaxEntries HMACs per secret.
//
// Keys are derived with HKDF-SHA256 from the configured secrets, one for the
// MAC and one for the pseudonym of each. The first secret signs, all of them
// verify, so secrets rotate by prepending a new one. Because the cookie
// outlives session cookies by far, an old secret must stay listed for as long as
// its cookies should keep working: the lifespan plus the rotation window.
// Dropping it makes those cookies fail verification, and the defense sees a
// forged cookie (defense.DeviceInvalid: stricter limits) until the user's next
// login replaces it. A cookie of a dropped secret cannot be told from a forged
// one.
package knowndevicecookie

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/kratos/defense"
)

const (
	// DefaultName is the cookie name used when Config.Name is empty.
	DefaultName = "ory_kratos_known_device"
	// DefaultLifespan is used when Config.Lifespan is not positive.
	DefaultLifespan = 90 * 24 * time.Hour

	// MaxEntries is the number of accounts remembered per device. Issuing for
	// a further account evicts the oldest entry.
	MaxEntries = 3
	// MaxIdentifierLength is the longest identifier, in bytes after
	// canonicalization, that an entry can be issued for.
	MaxIdentifierLength = 254
	// MaxValueLength bounds the cookie value that is looked at. An entry is
	// fixed in size, at most 110 bytes; MaxEntries of them and their separators
	// take 332, so this leaves room.
	MaxValueLength = 512

	// version prefixes the wire format of an entry, which is
	// version "." base64url(pseudonym) "." issued-at "." base64url(mac).
	// Entries are joined by entrySeparator, which none of their characters is.
	version        = "v1"
	entrySeparator = "~"
	// kdfInfo domain-separates the HKDF derivation of the MAC key, and
	// kdfPseudonymInfo that of the pseudonym key.
	kdfInfo          = "ory/kratos/knowndevicecookie/v1"
	kdfPseudonymInfo = "ory/kratos/knowndevicecookie/identifier/v1"
)

// Config configures a Codec.
type Config struct {
	// Name is the cookie name. It is bound into the MAC. Default DefaultName.
	Name string
	// Lifespan is how long an entry is valid, counted from the last login to
	// its account. Default DefaultLifespan.
	Lifespan time.Duration
	// Domain and Path scope the cookie. Path defaults to "/".
	Domain, Path string
	// Secure sets the Secure attribute.
	Secure bool
	// SameSite sets the SameSite attribute. Default http.SameSiteLaxMode.
	SameSite http.SameSite
}

// Provider gives access to the KnownDeviceCookie Codec.
type Provider interface {
	// KnownDeviceCookie returns the Codec, or nil if known device cookies are
	// disabled. A nil *Codec is valid: it issues nothing and verifies to
	// defense.DeviceNone.
	KnownDeviceCookie(ctx context.Context) *Codec
}

// Codec issues and validates KnownDeviceCookies. It is safe for concurrent use.
// The nil Codec is the disabled one: Issue does nothing and Verify returns
// defense.DeviceNone.
type Codec struct {
	cfg  Config
	keys []keyPair
}

// keyPair is what one secret yields: a key to sign entries, and one to make
// the pseudonyms of identifiers.
type keyPair struct{ mac, pseudonym []byte }

// entry is one remembered account.
type entry struct {
	pseudonym []byte
	iat       int64
	mac       []byte
	raw       string
}

// New returns a Codec signing with the first secret and verifying with all.
func New(secrets [][]byte, cfg Config) (*Codec, error) {
	if len(secrets) == 0 {
		return nil, errors.New("knowndevicecookie: at least one secret is required")
	}
	if cfg.Name == "" {
		cfg.Name = DefaultName
	}
	if cfg.Lifespan <= 0 {
		cfg.Lifespan = DefaultLifespan
	}
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	if cfg.SameSite == 0 {
		cfg.SameSite = http.SameSiteLaxMode
	}
	keys := make([]keyPair, len(secrets))
	for i, s := range secrets {
		mac, err := hkdf.Key(sha256.New, s, nil, kdfInfo, sha256.Size)
		if err != nil {
			return nil, errors.Wrap(err, "knowndevicecookie: cannot derive key")
		}
		pseudonym, err := hkdf.Key(sha256.New, s, nil, kdfPseudonymInfo, sha256.Size)
		if err != nil {
			return nil, errors.Wrap(err, "knowndevicecookie: cannot derive key")
		}
		keys[i] = keyPair{mac, pseudonym}
	}
	return &Codec{cfg: cfg, keys: keys}, nil
}

// Issue sets a cookie on w that remembers identifier. Call it on every
// successful login, so the entry's lifespan slides.
//
// The entries of the cookie on r are carried over, newest first, unless they
// are for the same account, expired or not authentic. The oldest are evicted
// beyond MaxEntries. Carried entries keep their issue time: only the account
// that just logged in gets a fresh lifespan.
func (c *Codec) Issue(w http.ResponseWriter, r *http.Request, identifier string) error {
	if c == nil {
		return nil
	}
	// Over the bound of defense.Canonicalize, it has the canonical form of all oversized identifiers.
	if len(identifier) > defense.MaxIdentifierLength {
		return errors.New("knowndevicecookie: identifier is empty or too long")
	}
	id := defense.Canonicalize(identifier)
	if id == "" || len(id) > MaxIdentifierLength {
		return errors.New("knowndevicecookie: identifier is empty or too long")
	}
	iat := time.Now().Unix()
	pseudonym := c.pseudonym(0, id)
	entries := []string{version + "." +
		base64.RawURLEncoding.EncodeToString(pseudonym) + "." +
		strconv.FormatInt(iat, 10) + "." +
		base64.RawURLEncoding.EncodeToString(c.mac(c.keys[0].mac, iat, pseudonym))}

	if ck, err := r.Cookie(c.cfg.Name); err == nil && len(ck.Value) <= MaxValueLength {
		for _, raw := range strings.Split(ck.Value, entrySeparator) {
			if len(entries) == MaxEntries {
				break
			}
			e, ok := parseEntry(raw)
			if !ok || c.expired(e) {
				continue
			}
			// An entry made under an older secret has another pseudonym for the
			// same account, so compare under the key that verifies it.
			key, ok := c.verifies(e)
			if ok && !hmac.Equal(e.pseudonym, c.pseudonym(key, id)) {
				entries = append(entries, e.raw)
			}
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.cfg.Name,
		Value:    strings.Join(entries, entrySeparator),
		Domain:   c.cfg.Domain,
		Path:     c.cfg.Path,
		MaxAge:   int(c.cfg.Lifespan / time.Second),
		Secure:   c.cfg.Secure,
		HttpOnly: true,
		SameSite: c.cfg.SameSite,
	})
	return nil
}

// Verify returns the verdict on the cookie of r for the identifier being
// attempted, in canonical form (defense.Canonicalize): the caller has it for the
// defense already, and canonicalizing costs more than all the HMACs here. It
// does no I/O.
//
//   - DeviceNone: no cookie, or an authentic one without a current entry for
//     the identifier. On a shared device that is a new account, not a suspect.
//     An expired entry is authentic but stale, a returning user whose entry
//     ran out.
//   - DeviceInvalid: a cookie that is malformed, oversized or has too many
//     entries, or any entry of which fails its MAC, whichever account it is for.
//   - DeviceKnown: an authentic cookie with a valid, unexpired entry for the
//     identifier.
func (c *Codec) Verify(r *http.Request, canonicalIdentifier string) defense.DeviceState {
	if c == nil {
		return defense.DeviceNone
	}
	// A password change does not revoke the cookie: it only marks the device as known to the account and never grants a login.
	ck, err := r.Cookie(c.cfg.Name)
	if err != nil {
		return defense.DeviceNone
	}
	if len(ck.Value) > MaxValueLength {
		return defense.DeviceInvalid
	}
	raws := strings.Split(ck.Value, entrySeparator)
	if len(raws) > MaxEntries {
		return defense.DeviceInvalid
	}
	var match *entry
	for _, raw := range raws {
		e, ok := parseEntry(raw)
		// One bad entry condemns the whole cookie, whichever account it is for:
		// a cookie someone has tampered with is not to be trusted at all.
		if !ok {
			return defense.DeviceInvalid
		}
		key, ok := c.verifies(e)
		if !ok {
			return defense.DeviceInvalid
		}
		if match == nil && hmac.Equal(e.pseudonym, c.pseudonym(key, canonicalIdentifier)) {
			match = &e
		}
	}
	switch {
	case match == nil:
		return defense.DeviceNone
	case c.expired(*match):
		return defense.DeviceNone
	}
	return defense.DeviceKnown
}

func parseEntry(raw string) (e entry, ok bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 || parts[0] != version {
		return entry{}, false
	}
	pseudonym, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(pseudonym) != sha256.Size {
		return entry{}, false
	}
	iat, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return entry{}, false
	}
	mac, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return entry{}, false
	}
	return entry{pseudonym: pseudonym, iat: iat, mac: mac, raw: raw}, true
}

func (c *Codec) expired(e entry) bool {
	return time.Since(time.Unix(e.iat, 0)) > c.cfg.Lifespan
}

// verifies checks the entry against every key, so rotated secrets keep working,
// and returns the index of the key that signed it.
func (c *Codec) verifies(e entry) (key int, ok bool) {
	key = -1
	for i, k := range c.keys {
		if hmac.Equal(e.mac, c.mac(k.mac, e.iat, e.pseudonym)) && key < 0 {
			key = i
		}
	}
	return key, key >= 0
}

// pseudonym returns the pseudonym of the canonicalized identifier under the
// key of the secret at index key: a keyed hash, so it reveals no address and
// cannot be checked against a guess without the secret. It is domain separated
// from every other use of the secret. It is the whole HMAC-SHA256.
func (c *Codec) pseudonym(key int, id string) []byte {
	h := hmac.New(sha256.New, c.keys[key].pseudonym)
	h.Write([]byte(kdfPseudonymInfo))
	h.Write([]byte{0})
	h.Write([]byte(id))
	return h.Sum(nil)
}

// mac covers the cookie name, the issue time and the pseudonym. The pseudonym
// comes last and has a fixed length, the name has no NUL and the issue time is
// decimal, so the encoding is unambiguous.
func (c *Codec) mac(key []byte, iat int64, pseudonym []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(c.cfg.Name))
	h.Write([]byte{0})
	h.Write(strconv.AppendInt(nil, iat, 10))
	h.Write([]byte{0})
	h.Write(pseudonym)
	return h.Sum(nil)
}
