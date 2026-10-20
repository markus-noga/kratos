// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cipher

import (
	"context"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	"github.com/ory/herodot"
)

// KeyEntry is a named key. The ID is stored with the ciphertext and selects the key on decryption.
type KeyEntry struct {
	ID  string
	Key [32]byte
}

// KeyID syntax: alphanumeric, so it can never contain the `:` separator.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// ReservedKeyID is not a valid key ID: `otpauth:` is the start of a plaintext TOTP URL, and must stay distinguishable
// from `<key-id>:<ciphertext>`.
const ReservedKeyID = "otpauth"

// ValidateKeyID reports whether id may name a key.
func ValidateKeyID(id string) error {
	if !keyIDPattern.MatchString(id) {
		return errors.Errorf("key id %q must be alphanumeric and not empty", id)
	}
	if strings.EqualFold(id, ReservedKeyID) {
		return errors.Errorf("key id %q is reserved", id)
	}
	return nil
}

// ErrUnknownKeyID is the cause of a DecryptWithAAD failure for a ciphertext whose key is not configured, such as one
// dropped from the configuration while it was still in use.
var ErrUnknownKeyID = errors.New("unknown key id")

// KeyedSecretsProvider returns the keys of a KeyedAES. The first one encrypts, all of them decrypt.
type KeyedSecretsProvider interface {
	KeyedSecrets(ctx context.Context) []KeyEntry
}

// AADCipher encrypts with additional authenticated data (AAD): decryption fails unless the same AAD is given, so a
// ciphertext cannot be copied to another record. Unlike Cipher, the ciphertext names its key.
type AADCipher interface {
	// EncryptWithAAD encrypts the message with the first key. The result is `<key-id>:<hex(nonce|ciphertext|tag)>`.
	// An empty message gives an empty ciphertext.
	EncryptWithAAD(ctx context.Context, message, aad []byte) (string, error)

	// DecryptWithAAD selects the key named in the ciphertext and fails if there is none, or if the AAD differs.
	// An empty ciphertext gives nil.
	DecryptWithAAD(ctx context.Context, encrypted string, aad []byte) ([]byte, error)

	// IsCurrent reports whether the ciphertext was made with the first key, i.e. needs no re-encryption.
	IsCurrent(ctx context.Context, encrypted string) bool
}

// IsKeyed reports whether s has the shape `<key-id>:<hex>` of AADCipher ciphertexts (not whether it decrypts).
func IsKeyed(s string) bool {
	id, ct, ok := strings.Cut(s, ":")
	if !ok || len(ct) == 0 || ValidateKeyID(id) != nil {
		return false
	}
	_, err := hex.DecodeString(ct)
	return err == nil
}

// KeyedAES is an AADCipher with AES-256-GCM.
type KeyedAES struct {
	c KeyedSecretsProvider
}

var _ AADCipher = (*KeyedAES)(nil)

func NewKeyedAES(c KeyedSecretsProvider) *KeyedAES { return &KeyedAES{c: c} }

func (a *KeyedAES) EncryptWithAAD(ctx context.Context, message, aad []byte) (string, error) {
	if len(message) == 0 {
		return "", nil
	}

	keys := a.c.KeyedSecrets(ctx)
	if len(keys) == 0 {
		return "", errors.WithStack(herodot.ErrMisconfiguration().WithReason("Unable to encrypt message because no keys were configured."))
	}

	gcm, err := aesGCM(&keys[0].Key)
	if err != nil {
		return "", errors.WithStack(herodot.ErrInternalServerError().WithWrap(err))
	}

	return keys[0].ID + ":" + hex.EncodeToString(gcm.Seal(nil, nil, message, aad)), nil
}

func (a *KeyedAES) DecryptWithAAD(ctx context.Context, encrypted string, aad []byte) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, nil
	}

	id, ct, ok := strings.Cut(encrypted, ":")
	if !ok {
		return nil, errors.WithStack(herodot.ErrBadRequest().WithReason("The encrypted message has no key id."))
	}

	// Select by ID: no trial decryption, so a wrong key and a wrong AAD are the same failure.
	var key *KeyEntry
	keys := a.c.KeyedSecrets(ctx)
	for i := range keys {
		if keys[i].ID == id {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return nil, errors.WithStack(herodot.ErrForbidden().WithReasonf("Unable to decipher the encrypted message: unknown key id %q.", id).WithWrap(ErrUnknownKeyID))
	}

	raw, err := hex.DecodeString(ct)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest().WithWrap(err))
	}

	gcm, err := aesGCM(&key.Key)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError().WithWrap(err))
	}

	plaintext, err := gcm.Open(nil, nil, raw, aad)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrForbidden().WithReason("Unable to decipher the encrypted message."))
	}
	return plaintext, nil
}

func (a *KeyedAES) IsCurrent(ctx context.Context, encrypted string) bool {
	keys := a.c.KeyedSecrets(ctx)
	id, _, ok := strings.Cut(encrypted, ":")
	return ok && len(keys) > 0 && keys[0].ID == id
}
