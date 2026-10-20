// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package defense defines the attack-defense extension point for credential
// checks. An implementation can rate limit, back off, or block attempts before
// any expensive work (database lookup, password hashing) happens, and learn
// from the outcome afterwards.
package defense

import (
	"context"
	"net/netip"
	"time"
)

// Digest is a 256 bit keyed digest. Kratos computes it, the key never leaves
// Kratos. Implementations may truncate it.
type Digest [32]byte

// IsZero reports whether the digest is unset.
func (d Digest) IsZero() bool { return d == Digest{} }

// MethodID identifies the credential method of an Attempt. It is a small
// enum, so it can be used as an array index or metric label without allocating.
type MethodID uint8

const (
	// MethodUnknown is the zero value and is never passed by Kratos.
	MethodUnknown MethodID = iota
	MethodPassword
	MethodCode
	MethodLookupSecret
	MethodAppPassword
	MethodTOTP
	MethodWebAuthn
	MethodPasskey
	// MethodIdentifierFirst is the identifier-first step of a login: the client
	// names an account and no credential is checked. The step may look the
	// account up and send a code to it, so it is defended like a route that
	// sends messages. After calls say nothing about credentials.
	MethodIdentifierFirst
	// MethodRecovery, MethodVerification and MethodRegistration are not
	// credential checks but the routes of those flows that send a message to
	// an address named by the client. The identifier digest is that address.
	// Each verification message of a settings update counts as
	// MethodVerification too: for an address the update adds, before anything
	// is saved, and for any other address, right before the message is sent.
	// The verification flow of a change that verify_new_address keeps pending
	// resends its code to the pending address, and counts the resend for it,
	// whatever address the client names.
	MethodRecovery
	MethodVerification
	MethodRegistration
	// MethodOIDC is the callback of an OpenID Connect or OAuth2 sign-in: the
	// user has proven themselves to the provider, the request carries the code to
	// exchange for tokens. The exchange is an outbound call that costs us a
	// round trip and counts against our client at the provider. No account is
	// known yet: the identifier digest names the provider (a scope, not an
	// account), the credential digest the code.
	MethodOIDC
	// NumMethods is the number of defined IDs, including MethodUnknown.
	NumMethods
)

var methodNames = [NumMethods]string{
	"unknown", "password", "code", "lookup_secret", "app_password",
	"totp", "webauthn", "passkey", "identifier_first", "recovery", "verification", "registration",
	"oidc",
}

// String returns the stable name of the method, for logs and metrics.
func (m MethodID) String() string {
	if m >= NumMethods {
		return methodNames[MethodUnknown]
	}
	return methodNames[m]
}

// DeviceState is Kratos' verdict on the KnownDeviceCookie of an attempt. Kratos
// validates the cookie, the implementation never sees it nor the key.
type DeviceState uint8

const (
	// DeviceNone means no usable KnownDeviceCookie entry for the account was
	// presented. It is the zero value. That covers no cookie, a cookie that
	// remembers only other accounts (a new account on a shared device), and an
	// expired entry: expiry is routine for returning users and says nothing
	// about the client, so none of these may be treated as suspicious.
	DeviceNone DeviceState = iota
	// DeviceInvalid means the cookie is forged or malformed, or its entry for
	// the account fails verification.
	DeviceInvalid
	// DeviceKnown means a valid, unexpired entry for the identifier of this
	// attempt.
	DeviceKnown
)

var deviceStateNames = [...]string{"none", "invalid", "known"}

// String returns the stable name of the state, for logs and metrics.
func (d DeviceState) String() string {
	if int(d) >= len(deviceStateNames) {
		return "invalid"
	}
	return deviceStateNames[d]
}

// Attempt describes a single credential check. It carries no plaintext
// identifier or credential, and no request: everything an implementation may
// act on is listed here, and is the same in all three calls.
type Attempt struct {
	// Method is the credential method being attempted.
	Method MethodID
	// IdentifierDigest identifies the account being attacked: a keyed digest of
	// the canonicalized identifier as supplied by the client. It is derived
	// from the input alone, so it is identical for existing and non-existing
	// accounts and available before any database lookup.
	IdentifierDigest Digest
	// CredentialDigest is a keyed digest of the submitted secret, for
	// detecting one secret tried across many accounts (credential stuffing).
	// It is zero for methods without a client-supplied secret.
	CredentialDigest Digest
	// Device is the verdict on the device cookie. It is DeviceNone until
	// Kratos issues and validates device cookies.
	Device DeviceState
	// IP is the client IP address as determined by Kratos, with IPv4-mapped
	// IPv6 addresses unmapped. It is the zero Addr if it could not be determined.
	IP netip.Addr
}

// Verdict is the kind of decision taken in BeforeAttempt.
type Verdict int

const (
	// Allow lets the attempt proceed. It is the zero value.
	Allow Verdict = iota
	// Deny rejects the attempt without looking up the identity or hashing.
	Deny
)

// Decision is the result of BeforeAttempt.
type Decision struct {
	Verdict Verdict
	// Delay, if positive, is slept before the attempt proceeds (Allow) or
	// before the rejection is returned (Deny). The defense decides the policy;
	// defense.max_delay (default 10s) only guards against a faulty one.
	Delay time.Duration
	// RetryAfter, if positive on Deny, is reported to the client.
	RetryAfter time.Duration
	// Reason is for logs only and is never shown to the client.
	Reason string
}

// Defense is called around credential checks.
//
// Kratos calls it through the gate package, in two parts. Each strategy calls
// BeforeAttempt itself, via Gate.Check, because only the strategy knows when it
// is responsible and has the payload; it does so before any database lookup or
// hashing. The flow handler calls AfterSuccess and AfterFailure for all
// strategies alike, based on what the strategy returned, so a strategy never
// calls them. A strategy that is not to be defended must say so, with a reason,
// in the coverage test of the driver package.
type Defense interface {
	// BeforeAttempt is called before database lookup and password hashing.
	// An error fails open: it is logged and the attempt is allowed without delay.
	BeforeAttempt(ctx context.Context, a Attempt) (Decision, error)
	// AfterSuccess is called after the credential was verified.
	AfterSuccess(ctx context.Context, a Attempt)
	// AfterFailure is called after the credential check failed because the
	// credential was wrong, including when the identifier matched no identity.
	// Server-side faults (corrupt records, misconfiguration) are reported to
	// neither After method, as they say nothing about the client.
	AfterFailure(ctx context.Context, a Attempt)
	// UsesKnownDeviceVerdict reports whether the defense acts on Attempt.Device.
	// With defense.known_device_cookie.enabled at its default, auto, Kratos
	// issues and validates the KnownDeviceCookie only for a defense that does:
	// for any other it would be a long-lived cookie that nobody reads. It is
	// asked on every use, so the answer may change over the life of the process.
	UsesKnownDeviceVerdict() bool
}

// Provider gives access to the active Defense.
type Provider interface {
	Defense() Defense
}

// Noop allows every attempt and records nothing.
type Noop struct{}

var _ Defense = Noop{}

func (Noop) BeforeAttempt(context.Context, Attempt) (Decision, error) { return Decision{}, nil }
func (Noop) AfterSuccess(context.Context, Attempt)                    {}
func (Noop) AfterFailure(context.Context, Attempt)                    {}
func (Noop) UsesKnownDeviceVerdict() bool                             { return false }

// Wait sleeps for the decision's Delay, capped at maxDelay. See the package
// level Wait for the semantics.
func (d Decision) Wait(ctx context.Context, maxDelay time.Duration) error {
	return Wait(ctx, min(d.Delay, maxDelay))
}

// Wait sleeps for d, or until ctx is done, whichever comes first. It returns
// ctx.Err() if the context ended the wait. A non-positive d returns at once.
func Wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
