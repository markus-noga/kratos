// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package gate connects flows to a defense.Defense. A flow handler creates a
// Gate per request and passes it to its strategy through the context. The
// strategy enters it with Check once it knows it is responsible and has
// decoded the payload, but before any database lookup or expensive
// computation. The handler then reports the outcome with Done, so strategies
// never call AfterSuccess or AfterFailure themselves.
package gate

import (
	"context"
	"math"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/ory/herodot"
	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/knowndevicecookie"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/x"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
)

// Dependencies are what a Gate needs from the registry.
type Dependencies interface {
	defense.Provider
	knowndevicecookie.Provider
	config.Provider
	logrusx.Provider
}

// Gate is the entry of one request into the defense. A nil *Gate is valid and
// lets everything through, for strategies run outside a handler.
type Gate struct {
	d        Dependencies
	w        http.ResponseWriter
	r        *http.Request
	method   defense.MethodID
	attempt  *defense.Attempt
	reported bool
}

// New returns the Gate for a request that attempts method. w receives the
// Retry-After header of a deny. It may be nil where a deny refuses no request,
// such as a check before a message that the caller leaves unsent while the
// request succeeds (see Denied).
func New(d Dependencies, w http.ResponseWriter, r *http.Request, method defense.MethodID) *Gate {
	return &Gate{d: d, w: w, r: r, method: method}
}

// Install creates the Gate for a request and puts it into the context of r,
// in place, not on a copy: strategies keep the request body readable for the
// next one by replacing it on r.
func Install(d Dependencies, w http.ResponseWriter, r *http.Request, method defense.MethodID) *Gate {
	g := New(d, w, r, method)
	*r = *r.WithContext(With(r.Context(), g))
	return g
}

type ctxKey struct{}

// With returns a context that carries g.
func With(ctx context.Context, g *Gate) context.Context {
	return context.WithValue(ctx, ctxKey{}, g)
}

// From returns the Gate of the context, or nil.
func From(ctx context.Context) *Gate {
	g, _ := ctx.Value(ctxKey{}).(*Gate)
	return g
}

// Check asks the defense whether the attempt may proceed. identifier is the
// account being attacked as the client names it, and secret the credential
// being tried; either is empty if the client supplies none. It sleeps for the
// delay the defense asks for, and returns a 429 error if the defense denies
// the attempt. The caller returns that error like any other of its own.
func (g *Gate) Check(ctx context.Context, identifier, secret string) error {
	if g == nil {
		return nil
	}
	fp := g.fingerprinter(ctx)
	a := g.attemptOf(fp, secret)
	// Canonicalized once, for the digest and the device verdict: it is the costliest step.
	id := defense.Canonicalize(identifier)
	if identifier != "" {
		a.IdentifierDigest = fp.CanonicalIdentifier(id)
	}
	// Only the first factor may lean on a known device: it must not ease the guessing of a second factor.
	if g.method == defense.MethodPassword {
		// A pure HMAC check of the cookie, no database access, so it is ready in time for BeforeAttempt.
		a.Device = g.d.KnownDeviceCookie(ctx).Verify(g.r, id)
	}
	return g.enter(ctx, a)
}

// CheckScope is Check for an attempt that names no account but something else,
// such as the identity provider whose token endpoint the request would hit. The
// scope is digested in a space of its own, so a client can never make an
// identifier collide with it.
func (g *Gate) CheckScope(ctx context.Context, scope, secret string) error {
	if g == nil {
		return nil
	}
	fp := g.fingerprinter(ctx)
	a := g.attemptOf(fp, secret)
	a.IdentifierDigest = fp.Scope(scope)
	return g.enter(ctx, a)
}

func (g *Gate) fingerprinter(ctx context.Context) *defense.Fingerprinter {
	return defense.NewFingerprinter(g.d.Config().DefenseFingerprintSecret(ctx))
}

func (g *Gate) attemptOf(fp *defense.Fingerprinter, secret string) defense.Attempt {
	a := defense.Attempt{
		Method: g.method,
		IP:     defense.ParseIP(httpx.ClientIP(g.r)),
	}
	if secret != "" {
		a.CredentialDigest = fp.Credential(secret)
	}
	return a
}

// enter asks the defense about the attempt, and remembers it for the outcome.
func (g *Gate) enter(ctx context.Context, a defense.Attempt) error {
	dec, err := g.d.Defense().BeforeAttempt(ctx, a)
	if err != nil {
		// Fail open: an unavailable defense (e.g. its backing store) must not lock out all users.
		g.d.Logger().WithError(err).Error("Defense.BeforeAttempt failed, allowing the attempt.")
		dec = defense.Decision{}
	}
	if err := dec.Wait(ctx, g.d.Config().DefenseMaxDelay(ctx)); err != nil {
		return errors.WithStack(err)
	}
	if dec.Verdict == defense.Deny {
		g.d.Logger().WithField("reason", dec.Reason).Info("Attempt denied by defense.")
		if dec.RetryAfter > 0 && g.w != nil {
			g.w.Header().Set("Retry-After", strconv.FormatInt(int64(math.Ceil(dec.RetryAfter.Seconds())), 10))
		}
		return errors.WithStack(&herodot.DefaultError{
			StatusField: http.StatusText(http.StatusTooManyRequests),
			ErrorField:  "Too Many Requests",
			CodeField:   http.StatusTooManyRequests,
			ReasonField: "Too many attempts. Please try again later.",
		})
	}
	g.attempt = &a
	return nil
}

// Succeeded reports that the credential of the attempt was verified. A strategy
// calls it where it alone knows the outcome: a flow that shows a wrong code as a
// message instead of returning an error. At most one outcome is reported per
// attempt, and none for an attempt the defense did not let through.
func (g *Gate) Succeeded(ctx context.Context) {
	if g == nil || g.attempt == nil || g.reported {
		return
	}
	g.reported = true
	g.d.Defense().AfterSuccess(ctx, *g.attempt)
}

// Failed reports that the credential of the attempt was wrong. See Succeeded.
func (g *Gate) Failed(ctx context.Context) {
	if g == nil || g.attempt == nil || g.reported {
		return
	}
	g.reported = true
	g.d.Defense().AfterFailure(ctx, *g.attempt)
}

// Done reports the outcome of a request to the defense, unless the strategy has
// done so itself with Succeeded or Failed. succeeded says that the credential
// was verified, err is what the strategy returned.
//
// Only an attempt the defense let through is reported. A failure is an error
// the client caused, such as a wrong credential: an invalid or missing value,
// not a server fault, so that broken records cannot lock out their owner.
// Anything else, such as a step that sent a code or a redirect, is no verdict
// on the credential and reports nothing.
func (g *Gate) Done(ctx context.Context, succeeded bool, err error) {
	switch {
	case succeeded && err == nil:
		g.Succeeded(ctx)
	case err != nil && ClientFault(err):
		g.Failed(ctx)
	}
}

// Denied reports whether err is the error with which Check refuses an attempt
// that the defense denied. The only other error Check returns is that of a
// context that ended while it waited for a delay. A caller that answers a deny
// by leaving out what the attempt was for, such as a message, tells the two
// apart with it.
func Denied(err error) bool {
	var e *herodot.DefaultError
	return errors.As(err, &e) && e.CodeField == http.StatusTooManyRequests
}

// ClientFault reports whether err was caused by the client: a validation
// error, or any other error with a 4xx status.
func ClientFault(err error) bool {
	if ve := new(schema.ValidationError); errors.As(err, &ve) {
		return true
	}
	code := x.RecoverStatusCode(err, http.StatusInternalServerError)
	return code >= http.StatusBadRequest && code < http.StatusInternalServerError
}
