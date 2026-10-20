// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"
	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/defense/gate"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/knowndevicecookie"
	"github.com/ory/kratos/schema"
	"github.com/ory/x/configx"
	"github.com/ory/x/contextx"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
)

type deps struct {
	defense *defensetest.Recorder
	cfg     *config.Config
	codec   *knowndevicecookie.Codec
	log     *logrusx.Logger
}

func (d *deps) Defense() defense.Defense                                   { return d.defense }
func (d *deps) KnownDeviceCookie(context.Context) *knowndevicecookie.Codec { return d.codec }
func (d *deps) Config() *config.Config                                     { return d.cfg }
func (d *deps) Logger() *logrusx.Logger                                    { return d.log }

func newDeps(t *testing.T) *deps {
	t.Helper()
	cfg := config.MustNew(t, logrusx.New("", ""), &contextx.Default{}, configx.SkipValidation(),
		configx.WithValue(config.ViperKeyDefenseFingerprintKey, "fingerprint-key-for-tests"))
	codec, err := knowndevicecookie.New([][]byte{[]byte("device-secret-for-tests")}, knowndevicecookie.Config{})
	require.NoError(t, err)
	return &deps{defense: new(defensetest.Recorder), cfg: cfg, codec: codec, log: logrusx.New("", "")}
}

func newRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/self-service/login", nil)
	r.RemoteAddr = "192.0.2.7:4711"
	return r
}

func TestNilGate(t *testing.T) {
	t.Parallel()
	var g *gate.Gate
	assert.NoError(t, g.Check(t.Context(), "alice", "secret"))
	assert.NotPanics(t, func() { g.Done(t.Context(), true, nil) })
	assert.Nil(t, gate.From(t.Context()), "no gate in a plain context")
}

func TestContext(t *testing.T) {
	t.Parallel()
	g := gate.New(newDeps(t), httptest.NewRecorder(), newRequest(), defense.MethodTOTP)
	assert.Same(t, g, gate.From(gate.With(t.Context(), g)))
}

func TestCheck(t *testing.T) {
	t.Parallel()

	t.Run("case=builds the attempt from the request", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		g := gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodCode)
		require.NoError(t, g.Check(t.Context(), " Alice@Example.com ", "123456"))

		require.Equal(t, []string{"BeforeAttempt"}, d.defense.Names())
		a := d.defense.Calls()[0].Attempt
		fp := defense.NewFingerprinter([]byte("fingerprint-key-for-tests"))
		assert.Equal(t, defense.MethodCode, a.Method)
		assert.Equal(t, fp.Identifier("alice@example.com"), a.IdentifierDigest)
		assert.Equal(t, fp.Credential("123456"), a.CredentialDigest)
		assert.Equal(t, netip.MustParseAddr("192.0.2.7"), a.IP)
	})

	t.Run("case=an absent identifier or secret has the zero digest", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		require.NoError(t, gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodPasskey).Check(t.Context(), "", ""))
		a := d.defense.Calls()[0].Attempt
		assert.True(t, a.IdentifierDigest.IsZero())
		assert.True(t, a.CredentialDigest.IsZero())
	})

	t.Run("case=only the first factor gets the device verdict", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		w := httptest.NewRecorder()
		require.NoError(t, d.codec.Issue(w, newRequest(), "alice@example.com"))
		r := newRequest()
		r.AddCookie(w.Result().Cookies()[0])

		for method, want := range map[defense.MethodID]defense.DeviceState{
			defense.MethodPassword:     defense.DeviceKnown,
			defense.MethodCode:         defense.DeviceNone,
			defense.MethodTOTP:         defense.DeviceNone,
			defense.MethodLookupSecret: defense.DeviceNone,
		} {
			d.defense.Reset()
			require.NoError(t, gate.New(d, httptest.NewRecorder(), r, method).Check(t.Context(), "alice@example.com", "x"))
			assert.Equal(t, want, d.defense.Calls()[0].Attempt.Device, method.String())
		}
	})

	t.Run("case=the digest and the device verdict see one canonical identifier", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		w := httptest.NewRecorder()
		require.NoError(t, d.codec.Issue(w, newRequest(), "alice@example.com"))
		fp := defense.NewFingerprinter([]byte("fingerprint-key-for-tests"))

		for _, tc := range []struct {
			identifier string
			device     defense.DeviceState
		}{
			{"  ALICE@example.com\t", defense.DeviceKnown},
			// Over the bound, whatever it hides: the digest of all oversized identifiers, and no known device.
			{"alice@example.com" + strings.Repeat("\u200b", defense.MaxIdentifierLength), defense.DeviceNone},
		} {
			r := newRequest()
			r.AddCookie(w.Result().Cookies()[0])
			d.defense.Reset()
			require.NoError(t, gate.New(d, httptest.NewRecorder(), r, defense.MethodPassword).Check(t.Context(), tc.identifier, "x"))
			a := d.defense.Calls()[0].Attempt
			assert.Equal(t, tc.device, a.Device)
			assert.Equal(t, fp.Identifier(tc.identifier), a.IdentifierDigest)
		}
	})

	t.Run("case=deny returns 429 with Retry-After and is not reported afterwards", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		d.defense.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: 1500 * time.Millisecond}, nil)
		w := httptest.NewRecorder()
		g := gate.New(d, w, newRequest(), defense.MethodPassword)

		err := g.Check(t.Context(), "alice", "secret")
		require.Error(t, err)
		var sc herodot.StatusCodeCarrier
		require.ErrorAs(t, err, &sc)
		assert.Equal(t, http.StatusTooManyRequests, sc.StatusCode())
		assert.Equal(t, "2", w.Header().Get("Retry-After"), "rounded up to whole seconds")
		assert.True(t, gate.Denied(err))

		g.Done(t.Context(), false, err)
		assert.Equal(t, []string{"BeforeAttempt"}, d.defense.Names(), "a denied attempt says nothing about the credential")
	})

	t.Run("case=deny without RetryAfter sets no header", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		d.defense.Answer(defense.Decision{Verdict: defense.Deny}, nil)
		w := httptest.NewRecorder()
		require.Error(t, gate.New(d, w, newRequest(), defense.MethodPassword).Check(t.Context(), "a", "b"))
		assert.Empty(t, w.Header().Get("Retry-After"))
	})

	t.Run("case=a gate without a response writer denies without a header", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		d.defense.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, nil)
		err := gate.New(d, nil, newRequest(), defense.MethodVerification).Check(t.Context(), "alice@example.com", "")
		assert.True(t, gate.Denied(err), "the caller answers the deny itself")
	})

	t.Run("case=other errors are no deny", func(t *testing.T) {
		t.Parallel()
		assert.False(t, gate.Denied(nil))
		assert.False(t, gate.Denied(errors.New("valkey is down")))
		assert.False(t, gate.Denied(herodot.ErrBadRequest().WithReason("no")))
	})

	t.Run("case=a defense error fails open", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		// Whatever is returned next to the error is ignored.
		d.defense.Answer(defense.Decision{Verdict: defense.Deny, Delay: time.Hour}, errors.New("valkey is down"))
		g := gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodPassword)
		assert.NoError(t, g.Check(t.Context(), "alice", "secret"))

		g.Done(t.Context(), true, nil)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, d.defense.Names())
	})

	t.Run("case=sleeps for the delay", func(t *testing.T) {
		t.Parallel()
		// Built outside the bubble: the config may keep background goroutines that must not take part in it.
		d := newDeps(t)
		d.defense.Answer(defense.Decision{Delay: 5 * time.Second}, nil)
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			require.NoError(t, gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodPassword).Check(t.Context(), "alice", "secret"))
			assert.Equal(t, 5*time.Second, time.Since(start))
		})
	})

	t.Run("case=a delay is capped at the configured maximum", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		require.NoError(t, d.cfg.Set(t.Context(), config.ViperKeyDefenseMaxDelay, "2s"))
		d.defense.Answer(defense.Decision{Delay: time.Hour}, nil)
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			require.NoError(t, gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodPassword).Check(t.Context(), "alice", "secret"))
			assert.Equal(t, 2*time.Second, time.Since(start))
		})
	})

	t.Run("case=a cancelled context ends the wait with an error", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		d.defense.Answer(defense.Decision{Delay: time.Minute}, nil)
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			time.AfterFunc(time.Second, cancel)
			start := time.Now()
			err := gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodPassword).Check(ctx, "alice", "secret")
			assert.ErrorIs(t, err, context.Canceled)
			assert.False(t, gate.Denied(err), "a wait cut short is no deny")
			assert.Equal(t, time.Second, time.Since(start))
		})
	})
}

func TestDone(t *testing.T) {
	t.Parallel()

	serverFault := herodot.ErrInternalServerError().WithReason("boom")
	for name, tc := range map[string]struct {
		succeeded bool
		err       error
		want      []string
	}{
		"success":                      {true, nil, []string{"BeforeAttempt", "AfterSuccess"}},
		"invalid credentials":          {false, schema.NewInvalidCredentialsError(), []string{"BeforeAttempt", "AfterFailure"}},
		"invalid code":                 {false, schema.NewLoginCodeInvalid(), []string{"BeforeAttempt", "AfterFailure"}},
		"client error":                 {false, herodot.ErrBadRequest().WithReason("no"), []string{"BeforeAttempt", "AfterFailure"}},
		"server fault":                 {false, serverFault, []string{"BeforeAttempt"}},
		"unclassified error":           {false, errors.New("who knows"), []string{"BeforeAttempt"}},
		"a step that only sent a code": {false, nil, []string{"BeforeAttempt"}},
		"success with an error":        {true, serverFault, []string{"BeforeAttempt"}},
	} {
		t.Run("case="+name, func(t *testing.T) {
			t.Parallel()
			d := newDeps(t)
			g := gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodPassword)
			require.NoError(t, g.Check(t.Context(), "alice", "secret"))
			g.Done(t.Context(), tc.succeeded, tc.err)
			assert.Equal(t, tc.want, d.defense.Names())
			for _, c := range d.defense.Calls() {
				assert.Equal(t, d.defense.Calls()[0].Attempt, c.Attempt, "all calls of one attempt see the same Attempt")
			}
		})
	}

	t.Run("case=nothing is reported for a gate that was never entered", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		g := gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodPassword)
		g.Done(t.Context(), true, nil)
		g.Done(t.Context(), false, schema.NewInvalidCredentialsError())
		assert.Empty(t, d.defense.Calls())
	})
}

func TestExplicitOutcome(t *testing.T) {
	t.Parallel()

	t.Run("case=an outcome the strategy reports is reported once, and wins over Done", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		g := gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodRecovery)
		require.NoError(t, g.Check(t.Context(), "alice", "123456"))

		g.Failed(t.Context())
		g.Failed(t.Context())
		g.Succeeded(t.Context())
		g.Done(t.Context(), true, nil)
		assert.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, d.defense.Names())
	})

	t.Run("case=a success reported by the strategy is not repeated by Done", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		g := gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodRecovery)
		require.NoError(t, g.Check(t.Context(), "alice", "123456"))

		g.Succeeded(t.Context())
		g.Done(t.Context(), false, schema.NewInvalidCredentialsError())
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, d.defense.Names())
	})

	t.Run("case=nothing is reported for an attempt that was not let through", func(t *testing.T) {
		t.Parallel()
		d := newDeps(t)
		d.defense.Answer(defense.Decision{Verdict: defense.Deny}, nil)
		g := gate.New(d, httptest.NewRecorder(), newRequest(), defense.MethodRecovery)
		require.Error(t, g.Check(t.Context(), "alice", "123456"))

		g.Failed(t.Context())
		g.Succeeded(t.Context())
		assert.Equal(t, []string{"BeforeAttempt"}, d.defense.Names())
	})

	t.Run("case=a nil gate ignores outcomes", func(t *testing.T) {
		t.Parallel()
		var g *gate.Gate
		assert.NotPanics(t, func() { g.Failed(t.Context()); g.Succeeded(t.Context()) })
	})
}

func TestInstall(t *testing.T) {
	t.Parallel()
	d := newDeps(t)
	r := newRequest()
	g := gate.Install(d, httptest.NewRecorder(), r, defense.MethodRecovery)
	assert.Same(t, g, gate.From(r.Context()), "installed on the request itself, so a body swapped by a strategy stays visible to the next")
}

func TestCheckClientIP(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, peer string
		want       string
	}{
		{"spoofed header from an untrusted peer", "198.51.100.7:1", "198.51.100.7"},
		{"header from a trusted proxy", "10.0.0.1:1", "203.0.113.9"},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			t.Parallel()
			d := newDeps(t)
			r := newRequest()
			r.RemoteAddr = tc.peer
			r.Header.Set("True-Client-IP", "203.0.113.9")
			tp, err := httpx.ParseTrustedProxies("True-Client-IP", []string{"10.0.0.0/8"})
			require.NoError(t, err)
			r = r.WithContext(httpx.ContextWithClientInfo(r, tp))

			g := gate.New(d, httptest.NewRecorder(), r, defense.MethodCode)
			require.NoError(t, g.Check(t.Context(), "alice", "123456"))
			calls := d.defense.Calls()
			require.NotEmpty(t, calls)
			assert.Equal(t, tc.want, calls[0].Attempt.IP.String())
		})
	}
}
