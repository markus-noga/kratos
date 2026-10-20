// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package password_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/x"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
	"github.com/ory/x/sqlxx"
)

type recordedCall struct {
	Name    string
	Attempt defense.Attempt
}

type recordingDefense struct {
	mu       sync.Mutex
	calls    []recordedCall
	decision defense.Decision
	err      error
	// uses is the answer of UsesKnownDeviceVerdict.
	uses bool
}

func (r *recordingDefense) record(name string, a defense.Attempt) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordedCall{name, a})
}

func (r *recordingDefense) BeforeAttempt(_ context.Context, a defense.Attempt) (defense.Decision, error) {
	r.record("BeforeAttempt", a)
	return r.decision, r.err
}
func (r *recordingDefense) AfterSuccess(_ context.Context, a defense.Attempt) {
	r.record("AfterSuccess", a)
}
func (r *recordingDefense) AfterFailure(_ context.Context, a defense.Attempt) {
	r.record("AfterFailure", a)
}

// UsesKnownDeviceVerdict is false unless the test sets uses, so that the tests
// that want the cookie ask for it, by configuration or by this.
func (r *recordingDefense) UsesKnownDeviceVerdict() bool { return r.uses }

func (r *recordingDefense) names() (n []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		n = append(n, c.Name)
	}
	return n
}

func (r *recordingDefense) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls, r.decision, r.err = nil, defense.Decision{}, nil
}

func TestLoginDefense(t *testing.T) {
	t.Parallel()

	_, reg := pkg.NewFastRegistryWithMocks(t,
		configx.WithValue(config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword)+".enabled", true),
		configx.WithValues(testhelpers.IdentitySchemasConfig(map[string]string{
			"default": "file://./stub/login.schema.json",
		})),
	)
	rec := new(recordingDefense)
	reg.WithDefense(rec)
	require.Same(t, defense.Defense(rec), reg.Defense())

	publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
	testhelpers.NewErrorTestServer(t, reg)
	// A local login UI: the browser flow redirects there, not to the public fallback UI.
	testhelpers.NewLoginUIFlowEchoServer(t, reg)
	apiClient := testhelpers.NewDebugClient(t)

	identifier, pwd := x.NewUUID().String(), "password"
	createIdentity(t.Context(), reg, t, identifier, pwd)

	loginRaw := func(t *testing.T, client *http.Client, payload map[string]string) (string, *http.Response) {
		f := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, client, publicTS, false)
		b, err := json.Marshal(payload)
		require.NoError(t, err)
		return testhelpers.LoginMakeRequest(t, true, false, f, client, string(b))
	}
	login := func(t *testing.T, identifier, password string) (string, *http.Response) {
		return loginRaw(t, apiClient, map[string]string{"method": "password", "identifier": identifier, "password": password})
	}

	t.Run("case=default registry uses the no-op defense", func(t *testing.T) {
		t.Parallel()
		_, fresh := pkg.NewFastRegistryWithMocks(t)
		assert.IsType(t, defense.Noop{}, fresh.Defense())
	})

	t.Run("case=success calls BeforeAttempt then AfterSuccess", func(t *testing.T) {
		rec.reset()
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, rec.names())

		before, after := rec.calls[0].Attempt, rec.calls[1].Attempt
		assert.Equal(t, defense.MethodPassword, before.Method)
		fp := defense.NewFingerprinter(reg.Config().DefenseFingerprintSecret(t.Context()))
		assert.Equal(t, fp.Identifier(identifier), before.IdentifierDigest)
		assert.Equal(t, fp.Credential(pwd), before.CredentialDigest)
		assert.True(t, before.IP.IsValid() || before.IP == netip.Addr{})
		assert.Equal(t, before, after, "all calls of one attempt see the same Attempt")
	})

	t.Run("case=wrong password calls BeforeAttempt then AfterFailure", func(t *testing.T) {
		rec.reset()
		_, res := login(t, identifier, "wrong-password")
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, rec.names())
		assert.Equal(t, rec.calls[0].Attempt, rec.calls[1].Attempt)
	})

	t.Run("case=unknown identifier calls BeforeAttempt then AfterFailure", func(t *testing.T) {
		rec.reset()
		_, res := login(t, x.NewUUID().String(), pwd)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, rec.names())
		assert.Equal(t, rec.calls[0].Attempt, rec.calls[1].Attempt, "unknown accounts look the same as known ones")
	})

	t.Run("case=deny stops before lookup and hashing and reports 429", func(t *testing.T) {
		rec.reset()
		rec.decision = defense.Decision{Verdict: defense.Deny, Reason: "test"}
		// The correct password must still be rejected.
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.names())
	})

	t.Run("case=BeforeAttempt error fails open", func(t *testing.T) {
		rec.reset()
		rec.err = errors.New("valkey is down")
		// Any decision returned alongside the error is ignored.
		rec.decision = defense.Decision{Verdict: defense.Deny, Delay: time.Hour}
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, rec.names())
	})

	t.Run("case=deny reports Retry-After rounded up to whole seconds", func(t *testing.T) {
		rec.reset()
		rec.decision = defense.Decision{Verdict: defense.Deny, RetryAfter: 1500 * time.Millisecond}
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, "2", res.Header.Get("Retry-After"))
	})

	t.Run("case=deny without RetryAfter sets no header", func(t *testing.T) {
		rec.reset()
		rec.decision = defense.Decision{Verdict: defense.Deny}
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Empty(t, res.Header.Get("Retry-After"))
	})

	// Timing of the delay is covered with synctest in defense.TestWait; here we
	// only check that the flow continues, or stops, correctly after a delay.
	const delay = time.Millisecond

	t.Run("case=allow with delay proceeds", func(t *testing.T) {
		rec.reset()
		rec.decision = defense.Decision{Delay: delay}
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, rec.names())
	})

	t.Run("case=deny with delay rejects", func(t *testing.T) {
		rec.reset()
		rec.decision = defense.Decision{Verdict: defense.Deny, Delay: delay}
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.names())
	})

	// The cap itself is tested with synctest in defense.TestDecisionWait; here
	// only the configuration wiring.
	t.Run("case=max delay is configurable", func(t *testing.T) {
		t.Parallel()
		_, fresh := pkg.NewFastRegistryWithMocks(t)
		assert.Equal(t, config.DefenseDefaultMaxDelay, fresh.Config().DefenseMaxDelay(t.Context()))
		require.NoError(t, fresh.Config().Set(t.Context(), config.ViperKeyDefenseMaxDelay, "10ms"))
		assert.Equal(t, 10*time.Millisecond, fresh.Config().DefenseMaxDelay(t.Context()))
	})

	t.Run("case=undecodable credentials are reported to neither After method", func(t *testing.T) {
		rec.reset()
		broken, iid := x.NewUUID().String(), x.NewUUID()
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(t.Context(), &identity.Identity{
			ID:     iid,
			Traits: identity.Traits(fmt.Sprintf(`{"subject":"%s"}`, broken)),
			Credentials: map[identity.CredentialsType]identity.Credentials{
				identity.CredentialsTypePassword: {
					Type:        identity.CredentialsTypePassword,
					Identifiers: []string{broken},
					Config:      sqlxx.JSONRawMessage(`{"hashed_password": 5}`),
				},
			},
		}))
		_, res := login(t, broken, pwd)
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.names())
	})

	t.Run("case=rejections before the defense make no calls", func(t *testing.T) {
		t.Run("malformed payload", func(t *testing.T) {
			rec.reset()
			_, res := loginRaw(t, apiClient, map[string]string{"method": "password", "identifier": identifier})
			assert.Equal(t, http.StatusBadRequest, res.StatusCode)
			assert.Empty(t, rec.names())
		})

		t.Run("AAL2 requested", func(t *testing.T) {
			rec.reset()
			f := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, apiClient, publicTS, false)
			update, err := reg.LoginFlowPersister().GetLoginFlow(t.Context(), uuid.FromStringOrNil(f.Id))
			require.NoError(t, err)
			update.RequestedAAL = identity.AuthenticatorAssuranceLevel2
			require.NoError(t, reg.LoginFlowPersister().UpdateLoginFlow(t.Context(), update))
			testhelpers.LoginMakeRequest(t, true, false, f, apiClient,
				fmt.Sprintf(`{"method":"password","identifier":%q,"password":%q}`, identifier, pwd))
			assert.Empty(t, rec.names())
		})
	})

	t.Run("case=browser flow calls the defense too", func(t *testing.T) {
		rec.reset()
		redirTS := testhelpers.NewRedirSessionEchoTS(t, reg)
		browserClient := testhelpers.NewClientWithCookies(t)
		testhelpers.SubmitLoginForm(t, false, browserClient, publicTS, func(v url.Values) {
			v.Set("identifier", identifier)
			v.Set("password", pwd)
		}, false, false, http.StatusOK, redirTS.URL)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, rec.names())
	})

	t.Run("suite=password migration hook", func(t *testing.T) {
		var (
			mu   sync.Mutex
			resp = `{"status":"password_match"}`
		)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			mu.Lock()
			defer mu.Unlock()
			_, _ = io.WriteString(w, resp)
		}))
		t.Cleanup(ts.Close)

		_, hookReg := pkg.NewFastRegistryWithMocks(t,
			configx.WithValue(config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword)+".enabled", true),
			configx.WithValues(testhelpers.IdentitySchemasConfig(map[string]string{
				"default": "file://./stub/migration.schema.json",
			})),
			configx.WithValue(config.ViperKeyPasswordMigrationHook, map[string]any{
				"config":  map[string]any{"url": ts.URL},
				"enabled": true,
			}),
		)
		hookRec := new(recordingDefense)
		hookReg.WithDefense(hookRec)
		hookTS, _ := testhelpers.NewKratosServerWithRouters(t, hookReg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
		testhelpers.NewErrorTestServer(t, hookReg)
		client := testhelpers.NewDebugClient(t)

		create := func(t *testing.T) string {
			email := x.NewUUID().String() + "@example.com"
			iid := x.NewUUID()
			require.NoError(t, hookReg.PrivilegedIdentityPool().CreateIdentity(t.Context(), &identity.Identity{
				ID:     iid,
				Traits: identity.Traits(fmt.Sprintf(`{"email":%q}`, email)),
				Credentials: map[identity.CredentialsType]identity.Credentials{
					identity.CredentialsTypePassword: {
						Type:        identity.CredentialsTypePassword,
						Identifiers: []string{email},
						Config:      sqlxx.JSONRawMessage(`{"use_password_migration_hook": true}`),
					},
				},
			}))
			return email
		}
		submit := func(t *testing.T, email string) *http.Response {
			f := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, client, hookTS, false)
			_, res := testhelpers.LoginMakeRequest(t, true, false, f, client,
				fmt.Sprintf(`{"method":"password","identifier":%q,"password":"whatever-password"}`, email))
			return res
		}
		setResp := func(r string) { mu.Lock(); resp = r; mu.Unlock() }

		t.Run("case=hook accepts the password", func(t *testing.T) {
			setResp(`{"status":"password_match"}`)
			hookRec.reset()
			assert.Equal(t, http.StatusOK, submit(t, create(t)).StatusCode)
			assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, hookRec.names())
		})

		t.Run("case=hook rejects the password", func(t *testing.T) {
			setResp(`{"status":"password_no_match"}`)
			hookRec.reset()
			assert.NotEqual(t, http.StatusOK, submit(t, create(t)).StatusCode)
			assert.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, hookRec.names())
		})
	})
}
