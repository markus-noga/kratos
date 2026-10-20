// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package totp_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	stdtotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/cipher"
	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/persistence"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

// TestLoginDefense checks the wiring of the TOTP strategy to the defense gate.
// Every subtest has its own registry, server and recorder.
func TestLoginDefense(t *testing.T) {
	t.Parallel()

	// login submits the second factor of a fresh identity and returns what the defense saw, and the answer.
	// prepare, if not nil, runs just before the code is submitted.
	login := func(t *testing.T, answer defense.Decision, code func(*testing.T, string) string, prepare func(*testing.T, *driver.RegistryDefault, *identity.Identity)) (*driver.RegistryDefault, *defensetest.Recorder, *identity.Identity, *http.Response, string) {
		_, reg := pkg.NewFastRegistryWithMocks(t,
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypePassword, true)),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypeTOTP, true)),
			configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/login.schema.json")),
		)
		rec := new(defensetest.Recorder)
		rec.Answer(answer, nil)
		reg.WithDefense(rec)
		publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
		testhelpers.NewErrorTestServer(t, reg)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)

		id, _, key := createIdentity(t.Context(), t, reg)
		secret := key.Secret()
		client := testhelpers.NewHTTPClientWithIdentitySessionToken(t.Context(), t, reg, id)
		f := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, client, publicTS, false, testhelpers.InitFlowWithAAL(identity.AuthenticatorAssuranceLevel2))
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "totp")
		values.Set("totp_code", code(t, secret))
		if prepare != nil {
			prepare(t, reg, id)
		}
		body, res := testhelpers.LoginMakeRequestCtx(t.Context(), t, true, false, f, client, testhelpers.EncodeFormAsJSON(t, true, values))
		return reg, rec, id, res, body
	}
	wrong := func(*testing.T, string) string { return "111111" }
	right := func(t *testing.T, secret string) string {
		c, err := stdtotp.GenerateCode(secret, time.Now())
		require.NoError(t, err)
		return c
	}

	check := func(t *testing.T, reg *driver.RegistryDefault, rec *defensetest.Recorder, id *identity.Identity, names ...string) {
		t.Helper()
		require.Equal(t, names, rec.Names())
		a := rec.Calls()[0].Attempt
		fp := defense.NewFingerprinter(reg.Config().DefenseFingerprintSecret(t.Context()))
		assert.Equal(t, defense.MethodTOTP, a.Method)
		// A second factor is counted against the account of the session, and never gets a known device.
		assert.Equal(t, fp.Identifier(id.ID.String()), a.IdentifierDigest)
		assert.Equal(t, defense.DeviceNone, a.Device)
	}

	t.Run("case=a wrong code is a failure", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, res, _ := login(t, defense.Decision{}, wrong, nil)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		check(t, reg, rec, id, "BeforeAttempt", "AfterFailure")
	})

	t.Run("case=a right code is a success", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, res, _ := login(t, defense.Decision{}, right, nil)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		check(t, reg, rec, id, "BeforeAttempt", "AfterSuccess")
	})

	t.Run("case=a denied attempt stops before the code is checked", func(t *testing.T) {
		t.Parallel()
		// Even the right code is refused.
		reg, rec, id, res, _ := login(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, right, nil)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, "1", res.Header.Get("Retry-After"))
		check(t, reg, rec, id, "BeforeAttempt")
	})

	// Server faults report no outcome: a failure would add backoff for the account, and for others behind the
	// same address, that outlives the repair.
	t.Run("case=a secret that cannot be opened reports no outcome", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, res, _ := login(t, defense.Decision{}, right, func(t *testing.T, reg *driver.RegistryDefault, id *identity.Identity) {
			// Under a key that secrets.totp does not list, e.g. one dropped too early.
			retired, err := cipher.NewKeyedAES(oneKey{id: "retired"}).EncryptWithAAD(t.Context(), []byte("otpauth://totp/x?secret=ABC"), []byte(id.ID.String()))
			require.NoError(t, err)
			setStoredURL(t, reg, id.ID, retired)
		})
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		check(t, reg, rec, id, "BeforeAttempt")
	})

	t.Run("case=a failed lookup of the TOTP credentials reports no outcome", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, _, body := login(t, defense.Decision{}, right, func(_ *testing.T, reg *driver.RegistryDefault, _ *identity.Identity) {
			reg.SetPersister(failingTOTPLookup{reg.Persister()})
		})
		// Not "no TOTP device registered": an error, whose status the API flow takes from it, 400 if it has none.
		assert.EqualValues(t, http.StatusInternalServerError, gjson.Get(body, "error.code").Int(), body)
		check(t, reg, rec, id, "BeforeAttempt")
	})
}

// failingTOTPLookup fails the lookup of TOTP credentials, as an unavailable database does.
type failingTOTPLookup struct{ persistence.Persister }

func (f failingTOTPLookup) FindByCredentialsIdentifier(ctx context.Context, ct identity.CredentialsType, match string) (*identity.Identity, *identity.Credentials, error) {
	if ct == identity.CredentialsTypeTOTP {
		return nil, nil, errors.New("the database is unavailable")
	}
	return f.Persister.FindByCredentialsIdentifier(ctx, ct, match)
}
