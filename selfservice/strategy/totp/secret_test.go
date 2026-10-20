// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package totp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	stdtotp "github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/herodot"
	"github.com/ory/kratos/cipher"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/strategy/totp"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

const (
	keyOne = "0123456789abcdef0123456789abcdef"
	keyTwo = "fedcba9876543210fedcba9876543210"
)

func totpKeys(ids ...string) []map[string]string {
	secrets := map[string]string{"one": keyOne, "two": keyTwo}
	var out []map[string]string
	for _, id := range ids {
		out = append(out, map[string]string{"id": id, "key": secrets[id]})
	}
	return out
}

// newSecretsRegistry has its own registry, so that each test owns its configuration.
func newSecretsRegistry(t *testing.T, keys []map[string]string, acceptPlaintext bool) (*config.Config, *driver.RegistryDefault, *httptest.Server) {
	conf, reg := pkg.NewFastRegistryWithMocks(t,
		configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypePassword, true)),
		configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypeTOTP, true)),
		configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/login.schema.json")),
		configx.WithValues(map[string]any{
			config.ViperKeySecretsTOTP:         keys,
			config.ViperKeyTOTPAcceptPlaintext: acceptPlaintext,
		}),
	)
	publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
	return conf, reg, publicTS
}

func storedURL(t *testing.T, reg *driver.RegistryDefault, id uuid.UUID) string {
	_, cred, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(t.Context(), identity.CredentialsTypeTOTP, id.String())
	require.NoError(t, err)
	return gjson.GetBytes(cred.Config, "totp_url").String()
}

func setStoredURL(t *testing.T, reg *driver.RegistryDefault, id uuid.UUID, value string) {
	require.NoError(t, reg.PrivilegedIdentityPool().UpdateCredentialsConfig(t.Context(), id, identity.CredentialsTypeTOTP, func([]byte) ([]byte, error) {
		return json.Marshal(identity.CredentialsTOTPConfig{TOTPURL: value})
	}))
}

// loginAAL2 submits the code in an AAL2 API login flow and returns whether it was accepted.
func loginAAL2(t *testing.T, reg *driver.RegistryDefault, publicTS *httptest.Server, id *identity.Identity, code string) bool {
	status, body := loginAAL2Response(t, reg, publicTS, id, code)
	return status == http.StatusOK && gjson.Get(body, "session.active").Bool()
}

// loginAAL2Response submits the code in an AAL2 API login flow and returns the status and body of the answer.
func loginAAL2Response(t *testing.T, reg *driver.RegistryDefault, publicTS *httptest.Server, id *identity.Identity, code string) (int, string) {
	apiClient := testhelpers.NewHTTPClientWithIdentitySessionToken(t.Context(), t, reg, id)
	f := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, apiClient, publicTS, false, testhelpers.InitFlowWithAAL(identity.AuthenticatorAssuranceLevel2))
	values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
	values.Set("method", "totp")
	values.Set("totp_code", code)
	body, res := testhelpers.LoginMakeRequestCtx(t.Context(), t, true, false, f, apiClient, testhelpers.EncodeFormAsJSON(t, true, values))
	return res.StatusCode, body
}

func TestSecretsAtRestLogin(t *testing.T) {
	t.Parallel()

	// Each subtest has its own registry and database: parallel writers on one SQLite database get SQLITE_BUSY.
	t.Run("case=a plaintext secret is encrypted with the first key on use", func(t *testing.T) {
		t.Parallel()
		_, reg, publicTS := newSecretsRegistry(t, totpKeys("two", "one"), true)
		id, _, key := createIdentity(t.Context(), t, reg)
		require.Equal(t, key.URL(), storedURL(t, reg, id.ID))

		// A wrong code does not migrate.
		assert.False(t, loginAAL2(t, reg, publicTS, id, "111111"))
		assert.Equal(t, key.URL(), storedURL(t, reg, id.ID))

		code, err := stdtotp.GenerateCode(key.Secret(), time.Now())
		require.NoError(t, err)
		assert.True(t, loginAAL2(t, reg, publicTS, id, code))

		stored := storedURL(t, reg, id.ID)
		assert.Regexp(t, `^two:[0-9a-f]+$`, stored)
		assert.NotContains(t, stored, key.Secret())

		// The encrypted secret works.
		code, err = stdtotp.GenerateCode(key.Secret(), time.Now())
		require.NoError(t, err)
		assert.True(t, loginAAL2(t, reg, publicTS, id, code))
		assert.Equal(t, stored, storedURL(t, reg, id.ID), "unchanged")
	})

	t.Run("case=a secret under an old key is re-encrypted with the first one", func(t *testing.T) {
		t.Parallel()
		_, reg, publicTS := newSecretsRegistry(t, totpKeys("two", "one"), true)
		id, _, key := createIdentity(t.Context(), t, reg)
		// As an older version of the configuration encrypted it, with key "one" first.
		old, err := cipher.NewKeyedAES(oneKey{}).EncryptWithAAD(t.Context(), []byte(key.URL()), []byte(id.ID.String()))
		require.NoError(t, err)
		require.Regexp(t, `^one:`, old)
		setStoredURL(t, reg, id.ID, old)

		code, err := stdtotp.GenerateCode(key.Secret(), time.Now())
		require.NoError(t, err)
		assert.True(t, loginAAL2(t, reg, publicTS, id, code))
		assert.Regexp(t, `^two:[0-9a-f]+$`, storedURL(t, reg, id.ID))
	})

	t.Run("case=a ciphertext copied to another identity is useless", func(t *testing.T) {
		t.Parallel()
		_, reg, publicTS := newSecretsRegistry(t, totpKeys("two", "one"), true)
		victim, _, key := createIdentity(t.Context(), t, reg)
		code, err := stdtotp.GenerateCode(key.Secret(), time.Now())
		require.NoError(t, err)
		require.True(t, loginAAL2(t, reg, publicTS, victim, code))
		copied := storedURL(t, reg, victim.ID)
		require.Regexp(t, `^two:`, copied)

		attacker, _, _ := createIdentity(t.Context(), t, reg)
		setStoredURL(t, reg, attacker.ID, copied)

		assert.False(t, loginAAL2(t, reg, publicTS, attacker, code))
		assert.Equal(t, copied, storedURL(t, reg, attacker.ID), "left alone")
	})

	t.Run("case=an unknown key id fails", func(t *testing.T) {
		t.Parallel()
		_, reg, publicTS := newSecretsRegistry(t, totpKeys("two", "one"), true)
		hook := logtest.NewLocal(reg.Logger().Logger)
		id, _, key := createIdentity(t.Context(), t, reg)
		retired, err := cipher.NewKeyedAES(oneKey{id: "retired"}).EncryptWithAAD(t.Context(), []byte(key.URL()), []byte(id.ID.String()))
		require.NoError(t, err)
		setStoredURL(t, reg, id.ID, retired)

		code, err := stdtotp.GenerateCode(key.Secret(), time.Now())
		require.NoError(t, err)
		// The right code, but the secret cannot be opened: a fault of the server (a key dropped from
		// secrets.totp), which the user cannot fix.
		status, body := loginAAL2Response(t, reg, publicTS, id, code)
		assert.Equal(t, http.StatusInternalServerError, status, body)
		assert.Equal(t, "invalid_configuration", gjson.Get(body, "error.id").String(), body)
		assert.Equal(t, "The TOTP secret could not be opened.", gjson.Get(body, "error.reason").String(), body)
		assert.NotContains(t, body, "retired", "the key id is for the log only")
		assert.Equal(t, retired, storedURL(t, reg, id.ID))

		// The operator learns which key is missing.
		assert.True(t, slices.ContainsFunc(hook.AllEntries(), func(e *logrus.Entry) bool {
			fields, _ := e.Data["error"].(map[string]any)
			debug, _ := fields["debug"].(string)
			return strings.Contains(debug, `unknown key id "retired"`)
		}), "no log line names the key id")
	})

	t.Run("case=the identity still counts as having TOTP once encrypted", func(t *testing.T) {
		t.Parallel()
		_, reg, publicTS := newSecretsRegistry(t, totpKeys("two", "one"), true)
		id, _, key := createIdentity(t.Context(), t, reg)
		code, err := stdtotp.GenerateCode(key.Secret(), time.Now())
		require.NoError(t, err)
		require.True(t, loginAAL2(t, reg, publicTS, id, code))

		got, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(t.Context(), id.ID)
		require.NoError(t, err)
		n, err := totp.NewStrategy(reg).CountActiveMultiFactorCredentials(t.Context(), got.Credentials)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
	})
}

func TestSecretsAtRestPlaintextRefused(t *testing.T) {
	t.Parallel()

	_, reg, publicTS := newSecretsRegistry(t, totpKeys("one"), false)
	id, _, key := createIdentity(t.Context(), t, reg)

	code, err := stdtotp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	// Refused by configuration: a fault of the server, not of the code (see "an unknown key id fails").
	status, body := loginAAL2Response(t, reg, publicTS, id, code)
	assert.Equal(t, http.StatusInternalServerError, status, body)
	assert.Equal(t, "invalid_configuration", gjson.Get(body, "error.id").String(), body)
	assert.Equal(t, "The TOTP secret could not be opened.", gjson.Get(body, "error.reason").String(), body)
	assert.Equal(t, key.URL(), storedURL(t, reg, id.ID), "not touched")
}

func TestSecretsAtRestSettings(t *testing.T) {
	t.Parallel()

	enroll := func(t *testing.T, reg *driver.RegistryDefault, publicTS *httptest.Server) (*identity.Identity, string) {
		id := createIdentityWithoutTOTP(t.Context(), t, reg)
		apiClient := testhelpers.NewHTTPClientWithIdentitySessionToken(t.Context(), t, reg, id)
		f := testhelpers.InitializeSettingsFlowViaAPI(t, apiClient, publicTS)

		nodes, err := json.Marshal(f.Ui.Nodes)
		require.NoError(t, err)
		secret := gjson.GetBytes(nodes, "#(attributes.id==totp_secret_key).attributes.text.context.secret").String()
		require.NotEmpty(t, secret)
		code, err := stdtotp.GenerateCode(secret, time.Now())
		require.NoError(t, err)

		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "totp")
		values.Set("totp_code", code)
		body, res := testhelpers.SettingsMakeRequest(t, true, false, f, apiClient, testhelpers.EncodeFormAsJSON(t, true, values))
		require.Equal(t, http.StatusOK, res.StatusCode, body)
		return id, secret
	}

	t.Run("case=a new secret is encrypted before it enters the database", func(t *testing.T) {
		t.Parallel()
		_, reg, publicTS := newSecretsRegistry(t, totpKeys("two", "one"), false)
		id, secret := enroll(t, reg, publicTS)

		stored := storedURL(t, reg, id.ID)
		assert.Regexp(t, `^two:[0-9a-f]+$`, stored)
		assert.NotContains(t, stored, secret)

		plain, err := reg.TOTPCipher(t.Context()).DecryptWithAAD(t.Context(), stored, []byte(id.ID.String()))
		require.NoError(t, err)
		assert.Contains(t, string(plain), secret)
	})

	t.Run("case=without keys it is stored as before while plaintext is accepted", func(t *testing.T) {
		t.Parallel()
		_, reg, publicTS := newSecretsRegistry(t, nil, true)
		id, secret := enroll(t, reg, publicTS)
		assert.Contains(t, storedURL(t, reg, id.ID), secret)
	})

	t.Run("case=without keys and without plaintext enrollment fails and stores nothing", func(t *testing.T) {
		t.Parallel()
		_, reg, publicTS := newSecretsRegistry(t, nil, false)
		id := createIdentityWithoutTOTP(t.Context(), t, reg)
		apiClient := testhelpers.NewHTTPClientWithIdentitySessionToken(t.Context(), t, reg, id)
		f := testhelpers.InitializeSettingsFlowViaAPI(t, apiClient, publicTS)
		nodes, err := json.Marshal(f.Ui.Nodes)
		require.NoError(t, err)
		code, err := stdtotp.GenerateCode(gjson.GetBytes(nodes, "#(attributes.id==totp_secret_key).attributes.text.context.secret").String(), time.Now())
		require.NoError(t, err)

		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "totp")
		values.Set("totp_code", code)
		_, res := testhelpers.SettingsMakeRequest(t, true, false, f, apiClient, testhelpers.EncodeFormAsJSON(t, true, values))
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)

		_, _, err = reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(t.Context(), identity.CredentialsTypeTOTP, id.ID.String())
		require.Error(t, err)
	})
}

func TestSealOpenURL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	newReg := func(t *testing.T, keys []map[string]string, accept bool) driver.Registry {
		_, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValues(map[string]any{
			config.ViperKeySecretsTOTP:         keys,
			config.ViperKeyTOTPAcceptPlaintext: accept,
		}))
		return reg
	}
	owner := uuid.Must(uuid.NewV4())
	const plain = "otpauth://totp/x?secret=ABC"

	t.Run("case=upgrade is empty when current, and for plaintext without keys", func(t *testing.T) {
		t.Parallel()
		reg := newReg(t, totpKeys("one"), true)
		sealed, err := totp.SealURL(ctx, reg, owner, plain)
		require.NoError(t, err)
		up, err := totp.UpgradeURL(ctx, reg, owner, sealed)
		require.NoError(t, err)
		assert.Empty(t, up)

		up, err = totp.UpgradeURL(ctx, newReg(t, nil, true), owner, plain)
		require.NoError(t, err)
		assert.Empty(t, up)
	})

	t.Run("case=the migration reads plaintext even if login does not", func(t *testing.T) {
		t.Parallel()
		reg := newReg(t, totpKeys("one"), false)
		_, _, err := totp.OpenURL(ctx, reg, owner, plain)
		require.Error(t, err)

		up, err := totp.UpgradeURL(ctx, reg, owner, plain)
		require.NoError(t, err)
		assert.Regexp(t, `^one:`, up)
	})

	t.Run("case=garbage is neither", func(t *testing.T) {
		t.Parallel()
		_, _, err := totp.OpenURL(ctx, newReg(t, totpKeys("one"), true), owner, "totp://")
		require.Error(t, err)
	})

	// A secret that cannot be opened is a fault of the server, which the user cannot fix. The reason is the same
	// for every cause; the cause, which may name a key id, is in debug, which the log shows and responses do not.
	assertServerFault := func(t *testing.T, err error, id, cause string) {
		t.Helper()
		var e *herodot.DefaultError
		require.ErrorAs(t, err, &e)
		assert.Equal(t, http.StatusInternalServerError, e.StatusCode())
		assert.Equal(t, id, e.ID())
		assert.Equal(t, "The TOTP secret could not be opened.", e.Reason())
		assert.Contains(t, e.Debug(), cause)
	}

	t.Run("case=an unknown key id is a misconfiguration", func(t *testing.T) {
		t.Parallel()
		retired, err := cipher.NewKeyedAES(oneKey{id: "retired"}).EncryptWithAAD(ctx, []byte(plain), []byte(owner.String()))
		require.NoError(t, err)
		_, _, err = totp.OpenURL(ctx, newReg(t, totpKeys("one"), true), owner, retired)
		assertServerFault(t, err, "invalid_configuration", `unknown key id "retired"`)
		assert.ErrorIs(t, err, cipher.ErrUnknownKeyID)
	})

	t.Run("case=refused plaintext is a misconfiguration", func(t *testing.T) {
		t.Parallel()
		_, _, err := totp.OpenURL(ctx, newReg(t, totpKeys("one"), false), owner, plain)
		assertServerFault(t, err, "invalid_configuration", "plaintext")
	})

	t.Run("case=a secret of another identity does not decrypt", func(t *testing.T) {
		t.Parallel()
		reg := newReg(t, totpKeys("one"), true)
		sealed, err := totp.SealURL(ctx, reg, uuid.Must(uuid.NewV4()), plain)
		require.NoError(t, err)
		_, _, err = totp.OpenURL(ctx, reg, owner, sealed)
		assertServerFault(t, err, "", "Unable to decipher the encrypted message.")
	})
}

type oneKey struct{ id string }

func (o oneKey) KeyedSecrets(context.Context) []cipher.KeyEntry {
	id := o.id
	if id == "" {
		id = "one"
	}
	e := cipher.KeyEntry{ID: id}
	copy(e.Key[:], keyOne)
	return []cipher.KeyEntry{e}
}
