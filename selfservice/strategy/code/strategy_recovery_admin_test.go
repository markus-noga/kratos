// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	kratos "github.com/ory/kratos/pkg/httpclient"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/recovery"
	. "github.com/ory/kratos/selfservice/strategy/code"
	"github.com/ory/kratos/x"
	"github.com/ory/x/configx"
	"github.com/ory/x/ioutilx"
	"github.com/ory/x/snapshotx"
)

func TestAdminStrategy(t *testing.T) {
	t.Parallel()

	conf, reg := pkg.NewFastRegistryWithMocks(t,
		configx.WithValues(defaultConfig),
		configx.WithValue(config.ViperKeyUseContinueWithTransitions, true),
	)

	_ = testhelpers.NewRecoveryUIFlowEchoServer(t, reg)
	_ = testhelpers.NewSettingsUIFlowEchoServer(t, reg)
	_ = testhelpers.NewLoginUIFlowEchoServer(t, reg)
	_ = testhelpers.NewErrorTestServer(t, reg)

	publicTS, adminTS := testhelpers.NewKratosServer(t, reg)
	adminSDK := testhelpers.NewSDKClient(adminTS)

	type createCodeParams = kratos.CreateRecoveryCodeForIdentityBody
	createCode := func(params createCodeParams) (*kratos.RecoveryCodeForIdentity, *http.Response, error) {
		return adminSDK.IdentityAPI.
			CreateRecoveryCodeForIdentity(context.Background()).
			CreateRecoveryCodeForIdentityBody(params).Execute()
	}

	t.Run("no panic on empty body #1384", func(t *testing.T) {
		ctx := context.Background()
		s, ps, err := reg.RecoveryStrategies(ctx).ActiveStrategies("code")
		require.NoError(t, err)
		require.Len(t, s, 1)
		w := httptest.NewRecorder()
		r := &http.Request{URL: new(url.URL)}
		f, err := recovery.NewFlow(reg, time.Minute, "", r, s, flow.TypeBrowser)
		require.NoError(t, err)
		require.NotPanics(t, func() {
			require.Error(t, ps.(*Strategy).HandleRecoveryError(w, r, f, nil, errors.New("test")))
		})
	})

	t.Run("description=should not be able to recover an account that does not exist", func(t *testing.T) {
		_, _, err := createCode(createCodeParams{IdentityId: x.NewUUID().String()})

		require.IsType(t, err, new(kratos.GenericOpenAPIError), "%T", err)
		snapshotx.SnapshotT(t, err.(*kratos.GenericOpenAPIError).Model())
	})

	t.Run("description=should fail on malformed expiry time", func(t *testing.T) {
		_, _, err := createCode(createCodeParams{IdentityId: x.NewUUID().String(), ExpiresIn: new("not-a-valid-value")})
		require.IsType(t, err, new(kratos.GenericOpenAPIError), "%T", err)
		snapshotx.SnapshotT(t, err.(*kratos.GenericOpenAPIError).Model())
	})

	t.Run("description=should fail on negative expiry time", func(t *testing.T) {
		_, _, err := createCode(createCodeParams{IdentityId: x.NewUUID().String(), ExpiresIn: new("-1h")})
		require.IsType(t, err, new(kratos.GenericOpenAPIError), "%T", err)
		snapshotx.SnapshotT(t, err.(*kratos.GenericOpenAPIError).Model())
	})

	submitRecoveryCode := func(t *testing.T, client *http.Client, link string, code string) []byte {
		t.Helper()
		if client == nil {
			client = publicTS.Client()
		}
		res, err := client.Get(link)
		require.NoError(t, err)
		body := ioutilx.MustReadAll(res.Body)

		action := gjson.GetBytes(body, "ui.action").String()
		require.NotEmpty(t, action)

		res, err = client.PostForm(action, url.Values{
			"code": {code},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		return ioutilx.MustReadAll(res.Body)
	}

	assertEmailNotVerified := func(t *testing.T, email string) {
		addr, err := reg.IdentityPool().FindVerifiableAddressByValue(context.Background(), identity.AddressTypeEmail, email)
		assert.NoError(t, err)
		assert.False(t, addr.Verified)
		assert.Nil(t, addr.VerifiedAt)
		assert.Equal(t, identity.VerifiableAddressStatusPending, addr.Status)
	}

	t.Run("description=should create code without email", func(t *testing.T) {
		id := identity.Identity{Traits: identity.Traits(`{}`)}

		require.NoError(t, reg.IdentityManager().Create(context.Background(),
			&id, identity.ManagerAllowWriteProtectedTraits))

		code, _, err := createCode(createCodeParams{IdentityId: id.ID.String()})
		require.NoError(t, err)

		require.NotEmpty(t, code.RecoveryLink)
		require.Contains(t, code.RecoveryLink, "flow=")
		require.NotContains(t, code.RecoveryLink, "code=")
		require.NotEmpty(t, code.RecoveryCode)
		require.True(t, code.ExpiresAt.Before(time.Now().Add(conf.SelfServiceFlowRecoveryRequestLifespan(t.Context()))))

		client := new(*publicTS.Client())
		client.Jar, _ = cookiejar.New(nil)
		body := submitRecoveryCode(t, client, code.RecoveryLink, code.RecoveryCode)
		testhelpers.AssertMessage(t, body, "You successfully recovered your account. Please change your password or set up an alternative login method (e.g. social sign in) within the next 60.00 minutes.")
		u, err := url.Parse(publicTS.URL)
		require.NoError(t, err)
		cs := client.Jar.Cookies(u)
		require.Len(t, cs, 1, "%s", body)
		assert.Equal(t, "ory_kratos_session", cs[0].Name, "%s", body)
	})

	t.Run("description=should not be able to recover with expired code", func(t *testing.T) {
		recoveryEmail := "recover.expired@ory.sh"
		id := identity.Identity{Traits: identity.Traits(fmt.Sprintf(`{"email":"%s"}`, recoveryEmail))}

		require.NoError(t, reg.IdentityManager().Create(context.Background(),
			&id, identity.ManagerAllowWriteProtectedTraits))

		code, _, err := createCode(createCodeParams{IdentityId: id.ID.String(), ExpiresIn: new("100ms")})
		require.NoError(t, err)

		time.Sleep(time.Millisecond * 100)
		require.NotEmpty(t, code.RecoveryLink)
		require.True(t, code.ExpiresAt.Before(time.Now().Add(conf.SelfServiceFlowRecoveryRequestLifespan(t.Context()))))

		body := submitRecoveryCode(t, nil, code.RecoveryLink, code.RecoveryCode)
		assert.Contains(t, gjson.GetBytes(body, "ui.messages.0.text").Str, "The recovery flow expired", "%s", body)

		// The recovery address should not be verified if the flow was initiated by the admins
		assertEmailNotVerified(t, recoveryEmail)
	})

	t.Run("description=should create a valid recovery link and set the expiry time as well and recover the account", func(t *testing.T) {
		recoveryEmail := "recoverme@ory.sh"
		id := identity.Identity{Traits: identity.Traits(fmt.Sprintf(`{"email":"%s"}`, recoveryEmail))}

		require.NoError(t, reg.IdentityManager().Create(context.Background(),
			&id, identity.ManagerAllowWriteProtectedTraits))

		code, _, err := createCode(createCodeParams{IdentityId: id.ID.String()})
		require.NoError(t, err)

		require.NotEmpty(t, code.RecoveryLink)
		require.True(t, code.ExpiresAt.Before(time.Now().Add(conf.SelfServiceFlowRecoveryRequestLifespan(t.Context())+time.Second)))

		body := submitRecoveryCode(t, nil, code.RecoveryLink, code.RecoveryCode)

		testhelpers.AssertMessage(t, body, "You successfully recovered your account. Please change your password or set up an alternative login method (e.g. social sign in) within the next 60.00 minutes.")

		// The recovery address should be verified if the flow was initiated by the admins
		assertEmailNotVerified(t, recoveryEmail)
	})

	t.Run("description=should respect custom expires_in in response", func(t *testing.T) {
		id := identity.Identity{Traits: identity.Traits(`{}`)}
		require.NoError(t, reg.IdentityManager().Create(context.Background(),
			&id, identity.ManagerAllowWriteProtectedTraits))

		code, _, err := createCode(createCodeParams{IdentityId: id.ID.String(), ExpiresIn: new("24h")})
		require.NoError(t, err)

		// The response expires_at must reflect the requested 24h, not the default 1h lifespan.
		require.WithinDuration(t, time.Now().Add(24*time.Hour), *code.ExpiresAt, time.Hour)
	})

	t.Run("case=should not be able to use code from different flow", func(t *testing.T) {
		email := testhelpers.RandomEmail()
		i := createIdentityToRecover(t, reg, email)

		c1, _, err := createCode(createCodeParams{IdentityId: i.ID.String(), ExpiresIn: new("1h")})
		require.NoError(t, err)
		c2, _, err := createCode(createCodeParams{IdentityId: i.ID.String(), ExpiresIn: new("1h")})
		require.NoError(t, err)
		code2 := c2.RecoveryCode
		require.NotEmpty(t, code2)

		body := submitRecoveryCode(t, nil, c1.RecoveryLink, c2.RecoveryCode)

		testhelpers.AssertMessage(t, body, "The recovery code is invalid or has already been used. Please try again.")
	})

	t.Run("case=form should not contain email field when creating recovery code", func(t *testing.T) {
		email := testhelpers.RandomEmail()
		i := createIdentityToRecover(t, reg, email)

		c1, _, err := createCode(createCodeParams{IdentityId: i.ID.String(), ExpiresIn: new("1h")})
		require.NoError(t, err)

		res, err := testhelpers.NewTestClient(t).Get(c1.RecoveryLink)
		require.NoError(t, err)
		body := ioutilx.MustReadAll(res.Body)

		snapshotx.SnapshotT(t, json.RawMessage(gjson.GetBytes(body, "ui.nodes").String()))
	})

	t.Run("case=should be able to create and complete an API flow", func(t *testing.T) {
		email := testhelpers.RandomEmail()
		i := createIdentityToRecover(t, reg, email)

		code, _, err := createCode(createCodeParams{IdentityId: i.ID.String(), FlowType: new(string(flow.TypeAPI))})
		require.NoError(t, err)

		res, err := publicTS.Client().Get(code.RecoveryLink)
		require.NoError(t, err)
		body := ioutilx.MustReadAll(res.Body)

		action := gjson.GetBytes(body, "ui.action").String()
		require.NotEmpty(t, action)

		res, err = publicTS.Client().Post(action, "application/json", strings.NewReader(fmt.Sprintf(`{"code":"%s"}`, code.RecoveryCode)))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		continueWith := gjson.GetBytes(ioutilx.MustReadAll(res.Body), "continue_with").Array()
		require.Len(t, continueWith, 2)
		assert.EqualValues(t, flow.ContinueWithActionSetOrySessionTokenString, continueWith[0].Get("action").String())
	})

	const (
		recovered     = "You successfully recovered your account. Please change your password or set up an alternative login method (e.g. social sign in) within the next 60.00 minutes."
		invalidOrUsed = "The recovery code is invalid or has already been used. Please try again."
	)

	setState := func(t *testing.T, i *identity.Identity, state identity.State, method string) {
		t.Helper()
		var err error
		switch method {
		case "update":
			var traits map[string]any
			require.NoError(t, json.Unmarshal(i.Traits, &traits))
			_, _, err = adminSDK.IdentityAPI.UpdateIdentity(t.Context(), i.ID.String()).UpdateIdentityBody(kratos.UpdateIdentityBody{
				SchemaId: i.SchemaID,
				State:    string(state),
				Traits:   traits,
			}).Execute()
		case "patch":
			_, _, err = adminSDK.IdentityAPI.PatchIdentity(t.Context(), i.ID.String()).JsonPatch([]kratos.JsonPatch{
				{Op: "replace", Path: "/state", Value: string(state)},
			}).Execute()
		default:
			t.Fatalf("unknown method %q", method)
		}
		require.NoError(t, err)
	}

	// recordLog records the registry's log at info level until the case ends. The registry is shared: the cases that
	// use it run one at a time, as all here do.
	recordLog := func(t *testing.T) *logtest.Hook {
		t.Helper()
		l := reg.Logger().Logger
		level := l.GetLevel()
		l.SetLevel(logrus.InfoLevel)
		// The hook goes into a copy of the logger's hooks, and the case's end puts the
		// old ones back, so that it stops recording when the case ends.
		hooks := make(logrus.LevelHooks)
		for lvl, hs := range l.Hooks {
			hooks[lvl] = append([]logrus.Hook(nil), hs...)
		}
		old := l.ReplaceHooks(hooks)
		t.Cleanup(func() { l.ReplaceHooks(old); l.SetLevel(level) })
		return logtest.NewLocal(l)
	}
	// voidedInLog returns the voided counts of the last log line with the message for the identity.
	voidedInLog := func(t *testing.T, log *logtest.Hook, message string, id uuid.UUID) (codes, links any) {
		t.Helper()
		for _, e := range slices.Backward(log.AllEntries()) {
			if e.Message == message && e.Data["identity_id"] == id {
				return e.Data["voided_recovery_codes"], e.Data["voided_recovery_links"]
			}
		}
		t.Fatalf("no log line %q for identity %s", message, id)
		return nil, nil
	}

	// Sequential like the cases above: they share one SQLite database, where concurrent requests can deadlock on
	// pop's statement mutex against the write lock until the busy timeout.
	t.Run("case=a new code voids the codes created before", func(t *testing.T) {
		i := createIdentityToRecover(t, reg, testhelpers.RandomEmail())
		log := recordLog(t)

		older, _, err := createCode(createCodeParams{IdentityId: i.ID.String()})
		require.NoError(t, err)
		newer, _, err := createCode(createCodeParams{IdentityId: i.ID.String()})
		require.NoError(t, err)

		testhelpers.AssertMessage(t, submitRecoveryCode(t, nil, older.RecoveryLink, older.RecoveryCode), invalidOrUsed)
		testhelpers.AssertMessage(t, submitRecoveryCode(t, nil, newer.RecoveryLink, newer.RecoveryCode), recovered)

		// The log tells why the older code stopped working.
		codes, links := voidedInLog(t, log, "A recovery code has been created.", i.ID)
		assert.Equal(t, 1, codes, "voided codes")
		assert.Equal(t, 0, links, "voided links")
	})

	t.Run("case=deactivating the identity voids its codes", func(t *testing.T) {
		for _, method := range []string{"update", "patch"} {
			t.Run("method="+method, func(t *testing.T) {
				i := createIdentityToRecover(t, reg, testhelpers.RandomEmail())
				log := recordLog(t)

				c, _, err := createCode(createCodeParams{IdentityId: i.ID.String()})
				require.NoError(t, err)
				setState(t, i, identity.StateInactive, method)
				setState(t, i, identity.StateActive, method)

				testhelpers.AssertMessage(t, submitRecoveryCode(t, nil, c.RecoveryLink, c.RecoveryCode), invalidOrUsed)
				codes, links := voidedInLog(t, log, "Deactivating the identity voided its unused recovery codes and links from the admin API.", i.ID)
				assert.Equal(t, 1, codes, "voided codes")
				assert.Equal(t, 0, links, "voided links")
			})
		}
	})

	t.Run("case=an update that keeps the identity active keeps its code", func(t *testing.T) {
		for _, method := range []string{"update", "patch"} {
			t.Run("method="+method, func(t *testing.T) {
				i := createIdentityToRecover(t, reg, testhelpers.RandomEmail())

				c, _, err := createCode(createCodeParams{IdentityId: i.ID.String()})
				require.NoError(t, err)
				// Only a deactivation voids it. Settings, a password rehash at login and admin edits update an active
				// identity too.
				setState(t, i, identity.StateActive, method)

				testhelpers.AssertMessage(t, submitRecoveryCode(t, nil, c.RecoveryLink, c.RecoveryCode), recovered)
			})
		}
	})

	t.Run("case=a code created while the identity is inactive survives its reactivation", func(t *testing.T) {
		i := createIdentityToRecover(t, reg, testhelpers.RandomEmail())

		setState(t, i, identity.StateInactive, "update")
		c, _, err := createCode(createCodeParams{IdentityId: i.ID.String()})
		require.NoError(t, err)
		// Neither an update that leaves the identity inactive nor the reactivation voids it.
		setState(t, i, identity.StateInactive, "update")
		setState(t, i, identity.StateActive, "update")

		testhelpers.AssertMessage(t, submitRecoveryCode(t, nil, c.RecoveryLink, c.RecoveryCode), recovered)
	})
}
