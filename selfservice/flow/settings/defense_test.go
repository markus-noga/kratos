// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package settings_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/courier"
	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	kratos "github.com/ory/kratos/pkg/httpclient"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/x/configx"
)

// denyAfter lets the first n attempts through and denies every later one. The
// recorder sees them all.
type denyAfter struct {
	*defensetest.Recorder
	n int
}

func (d denyAfter) BeforeAttempt(ctx context.Context, a defense.Attempt) (defense.Decision, error) {
	if _, err := d.Recorder.BeforeAttempt(ctx, a); err != nil {
		return defense.Decision{}, err
	}
	if len(d.Names()) > d.n {
		return defense.Decision{Verdict: defense.Deny}, nil
	}
	return defense.Decision{}, nil
}

// TestSettingsDefense checks the wiring of the settings flow to the defense.
// Each message a settings update has Kratos send to an address counts as an
// attempt to verify the address. An address the update adds, chosen by the
// client, is checked before anything is saved, so that a deny refuses the
// update, which changes and sends nothing. After any update, whatever its
// strategy, the verification hook messages the identity's pending addresses,
// and checks each of the others right before it is sent: a denied one is
// withheld, and the update stands. The verification flow of a change that
// verify_new_address keeps pending resends its code to the pending address,
// whatever address the client names, and counts the resend for the pending
// address. Every subtest has its own registry, server, identity and recorder.
func TestSettingsDefense(t *testing.T) {
	t.Parallel()

	const (
		owner  = "owner@example.com"
		added  = "added@example.com"
		backup = "backup@example.com"
	)

	verifyNewAddress := configx.WithValue(config.HookStrategyKey(config.ViperKeySelfServiceSettingsAfter, settings.StrategyProfile),
		[]map[string]any{{"hook": "verify_new_address"}})

	type fixture struct {
		reg    *driver.RegistryDefault
		rec    *defensetest.Recorder
		public *httptest.Server
		client *http.Client
		id     *identity.Identity
	}

	// setup serves a registry with verification on, so that the verification hook
	// runs after every update, and creates an identity whose own address is
	// verified. With pending set, it also has the backup address, which is still
	// pending: no message has been sent to it yet. The client holds a privileged
	// API session of the identity. defend, if set, wraps the recorder.
	setup := func(t *testing.T, pending bool, defend func(*defensetest.Recorder) defense.Defense, opts ...configx.OptionModifier) *fixture {
		_, reg := pkg.NewFastRegistryWithMocks(t, append([]configx.OptionModifier{
			configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/defense.schema.json")),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypePassword, true)),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypeLookup, true)),
			configx.WithValues(map[string]any{
				config.ViperKeySelfServiceVerificationEnabled:                   true,
				config.ViperKeySelfServiceVerificationUse:                       "code",
				config.ViperKeySelfServiceSettingsPrivilegedAuthenticationAfter: "10m",
				config.ViperKeyPasswordHaveIBeenPwnedEnabled:                    false,
			}),
		}, opts...)...)
		rec := new(defensetest.Recorder)
		var d defense.Defense = rec
		if defend != nil {
			d = defend(rec)
		}
		reg.WithDefense(d)
		public, _ := testhelpers.NewKratosServer(t, reg)
		testhelpers.NewSettingsUIFlowEchoServer(t, reg)
		testhelpers.NewErrorTestServer(t, reg)

		traits := `{"email":"` + owner + `","name":"Owner"}`
		if pending {
			traits = `{"email":"` + owner + `","backup_email":"` + backup + `","name":"Owner"}`
		}
		id := &identity.Identity{
			Traits:   identity.Traits(traits),
			SchemaID: config.DefaultIdentityTraitsSchemaID,
			State:    identity.StateActive,
		}
		require.NoError(t, reg.IdentityManager().Create(t.Context(), id))
		for k := range id.VerifiableAddresses {
			if a := &id.VerifiableAddresses[k]; a.Value == owner {
				a.Verified, a.Status = true, identity.VerifiableAddressStatusCompleted
				require.NoError(t, reg.PrivilegedIdentityPool().UpdateVerifiableAddress(t.Context(), a, "verified", "status"))
			}
		}

		client := testhelpers.NewHTTPClientWithIdentitySessionToken(t.Context(), t, reg, id)
		return &fixture{reg: reg, rec: rec, public: public, client: client, id: id}
	}

	// submit sends values as a settings update of an API client, in a flow of its own.
	submit := func(t *testing.T, f *fixture, values url.Values) (*http.Response, string) {
		t.Helper()
		sf := testhelpers.InitializeSettingsFlowViaAPI(t, f.client, f.public)
		body, res := testhelpers.SettingsMakeRequest(t, true, false, sf, f.client, testhelpers.EncodeFormAsJSON(t, true, values))
		return res, body
	}

	// profile is a profile update to the given name, keeping the identity's addresses.
	profile := func(f *fixture, name string) url.Values {
		v := url.Values{"method": {settings.StrategyProfile}, "traits.name": {name}}
		for _, k := range []string{"email", "backup_email"} {
			if a := gjson.GetBytes(f.id.Traits, k).String(); a != "" {
				v.Set("traits."+k, a)
			}
		}
		return v
	}

	// addresses is a profile update to the given addresses.
	addresses := func(email, backupEmail string) url.Values {
		v := url.Values{"method": {settings.StrategyProfile}, "traits.email": {email}, "traits.name": {"Owner"}}
		if backupEmail != "" {
			v.Set("traits.backup_email", backupEmail)
		}
		return v
	}

	password := url.Values{"method": {"password"}, "password": {"a-long-and-unusual-settings-password-2026"}}
	lookupSecret := url.Values{"method": {"lookup_secret"}, "lookup_secret_regenerate": {"true"}}

	recipients := func(t *testing.T, f *fixture) []string {
		t.Helper()
		messages, _, err := f.reg.CourierPersister().ListMessages(t.Context(), courier.ListCourierMessagesParameters{}, nil)
		require.NoError(t, err)
		rs := make([]string, 0, len(messages))
		for _, m := range messages {
			rs = append(rs, m.Recipient)
		}
		return rs
	}

	// digest is what the verification flow, too, counts an address by.
	digest := func(t *testing.T, f *fixture, address string) defense.Digest {
		return defense.NewFingerprinter(f.reg.Config().DefenseFingerprintSecret(t.Context())).Identifier(address)
	}

	stored := func(t *testing.T, f *fixture) *identity.Identity {
		t.Helper()
		i, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(t.Context(), f.id.ID)
		require.NoError(t, err)
		return i
	}

	status := func(t *testing.T, f *fixture, address string) identity.VerifiableAddressStatus {
		t.Helper()
		a, err := f.reg.IdentityPool().FindVerifiableAddressByValue(t.Context(), identity.AddressTypeEmail, address)
		require.NoError(t, err)
		return a.Status
	}

	// unchanged asserts that an identity set up without the backup address was neither saved nor messaged.
	unchanged := func(t *testing.T, f *fixture) {
		t.Helper()
		i := stored(t, f)
		assert.JSONEq(t, string(f.id.Traits), string(i.Traits))
		require.Len(t, i.VerifiableAddresses, 1)
		assert.Equal(t, owner, i.VerifiableAddresses[0].Value)
		assert.Empty(t, recipients(t, f), "no message may be queued")
	}

	t.Run("case=an added address is checked once, before it is saved", func(t *testing.T) {
		t.Parallel()
		f := setup(t, false, nil)
		res, body := submit(t, f, addresses(added, ""))
		require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)

		require.Equal(t, []string{"BeforeAttempt"}, f.rec.Names(), "the verification hook does not check it again")
		a := f.rec.Calls()[0].Attempt
		assert.Equal(t, defense.MethodVerification, a.Method)
		assert.Equal(t, digest(t, f, added), a.IdentifierDigest)
		assert.True(t, a.CredentialDigest.IsZero())
		assert.Equal(t, []string{added}, recipients(t, f), "let through, the message is sent: the denied cases below are not vacuous")
	})

	// A deny that came after the message was queued, or after the update was saved, fails here.
	for name, opts := range map[string][]configx.OptionModifier{
		"verification":       nil,
		"verify_new_address": {verifyNewAddress},
	} {
		t.Run("case=a denied update changes nothing and sends nothing/hook="+name, func(t *testing.T) {
			t.Parallel()
			f := setup(t, false, nil, opts...)
			f.rec.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, nil)
			res, body := submit(t, f, addresses(added, ""))
			assert.Equal(t, http.StatusTooManyRequests, res.StatusCode, "%s", body)
			assert.Equal(t, "1", res.Header.Get("Retry-After"))
			assert.Equal(t, []string{"BeforeAttempt"}, f.rec.Names())
			unchanged(t, f)
		})
	}

	t.Run("case=a browser client is refused with 429 and Retry-After too", func(t *testing.T) {
		t.Parallel()
		f := setup(t, false, nil)
		f.rec.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, nil)
		browser := testhelpers.NewHTTPClientWithIdentitySessionCookie(t.Context(), t, f.reg, f.id)
		sf := testhelpers.InitializeSettingsFlowViaBrowser(t, browser, true, f.public)
		values := testhelpers.SDKFormFieldsToURLValues(sf.Ui.Nodes) // with the CSRF token
		for k, v := range addresses(added, "") {
			values[k] = v
		}
		body, res := testhelpers.SettingsMakeRequest(t, false, true, sf, browser, testhelpers.EncodeFormAsJSON(t, true, values))
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode, "%s", body)
		assert.Equal(t, "1", res.Header.Get("Retry-After"))
		unchanged(t, f)
	})

	t.Run("case=each added address is checked, and a deny of any one changes nothing", func(t *testing.T) {
		t.Parallel()
		f := setup(t, false, func(r *defensetest.Recorder) defense.Defense { return denyAfter{Recorder: r, n: 1} })
		res, body := submit(t, f, addresses(added, backup))
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode, "%s", body)

		require.Equal(t, []string{"BeforeAttempt", "BeforeAttempt"}, f.rec.Names(), "the first is let through, the second denied")
		var digests []defense.Digest
		for _, c := range f.rec.Calls() {
			assert.Equal(t, defense.MethodVerification, c.Attempt.Method)
			digests = append(digests, c.Attempt.IdentifierDigest)
		}
		assert.ElementsMatch(t, []defense.Digest{digest(t, f, added), digest(t, f, backup)}, digests)
		unchanged(t, f)
	})

	t.Run("case=verify_new_address is checked on every update that adds the same address", func(t *testing.T) {
		t.Parallel()
		f := setup(t, false, nil, verifyNewAddress)
		for range 2 {
			res, body := submit(t, f, addresses(added, ""))
			require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
		}

		require.Equal(t, []string{"BeforeAttempt", "BeforeAttempt"}, f.rec.Names())
		for _, c := range f.rec.Calls() {
			assert.Equal(t, digest(t, f, added), c.Attempt.IdentifierDigest)
		}
		assert.Equal(t, []string{added, added}, recipients(t, f), "the hook saves nothing until the address is verified, so it sends on every update")
	})

	// Counted for the address the client names, resends that name a different one each time would message the
	// pending address without end. The verification flow needs no session.
	t.Run("case=a resend of a pending change's code is counted for the pending address", func(t *testing.T) {
		t.Parallel()
		f := setup(t, false, nil, verifyNewAddress)
		res, body := submit(t, f, addresses(added, ""))
		require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
		flowID := gjson.Get(body, `continue_with.#(action=="show_verification_ui").flow.id`).String()
		require.NotEmpty(t, flowID, "%s", body)
		vf := &kratos.VerificationFlow{Ui: kratos.UiContainer{Action: f.public.URL + verification.RouteSubmitFlow + "?flow=" + flowID}}
		resend := func(t *testing.T, named string) (*http.Response, string) {
			t.Helper()
			body, res := testhelpers.VerificationMakeRequest(t, true, vf, testhelpers.NewDebugClient(t),
				testhelpers.EncodeFormAsJSON(t, true, url.Values{"method": {"code"}, "email": {named}}))
			return res, body
		}

		res, body = resend(t, "decoy@example.com")
		require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
		assert.Equal(t, []string{added, added}, recipients(t, f), "the code goes to the pending address")

		f.rec.Answer(defense.Decision{Verdict: defense.Deny}, nil)
		res, body = resend(t, "another-decoy@example.com")
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode, "%s", body)
		assert.Equal(t, []string{added, added}, recipients(t, f), "a denied resend sends nothing")

		require.Equal(t, []string{"BeforeAttempt", "BeforeAttempt", "BeforeAttempt"}, f.rec.Names(), "the update and both resends")
		for _, c := range f.rec.Calls() {
			assert.Equal(t, defense.MethodVerification, c.Attempt.Method)
			assert.Equal(t, digest(t, f, added), c.Attempt.IdentifierDigest, "each counted for the address that receives the code")
		}
	})

	// Concurrent updates all read the address as pending, and each messages it: checked right before the message,
	// each of them is counted.
	for name, update := range map[string]func(*fixture) url.Values{
		"profile":  func(f *fixture) url.Values { return profile(f, "Renamed") },
		"password": func(*fixture) url.Values { return password },
	} {
		t.Run("case=a message to a pending address is checked first/strategy="+name, func(t *testing.T) {
			t.Parallel()
			f := setup(t, true, nil)
			res, body := submit(t, f, update(f))
			require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)

			require.Equal(t, []string{"BeforeAttempt"}, f.rec.Names(), "a send has no outcome to report")
			a := f.rec.Calls()[0].Attempt
			assert.Equal(t, defense.MethodVerification, a.Method)
			assert.Equal(t, digest(t, f, backup), a.IdentifierDigest)
			assert.True(t, a.CredentialDigest.IsZero())
			assert.Equal(t, []string{backup}, recipients(t, f))
			assert.Equal(t, identity.VerifiableAddressStatusSent, status(t, f, backup))
		})

		t.Run("case=a denied message is withheld, and the update stands/strategy="+name, func(t *testing.T) {
			t.Parallel()
			f := setup(t, true, nil)
			f.rec.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, nil)
			res, body := submit(t, f, update(f))
			require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
			assert.Empty(t, res.Header.Get("Retry-After"))

			assert.Equal(t, []string{"BeforeAttempt"}, f.rec.Names())
			assert.Empty(t, recipients(t, f), "no message may be queued")
			assert.Equal(t, identity.VerifiableAddressStatusPending, status(t, f, backup), "a later update or the verification flow may still send it")
			i := stored(t, f)
			if name == "password" {
				assert.Contains(t, i.Credentials, identity.CredentialsTypePassword, "the password was set")
			} else {
				assert.Equal(t, "Renamed", gjson.GetBytes(i.Traits, "name").String(), "the update was saved")
			}
		})
	}

	for name, update := range map[string]func(*fixture) url.Values{
		"profile":       func(f *fixture) url.Values { return profile(f, "Renamed") },
		"password":      func(*fixture) url.Values { return password },
		"lookup_secret": func(*fixture) url.Values { return lookupSecret },
	} {
		t.Run("case=an update that sends nothing is not checked/strategy="+name, func(t *testing.T) {
			t.Parallel()
			f := setup(t, false, nil)
			res, body := submit(t, f, update(f))
			require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
			assert.Empty(t, f.rec.Calls())
			assert.Empty(t, recipients(t, f))
		})
	}
}
