// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/courier"
	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/hook"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

// TestVerifierDefense checks that the verification hook counts each message it
// sends after a settings update as an attempt to verify the address, right
// before it sends it, unless the update added the address and it was checked
// before the update was saved. Any settings update has the hook message the
// identity's pending addresses, and concurrent updates all read an address as
// pending before the first of them marks it sent. Every subtest has its own
// registry, identity and recorder.
func TestVerifierDefense(t *testing.T) {
	t.Parallel()

	const address = "pending@ory.sh"

	type fixture struct {
		reg *driver.RegistryDefault
		rec *defensetest.Recorder
		id  *identity.Identity
	}

	// setup creates an identity whose one address is pending: no message has been sent to it yet.
	setup := func(t *testing.T) *fixture {
		conf, reg := pkg.NewFastRegistryWithMocks(t)
		testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/verify.schema.json")
		conf.MustSet(t.Context(), config.ViperKeyPublicBaseURL, "https://www.ory.com/")
		conf.MustSet(t.Context(), config.ViperKeyCourierSMTPURL, "smtp://foo@bar@dev.null/")
		rec := new(defensetest.Recorder)
		reg.WithDefense(rec)

		id := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
		id.Traits = identity.Traits(`{"emails":["` + address + `"]}`)
		require.NoError(t, reg.IdentityManager().Create(t.Context(), id))
		return &fixture{reg: reg, rec: rec, id: id}
	}

	// read is the identity as an update reads it from the database.
	read := func(t *testing.T, f *fixture) *identity.Identity {
		t.Helper()
		i, err := f.reg.PrivilegedIdentityPool().GetIdentity(t.Context(), f.id.ID, identity.ExpandDefault)
		require.NoError(t, err)
		return i
	}

	newRequest := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "https://www.ory.com/self-service/settings", nil)
	}

	// settingsUpdate runs the hook as a settings update that read the identity as previous and saved it as updated.
	settingsUpdate := func(t *testing.T, f *fixture, w http.ResponseWriter, previous, updated *identity.Identity) {
		t.Helper()
		require.NoError(t, hook.NewVerifier(f.reg).ExecuteSettingsPostPersistHook(w, newRequest(), settings.PostHookPostPersistExecutorParams{
			Flow:     &settings.Flow{RequestURL: "https://www.ory.com/settings"},
			Previous: previous,
			Updated:  updated,
			Session:  &session.Session{ID: x.NewUUID(), Identity: previous},
		}))
	}

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

	status := func(t *testing.T, f *fixture) identity.VerifiableAddressStatus {
		t.Helper()
		a, err := f.reg.IdentityPool().FindVerifiableAddressByValue(t.Context(), identity.AddressTypeEmail, address)
		require.NoError(t, err)
		return a.Status
	}

	t.Run("case=updates that all read the address as pending are each counted", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		// Both read the identity before either runs the hook, as concurrent updates do.
		previous1, updated1 := read(t, f), read(t, f)
		previous2, updated2 := read(t, f), read(t, f)
		settingsUpdate(t, f, httptest.NewRecorder(), previous1, updated1)
		settingsUpdate(t, f, httptest.NewRecorder(), previous2, updated2)

		assert.Equal(t, []string{address, address}, recipients(t, f), "each update messages the address")
		require.Equal(t, []string{"BeforeAttempt", "BeforeAttempt"}, f.rec.Names(), "one check per message, no outcome")
		digest := defense.NewFingerprinter(f.reg.Config().DefenseFingerprintSecret(t.Context())).Identifier(address)
		for _, c := range f.rec.Calls() {
			assert.Equal(t, defense.MethodVerification, c.Attempt.Method)
			assert.Equal(t, digest, c.Attempt.IdentifierDigest)
			assert.True(t, c.Attempt.CredentialDigest.IsZero())
		}
		assert.Equal(t, identity.VerifiableAddressStatusSent, status(t, f))
	})

	t.Run("case=a denied message is withheld, and the address stays pending", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		f.rec.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, nil)
		w := httptest.NewRecorder()
		settingsUpdate(t, f, w, read(t, f), read(t, f))

		assert.Equal(t, []string{"BeforeAttempt"}, f.rec.Names())
		assert.Empty(t, recipients(t, f), "no message may be queued")
		assert.Equal(t, identity.VerifiableAddressStatusPending, status(t, f), "a later update or the verification flow may still send it")
		assert.Empty(t, w.Header().Get("Retry-After"), "the update stands, so its response says nothing about a retry")
	})

	t.Run("case=an address the update added is checked here unless it was checked before the save", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		// The identity lacked the address before the update, but nothing checked it before the save, as for an
		// address that a pre-persist web hook adds by rewriting the traits.
		previous := read(t, f)
		previous.Traits, previous.VerifiableAddresses = identity.Traits(`{"emails":[]}`), nil
		settingsUpdate(t, f, httptest.NewRecorder(), previous, read(t, f))

		assert.Equal(t, []string{address}, recipients(t, f))
		assert.Equal(t, []string{"BeforeAttempt"}, f.rec.Names())
	})

	t.Run("case=a registration is not checked here", func(t *testing.T) {
		t.Parallel()
		f := setup(t)
		// The registration flow counts the address as it is submitted, as MethodRegistration.
		require.NoError(t, hook.NewVerifier(f.reg).ExecutePostRegistrationPostPersistHook(httptest.NewRecorder(), newRequest(),
			&registration.Flow{RequestURL: "https://www.ory.com/registration"}, &session.Session{ID: x.NewUUID(), Identity: read(t, f)}))
		assert.Equal(t, []string{address}, recipients(t, f), "the message is sent")
		assert.Empty(t, f.rec.Calls())
	})
}
