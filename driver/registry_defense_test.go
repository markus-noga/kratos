// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/recovery"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/verification"
)

// TestLoginStrategiesAreDefendedOrExempt makes a new login strategy fail here
// until someone decides how it meets the defense gate: it implements
// login.DefendedStrategy and calls gate.From(ctx).Check, or it is listed below
// with the reason it need not.
func TestLoginStrategiesAreDefendedOrExempt(t *testing.T) {
	t.Parallel()

	exempt := map[identity.CredentialsType]string{
		identity.CredentialsTypeOIDC: "The user proves themselves to the provider, which applies its own defense; the login " +
			"step only redirects. The callback, which exchanges the code with the provider, is not a Login call: it is gated " +
			"in oidc.Strategy.HandleCallback.",
	}

	_, reg := pkg.NewVeryFastRegistryWithoutDB(t)
	seen := map[identity.CredentialsType]bool{}
	for _, s := range reg.AllLoginStrategies() {
		id := s.ID()
		seen[id] = true
		_, defended := s.(login.DefendedStrategy)
		_, isExempt := exempt[id]
		assert.NotEqualf(t, defended, isExempt,
			"login strategy %q must either implement login.DefendedStrategy and call gate.From(ctx).Check, or be exempt in this test with a reason; not both, not neither", id)
	}
	for id, reason := range exempt {
		assert.Truef(t, seen[id], "exempt strategy %q is not a login strategy any more: remove it from the list", id)
		assert.NotEmpty(t, reason)
	}
	assert.NotEmpty(t, seen, "no login strategies found")
}

// checkCoverage fails for a strategy that is neither defended nor exempt, or
// both, and for an exemption that no longer matches a strategy.
func checkCoverage(t *testing.T, flow string, ids []string, defended map[string]bool, exempt map[string]string) {
	t.Helper()
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
		_, isExempt := exempt[id]
		assert.NotEqualf(t, defended[id], isExempt,
			"%s strategy %q must either implement DefendedStrategy and call gate.From(ctx).Check, or be exempt in this test with a reason; not both, not neither", flow, id)
	}
	for id, reason := range exempt {
		assert.Truef(t, seen[id], "exempt %s strategy %q is not a strategy any more: remove it from the list", flow, id)
		assert.NotEmpty(t, reason)
	}
	assert.NotEmptyf(t, seen, "no %s strategies found", flow)
}

// TestFlowStrategiesAreDefendedOrExempt does for recovery, verification and
// registration what TestLoginStrategiesAreDefendedOrExempt does for login: a new
// strategy fails here until someone decides how it meets the defense gate.
// Settings strategies are not listed: none of them sends a message itself. The
// messages of a settings update are checked where they are sent, on a path that
// every strategy takes (settings.HookExecutor.PostSettingsHook, the
// verify_new_address and verification hooks).
func TestFlowStrategiesAreDefendedOrExempt(t *testing.T) {
	t.Parallel()

	// Each subtest has a registry of its own: a registry builds its strategies on first use, unsynchronized.
	t.Run("flow=recovery", func(t *testing.T) {
		t.Parallel()
		_, reg := pkg.NewVeryFastRegistryWithoutDB(t)
		var ids []string
		defended := map[string]bool{}
		for _, s := range reg.AllRecoveryStrategies() {
			id := s.RecoveryStrategyID()
			ids = append(ids, id)
			_, defended[id] = s.(recovery.DefendedStrategy)
		}
		checkCoverage(t, "recovery", ids, defended, map[string]string{})
	})

	t.Run("flow=verification", func(t *testing.T) {
		t.Parallel()
		_, reg := pkg.NewVeryFastRegistryWithoutDB(t)
		var ids []string
		defended := map[string]bool{}
		for _, s := range reg.AllVerificationStrategies() {
			id := s.VerificationStrategyID()
			ids = append(ids, id)
			_, defended[id] = s.(verification.DefendedStrategy)
		}
		checkCoverage(t, "verification", ids, defended, map[string]string{})
	})

	t.Run("flow=registration", func(t *testing.T) {
		t.Parallel()
		_, reg := pkg.NewVeryFastRegistryWithoutDB(t)
		var ids []string
		defended := map[string]bool{}
		for _, s := range reg.AllRegistrationStrategies() {
			id := s.ID().String()
			ids = append(ids, id)
			_, defended[id] = s.(registration.DefendedStrategy)
		}
		checkCoverage(t, "registration", ids, defended, map[string]string{
			identity.CredentialsTypeOIDC.String(): "The user proves themselves to the provider, which applies its own defense; " +
				"the registration step only redirects. The callback is gated in oidc.Strategy.HandleCallback.",
			"profile": "Collects the traits and shows the next screen: no credential is checked, nothing is hashed or sent, " +
				"and the traits are only validated, which touches no database.",
		})
	})
}
