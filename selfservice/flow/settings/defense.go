// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"net/http"
	"slices"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/gate"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/x"
)

// checkAddedAddresses checks each address that updated adds to previous, the
// identity before the update, as an attempt to verify it, before anything is
// saved: the client chooses these addresses, and the verification hook messages
// them once the update is saved, so a deny refuses the update. An address counts
// even if nothing is sent to it: verification may be off, the hook may leave it
// to a later update, which checks it again, or the update may fail because
// another identity holds the address, a lookup that comes after the check. The
// gate is one of its own, as the OIDC link callback carries a gate for the
// callback. The returned request carries the checked addresses, which the
// verification hook does not check again (AddressChecked).
func (e *HookExecutor) checkAddedAddresses(ctx context.Context, w http.ResponseWriter, r *http.Request, previous, updated *identity.Identity) (*http.Request, error) {
	sends := gate.New(e.d, w, r, defense.MethodVerification)
	var checked []identity.VerifiableAddress
	for _, a := range updated.VerifiableAddresses {
		if previous != nil && slices.ContainsFunc(previous.VerifiableAddresses, sameAddress(a)) {
			continue
		}
		if err := sends.Check(ctx, a.Value, ""); err != nil {
			return r, err
		}
		checked = append(checked, a)
	}
	return r.WithContext(context.WithValue(r.Context(), checkedAddressesKey{}, checked)), nil
}

type checkedAddressesKey struct{}

// AddressChecked reports whether a is one of the addresses that the update of
// the request of ctx added, and that were checked before it was saved.
func AddressChecked(ctx context.Context, a identity.VerifiableAddress) bool {
	checked, _ := ctx.Value(checkedAddressesKey{}).([]identity.VerifiableAddress)
	return slices.ContainsFunc(checked, sameAddress(a))
}

// sameAddress matches an address with the channel and normalized value of a, as
// the identity schema extension matches addresses, so that a value stored before
// normalization matches the normalized one that an update saves.
func sameAddress(a identity.VerifiableAddress) func(identity.VerifiableAddress) bool {
	value := x.GracefulNormalization(a.Value)
	return func(b identity.VerifiableAddress) bool {
		return b.Via == a.Via && x.GracefulNormalization(b.Value) == value
	}
}
