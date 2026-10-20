// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"

	"github.com/gofrs/uuid"
)

type (
	// AdminRecoveryPersister voids the recovery codes and links that an
	// administrator created for an identity. Both grant the same: a privileged
	// session that can set a new password. Creating one voids the others, so
	// that after calls one after another only the newest is valid, and
	// deactivating the identity voids them all. Concurrent calls for one
	// identity are not serialized: under PostgreSQL's default isolation (read
	// committed), a delete misses a code or link that a concurrent call has not
	// committed yet, which then stays valid until it expires.
	AdminRecoveryPersister interface {
		// DeleteUnusedAdminRecoveryCodesAndLinks deletes the identity's
		// recovery codes and links that were created through the admin API and
		// not used yet, and returns how many of each it deleted: callers log
		// them, as the deleted rows leave no other trace. Codes and links of the
		// self-service recovery flow are kept: the identity's owner requested
		// them.
		DeleteUnusedAdminRecoveryCodesAndLinks(ctx context.Context, identityID uuid.UUID) (codes, links int, err error)
	}

	AdminRecoveryPersistenceProvider interface {
		AdminRecoveryPersister() AdminRecoveryPersister
	}
)
