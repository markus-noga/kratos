// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/persistence"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/recovery"
	"github.com/ory/kratos/selfservice/strategy/code"
	"github.com/ory/kratos/selfservice/strategy/link"
	"github.com/ory/kratos/x"
	"github.com/ory/x/contextx"
	"github.com/ory/x/randx"
)

func TestPersister(ctx context.Context, p interface {
	persistence.Persister
},
) func(t *testing.T) {
	return func(t *testing.T) {
		nid, p := testhelpers.NewNetworkUnlessExisting(t, ctx, p)

		ctx := contextx.WithConfigValue(ctx, config.ViperKeySecretsDefault, []string{"secret-a", "secret-b"})

		t.Run("code=recovery", func(t *testing.T) {
			newRecoveryCodeDTO := func(t *testing.T, email string) (*code.CreateRecoveryCodeParams, *recovery.Flow, *identity.RecoveryAddress) {
				var f recovery.Flow
				require.NoError(t, faker.FakeData(&f))
				f.State = flow.StateChooseMethod

				require.NoError(t, p.CreateRecoveryFlow(ctx, &f))

				var i identity.Identity
				require.NoError(t, faker.FakeData(&i))

				address := &identity.RecoveryAddress{Value: email, Via: identity.AddressTypeEmail, IdentityID: i.ID}
				i.RecoveryAddresses = append(i.RecoveryAddresses, *address)

				require.NoError(t, p.CreateIdentity(ctx, &i))

				return &code.CreateRecoveryCodeParams{
					RawCode:         randx.MustString(8, randx.Numeric),
					FlowID:          f.ID,
					RecoveryAddress: &i.RecoveryAddresses[0],
					ExpiresIn:       time.Minute,
					IdentityID:      i.ID,
				}, &f, &i.RecoveryAddresses[0]
			}

			t.Run("case=should error when the recovery token does not exist", func(t *testing.T) {
				_, err := p.UseRecoveryCode(ctx, x.NewUUID(), "i-do-not-exist")
				require.Error(t, err)
			})

			t.Run("case=should create a new recovery code", func(t *testing.T) {
				dto, f, a := newRecoveryCodeDTO(t, "foo-user@ory.sh")
				rCode, err := p.CreateRecoveryCode(ctx, dto)
				require.NoError(t, err)
				assert.Equal(t, f.ID, rCode.FlowID)
				assert.Equal(t, dto.IdentityID, rCode.IdentityID)
				require.True(t, rCode.RecoveryAddressID.Valid)
				assert.Equal(t, a.ID, rCode.RecoveryAddressID.UUID)
				assert.Equal(t, a.ID, rCode.RecoveryAddress.ID)
			})

			t.Run("case=should create a recovery code and use it", func(t *testing.T) {
				dto, f, _ := newRecoveryCodeDTO(t, "other-user@ory.sh")
				_, err := p.CreateRecoveryCode(ctx, dto)
				require.NoError(t, err)

				t.Run("not work on another network", func(t *testing.T) {
					_, p := testhelpers.NewNetwork(t, ctx, p)
					_, err := p.UseRecoveryCode(ctx, f.ID, dto.RawCode)
					require.ErrorIs(t, err, code.ErrCodeNotFound())
				})

				actual, err := p.UseRecoveryCode(ctx, f.ID, dto.RawCode)
				require.NoError(t, err)
				assert.Equal(t, nid, actual.NID)
				assert.Equal(t, dto.IdentityID, actual.IdentityID)
				assert.NotEqual(t, dto.RawCode, actual.CodeHMAC)
				assert.EqualValues(t, f.ID, actual.FlowID)

				_, err = p.UseRecoveryCode(ctx, f.ID, dto.RawCode)
				require.ErrorIs(t, err, code.ErrCodeAlreadyUsed())
			})

			t.Run("case=concurrent use of the same code succeeds at most once", func(t *testing.T) {
				// HackerOne #3692149 / #3695625: the consume UPDATE must be
				// atomic. On READ COMMITTED backends two concurrent
				// submissions of the same valid code must not both succeed.
				dto, f, _ := newRecoveryCodeDTO(t, "concurrent-code@ory.sh")
				_, err := p.CreateRecoveryCode(ctx, dto)
				require.NoError(t, err)

				const concurrency = 8
				var success int32
				var start sync.WaitGroup
				var done sync.WaitGroup
				start.Add(1)
				for range concurrency {
					done.Add(1)
					go func() {
						defer done.Done()
						start.Wait()
						if _, err := p.UseRecoveryCode(ctx, f.ID, dto.RawCode); err == nil {
							atomic.AddInt32(&success, 1)
						}
					}()
				}
				start.Done()
				done.Wait()

				require.EqualValues(t, 1, atomic.LoadInt32(&success), "exactly one concurrent consumer may use the code")
			})

			t.Run("case=should not be able to use expired codes", func(t *testing.T) {
				dto, f, _ := newRecoveryCodeDTO(t, "expired-code@ory.sh")
				dto.ExpiresIn = -time.Hour
				_, err := p.CreateRecoveryCode(ctx, dto)
				require.NoError(t, err)

				_, err = p.UseRecoveryCode(ctx, f.ID, dto.RawCode)
				require.ErrorIs(t, err, code.ErrCodeNotFound())
			})

			t.Run("case=should increment flow submit count and fail after too many tries (default limit)", func(t *testing.T) {
				dto, f, _ := newRecoveryCodeDTO(t, "submit-count-default-limit@ory.sh")
				_, err := p.CreateRecoveryCode(ctx, dto)
				require.NoError(t, err)

				var tooOften, wrongCode int32
				var wg sync.WaitGroup
				for range 50 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, err := p.UseRecoveryCode(ctx, f.ID, "i-do-not-exist")
						if !assert.Error(t, err) {
							return
						}
						if errors.Is(err, code.ErrCodeSubmittedTooOften()) {
							atomic.AddInt32(&tooOften, 1)
						} else {
							atomic.AddInt32(&wrongCode, 1)
						}
					}()
				}
				wg.Wait()

				require.EqualValues(t, 50, wrongCode+tooOften, "all 50 attempts made")
				require.LessOrEqual(t, wrongCode, int32(5), "max. 5 attempts have gone past the duplication check")

				// Submit again, just to be sure
				_, err = p.UseRecoveryCode(ctx, f.ID, "i-do-not-exist")
				require.ErrorIs(t, err, code.ErrCodeSubmittedTooOften())
			})

			t.Run("case=should increment flow submit count and fail after too many tries (custom limit)", func(t *testing.T) {
				limit := 2
				ctx := contextx.WithConfigValue(ctx, config.ViperKeyCodeMaxSubmissions, limit)

				dto, f, _ := newRecoveryCodeDTO(t, "submit-count-custom-limit@ory.sh")
				_, err := p.CreateRecoveryCode(ctx, dto)
				require.NoError(t, err)

				var tooOften, wrongCode int32
				var wg sync.WaitGroup
				for range 50 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, err := p.UseRecoveryCode(ctx, f.ID, "i-do-not-exist")
						if !assert.Error(t, err) {
							return
						}
						if errors.Is(err, code.ErrCodeSubmittedTooOften()) {
							atomic.AddInt32(&tooOften, 1)
						} else {
							atomic.AddInt32(&wrongCode, 1)
						}
					}()
				}
				wg.Wait()

				require.EqualValues(t, 50, wrongCode+tooOften, "all 50 attempts made")
				require.LessOrEqual(t, wrongCode, int32(limit), "max. %d attempts have gone past the duplication check", limit)

				// Submit again, just to be sure
				_, err = p.UseRecoveryCode(ctx, f.ID, "i-do-not-exist")
				require.ErrorIs(t, err, code.ErrCodeSubmittedTooOften())
			})

			t.Run("case=should delete the unused admin codes and links of an identity", func(t *testing.T) {
				type row struct {
					model any
					id    uuid.UUID
				}
				newIdentity := func(t *testing.T) *identity.Identity {
					var i identity.Identity
					require.NoError(t, faker.FakeData(&i))
					i.RecoveryAddresses = []identity.RecoveryAddress{{Value: testhelpers.RandomEmail(), Via: identity.AddressTypeEmail, IdentityID: i.ID}}
					require.NoError(t, p.CreateIdentity(ctx, &i))
					return &i
				}
				// A code is looked up by its flow, so each one gets a flow of its own.
				newFlow := func(t *testing.T) uuid.UUID {
					var f recovery.Flow
					require.NoError(t, faker.FakeData(&f))
					f.State = flow.StateChooseMethod
					require.NoError(t, p.CreateRecoveryFlow(ctx, &f))
					return f.ID
				}
				newCode := func(t *testing.T, i *identity.Identity, codeType code.RecoveryCodeType, used bool) row {
					params := &code.CreateRecoveryCodeParams{
						RawCode:    randx.MustString(8, randx.Numeric),
						CodeType:   codeType,
						ExpiresIn:  time.Hour,
						FlowID:     newFlow(t),
						IdentityID: i.ID,
					}
					if codeType == code.RecoveryCodeTypeSelfService {
						params.RecoveryAddress = &i.RecoveryAddresses[0]
					}
					c, err := p.CreateRecoveryCode(ctx, params)
					require.NoError(t, err)
					if used {
						_, err := p.UseRecoveryCode(ctx, params.FlowID, params.RawCode)
						require.NoError(t, err)
					}
					return row{new(code.RecoveryCode), c.ID}
				}
				newLink := func(t *testing.T, i *identity.Identity, tokenType link.RecoveryTokenType, used bool) row {
					token := &link.RecoveryToken{
						ID:         x.NewUUID(),
						Token:      x.NewUUID().String(),
						FlowID:     uuid.NullUUID{UUID: newFlow(t), Valid: true},
						ExpiresAt:  time.Now().Add(time.Hour),
						IssuedAt:   time.Now(),
						IdentityID: i.ID,
						TokenType:  tokenType,
					}
					if tokenType == link.RecoveryTokenTypeSelfService {
						token.RecoveryAddressID = &i.RecoveryAddresses[0].ID
					}
					require.NoError(t, p.CreateRecoveryToken(ctx, token))
					if used {
						_, err := p.UseRecoveryToken(ctx, token.FlowID.UUID, token.Token)
						require.NoError(t, err)
					}
					return row{new(link.RecoveryToken), token.ID}
				}
				exists := func(t *testing.T, r row) bool {
					found, err := p.GetConnection(ctx).Where("id = ? AND nid = ?", r.id, nid).Exists(r.model)
					require.NoError(t, err)
					return found
				}

				member, other := newIdentity(t), newIdentity(t)
				voided := map[string]row{
					"unused admin code": newCode(t, member, code.RecoveryCodeTypeAdmin, false),
					"unused admin link": newLink(t, member, link.RecoveryTokenTypeAdmin, false),
				}
				kept := map[string]row{
					"used admin code":                newCode(t, member, code.RecoveryCodeTypeAdmin, true),
					"used admin link":                newLink(t, member, link.RecoveryTokenTypeAdmin, true),
					"self-service code":              newCode(t, member, code.RecoveryCodeTypeSelfService, false),
					"self-service link":              newLink(t, member, link.RecoveryTokenTypeSelfService, false),
					"admin code of another identity": newCode(t, other, code.RecoveryCodeTypeAdmin, false),
					"admin link of another identity": newLink(t, other, link.RecoveryTokenTypeAdmin, false),
				}

				t.Run("not on another network", func(t *testing.T) {
					_, p := testhelpers.NewNetwork(t, ctx, p)
					codes, links, err := p.DeleteUnusedAdminRecoveryCodesAndLinks(ctx, member.ID)
					require.NoError(t, err)
					assert.Zero(t, codes, "deleted codes")
					assert.Zero(t, links, "deleted links")
					for name, r := range voided {
						assert.Truef(t, exists(t, r), "%s was deleted from another network", name)
					}
				})

				codes, links, err := p.DeleteUnusedAdminRecoveryCodesAndLinks(ctx, member.ID)
				require.NoError(t, err)
				// The counts are what the callers log.
				assert.Equal(t, 1, codes, "deleted codes")
				assert.Equal(t, 1, links, "deleted links")
				for name, r := range voided {
					assert.Falsef(t, exists(t, r), "%s was kept", name)
				}
				for name, r := range kept {
					assert.Truef(t, exists(t, r), "%s was deleted", name)
				}
			})

			t.Run("case=should delete codes of flow", func(t *testing.T) {
				dto, f, _ := newRecoveryCodeDTO(t, testhelpers.RandomEmail())
				for i := 0; i < 10; i++ {
					dto.RawCode = string(randx.MustString(8, randx.Numeric))
					_, err := p.CreateRecoveryCode(ctx, dto)
					require.NoError(t, err)
				}

				count, err := p.GetConnection(ctx).Where("selfservice_recovery_flow_id = ?", f.ID).Count(&code.RecoveryCode{})
				require.NoError(t, err)
				require.Equal(t, 10, count)

				err = p.DeleteRecoveryCodesOfFlow(ctx, f.ID)
				require.NoError(t, err)

				// Count again, should be 0
				count, err = p.GetConnection(ctx).Where("selfservice_recovery_flow_id = ?", f.ID).Count(&code.RecoveryCode{})
				require.NoError(t, err)
				require.Equal(t, 0, count)
			})
		})
	}
}
