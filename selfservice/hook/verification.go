// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"context"
	"net/http"

	"github.com/tidwall/sjson"
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory/x/clock"
	"github.com/ory/x/httpx"
	"github.com/ory/x/otelx/semconv"

	"github.com/gofrs/uuid"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/gate"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x/nosurfx"
	"github.com/ory/x/otelx"
)

var (
	_ registration.PostHookPostPersistExecutor = new(Verifier)
	_ settings.PostHookPostPersistExecutor     = new(Verifier)
	_ login.PostHookExecutor                   = new(Verifier)
)

type (
	verifierDependencies interface {
		clock.Provider
		config.Provider
		nosurfx.CSRFTokenGeneratorProvider
		nosurfx.CSRFProvider
		verification.StrategyProvider
		verification.FlowPersistenceProvider
		identity.PrivilegedPoolProvider
		httpx.WriterProvider
		otelx.Provider
		gate.Dependencies
	}
	Verifier struct {
		r verifierDependencies
	}
)

func NewVerifier(r verifierDependencies) *Verifier {
	return &Verifier{r: r}
}

func (e *Verifier) ExecutePostRegistrationPostPersistHook(w http.ResponseWriter, r *http.Request, f *registration.Flow, s *session.Session) error {
	return otelx.WithSpan(r.Context(), "selfservice.hook.Verifier.ExecutePostRegistrationPostPersistHook", func(ctx context.Context) error {
		return e.do(w, r.WithContext(ctx), s.Identity, f, func(v *verification.Flow) {
			v.OAuth2LoginChallenge = f.OAuth2LoginChallenge
			v.SessionID = uuid.NullUUID{UUID: s.ID, Valid: true}
			v.IdentityID = uuid.NullUUID{UUID: s.Identity.ID, Valid: true}
			v.AMR = s.AMR
		}, nil)
	})
}

func (e *Verifier) ExecuteSettingsPostPersistHook(w http.ResponseWriter, r *http.Request, params settings.PostHookPostPersistExecutorParams) error {
	return otelx.WithSpan(r.Context(), "selfservice.hook.Verifier.ExecuteSettingsPostPersistHook", func(ctx context.Context) error {
		// Defense: any settings update has the identity's pending addresses messaged here, and concurrent updates all
		// read an address as pending, so each message is checked right before it is sent, as an attempt to verify the
		// address. The update is saved by then, so a deny withholds the message, not the update: no response writer.
		sends := gate.New(e.r, nil, r, defense.MethodVerification)
		return e.do(w, r.WithContext(ctx), params.Updated, params.Flow, nil, func(ctx context.Context, a *identity.VerifiableAddress) error {
			// An address the update added was checked before the update was saved.
			if settings.AddressChecked(ctx, *a) {
				return nil
			}
			return sends.Check(ctx, a.Value, "")
		})
	})
}

func (e *Verifier) ExecuteLoginPostHook(w http.ResponseWriter, r *http.Request, g node.UiNodeGroup, f *login.Flow, s *session.Session) (err error) {
	ctx, span := e.r.Tracer(r.Context()).Tracer().Start(r.Context(), "selfservice.hook.Verifier.ExecuteLoginPostHook")
	r = r.WithContext(ctx)
	defer otelx.End(span, &err)
	if f.RequestedAAL != identity.AuthenticatorAssuranceLevel1 {
		span.SetAttributes(attribute.String("skip_reason", "skipping verification hook because AAL is not 1"))
		return nil
	}

	return e.do(w, r.WithContext(ctx), s.Identity, f, func(vf *verification.Flow) {
		vf.OAuth2LoginChallenge = f.OAuth2LoginChallenge
		var sID uuid.UUID
		if s != nil {
			sID = s.ID
		}
		vf.SessionID = uuid.NullUUID{UUID: sID, Valid: sID != uuid.Nil}
		var iID uuid.UUID
		if s != nil && s.Identity != nil {
			iID = s.Identity.ID
		}
		vf.IdentityID = uuid.NullUUID{UUID: iID, Valid: iID != uuid.Nil}
		vf.AMR = s.AMR
	}, nil)
}

const InternalContextRegistrationVerificationFlow = "registration_verification_flow_continue_with"

func (e *Verifier) do(
	w http.ResponseWriter,
	r *http.Request,
	i *identity.Identity,
	f interface {
		flow.FlowWithContinueWith
		flow.InternalContexter
	},
	flowCallback func(*verification.Flow),
	// check, if set, is asked before each message. A message it denies (gate.Denied) is withheld, and its address
	// stays pending.
	check func(context.Context, *identity.VerifiableAddress) error,
) (err error) {
	ctx, span := e.r.Tracer(r.Context()).Tracer().Start(r.Context(), "selfservice.hook.Verifier.do")
	r = r.WithContext(ctx)
	defer otelx.End(span, &err)

	// This is called after the identity has been created so we can safely assume that all addresses are available
	// already.

	strategies, primaryStrategy, err := e.r.GetActiveVerificationStrategies(ctx)
	if err != nil {
		return err
	}

	isBrowserFlow := f.GetType() == flow.TypeBrowser
	isRegistrationOrLoginFlow := f.GetFlowName() == flow.RegistrationFlow || f.GetFlowName() == flow.LoginFlow

	for k := range i.VerifiableAddresses {
		address := &i.VerifiableAddresses[k]
		if isRegistrationOrLoginFlow && address.Verified {
			continue
		} else if !isRegistrationOrLoginFlow && address.Status != identity.VerifiableAddressStatusPending {
			// In case of the settings flow, we only want to create a new verification flow if there is no pending
			// verification flow for the address. Otherwise, we would create a new verification flow for each setting,
			// even if the address did not change.
			continue
		}

		if address.Value == "" {
			continue
		}

		if check != nil {
			if err := check(ctx, address); gate.Denied(err) {
				continue
			} else if err != nil {
				return err
			}
		}

		var csrf string

		// TODO: this is pretty ugly, we should probably have a better way to handle CSRF tokens here.
		if isBrowserFlow {
			if isRegistrationOrLoginFlow {
				// If this hook is executed from a registration flow, we need to regenerate the CSRF token.
				csrf = e.r.CSRFHandler().RegenerateToken(w, r)
			} else {
				// If it came from a settings flow, there already is a CSRF token, so we can just use that.
				csrf = e.r.GenerateCSRFToken(r)
			}
		}

		verificationFlow, err := verification.NewPostHookFlow(e.r,
			e.r.Config().SelfServiceFlowVerificationRequestLifespan(ctx),
			csrf, r, strategies, f)
		if err != nil {
			return err
		}

		if flowCallback != nil {
			flowCallback(verificationFlow)
		}

		verificationFlow.State = flow.StateEmailSent
		if err := primaryStrategy.PopulateVerificationMethod(r, verificationFlow); err != nil {
			return err
		}

		// The code strategy's PopulateVerificationMethod sets the email "code sent"
		// message unconditionally; override it with the message that matches the
		// channel the code was sent over. The legacy link strategy sends a link,
		// not a code, and sets no message — leave it untouched.
		if primaryStrategy.NodeGroup() == node.CodeGroup {
			verificationFlow.UI.Messages.Set(text.VerificationCodeSentMessage(address.Via))
		}

		verificationFlow.UI.Nodes.Append(
			node.NewInputField(address.Via, address.Value, node.CodeGroup, node.InputAttributeTypeSubmit).
				WithMetaLabel(text.NewInfoNodeResendOTP()),
		)

		if err := e.r.VerificationFlowPersister().CreateVerificationFlow(ctx, verificationFlow); err != nil {
			return err
		}

		if err := primaryStrategy.SendVerificationCode(ctx, verificationFlow, i, address); err != nil {
			return err
		}

		address.Status = identity.VerifiableAddressStatusSent
		if err := e.r.PrivilegedIdentityPool().UpdateVerifiableAddress(ctx, address, "status"); err != nil {
			return err
		}

		flowURL := ""
		if verificationFlow.Type == flow.TypeBrowser {
			flowURL = verificationFlow.AppendTo(e.r.Config().SelfServiceFlowVerificationUI(ctx)).String()
		}

		continueWith := flow.NewContinueWithVerificationUI(verificationFlow.ID, address.Value, flowURL)
		internalContext, err := sjson.SetBytes(f.GetInternalContext(), InternalContextRegistrationVerificationFlow, continueWith.Flow)
		if err != nil {
			return err
		}
		f.SetInternalContext(internalContext)

		if e.r.Config().UseLegacyShowVerificationUI(ctx) {
			span.AddEvent(semconv.NewDeprecatedFeatureUsedEvent(ctx, "legacy_continue_with_verification_ui"))
			f.AddContinueWith(continueWith)
			continue // Legacy behavior
		}

		break // We only do this for the first address we find as we can't redirect to multiple flows at once.
	}
	return nil
}
