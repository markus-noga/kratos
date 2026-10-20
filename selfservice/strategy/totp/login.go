// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package totp

import (
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory/herodot"
	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/gate"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/otelx"
	"github.com/ory/x/sqlcon"
)

func (s *Strategy) PopulateLoginMethod(r *http.Request, requestedAAL identity.AuthenticatorAssuranceLevel, sr *login.Flow) error {
	// This strategy can only solve AAL2
	if requestedAAL != identity.AuthenticatorAssuranceLevel2 {
		return nil
	}

	// We have done proper validation before so this should never error.
	// Only the identity ID is read below; the identity is re-fetched with its confidential
	// fields anyway, so skip expanding anything here.
	sess, err := s.d.SessionManager().FetchFromRequest(r.Context(), r, session.ExpandNothing, identity.ExpandNothing)
	if err != nil {
		return err
	}

	id, err := s.d.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), sess.IdentityID)
	if err != nil {
		return err
	}

	_, ok := id.GetCredentials(s.ID())
	if !ok {
		// Identity has no TOTP
		return nil
	}

	sr.UI.SetCSRF(s.d.GenerateCSRFToken(r))
	sr.UI.SetNode(node.NewInputField("totp_code", "", node.TOTPGroup, node.InputAttributeTypeText, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoLoginTOTPLabel()))
	sr.UI.GetNodes().Append(node.NewInputField("method", s.ID(), node.TOTPGroup, node.InputAttributeTypeSubmit).WithMetaLabel(text.NewInfoLoginTOTP()))

	return nil
}

func (s *Strategy) handleLoginError(r *http.Request, f *login.Flow, err error) error {
	if f != nil {
		f.UI.Nodes.ResetNodes("totp_code")
		if f.Type == flow.TypeBrowser {
			f.UI.SetCSRF(s.d.GenerateCSRFToken(r))
		}
	}

	return err
}

// Update Login Flow with TOTP Method
//
// swagger:model updateLoginFlowWithTotpMethod
type updateLoginFlowWithTotpMethod struct {
	// Method should be set to "totp" when logging in using the TOTP strategy.
	//
	// required: true
	Method string `json:"method"`

	// Sending the anti-csrf token is only required for browser login flows.
	CSRFToken string `json:"csrf_token"`

	// The TOTP code.
	//
	// required: true
	TOTPCode string `json:"totp_code"`

	// Transient data to pass along to any webhooks
	//
	// required: false
	TransientPayload json.RawMessage `json:"transient_payload,omitempty" form:"transient_payload"`
}

var _ login.DefendedStrategy = (*Strategy)(nil)

func (s *Strategy) DefenseMethod() defense.MethodID { return defense.MethodTOTP }

func (s *Strategy) Login(_ http.ResponseWriter, r *http.Request, f *login.Flow, sess *session.Session) (i *identity.Identity, err error) {
	ctx, span := s.d.Tracer(r.Context()).Tracer().Start(r.Context(), "selfservice.strategy.totp.Strategy.Login")
	defer otelx.End(span, &err)

	if err := login.CheckAAL(f, identity.AuthenticatorAssuranceLevel2); err != nil {
		span.SetAttributes(attribute.String("not_responsible_reason", "requested AAL is not AAL2"))
		return nil, err
	}

	if err := flow.MethodEnabledAndAllowedFromRequest(r, f.GetFlowName(), s.ID().String(), s.d); err != nil {
		return nil, err
	}

	var p updateLoginFlowWithTotpMethod
	if err := decoderx.Decode(r, &p,
		decoderx.HTTPDecoderSetValidatePayloads(true),
		decoderx.MustHTTPRawJSONSchemaCompiler(loginSchema),
		decoderx.HTTPDecoderJSONFollowsFormFormat()); err != nil {
		return nil, s.handleLoginError(r, f, err)
	}
	f.TransientPayload = p.TransientPayload

	if err := flow.EnsureCSRF(s.d, r, f.Type, s.d.Config().DisableAPIFlowEnforcement(ctx), s.d.GenerateCSRFToken, p.CSRFToken); err != nil {
		return nil, s.handleLoginError(r, f, err)
	}

	// Defense: BeforeAttempt via the gate, before any lookup or hashing. Only a strategy can call it, as only it knows
	// it is responsible and has its payload. Do not call AfterSuccess/AfterFailure: the login handler reports them.
	// The account is the one of the session: a second factor follows a verified first one.
	if err := gate.From(ctx).Check(ctx, sess.IdentityID.String(), p.TOTPCode); err != nil {
		return nil, s.handleLoginError(r, f, err)
	}

	i, c, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, s.ID(), sess.IdentityID.String())
	if errors.Is(err, sqlcon.ErrNoRows()) {
		return nil, s.handleLoginError(r, f, errors.WithStack(schema.NewNoTOTPDeviceRegistered()))
	} else if err != nil {
		// A failed lookup is a fault of the server, not a missing device.
		return nil, s.handleLoginError(r, f, err)
	}

	var o identity.CredentialsTOTPConfig
	if err := json.Unmarshal(c.Config, &o); err != nil {
		return nil, x.WrapWithIdentityIDError(errors.WithStack(herodot.ErrInternalServerError().WithReason("The TOTP credentials could not be decoded properly").WithDebug(err.Error()).WithWrap(err)), i.ID)
	}

	keyURL, upgraded, err := OpenURL(ctx, s.d, i.ID, o.TOTPURL)
	if err != nil {
		// A 5xx with the cause in debug (see OpenURL): returned as it is.
		return nil, s.handleLoginError(r, f, x.WrapWithIdentityIDError(err, i.ID))
	}

	key, err := otp.NewKeyFromURL(keyURL)
	if err != nil {
		return nil, s.handleLoginError(r, f, x.WrapWithIdentityIDError(errors.WithStack(err), i.ID))
	}

	if !totp.Validate(p.TOTPCode, key.Secret()) {
		return nil, s.handleLoginError(r, f, x.WrapWithIdentityIDError(errors.WithStack(schema.NewTOTPVerifierWrongError("#/")), i.ID))
	}

	// Migrate on use, and only for a correct code: a wrong guess proves nothing, and must not make us write to the
	// database (an attacker could otherwise force a write per attempt). Best effort: the next login tries again.
	if upgraded != "" {
		if err := StoreUpgrade(ctx, s.d.PrivilegedIdentityPool(), i.ID, o.TOTPURL, upgraded); err != nil {
			s.d.Logger().WithError(err).WithField("identity_id", i.ID).Warn("Unable to re-encrypt the TOTP secret.")
		}
	}

	f.Active = s.ID()
	if err = s.d.LoginFlowPersister().UpdateLoginFlow(ctx, f); err != nil {
		return nil, s.handleLoginError(r, f, x.WrapWithIdentityIDError(errors.WithStack(herodot.ErrInternalServerError().WithReason("Could not update flow").WithDebug(err.Error())), i.ID))
	}

	return i, nil
}
