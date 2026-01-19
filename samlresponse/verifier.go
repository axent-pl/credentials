package samlresponse

import (
	"context"
	"fmt"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
)

type SAMLResponseVerifier struct{}

var _ common.Verifier = &SAMLResponseVerifier{}

func (v *SAMLResponseVerifier) Kind() common.Kind { return common.SAMLResponse }

func (v *SAMLResponseVerifier) verify(ctx context.Context, in SAMLResponseCredentials, inXML SAMLResponseXML, s SAMLResponeSchemer) (common.Principal, error) {
	if s.GetRelayState() != "" && s.GetRelayState() != in.RelayState {
		logx.L().Debug("invalid RelayState", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid RelayState", common.ErrInvalidCredentials)
	}

	// validate required fields
	if inXML.Assertion == nil {
		logx.L().Debug("missing Assertion", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing Assertion", common.ErrInvalidCredentials)
	}
	if inXML.Issuer == nil || inXML.Issuer.Value == "" {
		logx.L().Debug("missing Issuer", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing Issuer", common.ErrInvalidCredentials)
	}
	if inXML.Assertion.Subject == nil || inXML.Assertion.Subject.NameID == nil || inXML.Assertion.Subject.NameID.Value == "" {
		logx.L().Debug("missing NameID", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing NameID", common.ErrInvalidCredentials)
	}

	// validate against schema
	if s.GetIssuer() != "" && inXML.Issuer.Value != s.GetIssuer() {
		logx.L().Debug("invalid Issuer", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid Issuer", common.ErrInvalidCredentials)
	}
	if s.GetNameIDFormat() != "" && inXML.Assertion.Subject.NameID.Format != s.GetNameIDFormat() {
		logx.L().Debug("invalid NameIDFormat", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid NameIDFormat", common.ErrInvalidCredentials)
	}

	return common.Principal{}, nil
}

func (v *SAMLResponseVerifier) Verify(ctx context.Context, in common.Credentials, s common.Scheme) (common.Principal, error) {
	scheme, err := v.parseScheme(ctx, s)
	if err != nil {
		return common.Principal{}, err
	}

	credentials, credentialsXML, err := v.parseInput(ctx, in)
	if err != nil {
		return common.Principal{}, err
	}

	return v.verify(ctx, credentials, credentialsXML, scheme)
}

func (v *SAMLResponseVerifier) VerifyAny(ctx context.Context, in common.Credentials, s []common.Scheme) (common.Principal, error) {
	_, _, err := v.parseInput(ctx, in)
	if err != nil {
		return common.Principal{}, err
	}

	return common.Principal{}, nil
}

func (v *SAMLResponseVerifier) parseScheme(ctx context.Context, s common.Scheme) (SAMLResponeSchemer, error) {
	scheme, ok := s.(SAMLResponeSchemer)
	if !ok {
		logx.L().Debug("could not cast scheme to SAMLResponeSchemer", "context", ctx)
		return nil, fmt.Errorf("%v: invalid scheme", common.ErrInternal)
	}

	return scheme, nil
}

func (v *SAMLResponseVerifier) parseInput(ctx context.Context, in common.Credentials) (SAMLResponseCredentials, SAMLResponseXML, error) {
	samlResponseCredentials, ok := in.(SAMLResponseCredentials)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to SAMLResponseCredentials", "context", ctx)
		return SAMLResponseCredentials{}, SAMLResponseXML{}, fmt.Errorf("%v: invalid token", common.ErrInvalidInput)
	}
	samlResponseCredentialsXML, err := samlResponseCredentials.UnmarshalSAMLResponse()
	if err != nil {
		logx.L().Debug("could not parse SAMLResponse", "context", ctx, "error", err)
		return SAMLResponseCredentials{}, SAMLResponseXML{}, fmt.Errorf("%v: invalid SAMLResponse", common.ErrInvalidInput)
	}

	return samlResponseCredentials, *samlResponseCredentialsXML, nil
}
