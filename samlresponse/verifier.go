package samlresponse

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"github.com/axent-pl/credentials/common/sig"
)

type SAMLResponseVerifier struct{}

var _ common.Verifier = &SAMLResponseVerifier{}

func (v *SAMLResponseVerifier) Kind() common.Kind { return common.SAMLResponse }

func (v *SAMLResponseVerifier) verify(ctx context.Context, in SAMLResponseCredentials, inXML SAMLResponseXML, s SAMLResponeSchemer) (common.Principal, error) {
	if err := v.verifySignature(inXML, s); err != nil {
		logx.L().Debug("invalid signature", "context", ctx, "error", err)
		return common.Principal{}, fmt.Errorf("%v: invalid signature", common.ErrInvalidCredentials)
	}

	if s.GetRelayState() != "" && s.GetRelayState() != in.RelayState {
		logx.L().Debug("invalid RelayState", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid RelayState", common.ErrInvalidCredentials)
	}

	// validate required fields
	if inXML.ID == "" {
		logx.L().Debug("missing ID", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing ID", common.ErrInvalidCredentials)
	}
	if inXML.Version == "" {
		logx.L().Debug("missing Version", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing Version", common.ErrInvalidCredentials)
	}
	if inXML.IssueInstant == "" {
		logx.L().Debug("missing IssueInstant", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing IssueInstant", common.ErrInvalidCredentials)
	}
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
	if inXML.Status == nil || inXML.Status.StatusCode == nil || inXML.Status.StatusCode.Value == "" {
		logx.L().Debug("missing StatusCode", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing StatusCode", common.ErrInvalidCredentials)
	}

	// validate against schema
	if s.GetVersion() != "" && inXML.Version != s.GetVersion() {
		logx.L().Debug("invalid Version", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid Version", common.ErrInvalidCredentials)
	}
	if s.GetIssuer() != "" && inXML.Issuer.Value != s.GetIssuer() {
		logx.L().Debug("invalid Issuer", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid Issuer", common.ErrInvalidCredentials)
	}
	if s.GetNameIDFormat() != "" && inXML.Assertion.Subject.NameID.Format != s.GetNameIDFormat() {
		logx.L().Debug("invalid NameIDFormat", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid NameIDFormat", common.ErrInvalidCredentials)
	}
	if s.GetDestination() != "" && inXML.Destination != s.GetDestination() {
		logx.L().Debug("invalid Destination", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid Destination", common.ErrInvalidCredentials)
	}
	if s.GetInResponseTo() != "" && inXML.InResponseTo != s.GetInResponseTo() {
		logx.L().Debug("invalid InResponseTo", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid InResponseTo", common.ErrInvalidCredentials)
	}
	if s.GetStatusCode() != "" && inXML.Status.StatusCode.Value != s.GetStatusCode() {
		logx.L().Debug("invalid StatusCode", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid StatusCode", common.ErrInvalidCredentials)
	}
	if err := validateConditions(inXML.Assertion.Conditions, s.GetLeeway()); err != nil {
		logx.L().Debug("invalid Conditions", "context", ctx, "error", err)
		return common.Principal{}, fmt.Errorf("%v: invalid Conditions", common.ErrInvalidCredentials)
	}

	principal := common.Principal{
		Subject:    common.SubjectID(inXML.Assertion.Subject.NameID.Value),
		Attributes: extractAttributes(inXML.Assertion.AttributeStatement),
	}
	return principal, nil
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
	credentials, credentialsXML, err := v.parseInput(ctx, in)
	if err != nil {
		return common.Principal{}, err
	}

	for _, scheme := range s {
		parsedScheme, err := v.parseScheme(ctx, scheme)
		if err != nil {
			continue
		}
		principal, err := v.verify(ctx, credentials, credentialsXML, parsedScheme)
		if err != nil {
			continue
		}
		return principal, nil
	}

	return common.Principal{}, common.ErrInvalidCredentials
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

func (v *SAMLResponseVerifier) verifySignature(inXML SAMLResponseXML, s SAMLResponeSchemer) error {
	keys := s.GetKeys()
	if len(keys) == 0 {
		return nil
	}

	signature := findSignature(inXML)
	if signature == nil {
		return errors.New("missing signature")
	}
	if signature.SignedInfo == nil || signature.SignedInfo.SignatureMethod == nil {
		return errors.New("missing SignedInfo")
	}
	if signature.SignatureValue == "" {
		return errors.New("missing SignatureValue")
	}

	sigAlg, err := sig.FromSAML(signature.SignedInfo.SignatureMethod.Algorithm)
	if err != nil {
		return fmt.Errorf("invalid signature algorithm: %w", err)
	}
	sigHash, err := sigAlg.ToCryptoHash()
	if err != nil {
		return fmt.Errorf("invalid signature hash: %w", err)
	}

	signedInfoBytes, err := xml.Marshal(signature.SignedInfo)
	if err != nil {
		return fmt.Errorf("could not marshal SignedInfo: %w", err)
	}
	digest, err := sig.Hash(signedInfoBytes, *sigHash)
	if err != nil {
		return fmt.Errorf("could not hash SignedInfo: %w", err)
	}

	signatureValue := compactBase64(signature.SignatureValue)
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureValue)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	for _, key := range keys {
		if key.Alg != sig.SigAlgUnknown && key.Alg != sigAlg {
			continue
		}
		if err := sig.Verify(signatureBytes, digest, key.Key, sigAlg); err == nil {
			return nil
		}
	}

	return errors.New("invalid signature")
}

func findSignature(inXML SAMLResponseXML) *SAMLResponseSignatureXML {
	if inXML.Signature != nil {
		return inXML.Signature
	}
	if inXML.Assertion != nil && inXML.Assertion.Signature != nil {
		return inXML.Assertion.Signature
	}
	return nil
}

func validateConditions(conditions *SAMLResponseConditionsXML, leeway time.Duration) error {
	if conditions == nil {
		return nil
	}
	now := time.Now().UTC()
	if conditions.NotBefore != "" {
		notBefore, err := parseSAMLTime(conditions.NotBefore)
		if err != nil {
			return err
		}
		if now.Add(leeway).Before(notBefore) {
			return errors.New("assertion not yet valid")
		}
	}
	if conditions.NotOnOrAfter != "" {
		notOnOrAfter, err := parseSAMLTime(conditions.NotOnOrAfter)
		if err != nil {
			return err
		}
		if !now.Add(-leeway).Before(notOnOrAfter) {
			return errors.New("assertion expired")
		}
	}
	return nil
}

func parseSAMLTime(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}

func extractAttributes(statement *SAMLResponseAttributeStatementXML) map[string]any {
	if statement == nil {
		return nil
	}
	attrs := make(map[string]any)
	for _, attr := range statement.Attributes {
		if attr.Name == "" {
			continue
		}
		values := make([]string, 0, len(attr.Values))
		for _, v := range attr.Values {
			if v.Value == "" {
				continue
			}
			values = append(values, v.Value)
		}
		switch len(values) {
		case 0:
			continue
		case 1:
			attrs[attr.Name] = values[0]
		default:
			attrs[attr.Name] = values
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func compactBase64(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		default:
			return r
		}
	}, strings.TrimSpace(value))
}
