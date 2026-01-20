package samlresponse

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"sort"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"github.com/axent-pl/credentials/common/sig"
)

type SAMLResponseIssueParams struct {
	Issuer       string
	Key          sig.SignatureKeyer
	Destination  string
	InResponseTo string

	RelayState   string
	NameIDFormat string
	StatusCode   string
	Exp          time.Duration

	IncludedAttributes []string
	OverlayAttributes  map[string]any
}

func (SAMLResponseIssueParams) Kind() common.Kind { return common.SAMLResponse }

type SAMLResponseIssuer struct{}

var _ common.Issuer = SAMLResponseIssuer{}

func (SAMLResponseIssuer) Kind() common.Kind { return common.SAMLResponse }

func (iss SAMLResponseIssuer) Issue(ctx context.Context, principal common.Principal, issueParams common.IssueParams) ([]common.Artifact, error) {
	p, ok := issueParams.(SAMLResponseIssueParams)
	if !ok {
		logx.L().Debug("could not cast IssueParams to SAMLResponseIssueParams", "context", ctx)
		return nil, common.ErrInternal
	}
	if principal.Subject == "" {
		logx.L().Debug("missing principal subject", "context", ctx)
		return nil, common.ErrInternal
	}
	if p.Issuer == "" {
		logx.L().Debug("missing issuer", "context", ctx)
		return nil, common.ErrInternal
	}

	now := time.Now().UTC()
	responseID, err := newSAMLID(16)
	if err != nil {
		logx.L().Debug("could not generate response ID", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}
	assertionID, err := newSAMLID(16)
	if err != nil {
		logx.L().Debug("could not generate assertion ID", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}

	statusCode := p.StatusCode
	if statusCode == "" {
		statusCode = "urn:oasis:names:tc:SAML:2.0:status:Success"
	}

	attrs := iss.PatchedAttributes(ctx, principal, p.IncludedAttributes, p.OverlayAttributes)
	var attributeStatement *SAMLResponseAttributeStatementXML
	if len(attrs) > 0 {
		attributeStatement = &SAMLResponseAttributeStatementXML{
			Attributes: attrs,
		}
	}

	var conditions *SAMLResponseConditionsXML
	if p.Exp > 0 {
		conditions = &SAMLResponseConditionsXML{
			NotBefore:    now.Format(time.RFC3339),
			NotOnOrAfter: now.Add(p.Exp).Format(time.RFC3339),
		}
	}

	samlResponseXML := SAMLResponseXML{
		ID:           responseID,
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339),
		Destination:  p.Destination,
		InResponseTo: p.InResponseTo,
		Issuer: &SAMLResponseIssuerXML{
			Value: p.Issuer,
		},
		Status: &SAMLResponseStatusXML{
			StatusCode: &SAMLResponseStatusCodeXML{
				Value: statusCode,
			},
		},
		Assertion: &SAMLResponseAssertionXML{
			ID:           assertionID,
			Version:      "2.0",
			IssueInstant: now.Format(time.RFC3339),
			Subject: &SAMLResponseSubjectXML{
				NameID: &SAMLResponseNameIDXML{
					Format: p.NameIDFormat,
					Value:  string(principal.Subject),
				},
			},
			Conditions: conditions,
			AuthnStatement: &SAMLResponseAuthnStatementXML{
				AuthnInstant: now.Format(time.RFC3339),
			},
			AttributeStatement: attributeStatement,
		},
	}

	if p.Key != nil {
		signature, err := iss.BuildSignature(ctx, p)
		if err != nil {
			logx.L().Debug("could not sign SAMLResponse", "context", ctx, "error", err)
			return nil, common.ErrInternal
		}
		samlResponseXML.Signature = signature
	}

	samlResponseCredentials := SAMLResponseCredentials{
		RelayState: p.RelayState,
	}
	if err := samlResponseCredentials.MarshalSAMLResponse(samlResponseXML); err != nil {
		logx.L().Debug("could not marshal SAMLResponse", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}

	artifacts := make([]common.Artifact, 0, 1)
	artifact := common.Artifact{
		Kind:      common.ArtifactSAMLResponse,
		MediaType: "text/plain",
		Bytes:     []byte(samlResponseCredentials.SAMLResponse),
	}
	if p.RelayState != "" {
		artifact.Metadata = map[string]any{
			"relay_state": p.RelayState,
		}
	}
	artifacts = append(artifacts, artifact)

	return artifacts, nil
}

func (iss SAMLResponseIssuer) BuildSignature(ctx context.Context, params SAMLResponseIssueParams) (*SAMLResponseSignatureXML, error) {
	if params.Key == nil {
		return nil, fmt.Errorf("missing key")
	}

	sigAlg, err := params.Key.GetAlg().ToSAML()
	if err != nil {
		return nil, fmt.Errorf("invalid signature algorithm: %w", err)
	}

	_ = ctx
	signedInfo := &SAMLResponseSignedInfoXML{
		CanonicalizationMethod: &SAMLResponseCanonicalizationMethodXML{
			Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
		},
		SignatureMethod: &SAMLResponseSignatureMethodXML{
			Algorithm: sigAlg,
		},
	}

	signatureValue, err := iss.SignSignedInfo(ctx, signedInfo, params)
	if err != nil {
		return nil, err
	}

	return &SAMLResponseSignatureXML{
		SignedInfo:     signedInfo,
		SignatureValue: signatureValue,
	}, nil
}

func (iss SAMLResponseIssuer) SignSignedInfo(ctx context.Context, signedInfo *SAMLResponseSignedInfoXML, params SAMLResponseIssueParams) (string, error) {
	if signedInfo == nil {
		return "", fmt.Errorf("missing signed info")
	}
	if params.Key == nil {
		return "", fmt.Errorf("missing key")
	}

	sigHash, err := params.Key.GetAlg().ToCryptoHash()
	if err != nil {
		return "", fmt.Errorf("invalid signature hash: %w", err)
	}

	signedInfoBytes, err := xml.Marshal(signedInfo)
	if err != nil {
		return "", fmt.Errorf("could not marshal SignedInfo: %w", err)
	}
	digest, err := sig.Hash(signedInfoBytes, *sigHash)
	if err != nil {
		return "", fmt.Errorf("could not hash SignedInfo: %w", err)
	}

	signer, ok := params.Key.GetKey().(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("key does not implement crypto.Signer")
	}

	signature, err := signer.Sign(rand.Reader, digest, crypto.SignerOpts(*sigHash))
	if err != nil {
		return "", fmt.Errorf("could not sign SignedInfo: %w", err)
	}

	_ = ctx
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (iss SAMLResponseIssuer) PatchedAttributes(ctx context.Context, principal common.Principal, includedAttributes []string, overlayAttributes map[string]any) []SAMLResponseAttributeXML {
	attrs := make(map[string][]string)

	if principal.Attributes != nil && len(includedAttributes) > 0 {
		allow := make(map[string]struct{}, len(includedAttributes))
		for _, k := range includedAttributes {
			allow[k] = struct{}{}
		}
		for k, v := range principal.Attributes {
			if _, ok := allow[k]; !ok {
				continue
			}
			if values := attributeValueStrings(v); len(values) > 0 {
				attrs[k] = values
			}
		}
	}

	for k, v := range overlayAttributes {
		if values := attributeValueStrings(v); len(values) > 0 {
			attrs[k] = values
		}
	}

	if len(attrs) == 0 {
		return nil
	}

	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]SAMLResponseAttributeXML, 0, len(attrs))
	for _, k := range keys {
		values := attrs[k]
		if len(values) == 0 {
			continue
		}
		attr := SAMLResponseAttributeXML{
			Name: k,
		}
		for _, v := range values {
			if v == "" {
				continue
			}
			attr.Values = append(attr.Values, SAMLResponseAttributeValueXML{Value: v})
		}
		if len(attr.Values) == 0 {
			continue
		}
		out = append(out, attr)
	}

	_ = ctx
	return out
}

func attributeValueStrings(value any) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if item == "" {
				continue
			}
			out = append(out, item)
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if item == nil {
				continue
			}
			out = append(out, fmt.Sprint(item))
		}
		return out
	default:
		return []string{fmt.Sprint(v)}
	}
}

func newSAMLID(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(b), nil
}
