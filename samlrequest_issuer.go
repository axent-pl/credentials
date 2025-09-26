package auth

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/axent-pl/auth/logx"
)

type SAMLRequestIssueScheme struct {
	// The actual entityID string (usually a URI) identifying the Service Provider.
	Issuer string
	Key    SAMLRequestIssueSchemeKey
}

func (SAMLRequestIssueScheme) Kind() Kind { return CredSAMLRequest }

type SAMLRequestIssueSchemeKey struct {
	HashAlg    crypto.Hash
	PrivateKey crypto.PrivateKey
}

type SAMLRequestIssueParams struct {
	// RelayState: Optional (but commonly used).
	// An opaque value sent by the Service Provider (SP) and returned unchanged
	// by the Identity Provider (IdP). Typically used for preserving state (e.g. return URL).
	RelayState string

	// Destination: Optional.
	// URI of the IdP endpoint where the AuthnRequest is being sent.
	Destination string
	// AssertionConsumerServiceURL: Optional (but usually required by SPs).
	// The URL at the SP to which the IdP should send the SAML Response.
	AssertionConsumerServiceURL string
	// ProtocolBinding: Optional.
	// URI specifying the binding (e.g., HTTP-POST, HTTP-Artifact) expected for the response.
	ProtocolBinding string
	// ForceAuthn: Optional.
	// If true, IdP must re-authenticate the user (ignore existing SSO session).
	ForceAuthn *bool
	// IsPassive: Optional.
	// If true, IdP must not interact with the user (silent authentication only).
	IsPassive *bool
}

func (SAMLRequestIssueParams) Kind() Kind { return CredSAMLRequest }

type SAMLRequestIssuer struct {
}

func (SAMLRequestIssuer) Kind() Kind { return CredSAMLRequest }

func (iss *SAMLRequestIssuer) Issue(ctx context.Context, principal Principal, scheme IssueScheme, issueParams IssueParams) ([]Artifact, error) {
	samlIssueScheme, ok := scheme.(SAMLRequestIssueScheme)
	if !ok {
		logx.L().Debug("could not cast IssueScheme to SAMLRequestIssueScheme", "context", ctx)
		return nil, ErrInternal
	}
	samlIssueParams, ok := issueParams.(SAMLRequestIssueParams)
	if !ok {
		logx.L().Debug("could not cast IssueParams to SAMLRequestIssueParams", "context", ctx)
		return nil, ErrInternal
	}

	samlRequest := SAMLRequestInput{
		RelayState: samlIssueParams.RelayState,
	}
	samlRequestXML := SAMLRequestXML{
		Version:                     "2.0",
		IssueInstant:                time.Now().Format(time.RFC3339),
		Destination:                 samlIssueParams.Destination,
		AssertionConsumerServiceURL: samlIssueParams.AssertionConsumerServiceURL,
		// ProtocolBinding: "",
		// ForceAuthn: nil,
		// IsPassive: nil,
		Issuer: &SAMLRequestIssuerXML{
			Value: samlIssueScheme.Issuer,
		},
	}
	samlRequestXMLEncoded, err := encodeSAMLRequestXML(samlRequestXML)
	if err != nil {
		logx.L().Error("could not encode SAMLRequestXML", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	samlRequest.SAMLRequest = samlRequestXMLEncoded
	signedData := buildSignedQuery(samlRequest)

	fmt.Println(samlIssueScheme)
	fmt.Println(samlIssueParams)
	fmt.Println(samlRequest)
	fmt.Println(samlRequestXML)
	fmt.Println(signedData)

	return nil, nil
}

func encodeSAMLRequestXML(req SAMLRequestXML) (string, error) {
	xmlBytes, err := xml.Marshal(req) // compact; keep it deterministic
	if err != nil {
		return "", err
	}
	var deflated bytes.Buffer
	// HTTP-Redirect uses raw DEFLATE (RFC1951) (no zlib header/footer),
	// which compress/flate writes by default.
	w, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(xmlBytes); err != nil {
		_ = w.Close()
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(deflated.Bytes()), nil
}
