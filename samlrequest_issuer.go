package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/axent-pl/auth/logx"
)

type SAMLRequestIssueScheme struct {
	// The actual entityID string (usually a URI) identifying the Service Provider.
	Issuer string
	Key    *SAMLRequestIssueSchemeKey
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

func (iss *SAMLRequestIssuer) Issue(ctx context.Context, _ Principal, scheme IssueScheme, issueParams IssueParams) ([]Artifact, error) {
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
		ProtocolBinding:             samlIssueParams.ProtocolBinding,
		ForceAuthn:                  samlIssueParams.ForceAuthn,
		IsPassive:                   samlIssueParams.IsPassive,
		Issuer: &SAMLRequestIssuerXML{
			Value: samlIssueScheme.Issuer,
		},
	}
	// marshal SAMLRequestXML
	if err := samlRequest.MarshalSAMLRequest(samlRequestXML); err != nil {
		logx.L().Error("could not encode SAMLRequestXML", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	// sign if signature key provided in scheme
	if samlIssueScheme.Key != nil {
		// determine SigAlg
		sigAlg, err := SAMLSigAlg(samlIssueScheme.Key.PrivateKey, samlIssueScheme.Key.HashAlg)
		if err != nil {
			logx.L().Error("could not determine SAMLRequest SigAlg", "context", ctx, "error", err)
			return nil, ErrInternal
		}
		// sign
		samlRequest.SigAlg = sigAlg
		signature, err := iss.Sign(samlRequest, samlIssueScheme.Key)
		if err != nil {
			logx.L().Error("could not sign SAMLRequest", "context", ctx, "error", err)
			return nil, ErrInternal
		}
		samlRequest.Signature = signature
	}

	samlRequestURI, err := iss.buildSAMLRequestURI(samlIssueParams.Destination, samlRequest)
	if err != nil {
		logx.L().Error("could not build SAMLRequest URI", "context", ctx, "error", err)
		return nil, ErrInternal
	}

	artifacts := make([]Artifact, 0)

	// SAML request URI
	artifacts = append(artifacts, Artifact{
		Kind:      ArtifactSAMLRequestURI, // or a custom ArtifactRedirectURL if you define one
		MediaType: "text/uri-list",        // standard for representing a URI
		Bytes:     []byte(samlRequestURI),
	})

	return artifacts, nil
}

func (iss *SAMLRequestIssuer) Sign(r SAMLRequestInput, key *SAMLRequestIssueSchemeKey) (string, error) {
	_, _ = SAMLSigAlg(key.PrivateKey, key.HashAlg)
	signedData := r.SignedQuery()
	digest, _ := hashSAMLSignedData(signedData, key.HashAlg)

	var opts crypto.SignerOpts
	switch key.PrivateKey.(type) {
	case *rsa.PrivateKey:
		opts = crypto.SignerOpts(key.HashAlg) // nil vs. hashAlg both OK for RSA in practice; hashAlg carries the hash choice
	default:
		opts = key.HashAlg
	}

	signer, ok := key.PrivateKey.(crypto.Signer)
	if !ok {
		return "", errors.New("could not sign SAML request: key does not implement crypto.Signer")
	}

	signature, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return "", fmt.Errorf("could not sign SAML request: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func (iss *SAMLRequestIssuer) buildSAMLRequestURI(destination string, in SAMLRequestInput) (string, error) {
	u, err := url.Parse(destination)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("SAMLRequest", in.SAMLRequest)

	if in.RelayState != "" {
		q.Set("RelayState", in.RelayState)
	}
	if in.SigAlg != "" {
		q.Set("SigAlg", in.SigAlg)
	}
	if in.Signature != "" {
		q.Set("Signature", in.Signature)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func SAMLSigAlg(privKey crypto.PrivateKey, hashAlg crypto.Hash) (string, error) {
	switch privKey.(type) {
	case *rsa.PrivateKey:
		switch hashAlg {
		case crypto.SHA1:
			return "http://www.w3.org/2000/09/xmldsig#rsa-sha1", nil
		case crypto.SHA256:
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", nil
		case crypto.SHA384:
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", nil
		case crypto.SHA512:
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", nil
		default:
			return "", fmt.Errorf("unsupported RSA hash: %v", hashAlg)
		}

	case *ecdsa.PrivateKey:
		switch hashAlg {
		case crypto.SHA256:
			return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", nil
		case crypto.SHA384:
			return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", nil
		case crypto.SHA512:
			return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA hash: %v", hashAlg)
		}

	default:
		return "", errors.New("unsupported key type")
	}
}
