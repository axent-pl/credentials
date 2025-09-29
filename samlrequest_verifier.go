package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/axent-pl/auth/logx"
	"github.com/axent-pl/auth/sig"
)

type SAMLRequestVerifier struct{}

func (v *SAMLRequestVerifier) Kind() Kind { return CredSAMLRequest }

func (v *SAMLRequestVerifier) Verify(ctx context.Context, in Credentials, schemes []Scheme) (Principal, error) {
	samlRequestInput, ok := in.(SAMLRequestInput)
	if !ok {
		logx.L().Debug("could not cast Input to SAMLRequestInput", "context", ctx)
		return Principal{}, ErrInvalidInput
	}
	if samlRequestInput.SAMLRequest == "" {
		logx.L().Debug("empty request", "context", ctx)
		return Principal{}, ErrInvalidInput
	}
	samlRequestXML, err := samlRequestInput.UnmarshalSAMLRequest()
	if err != nil {
		logx.L().Debug("could not parse SAML request", "context", ctx, "error", err)
		return Principal{}, ErrInvalidInput
	}

	for _, s := range schemes {
		scheme, ok := s.(SAMLRequestScheme)
		if !ok {
			continue
		}
		if err := v.VerifySignature(samlRequestInput, scheme); err != nil {
			continue
		}
		if samlRequestXML.Issuer.Value == "" {
			continue
		}
		return Principal{Subject: SubjectID(samlRequestXML.Issuer.Value)}, nil
	}

	return Principal{}, ErrInvalidCredentials
}

func (v *SAMLRequestVerifier) VerifySignature(r SAMLRequestInput, s SAMLRequestScheme) error {
	// no keys in scheme => no signature verification
	if len(s.Keys) == 0 {
		return nil
	}
	// keys in scheme => require signature algorithm
	if r.SigAlg == "" {
		return errors.New("missing signature algorithm")
	}
	// decode signature algorithm
	sigAlg, err := sig.FromSAML(r.SigAlg)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	// decode signature hash
	sigHash, err := sigAlg.ToCryptoHash()
	if err != nil {
		return fmt.Errorf("invalid signature hash: %w", err)
	}

	// keys in scheme => require signature
	if r.Signature == "" {
		return errors.New("missing signature")
	}
	// decode signature
	signature, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}

	// generate digest
	signedData := r.SignedQuery()
	digest, err := sig.Hash(signedData, *sigHash)
	if err != nil {
		return fmt.Errorf("could not hash signed data: %w", err)
	}

	for _, k := range s.Keys {
		// only consider keys that declare the same SigAlg
		if k.SigAlg != sigAlg {
			continue
		}

		if err := sig.Verify(signature, digest, k.Key, k.SigAlg); err == nil {
			return nil
		}
	}

	return errors.New("invalid signature")
}
