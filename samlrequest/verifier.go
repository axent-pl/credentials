package samlrequest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/logx"
	"github.com/axent-pl/credentials/sig"
)

type SAMLRequestVerifier struct{}

func (v *SAMLRequestVerifier) Kind() common.Kind { return common.SAMLRequest }

func (v *SAMLRequestVerifier) Verify(ctx context.Context, in common.Credentials, schemes []common.Scheme) (common.Principal, error) {
	samlRequestInput, ok := in.(SAMLRequestCredentials)
	if !ok {
		logx.L().Debug("could not cast Input to SAMLRequestInput", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	if samlRequestInput.SAMLRequest == "" {
		logx.L().Debug("empty request", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	samlRequestXML, err := samlRequestInput.UnmarshalSAMLRequest()
	if err != nil {
		logx.L().Debug("could not parse SAML request", "context", ctx, "error", err)
		return common.Principal{}, common.ErrInvalidInput
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
		return common.Principal{Subject: common.SubjectID(samlRequestXML.Issuer.Value)}, nil
	}

	return common.Principal{}, common.ErrInvalidCredentials
}

func (v *SAMLRequestVerifier) VerifySignature(r SAMLRequestCredentials, s SAMLRequestScheme) error {
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
