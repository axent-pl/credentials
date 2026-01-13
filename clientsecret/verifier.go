package clientsecret

import (
	"context"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
)

type ClientSecretVerifier struct{}

var _ common.Verifier = &ClientSecretVerifier{}

func (v *ClientSecretVerifier) Kind() common.Kind { return common.ClientSecret }

func (v *ClientSecretVerifier) parseInput(ctx context.Context, in common.Credentials) (ClientSecretCredentials, error) {
	clientSecretInput, ok := in.(ClientSecretCredentials)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to ClientSecretInput", "context", ctx)
		return ClientSecretCredentials{}, common.ErrInvalidInput
	}
	if clientSecretInput.ClientID == "" {
		logx.L().Debug("empty client_id", "context", ctx)
		return ClientSecretCredentials{}, common.ErrInvalidInput
	}
	if clientSecretInput.ClientSecret == "" {
		logx.L().Debug("empty client_secret", "context", ctx)
		return ClientSecretCredentials{}, common.ErrInvalidInput
	}
	return clientSecretInput, nil
}

func (v *ClientSecretVerifier) VerifyAny(ctx context.Context, in common.Credentials, schemes []common.Scheme) (common.Principal, error) {
	clientSecretInput, err := v.parseInput(ctx, in)
	if err != nil {
		return common.Principal{}, err
	}

	for _, s := range schemes {
		scheme, ok := s.(ClientSecretSchemer)
		if !ok {
			continue
		}
		if err := scheme.CompareIdAndSecret(clientSecretInput.ClientID, clientSecretInput.ClientSecret); err != nil {
			continue
		}

		return common.Principal{Subject: common.SubjectID(clientSecretInput.ClientID)}, nil

	}
	return common.Principal{}, common.ErrInvalidCredentials
}
