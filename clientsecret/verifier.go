package clientsecret

import (
	"context"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/logx"
	"golang.org/x/crypto/bcrypt"
)

type ClientSecretVerifier struct{}

func (v *ClientSecretVerifier) Kind() common.Kind { return common.ClientSecret }

func (v *ClientSecretVerifier) Verify(ctx context.Context, in common.Credentials, stored []common.Scheme) (common.Principal, error) {
	clientSecretInput, ok := in.(ClientSecretCredentials)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to ClientSecretInput", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	if clientSecretInput.ClientID == "" {
		logx.L().Debug("empty client_id", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	if clientSecretInput.ClientSecret == "" {
		logx.L().Debug("empty client_secret", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}

	for _, s := range stored {
		clientSecretStored, ok := s.(ClientSecretScheme)
		if !ok || clientSecretStored.ClientID != clientSecretInput.ClientID {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(clientSecretStored.SecretHash), []byte(clientSecretInput.ClientSecret)); err != nil {
			continue
		}

		return common.Principal{Subject: common.SubjectID(clientSecretStored.ClientID)}, nil

	}
	return common.Principal{}, common.ErrInvalidCredentials
}
