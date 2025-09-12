package auth

import (
	"context"

	"github.com/axent-pl/auth/logx"
	"golang.org/x/crypto/bcrypt"
)

type ClientSecretInput struct {
	ClientID     string
	ClientSecret string
}

func (ClientSecretInput) Kind() CredentialKind { return CredClientSecret }

type ClientSecretStored struct {
	ClientID   string
	SecretHash []byte
}

func (ClientSecretStored) Kind() CredentialKind { return CredClientSecret }

type ClientSecretVerifier struct{}

func (v *ClientSecretVerifier) Kind() CredentialKind { return CredClientSecret }

func (v *ClientSecretVerifier) Verify(ctx context.Context, in InputCredentials, stored []ValidationScheme) (Principal, error) {
	clientSecretInput, ok := in.(ClientSecretInput)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to ClientSecretInput", "context", ctx)
		return Principal{}, ErrInvalidInput
	}
	if clientSecretInput.ClientID == "" {
		logx.L().Debug("empty client_id", "context", ctx)
		return Principal{}, ErrInvalidInput
	}
	if clientSecretInput.ClientSecret == "" {
		logx.L().Debug("empty client_secret", "context", ctx)
		return Principal{}, ErrInvalidInput
	}

	for _, s := range stored {
		clientSecretStored, ok := s.(ClientSecretStored)
		if !ok || clientSecretStored.ClientID != clientSecretInput.ClientID {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(clientSecretStored.SecretHash), []byte(clientSecretInput.ClientSecret)); err != nil {
			continue
		}

		return Principal{Subject: SubjectID(clientSecretStored.ClientID)}, nil

	}
	return Principal{}, ErrInvalidCredentials
}
