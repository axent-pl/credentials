package auth

import (
	"context"

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
