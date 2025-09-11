package auth

import (
	"context"

	"golang.org/x/crypto/bcrypt"
)

type PasswordInput struct {
	Username string
	Password string
}

func (PasswordInput) Kind() CredentialKind { return CredPassword }

type PasswordStored struct {
	Username   string
	PasswordHash []byte
}

func (PasswordStored) Kind() CredentialKind { return CredPassword }

type PasswordVerifier struct{}

func (v *PasswordVerifier) Kind() CredentialKind { return CredPassword }

func (v *PasswordVerifier) Verify(ctx context.Context, in InputCredentials, stored []ValidationScheme) (Principal, error) {
	passwordInput, ok := in.(PasswordInput)
	if !ok {
		return Principal{}, ErrInvalidInput
	}
	for _, s := range stored {
		passwordStored, ok := s.(PasswordStored)
		if !ok || passwordStored.Username != passwordInput.Username {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(passwordStored.PasswordHash), []byte(passwordInput.Password)); err != nil {
			continue
		}

		return Principal{Subject: SubjectID(passwordStored.Username)}, nil
	}
	return Principal{}, ErrInvalidCredentials
}