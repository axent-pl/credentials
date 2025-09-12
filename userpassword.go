package auth

import (
	"context"

	"github.com/axent-pl/auth/logx"
	"golang.org/x/crypto/bcrypt"
)

type UserPasswordInput struct {
	Username string
	Password string
}

func (UserPasswordInput) Kind() CredentialKind { return CredPassword }

type UserPasswordScheme struct {
	Username     string
	PasswordHash []byte
}

func (UserPasswordScheme) Kind() CredentialKind { return CredPassword }

type UserPasswordVerifier struct{}

func (v *UserPasswordVerifier) Kind() CredentialKind { return CredPassword }

func (v *UserPasswordVerifier) Verify(ctx context.Context, in InputCredentials, schemes []ValidationScheme) (Principal, error) {
	userPasswordInput, ok := in.(UserPasswordInput)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to UserPasswordInput", "context", ctx)
		return Principal{}, ErrInvalidInput
	}
	if userPasswordInput.Username == "" {
		logx.L().Debug("empty username", "context", ctx)
		return Principal{}, ErrInvalidInput
	}
	if userPasswordInput.Password == "" {
		logx.L().Debug("empty password", "context", ctx)
		return Principal{}, ErrInvalidInput
	}
	for _, s := range schemes {
		userPasswordScheme, ok := s.(UserPasswordScheme)
		if !ok || userPasswordScheme.Username != userPasswordInput.Username {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(userPasswordScheme.PasswordHash), []byte(userPasswordInput.Password)); err != nil {
			continue
		}

		return Principal{Subject: SubjectID(userPasswordScheme.Username)}, nil
	}
	return Principal{}, ErrInvalidCredentials
}
