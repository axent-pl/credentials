package userpassword

import (
	"context"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"golang.org/x/crypto/bcrypt"
)

type UserPasswordVerifier struct{}

var _ common.Verifier = &UserPasswordVerifier{}

func (v *UserPasswordVerifier) Kind() common.Kind { return common.Password }

func (v *UserPasswordVerifier) VerifyAny(ctx context.Context, in common.Credentials, schemes []common.Scheme) (common.Principal, error) {
	userPasswordInput, ok := in.(UserPasswordInput)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to UserPasswordInput", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	if userPasswordInput.Username == "" {
		logx.L().Debug("empty username", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	if userPasswordInput.Password == "" {
		logx.L().Debug("empty password", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	for _, s := range schemes {
		userPasswordScheme, ok := s.(UserPasswordScheme)
		if !ok || userPasswordScheme.Username != userPasswordInput.Username {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(userPasswordScheme.PasswordHash), []byte(userPasswordInput.Password)); err != nil {
			continue
		}

		return common.Principal{Subject: common.SubjectID(userPasswordScheme.Username)}, nil
	}
	return common.Principal{}, common.ErrInvalidCredentials
}
