package userpassword

import (
	"context"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
)

type UserPasswordVerifier struct{}

var _ common.Verifier = &UserPasswordVerifier{}

func (v *UserPasswordVerifier) Kind() common.Kind { return common.Password }

func (v *UserPasswordVerifier) parseInput(ctx context.Context, in common.Credentials) (UserPasswordCredentials, error) {
	clientSecretInput, ok := in.(UserPasswordCredentials)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to UserPasswordCredentials", "context", ctx)
		return UserPasswordCredentials{}, common.ErrInvalidInput
	}
	if clientSecretInput.Username == "" {
		logx.L().Debug("empty username", "context", ctx)
		return UserPasswordCredentials{}, common.ErrInvalidInput
	}
	if clientSecretInput.Password == "" {
		logx.L().Debug("empty password", "context", ctx)
		return UserPasswordCredentials{}, common.ErrInvalidInput
	}
	return clientSecretInput, nil
}

func (v *UserPasswordVerifier) VerifyAny(ctx context.Context, in common.Credentials, schemes []common.Scheme) (common.Principal, error) {
	userPasswordInput, err := v.parseInput(ctx, in)
	if err != nil {
		return common.Principal{}, err
	}

	for _, s := range schemes {
		scheme, ok := s.(DefaultUserPasswordScheme)
		if !ok {
			continue
		}
		if err := scheme.CompareUsernameAndPassword(userPasswordInput.Username, userPasswordInput.Password); err != nil {
			continue
		}

		return common.Principal{Subject: common.SubjectID(scheme.Username)}, nil
	}
	return common.Principal{}, common.ErrInvalidCredentials
}
