package credentials

import (
	"context"

	"github.com/axent-pl/credentials/common"
)

type Authenticator struct {
	Provider  ValidationSchemeProvider
	Verifiers map[common.Kind]common.Verifier
}

func (a *Authenticator) Authenticate(ctx context.Context, in common.Credentials) (common.Principal, error) {
	kind := in.Kind()

	verifier, ok := a.Verifiers[kind]
	if !ok {
		return common.Principal{}, common.ErrInvalidCredentials
	}

	validationSchemes, err := a.Provider.ValidationSchemes(ctx, in)
	if err != nil {
		return common.Principal{}, common.ErrInvalidCredentials
	}

	principal, err := verifier.VerifyAny(ctx, in, validationSchemes)
	if err != nil {
		return common.Principal{}, common.ErrInvalidCredentials
	}

	return principal, nil
}
