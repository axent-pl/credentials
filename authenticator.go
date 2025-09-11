package auth

import "context"

type ValidationSchemeProvider interface {
	ValidationSchemes(ctx context.Context, in InputCredentials) ([]ValidationScheme, error)
}

type Authenticator struct {
	Provider  ValidationSchemeProvider
	Verifiers map[CredentialKind]Verifier
}

func (a *Authenticator) Authenticate(ctx context.Context, in InputCredentials) (Principal, error) {
	kind := in.Kind()

	verifier, ok := a.Verifiers[kind]
	if !ok {
		return Principal{}, ErrInvalidCredentials
	}

	validationSchemes, err := a.Provider.ValidationSchemes(ctx, in)
	if err != nil {
		return Principal{}, ErrInvalidCredentials
	}

	principal, err := verifier.Verify(ctx, in, validationSchemes)
	if err != nil {
		return Principal{}, ErrInvalidCredentials
	}

	return principal, nil
}
