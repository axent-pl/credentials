package auth

import "context"

type StoredCredentialsProvider interface {
	QueryCredentials(ctx context.Context, in InputCredentials) ([]StoredCredentials, error)
}

type Authenticator struct {
	Provider  StoredCredentialsProvider
	Verifiers map[CredentialKind]Verifier
}

func (a *Authenticator) Authenticate(ctx context.Context, in InputCredentials) (Principal, error) {
	kind := in.Kind()

	verifier, ok := a.Verifiers[kind]
	if !ok {
		return Principal{}, ErrInvalidCredentials
	}

	storedCredentials, err := a.Provider.QueryCredentials(ctx, in)
	if err != nil {
		return Principal{}, ErrInvalidCredentials
	}

	principal, err := verifier.Verify(ctx, in, storedCredentials)
	if err != nil {
		return Principal{}, ErrInvalidCredentials
	}

	return principal, nil
}
