package auth

import (
	"context"
	"errors"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidInput = errors.New("bad input")

type CredentialKind string

const (
	CredPassword     CredentialKind = "password"
	CredClientSecret CredentialKind = "client_secret"
	CredJWTAssertion CredentialKind = "jwt_assertion"
	CredJWT          CredentialKind = "jwt"
	CredMTLS         CredentialKind = "mtls"
	CredSAMLRequest  CredentialKind = "saml_request"
)

type SubjectID string

type Principal struct {
	Subject    SubjectID
	Attributes map[string]any
}

type InputCredentials interface {
	Kind() CredentialKind
}

type ValidationScheme interface {
	Kind() CredentialKind
}

type IssueScheme interface {
	Kind() CredentialKind
}

type Verifier interface {
	Kind() CredentialKind
	Verify(ctx context.Context, in InputCredentials, stored []ValidationScheme) (Principal, error)
}
