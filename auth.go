package auth

import (
	"context"
	"errors"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidInput = errors.New("bad input")
var ErrInternal = errors.New("internal error")

type CredentialKind string

const (
	CredPassword        CredentialKind = "password"
	CredClientSecret    CredentialKind = "client_secret"
	CredClientAssertion CredentialKind = "client_assertion"
	CredJWT             CredentialKind = "jwt"
	CredMTLS            CredentialKind = "mtls"
	CredSAMLRequest     CredentialKind = "saml_request"
)

type SubjectID string

type Principal struct {
	Subject    SubjectID
	Attributes map[string]any
}

// -- input --
type InputCredentials interface {
	Kind() CredentialKind
}

// -- validation --
type ValidationScheme interface {
	Kind() CredentialKind
}
type Verifier interface {
	Kind() CredentialKind
	Verify(ctx context.Context, in InputCredentials, stored []ValidationScheme) (Principal, error)
}

// -- issue --
type IssueScheme interface {
	Kind() CredentialKind
}

type IssueParams interface {
	Kind() CredentialKind
}

type ArtifactKind string

const (
	ArtifactUnknown      ArtifactKind = ""
	ArtifactAccessToken  ArtifactKind = "access_token"
	ArtifactRefreshToken ArtifactKind = "refresh_token"
	ArtifactIdToken      ArtifactKind = "id_token"
)

type Artifact struct {
	Kind      ArtifactKind
	MediaType string // e.g. "application/jwt", "text/plain", "application/pkix-cert"
	Bytes     []byte
	Metadata  map[string]any
}

type Issuer interface {
	Kind() CredentialKind
	Issue(ctx context.Context, principal Principal, scheme IssueScheme, issueParams IssueParams) ([]Artifact, error)
}
