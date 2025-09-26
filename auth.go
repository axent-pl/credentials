package auth

import (
	"context"
	"errors"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidInput = errors.New("bad input")
var ErrInternal = errors.New("internal error")

type Kind string

const (
	CredPassword        Kind = "password"
	CredClientSecret    Kind = "client_secret"
	CredClientAssertion Kind = "client_assertion"
	CredJWT             Kind = "jwt"
	CredMTLS            Kind = "mtls"
	CredSAMLRequest     Kind = "saml_request"
	CredSAMLResponse    Kind = "saml_response"
)

type SubjectID string

type Principal struct {
	Subject    SubjectID
	Attributes map[string]any
}

// -- input --
type Credentials interface {
	Kind() Kind
}

// -- validation --
type Scheme interface {
	Kind() Kind
}
type Verifier interface {
	Kind() Kind
	Verify(ctx context.Context, in Credentials, stored []Scheme) (Principal, error)
}

// -- issue --
type IssueScheme interface {
	Kind() Kind
}

type IssueParams interface {
	Kind() Kind
}

type ArtifactKind string

const (
	ArtifactUnknown      ArtifactKind = ""
	ArtifactAccessToken  ArtifactKind = "access_token"
	ArtifactRefreshToken ArtifactKind = "refresh_token"
	ArtifactIdToken      ArtifactKind = "id_token"
	// #nosec G101
	ArtifactOAuth2TokenResponse ArtifactKind = "oauth2_token_response"
	ArtifactSAMLRequestURI      ArtifactKind = "saml_request_uri"
)

type Artifact struct {
	Kind      ArtifactKind
	MediaType string // e.g. "application/jwt", "text/plain", "application/pkix-cert"
	Bytes     []byte
	Metadata  map[string]any
}

type Issuer interface {
	Kind() Kind
	Issue(ctx context.Context, principal Principal, scheme IssueScheme, issueParams IssueParams) ([]Artifact, error)
}
