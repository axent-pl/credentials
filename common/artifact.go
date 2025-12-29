package common

import "fmt"

type ArtifactKind string

const (
	ArtifactUnknown             ArtifactKind = ""
	ArtifactAccessToken         ArtifactKind = "access_token"
	ArtifactRefreshToken        ArtifactKind = "refresh_token"
	ArtifactIdToken             ArtifactKind = "id_token"
	ArtifactClientAssertion     ArtifactKind = "client_assertion"
	ArtifactClientAssertionType ArtifactKind = "client_assertion_type"
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

func ArtifactWithKind(artifacts []Artifact, kind ArtifactKind) (Artifact, error) {
	for _, artartifact := range artifacts {
		if artartifact.Kind == kind {
			return artartifact, nil
		}
	}
	return Artifact{}, fmt.Errorf("missing artifact %s", kind)
}
