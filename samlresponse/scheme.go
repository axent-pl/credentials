package samlresponse

import (
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
)

type SAMLResponeSchemer interface {
	Kind() common.Kind
	GetKeys() []sig.SignatureVerificationKey
	GetRelayState() string
	GetIssuer() string
	GetNameIDFormat() string
	// Optional.
	// URI of the SP endpoint where the response is being sent.
	GetDestination() string
	// Optional.
	// ID of the AuthnRequest that this response corresponds to.
	GetInResponseTo() string
	// Required.
	// Indicates success or failure of the SSO attempt.
	GetStatusCode() string
	// Required.
	// Must be "2.0"
	GetVersion() string
	GetLeeway() time.Duration
}

type DefaultSAMLResponeScheme struct {
	RelayState string

	Keys []sig.SignatureVerificationKey

	Issuer       string
	NameIDFormat string

	Destination  string
	InResponseTo string
	StatusCode   string
	Leeway       time.Duration
}

func (DefaultSAMLResponeScheme) Kind() common.Kind { return common.SAMLResponse }
func (DefaultSAMLResponeScheme) GetStatusCode() string {
	return "urn:oasis:names:tc:SAML:2.0:status:Success"
}
func (DefaultSAMLResponeScheme) GetVersion() string {
	return "2.0"
}
func (s DefaultSAMLResponeScheme) GetKeys() []sig.SignatureVerificationKey { return s.Keys }
func (s DefaultSAMLResponeScheme) GetRelayState() string                   { return s.RelayState }
func (s DefaultSAMLResponeScheme) GetIssuer() string                       { return s.Issuer }
func (s DefaultSAMLResponeScheme) GetNameIDFormat() string                 { return s.NameIDFormat }
func (s DefaultSAMLResponeScheme) GetDestination() string                  { return s.Destination }
func (s DefaultSAMLResponeScheme) GetInResponseTo() string                 { return s.InResponseTo }

func (s DefaultSAMLResponeScheme) GetLeeway() time.Duration { return s.Leeway }

var _ SAMLResponeSchemer = DefaultSAMLResponeScheme{}
