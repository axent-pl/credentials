package samlresponse

import (
	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
)

type SAMLResponeSchemer interface {
	Kind() common.Kind
	GetKeys() []sig.SignatureKey
	GetRelayState() string
	GetIssuer() string
	GetNameIDFormat() string
}

type DefaultSAMLResponeScheme struct {
	RelayState string

	Keys []sig.SignatureKey

	Issuer       string
	NameIDFormat string
}

func (DefaultSAMLResponeScheme) Kind() common.Kind             { return common.SAMLResponse }
func (s DefaultSAMLResponeScheme) GetKeys() []sig.SignatureKey { return s.Keys }
func (s DefaultSAMLResponeScheme) GetRelayState() string       { return s.RelayState }
func (s DefaultSAMLResponeScheme) GetIssuer() string           { return s.Issuer }
func (s DefaultSAMLResponeScheme) GetNameIDFormat() string     { return s.NameIDFormat }

var _ SAMLResponeSchemer = DefaultSAMLResponeScheme{}
