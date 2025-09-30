package credentials

import (
	"crypto"

	"github.com/axent-pl/credentials/sig"
)

type SAMLRequestScheme struct {
	Keys []SAMLRequestSchemeKey
}

type SAMLRequestSchemeKey struct {
	Key    crypto.PublicKey
	SigAlg sig.SigAlg
}

func (SAMLRequestScheme) Kind() Kind { return CredSAMLRequest }
