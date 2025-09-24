package auth

import "crypto"

type SAMLRequestScheme struct {
	Keys []SAMLRequestSchemeKey
}

type SAMLRequestSchemeKey struct {
	Key    crypto.PublicKey
	SigAlg string
}

func (SAMLRequestScheme) Kind() Kind { return CredSAMLRequest }
