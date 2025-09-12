package auth

import (
	"crypto"
	"time"
)

type JWTScheme struct {
	Subject      SubjectID
	MustMatchKid bool
	Keys         []JWTSchemeKey
	Issuer       string
	Audience     string
	// Leeway for "exp" and "nbf" claims
	// See
	//
	// - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	//
	// - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	Leeway time.Duration
}

type JWTSchemeKey struct {
	// "kid"
	ID  string
	Key crypto.PublicKey
	// Allowed value of the "alg"
	// E.g. "RS256", "RS384", "RS512",
	// "ES256", "ES384", "ES512",
	// "PS256", "PS384", "PS512"
	Alg string
}

func (JWTScheme) Kind() CredentialKind { return CredJWT }
