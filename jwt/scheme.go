package jwt

import (
	"crypto"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/sig"
)

type JWTScheme struct {
	Subject      common.SubjectID
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
	ID  string
	Key crypto.PublicKey
	Alg sig.SigAlg
}

func (JWTScheme) Kind() common.Kind { return common.JWT }
