package jwt

import (
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
)

type JWTScheme struct {
	Subject      common.SubjectID
	MustMatchKid bool
	Keys         []sig.SignatureKey
	Issuer       string
	Audience     string
	// Leeway for "exp" and "nbf" claims
	// See
	//
	// - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	//
	// - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	Leeway time.Duration
	Replay common.ReplayChecker
}

func (JWTScheme) Kind() common.Kind { return common.JWT }

func (s *JWTScheme) findKeyByKid(kid string) (*sig.SignatureKey, bool) {
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			return &s.Keys[i], true
		}
	}
	return nil, false
}
