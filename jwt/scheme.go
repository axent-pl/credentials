package jwt

import (
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
)

type JWTScheme struct {
	Subject      common.SubjectID
	MustMatchKid bool
	Keys         []sig.SignatureVerificationKey
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

func (s JWTScheme) GetSubject() common.SubjectID { return s.Subject }

func (s JWTScheme) GetMustMatchKid() bool { return s.MustMatchKid }

func (s JWTScheme) GetKeys() []sig.SignatureVerificationKey { return s.Keys }

func (s JWTScheme) GetIssuer() string { return s.Issuer }

func (s JWTScheme) GetAudience() string { return s.Audience }

func (s JWTScheme) GetLeeway() time.Duration { return s.Leeway }

func (s JWTScheme) GetReplay() common.ReplayChecker { return s.Replay }
