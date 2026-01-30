package jwt

import (
	"errors"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
)

type DefaultJWTScheme struct {
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

func (DefaultJWTScheme) Kind() common.Kind { return common.JWT }

func (s DefaultJWTScheme) GetSubject() common.SubjectID { return s.Subject }

func (s DefaultJWTScheme) GetMustMatchKid() bool { return s.MustMatchKid }

func (s DefaultJWTScheme) GetKeys() []sig.SignatureVerificationKey { return s.Keys }

func (s DefaultJWTScheme) GetIssuer() string { return s.Issuer }

func (s DefaultJWTScheme) GetAudience() string { return s.Audience }

func (s DefaultJWTScheme) GetLeeway() time.Duration { return s.Leeway }

func (s DefaultJWTScheme) GetReplay() common.ReplayChecker { return s.Replay }

func (s DefaultJWTScheme) ParsePrincipal(claims map[string]any) (common.Principal, error) {
	subject, ok := claims["sub"].(string)
	if !ok {
		return common.Principal{}, errors.New("missing `sub` claim")
	}
	principal := common.Principal{
		Subject:    common.SubjectID(subject),
		Attributes: claims,
	}
	return principal, nil
}

var _ JWTSchemer = DefaultJWTScheme{}
var _ common.Scheme = DefaultJWTScheme{}
