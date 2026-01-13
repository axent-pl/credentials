package jwt

import (
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
	"github.com/golang-jwt/jwt/v5"
)

type JWTSchemer interface {
	Kind() common.Kind
	GetSubject() common.SubjectID
	GetMustMatchKid() bool
	GetKeys() []sig.SignatureVerificationKey
	GetIssuer() string
	GetAudience() string
	GetLeeway() time.Duration
	GetReplay() common.ReplayChecker
	ParsePrincipal(claims *jwt.RegisteredClaims) (common.Principal, error)
}
