package jwt

import (
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
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
	ParsePrincipal(claims map[string]any) (common.Principal, error)
}
