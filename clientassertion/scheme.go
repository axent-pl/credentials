package clientassertion

import (
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
)

type ClientAssertionSchemer interface {
	Kind() common.Kind
	GetSubject() common.SubjectID
	GetMustMatchKid() bool
	GetKeys() []sig.SignatureVerificationKey
	GetIssuer() string
	GetAudience() string
	GetLeeway() time.Duration
	GetReplay() common.ReplayChecker
}

type DefaultClientAssertionScheme struct {
	// Should be present,
	// assertions are usually self signed
	// and attacker could take over application X
	// and issue assertion with sub=Y
	Subject      common.SubjectID
	MustMatchKid bool
	Keys         []sig.SignatureVerificationKey
	// It should be present,
	// for self signed assertion its value will be the same as "sub"
	Issuer string
	// Shoudl be present
	// and the value needs to be the URL of the /token endpoint.
	// Otherwise attacker may use a token not meant
	// for client authenticatio with client_assertion.
	Audience string
	Leeway   time.Duration
	Replay   common.ReplayChecker
}

func (DefaultClientAssertionScheme) Kind() common.Kind { return common.ClientAssertion }

func (s DefaultClientAssertionScheme) GetSubject() common.SubjectID { return s.Subject }

func (s DefaultClientAssertionScheme) GetMustMatchKid() bool { return s.MustMatchKid }

func (s DefaultClientAssertionScheme) GetKeys() []sig.SignatureVerificationKey { return s.Keys }

func (s DefaultClientAssertionScheme) GetIssuer() string { return s.Issuer }

func (s DefaultClientAssertionScheme) GetAudience() string { return s.Audience }

func (s DefaultClientAssertionScheme) GetLeeway() time.Duration { return s.Leeway }

func (s DefaultClientAssertionScheme) GetReplay() common.ReplayChecker { return s.Replay }
