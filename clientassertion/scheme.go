package clientassertion

import (
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
)

type ClientAssertionScheme struct {
	// Should be present,
	// assertions are usually self signed
	// and attacker could take over application X
	// and issue assertion with sub=Y
	Subject      common.SubjectID
	MustMatchKid bool
	Keys         []sig.SignatureKey
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

func (ClientAssertionScheme) Kind() common.Kind { return common.ClientAssertion }

func (s *ClientAssertionScheme) findKeyByKid(kid string) (*sig.SignatureKey, bool) {
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			return &s.Keys[i], true
		}
	}
	return nil, false
}
