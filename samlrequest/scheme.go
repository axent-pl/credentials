package samlrequest

import (
	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
)

type SAMLRequestScheme struct {
	Keys []sig.SignatureKey
}

func (SAMLRequestScheme) Kind() common.Kind { return common.SAMLRequest }
