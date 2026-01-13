package jwt

import (
	"github.com/axent-pl/credentials/common"
)

type JWTCredentials struct {
	Token string
}

func (JWTCredentials) Kind() common.Kind { return common.JWT }

var _ common.Credentials = JWTCredentials{}
