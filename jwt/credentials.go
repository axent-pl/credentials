package jwt

import "github.com/axent-pl/credentials/common"

type JWTInput struct {
	Token string
}

func (JWTInput) Kind() common.Kind { return common.JWT }
