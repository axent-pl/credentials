package clientsecret

import (
	"github.com/axent-pl/credentials/common"
)

type ClientSecretScheme struct {
	ClientID   string
	SecretHash []byte
}

func (ClientSecretScheme) Kind() common.Kind { return common.ClientSecret }

var _ common.Scheme = ClientSecretScheme{}
