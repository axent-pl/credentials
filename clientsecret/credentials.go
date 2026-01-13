package clientsecret

import (
	"github.com/axent-pl/credentials/common"
)

type ClientSecretCredentials struct {
	ClientID     string
	ClientSecret string
}

func (ClientSecretCredentials) Kind() common.Kind { return common.ClientSecret }

var _ common.Credentials = ClientSecretCredentials{}
