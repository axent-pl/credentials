package clientsecret

import (
	"errors"

	"github.com/axent-pl/credentials/common"
	"golang.org/x/crypto/bcrypt"
)

type DefaultClientSecretScheme struct {
	ClientID   string
	SecretHash []byte
}

func (DefaultClientSecretScheme) Kind() common.Kind     { return common.ClientSecret }
func (s DefaultClientSecretScheme) GetClientId() string { return s.ClientID }
func (s DefaultClientSecretScheme) CompareIdAndSecret(id string, secret string) error {
	if s.ClientID != id {
		return errors.New("invalid client id")
	}
	return bcrypt.CompareHashAndPassword(s.SecretHash, []byte(secret))
}

var _ common.Scheme = DefaultClientSecretScheme{}
var _ ClientSecretSchemer = DefaultClientSecretScheme{}
