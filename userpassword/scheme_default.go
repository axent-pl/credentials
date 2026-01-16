package userpassword

import (
	"errors"

	"github.com/axent-pl/credentials/common"
	"golang.org/x/crypto/bcrypt"
)

type DefaultUserPasswordScheme struct {
	Username     string
	PasswordHash []byte
}

func (DefaultUserPasswordScheme) Kind() common.Kind     { return common.Password }
func (s DefaultUserPasswordScheme) GetUsername() string { return s.Username }
func (s DefaultUserPasswordScheme) CompareUsernameAndPassword(username string, password string) error {
	if s.Username != username {
		return errors.New("invalid client id")
	}
	return bcrypt.CompareHashAndPassword(s.PasswordHash, []byte(password))
}

var _ common.Scheme = DefaultUserPasswordScheme{}
var _ UserPasswordSchemer = DefaultUserPasswordScheme{}
