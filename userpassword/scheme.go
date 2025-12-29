package userpassword

import "github.com/axent-pl/credentials/common"

type UserPasswordScheme struct {
	Username     string
	PasswordHash []byte
}

func (UserPasswordScheme) Kind() common.Kind { return common.Password }
