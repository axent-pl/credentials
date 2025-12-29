package userpassword

import "github.com/axent-pl/credentials/common"

type UserPasswordInput struct {
	Username string
	Password string
}

func (UserPasswordInput) Kind() common.Kind { return common.Password }
