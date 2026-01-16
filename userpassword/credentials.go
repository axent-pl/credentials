package userpassword

import "github.com/axent-pl/credentials/common"

type UserPasswordCredentials struct {
	Username string
	Password string
}

func (UserPasswordCredentials) Kind() common.Kind { return common.Password }

var _ common.Credentials = UserPasswordCredentials{}
