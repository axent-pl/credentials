package clientassertion

import "github.com/axent-pl/credentials/common"

type ClientAssertionCredentials struct {
	ClientId            string
	ClientAssertionType string
	ClientAssertion     string
}

func (ClientAssertionCredentials) Kind() common.Kind { return common.ClientAssertion }

var _ common.Credentials = ClientAssertionCredentials{}
