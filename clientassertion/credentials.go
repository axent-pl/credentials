package clientassertion

import "github.com/axent-pl/credentials/common"

type ClientAssertionInput struct {
	ClientId            string
	ClientAssertionType string
	ClientAssertion     string
}

func (ClientAssertionInput) Kind() common.Kind { return common.ClientAssertion }
