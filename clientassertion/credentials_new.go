package clientassertion

import (
	"fmt"
	"net/http"

	"github.com/axent-pl/credentials/common"
)

func NewClientAssertionCredentialsFromRequest(r *http.Request) (ClientAssertionCredentials, error) {
	if r == nil {
		return ClientAssertionCredentials{}, fmt.Errorf("%v: request is nil", common.ErrInvalidInput)
	}

	if err := r.ParseForm(); err != nil {
		return ClientAssertionCredentials{}, fmt.Errorf("%v: could not parse form: %w", common.ErrInvalidInput, err)
	}

	creds := ClientAssertionCredentials{
		ClientId:            r.FormValue("client_id"),
		ClientAssertionType: r.FormValue("client_assertion_type"),
		ClientAssertion:     r.FormValue("client_assertion"),
	}
	if creds.ClientAssertionType == "" {
		return ClientAssertionCredentials{}, fmt.Errorf("%v: missing client_assertion_type", common.ErrInvalidInput)
	}
	if creds.ClientAssertion == "" {
		return ClientAssertionCredentials{}, fmt.Errorf("%v: missing client_assertion", common.ErrInvalidInput)
	}

	return creds, nil
}
