package clientsecret

import (
	"fmt"
	"net/http"

	"github.com/axent-pl/credentials/common"
)

func NewClientSecretCredentialsFromRequest(r *http.Request) (ClientSecretCredentials, error) {
	if r == nil {
		return ClientSecretCredentials{}, fmt.Errorf("%v: request is nil", common.ErrInvalidInput)
	}

	if err := r.ParseForm(); err != nil {
		return ClientSecretCredentials{}, fmt.Errorf("%v: could not parse form: %w", common.ErrInvalidInput, err)
	}

	creds := ClientSecretCredentials{
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
	}
	if creds.ClientID == "" {
		return ClientSecretCredentials{}, fmt.Errorf("%v: missing client_id", common.ErrInvalidInput)
	}
	if creds.ClientSecret == "" {
		return ClientSecretCredentials{}, fmt.Errorf("%v: missing client_secret", common.ErrInvalidInput)
	}

	return creds, nil
}
