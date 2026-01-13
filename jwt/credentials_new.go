package jwt

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/axent-pl/credentials/common"
)

func NewJWTCredentialsFromRequest(r *http.Request) (JWTCredentials, error) {
	if r == nil {
		return JWTCredentials{}, fmt.Errorf("%v: request is nil", common.ErrInvalidInput)
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		parts := strings.Fields(authHeader)
		if len(parts) != 2 {
			return JWTCredentials{}, fmt.Errorf("%v: invalid Authorization header", common.ErrInvalidInput)
		}
		if !strings.EqualFold(parts[0], "Bearer") {
			return JWTCredentials{}, fmt.Errorf("%v: invalid Authorization scheme", common.ErrInvalidInput)
		}
		if parts[1] == "" {
			return JWTCredentials{}, fmt.Errorf("%v: missing token", common.ErrInvalidInput)
		}
		return JWTCredentials{Token: parts[1]}, nil
	}

	if err := r.ParseForm(); err != nil {
		return JWTCredentials{}, fmt.Errorf("%v: could not parse form: %w", common.ErrInvalidInput, err)
	}

	token := r.FormValue("access_token")
	if token == "" {
		return JWTCredentials{}, fmt.Errorf("%v: missing access_token", common.ErrInvalidInput)
	}

	return JWTCredentials{Token: token}, nil
}
