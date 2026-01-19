package common

type Kind string

const (
	Password        Kind = "password"
	ClientSecret    Kind = "client_secret"
	ClientAssertion Kind = "client_assertion"
	JWT             Kind = "jwt"
	MTLS            Kind = "mtls"
	SAMLRequest     Kind = "saml_request"
	SAMLResponse    Kind = "saml_response"
	JWKS            Kind = "json_web_key_set"
)

type Credentials interface {
	Kind() Kind
}
