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
)

type Credentials interface {
	Kind() Kind
}
