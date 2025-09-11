package auth

type JWTInput struct {
	Token string
}

func (JWTInput) Kind() CredentialKind { return CredJWT }
