package credentials

type JWTInput struct {
	Token string
}

func (JWTInput) Kind() Kind { return CredJWT }
