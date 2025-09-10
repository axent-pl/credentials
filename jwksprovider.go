package auth

import (
	"net/url"
)

type JWKSCredentialsProvider struct {
	JWKSURL url.URL
}

func (p *JWKSCredentialsProvider) GetKeys() ([]any, error) {
	// returns public keys from p.JWKSURL (e.g. rsa.PublicKey)
	return nil, nil
}

// func (p *JWKSCredentialsProvider) QueryCredentials(ctx context.Context, in InputCredentials) ([]StoredCredentials, error) {
// 	if in.Kind() != CredJWTAssertion {
// 		return nil, ErrBadInput
// 	}

// 	tokenString := "asdasdasd"

// 	keys, err := p.getKeys()
// 	if err != nil {
// 		return nil, err
// 	}

// 	for _, key := range keys {
// 		parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 			return key.handler.GetPublicKey(), nil
// 		})
// 	}
// }
