package auth

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type JWTVerifier struct{}

func (v *JWTVerifier) Kind() CredentialKind { return CredJWT }

func (v *JWTVerifier) Verify(_ context.Context, in InputCredentials, stored []ValidationScheme) (Principal, error) {
	jwtInput, ok := in.(JWTInput)
	if !ok || jwtInput.Token == "" {
		return Principal{}, ErrInvalidInput
	}

	kid, tokenHasKid := getKid(jwtInput.Token)

	for _, s := range stored {
		conf, ok := s.(JWTScheme)
		// not a JWTScheme or no keys in JWTScheme
		if !ok || len(conf.Keys) == 0 {
			continue
		}
		// scheme requires "kid" which is not present
		if conf.RequireKid && !tokenHasKid {
			continue
		}

		// Verify with the key(s)
		for _, keyConfig := range conf.Keys {
			if conf.RequireKid && kid != keyConfig.ID {
				continue
			}
			opts := buildParserOptions(conf, keyConfig)
			claims, err := parseToken(jwtInput.Token, keyConfig.Key, opts)
			if err != nil {
				continue
			}
			if claims.Subject == "" {
				continue
			}
			return Principal{Subject: SubjectID(claims.Subject)}, nil
		}
	}

	return Principal{}, ErrInvalidCredentials
}

// Build parser options
func buildParserOptions(conf JWTScheme, keyConf JWTSchemeKey) []jwt.ParserOption {
	var opts []jwt.ParserOption
	if conf.Leeway > 0 {
		opts = append(opts, jwt.WithLeeway(conf.Leeway))
	}
	if conf.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(conf.Issuer))
	}
	if conf.Audience != "" {
		opts = append(opts, jwt.WithAudience(conf.Audience))
	}
	if keyConf.Alg != "" {
		opts = append(opts, jwt.WithValidMethods([]string{keyConf.Alg}))
	}
	return opts
}

// Read "kid" (key id) claim from unverified token header
func getKid(token string) (string, bool) {
	var hdrClaims jwt.RegisteredClaims
	parser := jwt.NewParser()
	unverified, _, err := parser.ParseUnverified(token, &hdrClaims)
	if err != nil {
		return "", false
	}
	kid, ok := unverified.Header["kid"].(string)
	if !ok {
		return "", false
	}
	if kid == "" {
		return "", false
	}
	return kid, true
}

func parseToken(token string, key crypto.PublicKey, opts []jwt.ParserOption) (*jwt.RegisteredClaims, error) {
	// verify and parse token with given key and options
	claims := &jwt.RegisteredClaims{}
	jwtToken, err := jwt.ParseWithClaims(
		token,
		claims,
		func(t *jwt.Token) (interface{}, error) {
			return key, nil
		},
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("could not parse token: %w", err)
	}
	if jwtToken == nil {
		return nil, errors.New("token is empty")
	}
	if !jwtToken.Valid {
		return nil, errors.New("token is invalid")
	}
	return claims, nil
}
