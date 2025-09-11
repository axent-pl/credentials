package auth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// input

type JWTInput struct {
	Token string
}

func (JWTInput) Kind() CredentialKind { return CredJWT }

// stored

type JWTScheme struct {
	RequireKid bool
	Keys       []JWTSchemeKey
	Issuer     string
	Audience   string
	// Leeway for "exp" and "nbf" claims
	// See
	//
	// - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	//
	// - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	Leeway time.Duration
}

type JWTSchemeKey struct {
	// "kid"
	ID  string
	Key crypto.PublicKey
	// Allowed value of the "alg"
	// E.g. "RS256", "RS384", "RS512",
	// "ES256", "ES384", "ES512",
	// "PS256", "PS384", "PS512"
	Alg string
}

func (JWTScheme) Kind() CredentialKind { return CredJWT }

// verifier

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

		opts := buildParserOptions(conf)

		// Verify with the key(s)
		for _, keyConfig := range conf.Keys {
			if conf.RequireKid && kid != keyConfig.ID {
				continue
			}
			parseOptions := opts
			if keyConfig.Alg != "" {
				parseOptions = append(parseOptions, jwt.WithValidMethods([]string{keyConfig.Alg}))
			}
			claims, err := parseToken(jwtInput.Token, keyConfig.Key, parseOptions)
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
func buildParserOptions(conf JWTScheme) []jwt.ParserOption {
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
