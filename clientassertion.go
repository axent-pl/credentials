package auth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/axent-pl/auth/logx"
	"github.com/golang-jwt/jwt/v5"
)

// Common URN per RFC 7523 / OAuth 2.0 JWT bearer assertions.
const URNClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type ClientAssertionInput struct {
	ClientId            string
	ClientAssertionType string
	ClientAssertion     string
}

func (ClientAssertionInput) Kind() CredentialKind { return CredClientAssertion }

type ClientAssertionScheme struct {
	// Should be present,
	// assertions are usually self signed
	// and attacker could take over application X
	// and issue assertion with sub=Y
	Subject    SubjectID
	RequireKid bool
	Keys       []ClientAssertionSchemeKey
	// It should be present,
	// for self signed assertion its value will be the same as "sub"
	Issuer string
	// Shoudl be present
	// and the value needs to be the URL of the /token endpoint.
	// Otherwise attacker may use a token not meant
	// for client authenticatio with client_assertion.
	Audience string
	Leeway   time.Duration
}

type ClientAssertionSchemeKey struct {
	Kid       string
	PublicKey crypto.PublicKey
	Alg       string
}

func (ClientAssertionScheme) Kind() CredentialKind { return CredClientAssertion }

type ClientAssertionVerifier struct{}

func (v *ClientAssertionVerifier) Kind() CredentialKind { return CredClientAssertion }

func (v *ClientAssertionVerifier) Verify(ctx context.Context, in InputCredentials, stored []ValidationScheme) (Principal, error) {
	clientAssertionInput, ok := in.(ClientAssertionInput)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to ClientAssertionInput")
		return Principal{}, ErrInvalidInput
	}
	if clientAssertionInput.ClientAssertion == "" {
		logx.L().Debug("empty client_assertion")
		return Principal{}, ErrInvalidInput
	}
	if clientAssertionInput.ClientAssertionType != URNClientAssertionType {
		logx.L().Debug("invalid client_assertion_type")
		return Principal{}, ErrInvalidInput
	}

	kid, tokenHasKid := getClientAssertionKid(clientAssertionInput.ClientAssertion)

	for _, s := range stored {
		scheme, ok := s.(ClientAssertionScheme)
		if !ok || len(scheme.Keys) == 0 {
			continue
		}
		if scheme.RequireKid && !tokenHasKid {
			continue
		}
		for _, keyConfig := range scheme.Keys {
			if scheme.RequireKid && kid != keyConfig.Kid {
				continue
			}
			opts := buildClientAssertionParserOptions(scheme, keyConfig)
			claims, err := parseClientAssertion(clientAssertionInput.ClientAssertion, keyConfig.PublicKey, opts)
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

func buildClientAssertionParserOptions(scheme ClientAssertionScheme, keyConf ClientAssertionSchemeKey) []jwt.ParserOption {
	var opts []jwt.ParserOption
	if scheme.Subject != "" {
		opts = append(opts, jwt.WithSubject(string(scheme.Subject)))
	}
	if scheme.Leeway > 0 {
		opts = append(opts, jwt.WithLeeway(scheme.Leeway))
	}
	if scheme.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(scheme.Issuer))
	}
	if scheme.Audience != "" {
		opts = append(opts, jwt.WithAudience(scheme.Audience))
	}
	if keyConf.Alg != "" {
		opts = append(opts, jwt.WithValidMethods([]string{keyConf.Alg}))
	}
	return opts
}

func getClientAssertionKid(token string) (string, bool) {
	var hdrClaims jwt.RegisteredClaims
	parser := jwt.NewParser()
	unverified, _, err := parser.ParseUnverified(token, &hdrClaims)
	if err != nil {
		return "", false
	}
	kid, ok := unverified.Header["kid"].(string)
	if !ok || kid == "" {
		return "", false
	}
	return kid, true
}

func parseClientAssertion(token string, key crypto.PublicKey, opts []jwt.ParserOption) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	tok, err := jwt.ParseWithClaims(
		token,
		claims,
		func(t *jwt.Token) (interface{}, error) {
			return key, nil
		},
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("could not parse assertion: %w", err)
	}
	if tok == nil {
		return nil, errors.New("assertion is empty")
	}
	if !tok.Valid {
		return nil, errors.New("assertion is invalid")
	}
	return claims, nil
}
