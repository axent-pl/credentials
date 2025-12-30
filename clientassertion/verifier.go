package clientassertion

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"github.com/golang-jwt/jwt/v5"
)

// Common URN per RFC 7523 / OAuth 2.0 JWT bearer assertions.
const URNClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type ClientAssertionVerifier struct{}

func (v *ClientAssertionVerifier) Kind() common.Kind { return common.ClientAssertion }

func (v *ClientAssertionVerifier) Verify(ctx context.Context, in common.Credentials, schemes []common.Scheme) (common.Principal, error) {
	clientAssertionInput, ok := in.(ClientAssertionInput)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to ClientAssertionInput", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	if clientAssertionInput.ClientAssertion == "" {
		logx.L().Debug("empty client_assertion", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	if clientAssertionInput.ClientAssertionType != URNClientAssertionType {
		logx.L().Debug(fmt.Sprintf("invalid client_assertion_type: got '%s', want '%s", clientAssertionInput.ClientAssertionType, URNClientAssertionType), "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}

	headerKid, tokenHasKid, headerAlg, err := parseClientAssertionHeader(clientAssertionInput.ClientAssertion)
	if err != nil {
		logx.L().Debug("could not parse client_assertion token header", "context", ctx, "error", err)
		return common.Principal{}, common.ErrInvalidInput
	}

	for _, s := range schemes {
		scheme, ok := s.(ClientAssertionScheme)
		if !ok || len(scheme.Keys) == 0 {
			continue
		}
		if scheme.MustMatchKid && !tokenHasKid {
			continue
		}
		for _, keyScheme := range scheme.Keys {
			if scheme.MustMatchKid && headerKid != keyScheme.Kid {
				continue
			}
			if keyScheme.Alg != "" && keyScheme.Alg != headerAlg {
				continue
			}
			opts := buildClientAssertionParserOptions(scheme, keyScheme)
			claims, err := parseClientAssertion(clientAssertionInput.ClientAssertion, keyScheme.PublicKey, opts)
			if err != nil {
				continue
			}
			if claims.Subject == "" {
				continue
			}
			if scheme.Replay != nil && claims.ID != "" && claims.ExpiresAt != nil {
				if scheme.Replay.Seen(ctx, claims.ID, claims.ExpiresAt.Time) {
					continue
				}
			}
			return common.Principal{Subject: common.SubjectID(claims.Subject)}, nil
		}
	}
	return common.Principal{}, common.ErrInvalidCredentials
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

func parseClientAssertionHeader(token string) (kid string, hasKid bool, alg string, err error) {
	parser := jwt.NewParser()
	unverifiedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil || unverifiedToken == nil {
		return "", false, "", err
	}
	if k, ok := unverifiedToken.Header["kid"].(string); ok && k != "" {
		kid, hasKid = k, true
	}
	if a, ok := unverifiedToken.Header["alg"].(string); ok && a != "" {
		alg = a
	}
	return kid, hasKid, alg, nil
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
		return nil, fmt.Errorf("could not parse client_assertion: %w", err)
	}
	if tok == nil {
		return nil, errors.New("assertion is empty")
	}
	if !tok.Valid {
		return nil, errors.New("assertion is invalid")
	}
	return claims, nil
}
