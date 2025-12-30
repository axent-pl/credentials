package jwt

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	jwtx "github.com/golang-jwt/jwt/v5"
)

type JWTVerifier struct{}

var _ common.Verifier = &JWTVerifier{}

func (v *JWTVerifier) Kind() common.Kind { return common.JWT }

func (v *JWTVerifier) Verify(ctx context.Context, in common.Credentials, schemes []common.Scheme) (common.Principal, error) {
	jwtInput, ok := in.(JWTInput)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to JWTInput", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}
	if jwtInput.Token == "" {
		logx.L().Debug("empty token", "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}

	headerKid, tokenHasKid, headerAlg, err := v.parseJWTHeader(jwtInput.Token)
	if err != nil {
		logx.L().Debug("could not parse token header", "context", ctx, "error", err)
		return common.Principal{}, common.ErrInvalidInput
	}

	for _, s := range schemes {
		conf, ok := s.(JWTScheme)
		// not a JWTScheme or no keys in JWTScheme
		if !ok || len(conf.Keys) == 0 {
			continue
		}
		// scheme requires "kid" which is not present
		if conf.MustMatchKid && !tokenHasKid {
			continue
		}

		// Verify with the key(s)
		for _, keyConfig := range conf.Keys {
			if conf.MustMatchKid && headerKid != keyConfig.ID {
				continue
			}
			if alg, err := keyConfig.Alg.ToOAuth(); err == nil && alg != headerAlg {
				continue
			}
			opts := v.buildParserOptions(conf, keyConfig)
			claims, err := parseJWT(jwtInput.Token, keyConfig.Key, opts)
			if err != nil {
				continue
			}
			if claims.Subject == "" {
				continue
			}
			return common.Principal{Subject: common.SubjectID(claims.Subject)}, nil
		}
	}

	return common.Principal{}, common.ErrInvalidCredentials
}

// Build parser options
func (v *JWTVerifier) buildParserOptions(scheme JWTScheme, keyConf JWTSchemeKey) []jwtx.ParserOption {
	var opts []jwtx.ParserOption
	if scheme.Subject != "" {
		opts = append(opts, jwtx.WithSubject(string(scheme.Subject)))
	}
	if scheme.Leeway > 0 {
		opts = append(opts, jwtx.WithLeeway(scheme.Leeway))
	}
	if scheme.Issuer != "" {
		opts = append(opts, jwtx.WithIssuer(scheme.Issuer))
	}
	if scheme.Audience != "" {
		opts = append(opts, jwtx.WithAudience(scheme.Audience))
	}
	if alg, err := keyConf.Alg.ToOAuth(); err == nil {
		opts = append(opts, jwtx.WithValidMethods([]string{alg}))
	}
	return opts
}

func (v *JWTVerifier) parseJWTHeader(token string) (kid string, hasKid bool, alg string, err error) {
	parser := jwtx.NewParser()
	unverifiedToken, _, err := parser.ParseUnverified(token, jwtx.MapClaims{})
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

func parseJWT(token string, key crypto.PublicKey, opts []jwtx.ParserOption) (*jwtx.RegisteredClaims, error) {
	// verify and parse token with given key and options
	claims := &jwtx.RegisteredClaims{}
	jwtToken, err := jwtx.ParseWithClaims(
		token,
		claims,
		func(t *jwtx.Token) (interface{}, error) {
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
