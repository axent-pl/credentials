package jwt

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"github.com/axent-pl/credentials/common/sig"
	jwtx "github.com/golang-jwt/jwt/v5"
)

// JWTVerifier validates JWT-based credentials using configured schemes.
type JWTVerifier struct{}

var _ common.Verifier = &JWTVerifier{}

func (v *JWTVerifier) Kind() common.Kind { return common.JWT }

type jwtCredentialsHeader struct {
	kid    string
	hasKid bool
	alg    string
}

func (v *JWTVerifier) verify(ctx context.Context, c JWTCredentials, header jwtCredentialsHeader, scheme JWTScheme) (common.Principal, error) {
	if len(scheme.Keys) == 0 {
		logx.L().Debug("missing scheme keys", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing scheme keys", common.ErrInternal)
	}
	// scheme requires "kid" which is not present
	if scheme.MustMatchKid && !header.hasKid {
		logx.L().Debug("missing kid", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing kid", common.ErrInvalidInput)
	}

	// find key
	var key *sig.SignatureKey
	var keyFound bool = false
	if !header.hasKid && len(scheme.Keys) == 1 {
		key = &scheme.Keys[0]
		keyFound = true
	} else {
		key, keyFound = scheme.findKeyByKid(header.kid)
	}

	if !keyFound {
		logx.L().Debug("invalid key", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid key", common.ErrInvalidCredentials)
	}
	headerAlg, err := sig.FromOAuth(header.alg)
	if err != nil {
		logx.L().Debug("invalid key alg", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid key", common.ErrInvalidCredentials)
	}
	if key.Alg != sig.SigAlgUnknown && key.Alg != headerAlg {
		logx.L().Debug("invalid key alg", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid key alg", common.ErrInvalidCredentials)
	}

	opts := v.buildParserOptions(scheme, *key)
	claims, err := parseJWT(c.Token, key.Key, opts)
	if err != nil {
		logx.L().Debug("could not parse JWT", "context", ctx, "error", err)
		return common.Principal{}, fmt.Errorf("%v: %v", common.ErrInvalidCredentials, err)
	}
	if claims.Subject == "" {
		logx.L().Debug("missing `sub`", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing `sub`", common.ErrInvalidCredentials)
	}

	// replay
	if scheme.Replay != nil && claims.ID != "" && claims.ExpiresAt != nil {
		if scheme.Replay.Seen(ctx, claims.ID, claims.ExpiresAt.Time) {
			logx.L().Debug("already seen", "context", ctx)
			return common.Principal{}, fmt.Errorf("%v: already seen", common.ErrInvalidCredentials)
		}
	}

	return common.Principal{Subject: common.SubjectID(claims.Subject)}, nil
}

func (v *JWTVerifier) parseScheme(ctx context.Context, s common.Scheme) (JWTScheme, error) {
	scheme, ok := s.(JWTScheme)
	if !ok {
		logx.L().Debug("could not cast scheme to JWTScheme", "context", ctx)
		return JWTScheme{}, fmt.Errorf("%v: invalid scheme", common.ErrInternal)
	}

	return scheme, nil
}

func (v *JWTVerifier) parseInput(ctx context.Context, in common.Credentials) (JWTCredentials, jwtCredentialsHeader, error) {
	jwtInput, ok := in.(JWTCredentials)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to JWTInput", "context", ctx)
		return JWTCredentials{}, jwtCredentialsHeader{}, fmt.Errorf("%v: invalid token", common.ErrInvalidInput)
	}
	if jwtInput.Token == "" {
		logx.L().Debug("empty token", "context", ctx)
		return JWTCredentials{}, jwtCredentialsHeader{}, fmt.Errorf("%v: empty token", common.ErrInvalidInput)
	}
	headerKid, headerHasKid, headerAlg, err := v.parseJWTHeader(jwtInput.Token)
	if err != nil {
		logx.L().Debug("could not parse token header", "context", ctx, "error", err)
		return JWTCredentials{}, jwtCredentialsHeader{}, fmt.Errorf("%v: invalid token format", common.ErrInvalidInput)
	}
	header := jwtCredentialsHeader{
		kid:    headerKid,
		hasKid: headerHasKid,
		alg:    headerAlg,
	}

	return jwtInput, header, nil
}

// Verify validates input against a single scheme.
func (v *JWTVerifier) Verify(ctx context.Context, in common.Credentials, s common.Scheme) (common.Principal, error) {
	scheme, err := v.parseScheme(ctx, s)
	if err != nil {
		return common.Principal{}, err
	}

	jwtInput, header, err := v.parseInput(ctx, in)
	if err != nil {
		return common.Principal{}, err
	}

	return v.verify(ctx, jwtInput, header, scheme)
}

// VerifyAny validates input against the first matching scheme.
func (v *JWTVerifier) VerifyAny(ctx context.Context, in common.Credentials, schemes []common.Scheme) (common.Principal, error) {
	jwtInput, header, err := v.parseInput(ctx, in)
	if err != nil {
		return common.Principal{}, err
	}

	for _, s := range schemes {
		scheme, err := v.parseScheme(ctx, s)
		if err != nil {
			continue
		}
		principal, err := v.verify(ctx, jwtInput, header, scheme)
		if err != nil {
			continue
		}
		return principal, nil
	}

	return common.Principal{}, common.ErrInvalidCredentials
}

// Build parser options for JWT validation.
func (v *JWTVerifier) buildParserOptions(scheme JWTScheme, keyConf sig.SignatureKey) []jwtx.ParserOption {
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
	if keyConf.Alg != sig.SigAlgUnknown {
		alg, err := keyConf.Alg.ToOAuth()
		if err == nil {
			opts = append(opts, jwtx.WithValidMethods([]string{alg}))
		}
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
