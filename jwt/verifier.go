package jwt

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"github.com/axent-pl/credentials/common/sig"
	jwtx "github.com/golang-jwt/jwt/v5"
)

type JWTVerifier struct{}

var _ common.Verifier = &JWTVerifier{}

func (v *JWTVerifier) Kind() common.Kind { return common.JWT }

type jwtCredentialsHeader struct {
	kid    string
	hasKid bool
	alg    string
}

func (v *JWTVerifier) verify(ctx context.Context, c JWTCredentials, header jwtCredentialsHeader, scheme JWTSchemer) (common.Principal, error) {
	// validate signature key
	if len(scheme.GetKeys()) == 0 {
		logx.L().Debug("missing scheme keys", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing scheme keys", common.ErrInternal)
	}
	if scheme.GetMustMatchKid() && !header.hasKid {
		logx.L().Debug("missing kid", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing kid", common.ErrInvalidInput)
	}
	key, keyFound := sig.FindSignatureVerificationKey(scheme.GetKeys(), header.kid)

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

	// parse token
	opts := v.buildParserOptions(scheme, *key)
	registeredClaims, claims, err := parseJWT(c.Token, key.Key, opts)
	if err != nil {
		logx.L().Debug("could not parse JWT", "context", ctx, "error", err)
		return common.Principal{}, fmt.Errorf("%v: %v", common.ErrInvalidCredentials, err)
	}

	if registeredClaims.Subject == "" {
		logx.L().Debug("missing `sub`", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing `sub`", common.ErrInvalidCredentials)
	}

	// validate replay
	if scheme.GetReplay() != nil && registeredClaims.ID != "" && registeredClaims.ExpiresAt != nil {
		if scheme.GetReplay().Seen(ctx, registeredClaims.ID, registeredClaims.ExpiresAt.Time) {
			logx.L().Debug("already seen", "context", ctx)
			return common.Principal{}, fmt.Errorf("%v: already seen", common.ErrInvalidCredentials)
		}
	}

	return scheme.ParsePrincipal(claims)
}

func (v *JWTVerifier) parseScheme(ctx context.Context, s common.Scheme) (JWTSchemer, error) {
	scheme, ok := s.(JWTSchemer)
	if !ok {
		logx.L().Debug("could not cast scheme to JWTScheme", "context", ctx)
		return nil, fmt.Errorf("%v: invalid scheme", common.ErrInternal)
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
func (v *JWTVerifier) buildParserOptions(scheme JWTSchemer, keyConf sig.SignatureVerificationKey) []jwtx.ParserOption {
	var opts []jwtx.ParserOption
	if scheme.GetSubject() != "" {
		opts = append(opts, jwtx.WithSubject(string(scheme.GetSubject())))
	}
	if scheme.GetLeeway() > 0 {
		opts = append(opts, jwtx.WithLeeway(scheme.GetLeeway()))
	}
	if scheme.GetIssuer() != "" {
		opts = append(opts, jwtx.WithIssuer(scheme.GetIssuer()))
	}
	if scheme.GetAudience() != "" {
		opts = append(opts, jwtx.WithAudience(scheme.GetAudience()))
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

func parseJWT(token string, key crypto.PublicKey, opts []jwtx.ParserOption) (*jwtx.RegisteredClaims, map[string]any, error) {
	registeredClaims := &jwtx.RegisteredClaims{}
	tok, err := jwtx.ParseWithClaims(
		token,
		registeredClaims,
		func(t *jwtx.Token) (interface{}, error) {
			return key, nil
		},
		opts...,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse token: %w", err)
	}
	if tok == nil {
		return nil, nil, errors.New("token is empty")
	}
	if !tok.Valid {
		return nil, nil, errors.New("token is invalid")
	}
	claims, err := parseJWTClaims(token)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse token: %w", err)
	}
	return registeredClaims, claims, nil
}

func parseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token: not enough parts")
	}

	payloadPart := parts[1]
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return claims, nil
}
