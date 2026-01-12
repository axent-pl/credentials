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

var _ common.Verifier = &ClientAssertionVerifier{}

func (v *ClientAssertionVerifier) Kind() common.Kind { return common.ClientAssertion }

type clientAssertionCredentialsHeader struct {
	kid    string
	hasKid bool
	alg    string
}

func (v *ClientAssertionVerifier) verify(ctx context.Context, c ClientAssertionCredentials, h clientAssertionCredentialsHeader, scheme ClientAssertionScheme) (common.Principal, error) {
	if len(scheme.Keys) == 0 {
		logx.L().Debug("missing Keys in ClientAssertionScheme", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing keys in scheme", common.ErrInternal)
	}
	if scheme.MustMatchKid && !h.hasKid {
		logx.L().Debug("missing `kid`", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing `kid`", common.ErrInvalidCredentials)
	}

	// find key
	var key *ClientAssertionSchemeKey
	var keyFound bool = false
	if !h.hasKid && len(scheme.Keys) == 1 {
		key = &scheme.Keys[0]
		keyFound = true
	}
	key, keyFound = scheme.findKeyByKid(h.kid)
	if !keyFound {
		logx.L().Debug("invalid key", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid key", common.ErrInvalidCredentials)
	}

	// check key alg
	if key.Alg != "" && key.Alg != h.alg {
		logx.L().Debug("invalid key alg", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid key alg", common.ErrInvalidCredentials)
	}

	// parse assertion
	opts := buildClientAssertionParserOptions(scheme, *key)
	claims, err := parseClientAssertion(c.ClientAssertion, key.PublicKey, opts)
	if err != nil {
		logx.L().Debug("could not parse ClientAssertion", "context", ctx, "error", err)
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

func (v *ClientAssertionVerifier) Verify(ctx context.Context, in common.Credentials, s common.Scheme) (common.Principal, error) {
	scheme, ok := s.(ClientAssertionScheme)
	if !ok {
		logx.L().Debug("could not cast scheme to ClientAssertionScheme", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid scheme", common.ErrInternal)
	}

	clientAssertionInput, ok := in.(ClientAssertionCredentials)
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

	headerKid, headerHasKid, headerAlg, err := parseClientAssertionHeader(clientAssertionInput.ClientAssertion)
	if err != nil {
		logx.L().Debug("could not parse client_assertion token header", "context", ctx, "error", err)
		return common.Principal{}, common.ErrInvalidInput
	}
	header := clientAssertionCredentialsHeader{
		kid:    headerKid,
		hasKid: headerHasKid,
		alg:    headerAlg,
	}

	return v.verify(ctx, clientAssertionInput, header, scheme)
}

func (v *ClientAssertionVerifier) VerifyAny(ctx context.Context, in common.Credentials, schemes []common.Scheme) (common.Principal, error) {
	clientAssertionInput, ok := in.(ClientAssertionCredentials)
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

	headerKid, headerHasKid, headerAlg, err := parseClientAssertionHeader(clientAssertionInput.ClientAssertion)
	if err != nil {
		logx.L().Debug("could not parse client_assertion token header", "context", ctx, "error", err)
		return common.Principal{}, common.ErrInvalidInput
	}
	header := clientAssertionCredentialsHeader{
		kid:    headerKid,
		hasKid: headerHasKid,
		alg:    headerAlg,
	}

	for _, s := range schemes {
		scheme, ok := s.(ClientAssertionScheme)
		if !ok || len(scheme.Keys) == 0 {
			continue
		}
		principal, err := v.verify(ctx, clientAssertionInput, header, scheme)
		if err != nil {
			continue
		}
		return principal, nil
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
