package clientassertion

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"github.com/axent-pl/credentials/common/sig"
	"github.com/golang-jwt/jwt/v5"
)

type ClientAssertionVerifier struct{}

var _ common.Verifier = &ClientAssertionVerifier{}

func (v *ClientAssertionVerifier) Kind() common.Kind { return common.ClientAssertion }

type clientAssertionCredentialsHeader struct {
	kid    string
	hasKid bool
	alg    string
}

func (v *ClientAssertionVerifier) verify(ctx context.Context, c ClientAssertionCredentials, h clientAssertionCredentialsHeader, scheme ClientAssertionSchemer) (common.Principal, error) {
	// validate client assertion type
	if c.ClientAssertionType != scheme.GetClientAssertionType() {
		logx.L().Debug(fmt.Sprintf("invalid client_assertion_type: got '%s', want '%s", c.ClientAssertionType, scheme.GetClientAssertionType()), "context", ctx)
		return common.Principal{}, common.ErrInvalidInput
	}

	// validate signature key
	if len(scheme.GetKeys()) == 0 {
		logx.L().Debug("missing scheme keys", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing keys in scheme", common.ErrInternal)
	}
	if scheme.GetMustMatchKid() && !h.hasKid {
		logx.L().Debug("missing `kid`", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing `kid`", common.ErrInvalidCredentials)
	}
	key, keyFound := sig.FindSignatureVerificationKey(scheme.GetKeys(), h.kid)
	if !keyFound {
		logx.L().Debug("invalid key", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid key", common.ErrInvalidCredentials)
	}
	headerAlg, err := sig.FromOAuth(h.alg)
	if err != nil {
		logx.L().Debug("invalid key alg", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid key", common.ErrInvalidCredentials)
	}
	if key.Alg != headerAlg {
		logx.L().Debug("invalid key alg", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: invalid key alg", common.ErrInvalidCredentials)
	}

	// parse assertion
	opts := buildClientAssertionParserOptions(scheme, *key)
	claims, err := parseJWT(c.ClientAssertion, key.Key, opts)
	if err != nil {
		logx.L().Debug("could not parse ClientAssertion", "context", ctx, "error", err)
		return common.Principal{}, fmt.Errorf("%v: %v", common.ErrInvalidCredentials, err)
	}
	if claims.Subject == "" {
		logx.L().Debug("missing `sub`", "context", ctx)
		return common.Principal{}, fmt.Errorf("%v: missing `sub`", common.ErrInvalidCredentials)
	}

	// validate replay
	if scheme.GetReplay() != nil && claims.ID != "" && claims.ExpiresAt != nil {
		if scheme.GetReplay().Seen(ctx, claims.ID, claims.ExpiresAt.Time) {
			logx.L().Debug("already seen", "context", ctx)
			return common.Principal{}, fmt.Errorf("%v: already seen", common.ErrInvalidCredentials)
		}
	}

	return scheme.ParsePrincipal(claims)
}

func (v *ClientAssertionVerifier) parseScheme(ctx context.Context, s common.Scheme) (ClientAssertionSchemer, error) {
	scheme, ok := s.(ClientAssertionSchemer)
	if !ok {
		logx.L().Debug("scheme does not implement ClientAssertion Scheme", "context", ctx)
		return nil, fmt.Errorf("%v: invalid scheme", common.ErrInternal)
	}

	return scheme, nil
}

func (v *ClientAssertionVerifier) parseInput(ctx context.Context, in common.Credentials) (ClientAssertionCredentials, clientAssertionCredentialsHeader, error) {
	clientAssertionInput, ok := in.(ClientAssertionCredentials)
	if !ok {
		logx.L().Debug("could not cast InputCredentials to ClientAssertionInput", "context", ctx)
		return ClientAssertionCredentials{}, clientAssertionCredentialsHeader{}, common.ErrInvalidInput
	}
	if clientAssertionInput.ClientAssertion == "" {
		logx.L().Debug("empty client_assertion", "context", ctx)
		return ClientAssertionCredentials{}, clientAssertionCredentialsHeader{}, common.ErrInvalidInput
	}

	headerKid, headerHasKid, headerAlg, err := parseJWTHeader(clientAssertionInput.ClientAssertion)
	if err != nil {
		logx.L().Debug("could not parse client_assertion token header", "context", ctx, "error", err)
		return ClientAssertionCredentials{}, clientAssertionCredentialsHeader{}, common.ErrInvalidInput
	}
	header := clientAssertionCredentialsHeader{
		kid:    headerKid,
		hasKid: headerHasKid,
		alg:    headerAlg,
	}

	return clientAssertionInput, header, nil
}

func (v *ClientAssertionVerifier) Verify(ctx context.Context, in common.Credentials, s common.Scheme) (common.Principal, error) {
	scheme, err := v.parseScheme(ctx, s)
	if err != nil {
		return common.Principal{}, err
	}

	clientAssertionInput, header, err := v.parseInput(ctx, in)
	if err != nil {
		return common.Principal{}, err
	}

	return v.verify(ctx, clientAssertionInput, header, scheme)
}

func (v *ClientAssertionVerifier) VerifyAny(ctx context.Context, in common.Credentials, schemes []common.Scheme) (common.Principal, error) {
	clientAssertionInput, header, err := v.parseInput(ctx, in)
	if err != nil {
		return common.Principal{}, err
	}

	for _, s := range schemes {
		scheme, err := v.parseScheme(ctx, s)
		if err != nil {
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

func buildClientAssertionParserOptions(scheme ClientAssertionSchemer, keyConf sig.SignatureVerificationKey) []jwt.ParserOption {
	var opts []jwt.ParserOption
	if scheme.GetSubject() != "" {
		opts = append(opts, jwt.WithSubject(string(scheme.GetSubject())))
	}
	if scheme.GetLeeway() > 0 {
		opts = append(opts, jwt.WithLeeway(scheme.GetLeeway()))
	}
	if scheme.GetIssuer() != "" {
		opts = append(opts, jwt.WithIssuer(scheme.GetIssuer()))
	}
	if scheme.GetAudience() != "" {
		opts = append(opts, jwt.WithAudience(scheme.GetAudience()))
	}
	if alg, err := keyConf.Alg.ToOAuth(); err == nil {
		opts = append(opts, jwt.WithValidMethods([]string{alg}))
	}
	return opts
}

func parseJWTHeader(token string) (kid string, hasKid bool, alg string, err error) {
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

func parseJWT(token string, key crypto.PublicKey, opts []jwt.ParserOption) (*jwt.RegisteredClaims, error) {
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
		return nil, fmt.Errorf("could not parse token: %w", err)
	}
	if tok == nil {
		return nil, errors.New("token is empty")
	}
	if !tok.Valid {
		return nil, errors.New("token is invalid")
	}
	return claims, nil
}
