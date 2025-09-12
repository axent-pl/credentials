package auth

import (
	"context"
	"crypto"
	"fmt"
	"maps"
	"time"

	"github.com/axent-pl/auth/logx"
	"github.com/golang-jwt/jwt/v5"
)

// -- issue scheme
type JWTIssueScheme struct {
	Issuer string
	Key    JWTIssueSchemeKey
}

type JWTIssueSchemeKey struct {
	Kid        string
	Alg        string
	PrivateKey crypto.PrivateKey
}

func (JWTIssueScheme) Kind() CredentialKind { return CredJWT }

// -- issue params
type JWTIssueParams struct {
	AuthorizedParty SubjectID
}

func (JWTIssueParams) Kind() CredentialKind { return CredJWT }

// issuer
type JWTIssuer struct {
}

func (JWTIssuer) Kind() CredentialKind { return CredJWT }

func (iss *JWTIssuer) Issue(ctx context.Context, principal *Principal, scheme IssueScheme, issueParams IssueParams) ([]Artifact, error) {
	jwtIssueScheme, ok := issueParams.(JWTIssueScheme)
	if !ok {
		logx.L().Debug("could not cast IssueScheme to JWTIssueScheme", "context", ctx)
		return nil, ErrInternal
	}
	jwtIssueParams, ok := issueParams.(JWTIssueParams)
	if !ok {
		logx.L().Debug("could not cast IssueParams to JWTIssueParams", "context", ctx)
		return nil, ErrInternal
	}
	baseClaims, err := iss.BaseClaims(ctx, principal, jwtIssueScheme, jwtIssueParams)
	if err != nil {
		logx.L().Debug("could not build base claims", "context", ctx, "error", err)
		return nil, ErrInternal
	}

	fmt.Println(baseClaims) // just draft

	return nil, nil
}

func (iss *JWTIssuer) Sign(payload map[string]any, scheme JWTIssueScheme) ([]byte, error) {
	claims := jwt.MapClaims{}
	maps.Copy(claims, payload)

	signingMethod, err := algToJWTSigningMethod(scheme.Key.Alg)
	if err != nil {
		return nil, fmt.Errorf("could not sign payload: %w", err)
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	tokenString, err := token.SignedString(scheme.Key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("could not sign payload: %w", err)
	}

	return []byte(tokenString), nil
}

func (iss *JWTIssuer) BaseClaims(ctx context.Context, principal *Principal, scheme JWTIssueScheme, issueParams JWTIssueParams) (map[string]any, error) {
	claims := make(map[string]any)
	claims["sub"] = principal.Subject
	claims["iss"] = scheme.Issuer
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	claims["iat"] = time.Now().Unix()
	if issueParams.AuthorizedParty != "" {
		claims["azp"] = issueParams.AuthorizedParty
	}
	return claims, nil
}

func algToJWTSigningMethod(method string) (jwt.SigningMethod, error) {
	mapping := map[string]jwt.SigningMethod{
		"RS256": jwt.SigningMethodRS256,
		"RS384": jwt.SigningMethodRS384,
		"RS512": jwt.SigningMethodRS512,
		"ES256": jwt.SigningMethodES256,
		"ES384": jwt.SigningMethodES384,
		"ES512": jwt.SigningMethodES512,
		"PS256": jwt.SigningMethodPS256,
		"PS384": jwt.SigningMethodPS384,
		"PS512": jwt.SigningMethodPS512,
	}

	if alg, ok := mapping[method]; ok {
		return alg, nil
	}
	return nil, fmt.Errorf("invalid alg: %s", method)
}
