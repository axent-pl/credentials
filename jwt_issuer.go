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

	AccessIncludedClaims  []string
	AccessOverlayClaims   map[string]any
	IdIncludedClaims      []string
	IdOverlayClaims       map[string]any
	RefreshIncludedClaims []string
	RefreshOverlayClaims  map[string]any
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

	artifacts := make([]Artifact, 0)

	// access token
	accessClaims, err := iss.PatchedClaims(ctx, principal, baseClaims, jwtIssueParams.AccessIncludedClaims, jwtIssueParams.AccessOverlayClaims)
	if err != nil {
		logx.L().Debug("could not build access token claims", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	accessTokenBytes, err := iss.Sign(accessClaims, jwtIssueScheme)
	if err != nil {
		logx.L().Debug("could not sign access token", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	artifacts = append(artifacts, Artifact{
		Kind:      ArtifactAccessToken,
		MediaType: "application/jwt",
		Bytes:     accessTokenBytes,
	})

	// id token
	idClaims, err := iss.PatchedClaims(ctx, principal, baseClaims, jwtIssueParams.IdIncludedClaims, jwtIssueParams.IdOverlayClaims)
	if err != nil {
		logx.L().Debug("could not build id token claims", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	idTokenBytes, err := iss.Sign(idClaims, jwtIssueScheme)
	if err != nil {
		logx.L().Debug("could not sign id token", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	artifacts = append(artifacts, Artifact{
		Kind:      ArtifactIdToken,
		MediaType: "application/jwt",
		Bytes:     idTokenBytes,
	})

	// refresh token
	refreshClaims, err := iss.PatchedClaims(ctx, principal, baseClaims, jwtIssueParams.RefreshIncludedClaims, jwtIssueParams.RefreshOverlayClaims)
	if err != nil {
		logx.L().Debug("could not build refresh token claims", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	refreshTokenBytes, err := iss.Sign(refreshClaims, jwtIssueScheme)
	if err != nil {
		logx.L().Debug("could not sign refresh token", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	artifacts = append(artifacts, Artifact{
		Kind:      ArtifactRefreshToken,
		MediaType: "application/jwt",
		Bytes:     refreshTokenBytes,
	})

	return artifacts, nil
}

func (iss *JWTIssuer) Sign(payload map[string]any, scheme JWTIssueScheme) ([]byte, error) {
	claims := jwt.MapClaims{}
	maps.Copy(claims, payload)

	signingMethod, err := algToJWTSigningMethod(scheme.Key.Alg)
	if err != nil {
		return nil, fmt.Errorf("could not sign payload: %w", err)
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	if scheme.Key.Kid != "" {
		token.Header["kid"] = scheme.Key.Kid
	}

	tokenString, err := token.SignedString(scheme.Key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("could not sign payload: %w", err)
	}
	return []byte(tokenString), nil
}

func (iss *JWTIssuer) PatchedClaims(ctx context.Context, principal *Principal, baseClaims map[string]any, includedClaims []string, overlayClaims map[string]any) (map[string]any, error) {
	// 1) clone baseClaims
	out := maps.Clone(baseClaims)

	// 2) add claims from principal.Attributes where key is in includedClaims
	if principal != nil && principal.Attributes != nil && len(includedClaims) > 0 {
		allow := make(map[string]struct{}, len(includedClaims))
		for _, k := range includedClaims {
			allow[k] = struct{}{}
		}
		for k, v := range principal.Attributes {
			if _, ok := allow[k]; ok {
				out[k] = v
			}
		}
	}

	// 3) add overrides from overlayClaims
	if overlayClaims != nil {
		maps.Copy(out, overlayClaims)
	}

	return out, nil
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
