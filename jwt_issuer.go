package auth

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/axent-pl/auth/logx"
	"github.com/golang-jwt/jwt/v5"
)

type JWTIssueSchemeKey struct {
	Kid        string
	Alg        string
	PrivateKey crypto.PrivateKey
}

// -- issue params
type JWTIssueParams struct {
	Issuer string
	Exp    time.Duration
	Key    JWTIssueSchemeKey

	AuthorizedParty SubjectID

	AccessIncludedClaims  []string
	AccessOverlayClaims   map[string]any
	IdIncludedClaims      []string
	IdOverlayClaims       map[string]any
	RefreshIncludedClaims []string
	RefreshOverlayClaims  map[string]any
}

func (JWTIssueParams) Kind() Kind { return CredJWT }

// issuer
type JWTIssuer struct {
}

func (JWTIssuer) Kind() Kind { return CredJWT }

func (iss *JWTIssuer) Issue(ctx context.Context, principal Principal, issueParams IssueParams) ([]Artifact, error) {
	jwtIssueParams, ok := issueParams.(JWTIssueParams)
	if !ok {
		logx.L().Debug("could not cast IssueParams to JWTIssueParams", "context", ctx)
		return nil, ErrInternal
	}

	baseClaims, err := iss.BaseClaims(ctx, principal, jwtIssueParams)
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
	accessTokenBytes, err := iss.Sign(accessClaims, jwtIssueParams)
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
	idTokenBytes, err := iss.Sign(idClaims, jwtIssueParams)
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
	refreshTokenBytes, err := iss.Sign(refreshClaims, jwtIssueParams)
	if err != nil {
		logx.L().Debug("could not sign refresh token", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	artifacts = append(artifacts, Artifact{
		Kind:      ArtifactRefreshToken,
		MediaType: "application/jwt",
		Bytes:     refreshTokenBytes,
	})

	// oauth2 token response
	tokenResponse := map[string]any{
		"token_type":    "Bearer",
		"expires_in":    jwtIssueParams.Exp.Seconds(),
		"access_token":  string(accessTokenBytes),
		"id_token":      string(idTokenBytes),
		"refresh_token": string(refreshTokenBytes),
	}
	respBytes, err := json.Marshal(tokenResponse)
	if err != nil {
		logx.L().Debug("could not marshal oauth2 token response", "context", ctx, "error", err)
		return nil, ErrInternal
	}
	artifacts = append(artifacts, Artifact{
		Kind:      ArtifactOAuth2TokenResponse,
		MediaType: "application/json",
		Bytes:     respBytes,
	})

	return artifacts, nil
}

func (iss *JWTIssuer) Sign(payload map[string]any, params JWTIssueParams) ([]byte, error) {
	claims := jwt.MapClaims{}
	maps.Copy(claims, payload)

	signingMethod, err := algToJWTSigningMethod(params.Key.Alg)
	if err != nil {
		return nil, fmt.Errorf("could not sign payload: %w", err)
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	if params.Key.Kid != "" {
		token.Header["kid"] = params.Key.Kid
	}

	tokenString, err := token.SignedString(params.Key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("could not sign payload: %w", err)
	}
	return []byte(tokenString), nil
}

func (iss *JWTIssuer) PatchedClaims(ctx context.Context, principal Principal, baseClaims map[string]any, includedClaims []string, overlayClaims map[string]any) (map[string]any, error) {
	// 1) clone baseClaims
	out := maps.Clone(baseClaims)

	// 2) add claims from principal.Attributes where key is in includedClaims
	if principal.Attributes != nil && len(includedClaims) > 0 {
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

func (iss *JWTIssuer) BaseClaims(ctx context.Context, principal Principal, issueParams JWTIssueParams) (map[string]any, error) {
	claims := make(map[string]any)
	claims["sub"] = string(principal.Subject)
	claims["iss"] = issueParams.Issuer
	claims["exp"] = time.Now().Add(issueParams.Exp).Unix()
	claims["iat"] = time.Now().Unix()
	if issueParams.AuthorizedParty != "" {
		claims["azp"] = string(issueParams.AuthorizedParty)
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
