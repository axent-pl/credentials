package jwt

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/logx"
	"github.com/axent-pl/credentials/sig"
	jwtx "github.com/golang-jwt/jwt/v5"
)

type JWTIssueKey struct {
	Kid        string
	Alg        sig.SigAlg
	PrivateKey crypto.PrivateKey
}

// -- issue params
type JWTIssueParams struct {
	Issuer string
	Exp    time.Duration
	Key    JWTIssueKey

	AuthorizedParty common.SubjectID

	AccessIncludedClaims  []string
	AccessOverlayClaims   map[string]any
	IdIncludedClaims      []string
	IdOverlayClaims       map[string]any
	RefreshIncludedClaims []string
	RefreshOverlayClaims  map[string]any
}

func (JWTIssueParams) Kind() common.Kind { return common.JWT }

// issuer
type JWTIssuer struct {
}

func (JWTIssuer) Kind() common.Kind { return common.JWT }

func (iss *JWTIssuer) Issue(ctx context.Context, principal common.Principal, issueParams common.IssueParams) ([]common.Artifact, error) {
	jwtIssueParams, ok := issueParams.(JWTIssueParams)
	if !ok {
		logx.L().Debug("could not cast IssueParams to JWTIssueParams", "context", ctx)
		return nil, common.ErrInternal
	}

	baseClaims, err := iss.BaseClaims(ctx, principal, jwtIssueParams)
	if err != nil {
		logx.L().Debug("could not build base claims", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}

	artifacts := make([]common.Artifact, 0)

	// access token
	accessClaims, err := iss.PatchedClaims(ctx, principal, baseClaims, jwtIssueParams.AccessIncludedClaims, jwtIssueParams.AccessOverlayClaims)
	if err != nil {
		logx.L().Debug("could not build access token claims", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}
	accessTokenBytes, err := iss.Sign(accessClaims, jwtIssueParams)
	if err != nil {
		logx.L().Debug("could not sign access token", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}
	artifacts = append(artifacts, common.Artifact{
		Kind:      common.ArtifactAccessToken,
		MediaType: "application/jwt",
		Bytes:     accessTokenBytes,
	})

	// id token
	idClaims, err := iss.PatchedClaims(ctx, principal, baseClaims, jwtIssueParams.IdIncludedClaims, jwtIssueParams.IdOverlayClaims)
	if err != nil {
		logx.L().Debug("could not build id token claims", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}
	idTokenBytes, err := iss.Sign(idClaims, jwtIssueParams)
	if err != nil {
		logx.L().Debug("could not sign id token", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}
	artifacts = append(artifacts, common.Artifact{
		Kind:      common.ArtifactIdToken,
		MediaType: "application/jwt",
		Bytes:     idTokenBytes,
	})

	// refresh token
	refreshClaims, err := iss.PatchedClaims(ctx, principal, baseClaims, jwtIssueParams.RefreshIncludedClaims, jwtIssueParams.RefreshOverlayClaims)
	if err != nil {
		logx.L().Debug("could not build refresh token claims", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}
	refreshTokenBytes, err := iss.Sign(refreshClaims, jwtIssueParams)
	if err != nil {
		logx.L().Debug("could not sign refresh token", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}
	artifacts = append(artifacts, common.Artifact{
		Kind:      common.ArtifactRefreshToken,
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
		return nil, common.ErrInternal
	}
	artifacts = append(artifacts, common.Artifact{
		Kind:      common.ArtifactOAuth2TokenResponse,
		MediaType: "application/json",
		Bytes:     respBytes,
	})

	return artifacts, nil
}

func (iss *JWTIssuer) Sign(payload map[string]any, params JWTIssueParams) ([]byte, error) {
	claims := jwtx.MapClaims{}
	maps.Copy(claims, payload)

	signingMethod, err := params.Key.Alg.ToGoJWT()
	if err != nil {
		return nil, fmt.Errorf("could not sign payload: %w", err)
	}

	token := jwtx.NewWithClaims(signingMethod, claims)
	if params.Key.Kid != "" {
		token.Header["kid"] = params.Key.Kid
	}

	tokenString, err := token.SignedString(params.Key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("could not sign payload: %w", err)
	}
	return []byte(tokenString), nil
}

func (iss *JWTIssuer) PatchedClaims(ctx context.Context, principal common.Principal, baseClaims map[string]any, includedClaims []string, overlayClaims map[string]any) (map[string]any, error) {
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

func (iss *JWTIssuer) BaseClaims(ctx context.Context, principal common.Principal, issueParams JWTIssueParams) (map[string]any, error) {
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
