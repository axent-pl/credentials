package clientassertion

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"github.com/axent-pl/credentials/common/sig"
	jwtx "github.com/golang-jwt/jwt/v5"
)

// ---------- Client Assertion ----------

type ClientAssertionIssueKey struct {
	Kid        string
	Alg        sig.SigAlg
	PrivateKey crypto.PrivateKey
}

type ClientAssertionIssueParams struct {
	// OAuth2 Client ID
	ClientID string

	// Audience for the assertion (typically the token endpoint URL, or issuer, depending on server expectations)
	Audience string

	// Assertion validity (typical: 1-5 minutes)
	Exp time.Duration

	// Signing key material
	Key ClientAssertionIssueKey

	// Optional overlay claims (e.g. "nbf", custom claims)
	OverlayClaims map[string]any
}

// Adjust this if your common.Kind uses a different constant/name.
func (ClientAssertionIssueParams) Kind() common.Kind { return common.ClientAssertion }

// issuer
type ClientAssertionIssuer struct{}

func (ClientAssertionIssuer) Kind() common.Kind { return common.ClientAssertion }

func (iss *ClientAssertionIssuer) Issue(ctx context.Context, principal common.Principal, issueParams common.IssueParams) ([]common.Artifact, error) {
	p, ok := issueParams.(ClientAssertionIssueParams)
	if !ok {
		logx.L().Debug("could not cast IssueParams to ClientAssertionIssueParams", "context", ctx)
		return nil, common.ErrInternal
	}

	claims, err := iss.BaseClaims(ctx, principal, p)
	if err != nil {
		logx.L().Debug("could not build client assertion claims", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}

	// overlay
	if p.OverlayClaims != nil {
		maps.Copy(claims, p.OverlayClaims)
	}

	assertionBytes, err := iss.Sign(claims, p)
	if err != nil {
		logx.L().Debug("could not sign client assertion", "context", ctx, "error", err)
		return nil, common.ErrInternal
	}

	artifacts := make([]common.Artifact, 0, 2)

	// raw assertion
	artifacts = append(artifacts, common.Artifact{
		Kind:      common.ArtifactClientAssertion,
		MediaType: "application/jwt",
		Bytes:     assertionBytes,
	})

	// client assertion type artifact (RFC 7523)
	artifacts = append(artifacts, common.Artifact{
		Kind:      common.ArtifactClientAssertionType,
		MediaType: "text/plain",
		Bytes:     []byte("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
	})

	return artifacts, nil
}

func (iss *ClientAssertionIssuer) BaseClaims(ctx context.Context, principal common.Principal, p ClientAssertionIssueParams) (map[string]any, error) {
	now := time.Now()

	if p.Audience == "" {
		return nil, fmt.Errorf("audience is required")
	}
	if p.Exp <= 0 {
		return nil, fmt.Errorf("exp must be > 0")
	}

	jti, err := newJTI(16)
	if err != nil {
		return nil, fmt.Errorf("could not generate jti: %w", err)
	}

	claims := make(map[string]any)
	claims["iss"] = string(principal.Subject)
	claims["sub"] = string(principal.Subject)
	claims["aud"] = p.Audience
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(p.Exp).Unix()
	claims["jti"] = jti

	_ = ctx
	_ = principal // principal is not typically used for client assertions; keep for symmetry/future use

	return claims, nil
}

func (iss *ClientAssertionIssuer) Sign(payload map[string]any, params ClientAssertionIssueParams) ([]byte, error) {
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

func newJTI(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
