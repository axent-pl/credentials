package clientassertion_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/axent-pl/credentials/clientassertion"
	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
	jwtx "github.com/golang-jwt/jwt/v5"
)

func parseSignedToken(t *testing.T, tokenBytes []byte, key crypto.PublicKey) (*jwtx.Token, jwtx.MapClaims) {
	t.Helper()

	claims := jwtx.MapClaims{}
	token, err := jwtx.ParseWithClaims(string(tokenBytes), claims, func(_ *jwtx.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		t.Fatalf("ParseWithClaims() failed: %v", err)
	}
	if !token.Valid {
		t.Fatal("ParseWithClaims() returned invalid token")
	}
	return token, claims
}

func claimStringValue(t *testing.T, claims jwtx.MapClaims, claim, want string) {
	t.Helper()
	got, ok := claims[claim]
	if !ok {
		t.Fatalf("missing claim `%s`", claim)
	}
	if got != want {
		t.Fatalf("invalid claim `%s` value: want '%s' got '%v'", claim, want, got)
	}
}

func claimExists(t *testing.T, claims jwtx.MapClaims, claim string) {
	t.Helper()
	if _, ok := claims[claim]; !ok {
		t.Fatalf("missing claim `%s`", claim)
	}
}

func claimInt64(t *testing.T, claims jwtx.MapClaims, claim string) int64 {
	t.Helper()
	got, ok := claims[claim]
	if !ok {
		t.Fatalf("missing claim `%s`", claim)
	}
	switch v := got.(type) {
	case float64:
		return int64(v)
	case float32:
		return int64(v)
	case int64:
		return v
	case int32:
		return int64(v)
	case int:
		return int64(v)
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			t.Fatalf("invalid claim `%s` number: %v", claim, err)
		}
		return n
	default:
		t.Fatalf("unsupported claim `%s` type: %T", claim, got)
	}
	return 0
}

type InvalidIssueParams struct{}

func (InvalidIssueParams) Kind() common.Kind {
	return common.ClientAssertion
}

func TestClientAssertionIssuer_Sign(t *testing.T) {
	rsaKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKeyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaKeyP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaKeyP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	tests := []struct {
		name string
		// Named input parameters for target function.
		payload     map[string]any
		issueParams clientassertion.ClientAssertionIssueParams
		publicKey   crypto.PublicKey
		check       func(t *testing.T, token *jwtx.Token, claims jwtx.MapClaims)
		want        []byte
		wantErr     bool
	}{
		{
			name: "basic RS1 (want error)",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgRS1,
				},
			},
			wantErr: true,
		},
		{
			name: "basic RS256",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgRS256,
				},
			},
			publicKey: &rsaKey2048.PublicKey,
			wantErr:   false,
		},
		{
			name: "basic RS384",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgRS384,
				},
			},
			publicKey: &rsaKey2048.PublicKey,
			wantErr:   false,
		},
		{
			name: "basic RS512",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgRS512,
				},
			},
			publicKey: &rsaKey2048.PublicKey,
			wantErr:   false,
		},
		{
			name: "basic PS256",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgPS256,
				},
			},
			publicKey: &rsaKey2048.PublicKey,
			wantErr:   false,
		},
		{
			name: "basic PS384",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgPS384,
				},
			},
			publicKey: &rsaKey2048.PublicKey,
			wantErr:   false,
		},
		{
			name: "basic PS512",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgPS512,
				},
			},
			publicKey: &rsaKey2048.PublicKey,
			wantErr:   false,
		},
		{
			name: "basic ES256",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: ecdsaKeyP256,
					Alg: sig.SigAlgES256,
				},
			},
			publicKey: &ecdsaKeyP256.PublicKey,
			wantErr:   false,
		},
		{
			name: "basic ES384",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: ecdsaKeyP384,
					Alg: sig.SigAlgES384,
				},
			},
			publicKey: &ecdsaKeyP384.PublicKey,
			wantErr:   false,
		},
		{
			name: "basic ES512",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: ecdsaKeyP521,
					Alg: sig.SigAlgES512,
				},
			},
			publicKey: &ecdsaKeyP521.PublicKey,
			wantErr:   false,
		},
		{
			name: "basic ES384 (invalid key)",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: ecdsaKeyP256,
					Alg: sig.SigAlgES384,
				},
			},
			wantErr: true,
		},
		{
			name: "RS256 (invalid key type)",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: ecdsaKeyP256,
					Alg: sig.SigAlgRS256,
				},
			},
			wantErr: true,
		},
		{
			name: "unknown algorithm",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgUnknown,
				},
			},
			wantErr: true,
		},
		{
			name: "kid header included",
			payload: map[string]any{
				"sub": "client-id",
				"foo": "bar",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Kid: "kid-123",
					Key: rsaKey2048,
					Alg: sig.SigAlgRS256,
				},
			},
			publicKey: &rsaKey2048.PublicKey,
			check: func(t *testing.T, token *jwtx.Token, claims jwtx.MapClaims) {
				t.Helper()
				if token.Header["kid"] != "kid-123" {
					t.Fatalf("unexpected kid header: got %v", token.Header["kid"])
				}
				claimStringValue(t, claims, "foo", "bar")
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var iss clientassertion.ClientAssertionIssuer
			got, gotErr := iss.Sign(tt.payload, tt.issueParams)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Sign() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Sign() succeeded unexpectedly")
			}
			if tt.check != nil {
				token, claims := parseSignedToken(t, got, tt.publicKey)
				tt.check(t, token, claims)
			}
		})
	}
}

func TestClientAssertionIssuer_Issue(t *testing.T) {
	rsaKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKeyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name        string
		principal   common.Principal
		issueParams common.IssueParams
		check       func(t *testing.T, artifacts []common.Artifact)
		wantErr     bool
		wantErrIs   error
	}{
		{
			name:        "invalid params type",
			principal:   common.Principal{Subject: "client-id"},
			issueParams: InvalidIssueParams{},
			wantErr:     true,
			wantErrIs:   common.ErrInternal,
		},
		{
			name:      "missing audience",
			principal: common.Principal{Subject: "client-id"},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgRS256,
				},
			},
			wantErr:   true,
			wantErrIs: common.ErrInternal,
		},
		{
			name:      "invalid exp",
			principal: common.Principal{Subject: "client-id"},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Audience: "https://issuer.example.com/token",
				Exp:      0,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgRS256,
				},
			},
			wantErr:   true,
			wantErrIs: common.ErrInternal,
		},
		{
			name:      "unsupported signing algorithm",
			principal: common.Principal{Subject: "client-id"},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Audience: "https://issuer.example.com/token",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgRS1,
				},
			},
			wantErr:   true,
			wantErrIs: common.ErrInternal,
		},
		{
			name:      "invalid signing key",
			principal: common.Principal{Subject: "client-id"},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Audience: "https://issuer.example.com/token",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: ecdsaKeyP256,
					Alg: sig.SigAlgRS256,
				},
			},
			wantErr:   true,
			wantErrIs: common.ErrInternal,
		},
		{
			name:      "basic RS256",
			principal: common.Principal{Subject: "client-id"},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Audience: "https://issuer.example.com/token",
				Exp:      20 * time.Second,
				Key: &sig.SignatureKey{
					Key: rsaKey2048,
					Alg: sig.SigAlgRS256,
				},
			},
			check: func(t *testing.T, artifacts []common.Artifact) {
				t.Helper()
				assertionArtifact, err := common.ArtifactWithKind(artifacts, common.ArtifactClientAssertion)
				if err != nil {
					t.Fatalf("missing client assertion artifact: %v", err)
				}
				if assertionArtifact.MediaType != "application/jwt" {
					t.Fatalf("unexpected assertion mediatype: %s", assertionArtifact.MediaType)
				}
				typeArtifact, err := common.ArtifactWithKind(artifacts, common.ArtifactClientAssertionType)
				if err != nil {
					t.Fatalf("missing client assertion type artifact: %v", err)
				}
				if typeArtifact.MediaType != "text/plain" {
					t.Fatalf("unexpected assertion type mediatype: %s", typeArtifact.MediaType)
				}
				if string(typeArtifact.Bytes) != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
					t.Fatalf("unexpected client assertion type: %s", string(typeArtifact.Bytes))
				}

				_, claims := parseSignedToken(t, assertionArtifact.Bytes, &rsaKey2048.PublicKey)
				claimStringValue(t, claims, "iss", "client-id")
				claimStringValue(t, claims, "sub", "client-id")
				claimStringValue(t, claims, "aud", "https://issuer.example.com/token")
				claimExists(t, claims, "iat")
				claimExists(t, claims, "exp")
				claimExists(t, claims, "jti")
			},
			wantErr: false,
		},
		{
			name:      "overlay claims and kid header",
			principal: common.Principal{Subject: "client-id"},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Audience: "https://issuer.example.com/token",
				Exp:      30 * time.Second,
				Key: &sig.SignatureKey{
					Kid: "kid-789",
					Key: rsaKey2048,
					Alg: sig.SigAlgRS256,
				},
				OverlayClaims: map[string]any{
					"aud":    "https://issuer.example.com/override",
					"nbf":    int64(12345),
					"custom": "value",
				},
			},
			check: func(t *testing.T, artifacts []common.Artifact) {
				t.Helper()
				assertionArtifact, err := common.ArtifactWithKind(artifacts, common.ArtifactClientAssertion)
				if err != nil {
					t.Fatalf("missing client assertion artifact: %v", err)
				}
				token, claims := parseSignedToken(t, assertionArtifact.Bytes, &rsaKey2048.PublicKey)
				if token.Header["kid"] != "kid-789" {
					t.Fatalf("unexpected kid header: got %v", token.Header["kid"])
				}
				claimStringValue(t, claims, "aud", "https://issuer.example.com/override")
				claimStringValue(t, claims, "custom", "value")
				if got := claimInt64(t, claims, "nbf"); got != 12345 {
					t.Fatalf("invalid claim `nbf` value: want %d got %d", 12345, got)
				}
				iat := claimInt64(t, claims, "iat")
				exp := claimInt64(t, claims, "exp")
				if exp <= iat {
					t.Fatalf("invalid exp/iat ordering: exp=%d iat=%d", exp, iat)
				}
				claimExists(t, claims, "jti")
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var iss clientassertion.ClientAssertionIssuer
			artifacts, gotErr := iss.Issue(context.Background(), tt.principal, tt.issueParams)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Issue() failed: %v", gotErr)
				}
				if tt.wantErrIs != nil && gotErr != tt.wantErrIs {
					t.Errorf("Issue() unexpected error: want %v got %v", tt.wantErrIs, gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Issue() succeeded unexpectedly")
			}
			if tt.check != nil {
				tt.check(t, artifacts)
			}
		})
	}
}
