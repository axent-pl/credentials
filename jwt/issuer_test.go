package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/jwt"
	"github.com/axent-pl/credentials/sig"
)

type ClaimCheckFunction func(got map[string]any) error

func CheckClaimStringValue(claim string, value string) ClaimCheckFunction {
	return func(got map[string]any) error {
		if v, ok := got[claim]; ok {
			if v != value {
				return fmt.Errorf("invalid claim `%s` value: want '%s' got '%s'", claim, value, v)
			}
			return nil
		}
		return fmt.Errorf("missing claim `%s`", claim)
	}
}

func CheckClaimNotNil(claim string) ClaimCheckFunction {
	return func(got map[string]any) error {
		if v, ok := got[claim]; ok {
			if v != nil {
				return nil
			}
			return fmt.Errorf("empty claim `%s` value: got nil", claim)
		}
		return fmt.Errorf("missing claim `%s`", claim)
	}
}

func CheckClaimExists(claim string) ClaimCheckFunction {
	return func(got map[string]any) error {
		if _, ok := got[claim]; !ok {
			return fmt.Errorf("missing claim `%s`", claim)
		}
		return nil
	}
}

func CheckClaimNotExists(claim string) ClaimCheckFunction {
	return func(got map[string]any) error {
		if v, ok := got[claim]; ok {
			return fmt.Errorf("want empty claim `%s`, got value `%s`", claim, v)
		}
		return nil
	}
}

func TestJWTIssuer_BaseClaims(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		principal   common.Principal
		issueParams jwt.JWTIssueParams
		want        map[string]any
		checks      []ClaimCheckFunction
		wantErr     bool
	}{
		{
			name:      "basic",
			principal: common.Principal{Subject: "subject-id"},
			issueParams: jwt.JWTIssueParams{
				AuthorizedParty: "acme-registered-app",
				Issuer:          "https://acme-auth-server.com",
				Exp:             30 * time.Second,
			},
			checks: []ClaimCheckFunction{
				CheckClaimStringValue("sub", "subject-id"),
				CheckClaimStringValue("iss", "https://acme-auth-server.com"),
				CheckClaimStringValue("azp", "acme-registered-app"),
				CheckClaimNotNil("exp"),
				CheckClaimNotNil("iat"),
			},
			wantErr: false,
		},
		{
			name:      "no scheme.Exp",
			principal: common.Principal{Subject: "subject-id"},
			issueParams: jwt.JWTIssueParams{
				Issuer:          "https://acme-auth-server.com",
				AuthorizedParty: "acme-registered-app",
			},
			checks: []ClaimCheckFunction{
				CheckClaimStringValue("sub", "subject-id"),
				CheckClaimStringValue("iss", "https://acme-auth-server.com"),
				CheckClaimStringValue("azp", "acme-registered-app"),
				CheckClaimNotNil("exp"),
				CheckClaimNotNil("iat"),
			},
			wantErr: false,
		},
		{
			name:        "no azp",
			principal:   common.Principal{Subject: "subject-id"},
			issueParams: jwt.JWTIssueParams{Issuer: "https://acme-auth-server.com", Exp: 30 * time.Second},
			checks: []ClaimCheckFunction{
				CheckClaimStringValue("sub", "subject-id"),
				CheckClaimStringValue("iss", "https://acme-auth-server.com"),
				CheckClaimNotExists("azp"),
				CheckClaimNotNil("exp"),
				CheckClaimNotNil("iat"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var iss jwt.JWTIssuer
			got, gotErr := iss.BaseClaims(context.Background(), tt.principal, tt.issueParams)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("BaseClaims() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("BaseClaims() succeeded unexpectedly")
			}
			for _, checkFunc := range tt.checks {
				if err := checkFunc(got); err != nil {
					t.Errorf("BaseClaims(): %v", err)
				}
			}

		})
	}
}

func TestJWTIssuer_PatchedClaims(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		principal      common.Principal
		baseClaims     map[string]any
		includedClaims []string
		overlayClaims  map[string]any
		checks         []ClaimCheckFunction
		wantErr        bool
	}{
		{
			name: "simple clone",
			baseClaims: map[string]any{
				"sub": "subject-id",
				"iss": "https://acme-auth-server.com",
			},
			includedClaims: make([]string, 0),
			overlayClaims:  make(map[string]any),
			checks: []ClaimCheckFunction{
				CheckClaimStringValue("sub", "subject-id"),
				CheckClaimStringValue("iss", "https://acme-auth-server.com"),
			},
			wantErr: false,
		},
		{
			name: "include `first_name` if not in principal attributes",
			baseClaims: map[string]any{
				"sub": "subject-id",
				"iss": "https://acme-auth-server.com",
			},
			includedClaims: []string{"first_name"},
			overlayClaims:  make(map[string]any),
			checks: []ClaimCheckFunction{
				CheckClaimStringValue("sub", "subject-id"),
				CheckClaimStringValue("iss", "https://acme-auth-server.com"),
				CheckClaimNotExists("first_name"),
			},
			wantErr: false,
		},
		{
			name: "include `first_name`",
			baseClaims: map[string]any{
				"sub": "subject-id",
				"iss": "https://acme-auth-server.com",
			},
			principal: common.Principal{
				Attributes: map[string]any{
					"first_name": "Jane",
				},
			},
			includedClaims: []string{"first_name"},
			overlayClaims:  make(map[string]any),
			checks: []ClaimCheckFunction{
				CheckClaimStringValue("sub", "subject-id"),
				CheckClaimStringValue("iss", "https://acme-auth-server.com"),
				CheckClaimStringValue("first_name", "Jane"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var iss jwt.JWTIssuer
			got, gotErr := iss.PatchedClaims(context.Background(), tt.principal, tt.baseClaims, tt.includedClaims, tt.overlayClaims)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("PatchedClaims() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("PatchedClaims() succeeded unexpectedly")
			}
			for _, checkFunc := range tt.checks {
				if err := checkFunc(got); err != nil {
					t.Errorf("PatchedClaims(): %v", err)
				}
			}
		})
	}
}

func TestJWTIssuer_Sign(t *testing.T) {
	rsaKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKeyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaKeyP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		payload     map[string]any
		issueParams jwt.JWTIssueParams
		want        []byte
		wantErr     bool
	}{
		{
			name: "basic RS1 (want error)",
			payload: map[string]any{
				"sub": "subject-id",
			},
			issueParams: jwt.JWTIssueParams{
				Issuer: "acme-issuer",
				Exp:    20 * time.Second,
				Key: jwt.JWTIssueKey{
					PrivateKey: rsaKey2048,
					Alg:        sig.SigAlgRS1,
				},
			},
			wantErr: true,
		},
		{
			name: "basic RS256",
			payload: map[string]any{
				"sub": "subject-id",
			},
			issueParams: jwt.JWTIssueParams{
				Issuer: "acme-issuer",
				Exp:    20 * time.Second,
				Key: jwt.JWTIssueKey{
					PrivateKey: rsaKey2048,
					Alg:        sig.SigAlgRS256,
				},
			},
			wantErr: false,
		},
		{
			name: "basic RS384",
			payload: map[string]any{
				"sub": "subject-id",
			},
			issueParams: jwt.JWTIssueParams{
				Issuer: "acme-issuer",
				Exp:    20 * time.Second,
				Key: jwt.JWTIssueKey{
					PrivateKey: rsaKey2048,
					Alg:        sig.SigAlgRS384,
				},
			},
			wantErr: false,
		},
		{
			name: "basic RS512",
			payload: map[string]any{
				"sub": "subject-id",
			},
			issueParams: jwt.JWTIssueParams{
				Issuer: "acme-issuer",
				Exp:    20 * time.Second,
				Key: jwt.JWTIssueKey{
					PrivateKey: rsaKey2048,
					Alg:        sig.SigAlgRS512,
				},
			},
			wantErr: false,
		},
		{
			name: "basic ES256",
			payload: map[string]any{
				"sub": "subject-id",
			},
			issueParams: jwt.JWTIssueParams{
				Issuer: "acme-issuer",
				Exp:    20 * time.Second,
				Key: jwt.JWTIssueKey{
					PrivateKey: ecdsaKeyP256,
					Alg:        sig.SigAlgES256,
				},
			},
			wantErr: false,
		},
		{
			name: "basic ES384",
			payload: map[string]any{
				"sub": "subject-id",
			},
			issueParams: jwt.JWTIssueParams{
				Issuer: "acme-issuer",
				Exp:    20 * time.Second,
				Key: jwt.JWTIssueKey{
					PrivateKey: ecdsaKeyP384,
					Alg:        sig.SigAlgES384,
				},
			},
			wantErr: false,
		},
		{
			name: "basic ES384 (invalid key)",
			payload: map[string]any{
				"sub": "subject-id",
			},
			issueParams: jwt.JWTIssueParams{
				Issuer: "acme-issuer",
				Exp:    20 * time.Second,
				Key: jwt.JWTIssueKey{
					PrivateKey: ecdsaKeyP256,
					Alg:        sig.SigAlgES384,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var iss jwt.JWTIssuer
			_, gotErr := iss.Sign(tt.payload, tt.issueParams)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Sign() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Sign() succeeded unexpectedly")
			}
		})
	}
}

func TestJWTIssuer_Issue(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name        string
		principal   common.Principal
		issueParams common.IssueParams
		wantErr     bool
	}{
		{
			name: "basic RS256",
			principal: common.Principal{
				Subject: "subject-id",
			},
			issueParams: jwt.JWTIssueParams{
				Issuer: "acme-issuer",
				Exp:    20 * time.Second,
				Key: jwt.JWTIssueKey{
					PrivateKey: rsaKey,
					Alg:        sig.SigAlgRS256,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			var iss jwt.JWTIssuer
			_, gotErr := iss.Issue(context.Background(), tt.principal, tt.issueParams)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Issue() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Issue() succeeded unexpectedly")
			}
		})
	}
}
