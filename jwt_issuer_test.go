package auth_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/axent-pl/auth"
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
		principal   auth.Principal
		scheme      auth.JWTIssueScheme
		issueParams auth.JWTIssueParams
		want        map[string]any
		checks      []ClaimCheckFunction
		wantErr     bool
	}{
		{
			name:        "basic",
			principal:   auth.Principal{Subject: "subject-id"},
			scheme:      auth.JWTIssueScheme{Issuer: "https://acme-auth-server.com", Exp: 30 * time.Second},
			issueParams: auth.JWTIssueParams{AuthorizedParty: "acme-registered-app"},
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
			name:        "no scheme.Exp",
			principal:   auth.Principal{Subject: "subject-id"},
			scheme:      auth.JWTIssueScheme{Issuer: "https://acme-auth-server.com"},
			issueParams: auth.JWTIssueParams{AuthorizedParty: "acme-registered-app"},
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
			principal:   auth.Principal{Subject: "subject-id"},
			scheme:      auth.JWTIssueScheme{Issuer: "https://acme-auth-server.com", Exp: 30 * time.Second},
			issueParams: auth.JWTIssueParams{},
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
			var iss auth.JWTIssuer
			got, gotErr := iss.BaseClaims(context.Background(), tt.principal, tt.scheme, tt.issueParams)
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
		principal      auth.Principal
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
			principal: auth.Principal{
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
			var iss auth.JWTIssuer
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
