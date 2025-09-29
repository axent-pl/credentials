package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/axent-pl/auth"
)

func TestJWTVerifier_Verify(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issueParams := auth.JWTIssueParams{
		Issuer: "acme-issuer",
		Exp:    20 * time.Second,
		Key: auth.JWTIssueSchemeKey{
			PrivateKey: rsaKey,
			Alg:        "RS256",
		},
	}
	var issuer auth.JWTIssuer
	artifacts, _ := issuer.Issue(context.Background(), auth.Principal{Subject: "subject-id"}, issueParams)
	accessToken, _ := auth.ArtifactWithKind(artifacts, auth.ArtifactAccessToken)

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		in      auth.Credentials
		schemes []auth.Scheme
		want    auth.Principal
		wantErr bool
	}{
		{
			name: "valid RSA",
			in: auth.JWTInput{
				Token: string(accessToken.Bytes),
			},
			schemes: []auth.Scheme{
				auth.JWTScheme{
					Keys: []auth.JWTSchemeKey{
						{
							Key: &rsaKey.PublicKey,
						},
					},
				},
			},
			want: auth.Principal{
				Subject: "subject-id",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			var v auth.JWTVerifier
			got, gotErr := v.Verify(context.Background(), tt.in, tt.schemes)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Verify() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Verify() succeeded unexpectedly")
			}
			if tt.want.Subject != got.Subject {
				t.Errorf("Verify() = %v, want %v", got.Subject, tt.want.Subject)
			}
		})
	}
}
