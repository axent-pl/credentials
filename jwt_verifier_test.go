package credentials_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/axent-pl/credentials"
	"github.com/axent-pl/credentials/sig"
)

func TestJWTVerifier_Verify(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issueParams := credentials.JWTIssueParams{
		Issuer: "acme-issuer",
		Exp:    20 * time.Second,
		Key: credentials.JWTIssueKey{
			PrivateKey: rsaKey,
			Alg:        sig.SigAlgRS256,
		},
	}
	var issuer credentials.JWTIssuer
	artifacts, _ := issuer.Issue(context.Background(), credentials.Principal{Subject: "subject-id"}, issueParams)
	accessToken, _ := credentials.ArtifactWithKind(artifacts, credentials.ArtifactAccessToken)

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		in      credentials.Credentials
		schemes []credentials.Scheme
		want    credentials.Principal
		wantErr bool
	}{
		{
			name: "valid RSA",
			in: credentials.JWTInput{
				Token: string(accessToken.Bytes),
			},
			schemes: []credentials.Scheme{
				credentials.JWTScheme{
					Keys: []credentials.JWTSchemeKey{
						{
							Key: &rsaKey.PublicKey,
						},
					},
				},
			},
			want: credentials.Principal{
				Subject: "subject-id",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			var v credentials.JWTVerifier
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
