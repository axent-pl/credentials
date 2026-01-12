package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
	"github.com/axent-pl/credentials/jwt"
)

func TestJWTVerifier_Verify(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issueParams := jwt.JWTIssueParams{
		Issuer: "acme-issuer",
		Exp:    20 * time.Second,
		Key: sig.SignatureKey{
			Key: rsaKey,
			Alg: sig.SigAlgRS256,
		},
	}
	var issuer jwt.JWTIssuer
	artifacts, _ := issuer.Issue(context.Background(), common.Principal{Subject: "subject-id"}, issueParams)
	accessToken, _ := common.ArtifactWithKind(artifacts, common.ArtifactAccessToken)

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		in      common.Credentials
		schemes []common.Scheme
		want    common.Principal
		wantErr bool
	}{
		{
			name: "valid RSA",
			in: jwt.JWTCredentials{
				Token: string(accessToken.Bytes),
			},
			schemes: []common.Scheme{
				jwt.JWTScheme{
					Keys: []sig.SignatureVerificationKey{
						{
							Key: &rsaKey.PublicKey,
						},
					},
				},
			},
			want: common.Principal{
				Subject: "subject-id",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v jwt.JWTVerifier
			got, gotErr := v.VerifyAny(context.Background(), tt.in, tt.schemes)
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
