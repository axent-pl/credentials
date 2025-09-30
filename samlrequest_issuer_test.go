package credentials_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/axent-pl/credentials"
)

func TestSAMLRequestIssuer_Issue(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name        string
		issueParams credentials.IssueParams
		want        []credentials.Artifact
		wantErr     bool
	}{
		{
			name: "basic without signature success",
			issueParams: credentials.SAMLRequestIssueParams{
				Issuer:      "https://saml.application.org",
				Destination: "https://saml.idp.org",
			},
			wantErr: false,
		},
		{
			name: "basic with signature (rsa+sha256) success",
			issueParams: credentials.SAMLRequestIssueParams{
				Issuer: "https://saml.application.org",
				Key: &credentials.SAMLRequestIssueKey{
					PrivateKey: rsaKey,
					HashAlg:    crypto.SHA256,
				},
				Destination: "https://saml.idp.org",
			},
			wantErr: false,
		},
		{
			name: "basic with signature (ecdsa+sha256) success",
			issueParams: credentials.SAMLRequestIssueParams{
				Issuer: "https://saml.application.org",
				Key: &credentials.SAMLRequestIssueKey{
					PrivateKey: ecdsaKey,
					HashAlg:    crypto.SHA256,
				},
				Destination: "https://saml.idp.org",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			var iss credentials.SAMLRequestIssuer
			_, gotErr := iss.Issue(context.Background(), credentials.Principal{}, tt.issueParams)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Issue() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Issue() succeeded unexpectedly")
			}
			// TODO: update the condition below to compare got with tt.want.
			// if true {
			// 	t.Errorf("Issue() = %v, want %v", got, tt.want)
			// }
		})
	}
}
