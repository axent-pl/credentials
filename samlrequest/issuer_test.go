package samlrequest_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/samlrequest"
)

func TestSAMLRequestIssuer_Issue(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name        string
		issueParams common.IssueParams
		want        []common.Artifact
		wantErr     bool
	}{
		{
			name: "basic without signature success",
			issueParams: samlrequest.SAMLRequestIssueParams{
				Issuer:      "https://saml.application.org",
				Destination: "https://saml.idp.org",
			},
			wantErr: false,
		},
		{
			name: "basic with signature (rsa+sha256) success",
			issueParams: samlrequest.SAMLRequestIssueParams{
				Issuer: "https://saml.application.org",
				Key: &samlrequest.SAMLRequestIssueKey{
					Key: rsaKey,
					Alg: crypto.SHA256,
				},
				Destination: "https://saml.idp.org",
			},
			wantErr: false,
		},
		{
			name: "basic with signature (ecdsa+sha256) success",
			issueParams: samlrequest.SAMLRequestIssueParams{
				Issuer: "https://saml.application.org",
				Key: &samlrequest.SAMLRequestIssueKey{
					Key: ecdsaKey,
					Alg: crypto.SHA256,
				},
				Destination: "https://saml.idp.org",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			var iss samlrequest.SAMLRequestIssuer
			_, gotErr := iss.Issue(context.Background(), common.Principal{}, tt.issueParams)
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
