package credentials_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"

	"github.com/axent-pl/credentials"
	"github.com/axent-pl/credentials/sig"
)

func TestSAMLRequestVerifier_Verify(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	issuer := credentials.SAMLRequestIssuer{}
	artifacts, _ := issuer.Issue(context.Background(), credentials.Principal{}, credentials.SAMLRequestIssueParams{
		Issuer: "https://saml.application.org",
		Key: &credentials.SAMLRequestIssueKey{
			PrivateKey: rsaKey,
			HashAlg:    crypto.SHA256,
		},
		Destination: "https://saml.idp.org",
	})
	samlRequestURI, _ := credentials.ArtifactWithKind(artifacts, credentials.ArtifactSAMLRequestURI)
	u, _ := url.Parse(string(samlRequestURI.Bytes))
	samlRequest := credentials.SAMLRequestInput{
		SAMLRequest: u.Query().Get("SAMLRequest"),
		RelayState:  u.Query().Get("RelayState"),
		SigAlg:      u.Query().Get("SigAlg"),
		Signature:   u.Query().Get("Signature"),
	}

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		in      credentials.Credentials
		schemes []credentials.Scheme
		want    credentials.Principal
		wantErr bool
	}{
		{
			name: "basic success",
			in:   samlRequest,
			schemes: []credentials.Scheme{
				credentials.SAMLRequestScheme{
					Keys: []credentials.SAMLRequestSchemeKey{
						{
							Key:    rsaKey.PublicKey,
							SigAlg: sig.SigAlgRS256,
						},
					},
				},
			},
			wantErr: false,
			want: credentials.Principal{
				Subject: credentials.SubjectID("https://saml.application.org"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v credentials.SAMLRequestVerifier
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
			if got.Subject != tt.want.Subject {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
