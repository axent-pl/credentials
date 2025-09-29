package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"

	"github.com/axent-pl/auth"
)

func TestSAMLRequestVerifier_Verify(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	issuer := auth.SAMLRequestIssuer{}
	artifacts, _ := issuer.Issue(context.Background(), auth.Principal{}, auth.SAMLRequestIssueParams{
		Issuer: "https://saml.application.org",
		Key: &auth.SAMLRequestIssueKey{
			PrivateKey: rsaKey,
			HashAlg:    crypto.SHA256,
		},
		Destination: "https://saml.idp.org",
	})
	samlRequestURI, _ := auth.ArtifactWithKind(artifacts, auth.ArtifactSAMLRequestURI)
	u, _ := url.Parse(string(samlRequestURI.Bytes))
	samlRequest := auth.SAMLRequestInput{
		SAMLRequest: u.Query().Get("SAMLRequest"),
		RelayState:  u.Query().Get("RelayState"),
		SigAlg:      u.Query().Get("SigAlg"),
		Signature:   u.Query().Get("Signature"),
	}

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		in      auth.Credentials
		schemes []auth.Scheme
		want    auth.Principal
		wantErr bool
	}{
		{
			name: "basic success",
			in:   samlRequest,
			schemes: []auth.Scheme{
				auth.SAMLRequestScheme{
					Keys: []auth.SAMLRequestSchemeKey{
						{
							Key:    rsaKey.PublicKey,
							SigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
						},
					},
				},
			},
			wantErr: false,
			want: auth.Principal{
				Subject: auth.SubjectID("https://saml.application.org"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v auth.SAMLRequestVerifier
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
