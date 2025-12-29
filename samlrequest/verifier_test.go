package samlrequest_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/samlrequest"
	"github.com/axent-pl/credentials/sig"
)

func TestSAMLRequestVerifier_Verify(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	issuer := samlrequest.SAMLRequestIssuer{}
	artifacts, _ := issuer.Issue(context.Background(), common.Principal{}, samlrequest.SAMLRequestIssueParams{
		Issuer: "https://saml.application.org",
		Key: &samlrequest.SAMLRequestIssueKey{
			PrivateKey: rsaKey,
			HashAlg:    crypto.SHA256,
		},
		Destination: "https://saml.idp.org",
	})
	samlRequestURI, _ := common.ArtifactWithKind(artifacts, common.ArtifactSAMLRequestURI)
	u, _ := url.Parse(string(samlRequestURI.Bytes))
	samlRequest := samlrequest.SAMLRequestCredentials{
		SAMLRequest: u.Query().Get("SAMLRequest"),
		RelayState:  u.Query().Get("RelayState"),
		SigAlg:      u.Query().Get("SigAlg"),
		Signature:   u.Query().Get("Signature"),
	}

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		in      common.Credentials
		schemes []common.Scheme
		want    common.Principal
		wantErr bool
	}{
		{
			name: "basic success",
			in:   samlRequest,
			schemes: []common.Scheme{
				samlrequest.SAMLRequestScheme{
					Keys: []samlrequest.SAMLRequestSchemeKey{
						{
							Key:    rsaKey.PublicKey,
							SigAlg: sig.SigAlgRS256,
						},
					},
				},
			},
			wantErr: false,
			want: common.Principal{
				Subject: common.SubjectID("https://saml.application.org"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v samlrequest.SAMLRequestVerifier
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
