package samlrequest_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
	"github.com/axent-pl/credentials/samlrequest"
)

type testIssueParams struct{}

func (testIssueParams) Kind() common.Kind { return common.Kind("invalid") }

func TestSAMLRequestIssuer_Issue(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forceAuthn := true
	isPassive := false

	tests := []struct {
		name         string
		issueParams  common.IssueParams
		wantSigAlg   string
		wantRelay    string
		wantIssuer   string
		wantDest     string
		wantACSURL   string
		wantProtocol string
		wantFA       *bool
		wantIP       *bool
		wantErr      bool
	}{
		{
			name: "basic without signature success",
			issueParams: samlrequest.SAMLRequestIssueParams{
				Issuer:                      "https://saml.application.org",
				Destination:                 "https://saml.idp.org/sso",
				AssertionConsumerServiceURL: "https://saml.application.org/acs",
				ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				ForceAuthn:                  &forceAuthn,
				IsPassive:                   &isPassive,
			},
			wantIssuer:   "https://saml.application.org",
			wantDest:     "https://saml.idp.org/sso",
			wantACSURL:   "https://saml.application.org/acs",
			wantProtocol: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
			wantFA:       &forceAuthn,
			wantIP:       &isPassive,
			wantErr:      false,
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
			wantSigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			wantIssuer: "https://saml.application.org",
			wantDest:   "https://saml.idp.org",
			wantErr:    false,
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
			wantSigAlg: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
			wantIssuer: "https://saml.application.org",
			wantDest:   "https://saml.idp.org",
			wantErr:    false,
		},
		{
			name: "unsupported key hash",
			issueParams: samlrequest.SAMLRequestIssueParams{
				Issuer: "https://saml.application.org",
				Key: &samlrequest.SAMLRequestIssueKey{
					Key: ecdsaKey,
					Alg: crypto.SHA1,
				},
				Destination: "https://saml.idp.org",
			},
			wantErr: true,
		},
		{
			name: "invalid destination",
			issueParams: samlrequest.SAMLRequestIssueParams{
				Issuer:      "https://saml.application.org",
				Destination: "://bad",
			},
			wantErr: true,
		},
		{
			name:        "invalid issue params type",
			issueParams: testIssueParams{},
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var iss samlrequest.SAMLRequestIssuer
			artifacts, gotErr := iss.Issue(context.Background(), common.Principal{}, tt.issueParams)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Issue() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Issue() succeeded unexpectedly")
			}

			artifact, err := common.ArtifactWithKind(artifacts, common.ArtifactSAMLRequestURI)
			if err != nil {
				t.Fatalf("Issue() missing SAMLRequestURI: %v", err)
			}
			if artifact.MediaType != "text/uri-list" {
				t.Errorf("Issue() media type = %q, want %q", artifact.MediaType, "text/uri-list")
			}

			parsed, err := url.Parse(string(artifact.Bytes))
			if err != nil {
				t.Fatalf("Issue() returned invalid URI: %v", err)
			}
			if tt.wantDest != "" {
				wantDest, err := url.Parse(tt.wantDest)
				if err != nil {
					t.Fatalf("test destination invalid: %v", err)
				}
				if parsed.Scheme != wantDest.Scheme || parsed.Host != wantDest.Host || parsed.Path != wantDest.Path {
					t.Errorf("Issue() destination = %s://%s%s, want %s://%s%s", parsed.Scheme, parsed.Host, parsed.Path, wantDest.Scheme, wantDest.Host, wantDest.Path)
				}
			}

			q := parsed.Query()
			samlRequest := samlrequest.SAMLRequestCredentials{
				SAMLRequest: q.Get("SAMLRequest"),
				RelayState:  q.Get("RelayState"),
				SigAlg:      q.Get("SigAlg"),
				Signature:   q.Get("Signature"),
			}
			if samlRequest.SAMLRequest == "" {
				t.Fatal("Issue() missing SAMLRequest query parameter")
			}
			if tt.wantRelay != "" && samlRequest.RelayState != tt.wantRelay {
				t.Errorf("Issue() RelayState = %q, want %q", samlRequest.RelayState, tt.wantRelay)
			}

			if tt.wantSigAlg == "" {
				if samlRequest.SigAlg != "" || samlRequest.Signature != "" {
					t.Errorf("Issue() expected no signature, got SigAlg=%q Signature=%q", samlRequest.SigAlg, samlRequest.Signature)
				}
			} else {
				if samlRequest.SigAlg != tt.wantSigAlg {
					t.Errorf("Issue() SigAlg = %q, want %q", samlRequest.SigAlg, tt.wantSigAlg)
				}
				if samlRequest.Signature == "" {
					t.Error("Issue() missing Signature")
				} else {
					verify := samlrequest.SAMLRequestVerifier{}
					scheme := samlrequest.SAMLRequestScheme{
						Keys: []sig.SignatureVerificationKey{
							{
								Key: rsaKey.PublicKey,
								Alg: sig.SigAlgRS256,
							},
							{
								Key: ecdsaKey.PublicKey,
								Alg: sig.SigAlgES256,
							},
						},
					}
					if err := verify.VerifySignature(samlRequest, scheme); err != nil {
						t.Errorf("Issue() signature verification failed: %v", err)
					}
				}
			}

			reqXML, err := samlRequest.UnmarshalSAMLRequest()
			if err != nil {
				t.Fatalf("Issue() could not decode SAMLRequest: %v", err)
			}
			if tt.wantIssuer != "" && reqXML.Issuer != nil && reqXML.Issuer.Value != tt.wantIssuer {
				t.Errorf("Issue() Issuer = %q, want %q", reqXML.Issuer.Value, tt.wantIssuer)
			}
			if tt.wantIssuer != "" && reqXML.Issuer == nil {
				t.Errorf("Issue() missing Issuer, want %q", tt.wantIssuer)
			}
			if tt.wantDest != "" && reqXML.Destination != tt.wantDest {
				t.Errorf("Issue() Destination = %q, want %q", reqXML.Destination, tt.wantDest)
			}
			if tt.wantACSURL != "" && reqXML.AssertionConsumerServiceURL != tt.wantACSURL {
				t.Errorf("Issue() AssertionConsumerServiceURL = %q, want %q", reqXML.AssertionConsumerServiceURL, tt.wantACSURL)
			}
			if tt.wantProtocol != "" && reqXML.ProtocolBinding != tt.wantProtocol {
				t.Errorf("Issue() ProtocolBinding = %q, want %q", reqXML.ProtocolBinding, tt.wantProtocol)
			}
			if tt.wantFA != nil && (reqXML.ForceAuthn == nil || *reqXML.ForceAuthn != *tt.wantFA) {
				if reqXML.ForceAuthn == nil {
					t.Errorf("Issue() ForceAuthn = nil, want %v", *tt.wantFA)
				} else {
					t.Errorf("Issue() ForceAuthn = %v, want %v", *reqXML.ForceAuthn, *tt.wantFA)
				}
			}
			if tt.wantIP != nil && (reqXML.IsPassive == nil || *reqXML.IsPassive != *tt.wantIP) {
				if reqXML.IsPassive == nil {
					t.Errorf("Issue() IsPassive = nil, want %v", *tt.wantIP)
				} else {
					t.Errorf("Issue() IsPassive = %v, want %v", *reqXML.IsPassive, *tt.wantIP)
				}
			}
		})
	}
}
