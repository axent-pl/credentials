package clientassertion_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/axent-pl/credentials/clientassertion"
	"github.com/axent-pl/credentials/common/sig"
)

func TestClientAssertionIssuer_Sign(t *testing.T) {
	rsaKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKeyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaKeyP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		payload     map[string]any
		issueParams clientassertion.ClientAssertionIssueParams
		want        []byte
		wantErr     bool
	}{
		{
			name: "basic RS1 (want error)",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: clientassertion.ClientAssertionIssueKey{
					PrivateKey: rsaKey2048,
					Alg:        sig.SigAlgRS1,
				},
			},
			wantErr: true,
		},
		{
			name: "basic RS256",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: clientassertion.ClientAssertionIssueKey{
					PrivateKey: rsaKey2048,
					Alg:        sig.SigAlgRS256,
				},
			},
			wantErr: false,
		},
		{
			name: "basic RS384",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: clientassertion.ClientAssertionIssueKey{
					PrivateKey: rsaKey2048,
					Alg:        sig.SigAlgRS384,
				},
			},
			wantErr: false,
		},
		{
			name: "basic RS512",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: clientassertion.ClientAssertionIssueKey{
					PrivateKey: rsaKey2048,
					Alg:        sig.SigAlgRS512,
				},
			},
			wantErr: false,
		},
		{
			name: "basic ES256",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: clientassertion.ClientAssertionIssueKey{
					PrivateKey: ecdsaKeyP256,
					Alg:        sig.SigAlgES256,
				},
			},
			wantErr: false,
		},
		{
			name: "basic ES384",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: clientassertion.ClientAssertionIssueKey{
					PrivateKey: ecdsaKeyP384,
					Alg:        sig.SigAlgES384,
				},
			},
			wantErr: false,
		},
		{
			name: "basic ES384 (invalid key)",
			payload: map[string]any{
				"sub": "client-id",
			},
			issueParams: clientassertion.ClientAssertionIssueParams{
				ClientID: "client-id",
				Exp:      20 * time.Second,
				Key: clientassertion.ClientAssertionIssueKey{
					PrivateKey: ecdsaKeyP256,
					Alg:        sig.SigAlgES384,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			var iss clientassertion.ClientAssertionIssuer
			_, gotErr := iss.Sign(tt.payload, tt.issueParams)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Sign() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Sign() succeeded unexpectedly")
			}
		})
	}
}
