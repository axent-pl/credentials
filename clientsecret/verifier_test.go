package clientsecret_test

import (
	"context"
	"testing"

	"github.com/axent-pl/credentials/clientsecret"
	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/jwt"
	"golang.org/x/crypto/bcrypt"
)

func TestClientSecretVerifier_Verify(t *testing.T) {
	validPassword := "acme-secret"
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte(validPassword), 0)
	tests := []struct {
		name    string
		in      common.Credentials
		stored  []common.Scheme
		want    common.Principal
		wantErr bool
	}{
		{
			name: "client_id exists and client_secret is valid",
			in: clientsecret.ClientSecretCredentials{
				ClientID:     "acme",
				ClientSecret: validPassword,
			},
			stored: []common.Scheme{
				clientsecret.ClientSecretScheme{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    common.Principal{Subject: "acme"},
			wantErr: false,
		},
		{
			name: "client_id not exists and client_secret is valid",
			in: clientsecret.ClientSecretCredentials{
				ClientID:     "acme",
				ClientSecret: validPassword,
			},
			stored: []common.Scheme{
				clientsecret.ClientSecretScheme{
					ClientID:   "acme-other",
					SecretHash: validPasswordHash,
				},
			},
			want:    common.Principal{},
			wantErr: true,
		},
		{
			name: "client_id exists and client_secret is invalid",
			in: clientsecret.ClientSecretCredentials{
				ClientID:     "acme",
				ClientSecret: "invalid password",
			},
			stored: []common.Scheme{
				clientsecret.ClientSecretScheme{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    common.Principal{},
			wantErr: true,
		},
		{
			name: "empty input credentials",
			in:   clientsecret.ClientSecretCredentials{},
			stored: []common.Scheme{
				clientsecret.ClientSecretScheme{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    common.Principal{},
			wantErr: true,
		},
		{
			name: "invalid input credentials kind",
			in:   jwt.JWTInput{},
			stored: []common.Scheme{
				clientsecret.ClientSecretScheme{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    common.Principal{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v clientsecret.ClientSecretVerifier
			got, gotErr := v.Verify(context.Background(), tt.in, tt.stored)
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
