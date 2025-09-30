package credentials_test

import (
	"context"
	"testing"

	"github.com/axent-pl/credentials"
	"golang.org/x/crypto/bcrypt"
)

func TestClientSecretVerifier_Verify(t *testing.T) {
	validPassword := "acme-secret"
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte(validPassword), 0)
	tests := []struct {
		name    string
		in      credentials.Credentials
		stored  []credentials.Scheme
		want    credentials.Principal
		wantErr bool
	}{
		{
			name: "client_id exists and client_secret is valid",
			in: credentials.ClientSecretInput{
				ClientID:     "acme",
				ClientSecret: validPassword,
			},
			stored: []credentials.Scheme{
				credentials.ClientSecretStored{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    credentials.Principal{Subject: "acme"},
			wantErr: false,
		},
		{
			name: "client_id not exists and client_secret is valid",
			in: credentials.ClientSecretInput{
				ClientID:     "acme",
				ClientSecret: validPassword,
			},
			stored: []credentials.Scheme{
				credentials.ClientSecretStored{
					ClientID:   "acme-other",
					SecretHash: validPasswordHash,
				},
			},
			want:    credentials.Principal{},
			wantErr: true,
		},
		{
			name: "client_id exists and client_secret is invalid",
			in: credentials.ClientSecretInput{
				ClientID:     "acme",
				ClientSecret: "invalid password",
			},
			stored: []credentials.Scheme{
				credentials.ClientSecretStored{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    credentials.Principal{},
			wantErr: true,
		},
		{
			name: "empty input credentials",
			in:   credentials.ClientSecretInput{},
			stored: []credentials.Scheme{
				credentials.ClientSecretStored{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    credentials.Principal{},
			wantErr: true,
		},
		{
			name: "invalid input credentials kind",
			in:   credentials.JWTInput{},
			stored: []credentials.Scheme{
				credentials.ClientSecretStored{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    credentials.Principal{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v credentials.ClientSecretVerifier
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
