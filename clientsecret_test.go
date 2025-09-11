package auth_test

import (
	"context"
	"testing"

	"github.com/axent-pl/auth"
	"golang.org/x/crypto/bcrypt"
)

func TestClientSecretVerifier_Verify(t *testing.T) {
	validPassword := "acme-secret"
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte(validPassword), 0)
	tests := []struct {
		name    string
		in      auth.InputCredentials
		stored  []auth.ValidationScheme
		want    auth.Principal
		wantErr bool
	}{
		{
			name: "client_id exists and client_secret is valid",
			in: auth.ClientSecretInput{
				ClientID:     "acme",
				ClientSecret: validPassword,
			},
			stored: []auth.ValidationScheme{
				auth.ClientSecretStored{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    auth.Principal{Subject: "acme"},
			wantErr: false,
		},
		{
			name: "client_id not exists and client_secret is valid",
			in: auth.ClientSecretInput{
				ClientID:     "acme",
				ClientSecret: validPassword,
			},
			stored: []auth.ValidationScheme{
				auth.ClientSecretStored{
					ClientID:   "acme-other",
					SecretHash: validPasswordHash,
				},
			},
			want:    auth.Principal{},
			wantErr: true,
		},
		{
			name: "client_id exists and client_secret is invalid",
			in: auth.ClientSecretInput{
				ClientID:     "acme",
				ClientSecret: "invalid password",
			},
			stored: []auth.ValidationScheme{
				auth.ClientSecretStored{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    auth.Principal{},
			wantErr: true,
		},
		{
			name: "empty input credentials",
			in:   auth.ClientSecretInput{},
			stored: []auth.ValidationScheme{
				auth.ClientSecretStored{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    auth.Principal{},
			wantErr: true,
		},
		{
			name: "invalid input credentials kind",
			in:   auth.JWTInput{},
			stored: []auth.ValidationScheme{
				auth.ClientSecretStored{
					ClientID:   "acme",
					SecretHash: validPasswordHash,
				},
			},
			want:    auth.Principal{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v auth.ClientSecretVerifier
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
