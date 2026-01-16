package userpassword_test

import (
	"context"
	"testing"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/jwt"
	"github.com/axent-pl/credentials/userpassword"
	"golang.org/x/crypto/bcrypt"
)

func TestUserPasswordVerifier_Verify(t *testing.T) {
	validPassword := "acme-password"
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte(validPassword), 0)
	tests := []struct {
		name    string
		in      common.Credentials
		stored  []common.Scheme
		want    common.Principal
		wantErr bool
	}{
		{
			name: "username exists and password is valid",
			in: userpassword.UserPasswordCredentials{
				Username: "acme",
				Password: validPassword,
			},
			stored: []common.Scheme{
				userpassword.DefaultUserPasswordScheme{
					Username:     "acme",
					PasswordHash: validPasswordHash,
				},
			},
			want:    common.Principal{Subject: "acme"},
			wantErr: false,
		},
		{
			name: "username not exists and password is valid",
			in: userpassword.UserPasswordCredentials{
				Username: "acme",
				Password: validPassword,
			},
			stored: []common.Scheme{
				userpassword.DefaultUserPasswordScheme{
					Username:     "acme-other",
					PasswordHash: validPasswordHash,
				},
			},
			want:    common.Principal{},
			wantErr: true,
		},
		{
			name: "username exists and password is invalid",
			in: userpassword.UserPasswordCredentials{
				Username: "acme",
				Password: "invalid password",
			},
			stored: []common.Scheme{
				userpassword.DefaultUserPasswordScheme{
					Username:     "acme",
					PasswordHash: validPasswordHash,
				},
			},
			want:    common.Principal{},
			wantErr: true,
		},
		{
			name: "empty input credentials",
			in:   userpassword.UserPasswordCredentials{},
			stored: []common.Scheme{
				userpassword.DefaultUserPasswordScheme{
					Username:     "acme",
					PasswordHash: validPasswordHash,
				},
			},
			want:    common.Principal{},
			wantErr: true,
		},
		{
			name: "invalid input credentials kind",
			in:   jwt.JWTCredentials{},
			stored: []common.Scheme{
				userpassword.DefaultUserPasswordScheme{
					Username:     "acme",
					PasswordHash: validPasswordHash,
				},
			},
			want:    common.Principal{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v userpassword.UserPasswordVerifier
			got, gotErr := v.VerifyAny(context.Background(), tt.in, tt.stored)
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
