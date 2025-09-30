package credentials_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/axent-pl/credentials"
)

var jwksResponsePayload string = `{
    "keys": [
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "558a0b512cf2bc77c3ffa862308b89d7fb86b4e48f1e0ef30f6fb64dee2610dd",
            "alg": "PS256",
            "n": "4mGTm7XBEsGGkZEWDSKlLp4tRU6R6WhVnm9Tk1mDnSvMTFl9TFLlc-e_Ue8PdSCBKkEc33jOW7H6-TMLN0VZOLG1gbHuj_JenGGIE7srSvc9dDh67P6cTPbfo_7qqfuisnKDGwH7NUyUIntpBY1SSQLgeyYhUnMFXMxDfxHN8oZrcNHYZXPmCYd4BUlCdsOkHdzZ6phDP4B_6stmPqcFHX87YvNaHvk7UNL1mydLpiCXRv0ECmfE_0TQKPjUNUlD7ttfuSUYmvY1XBgffNGU3GEoTjOPu05fnjdeSTuayxKYUY0gCDLlO8lpPqpwLBBhOzE8Jf2aysswBDcKZ_hetQ",
            "e": "AAAAAAABAAE"
        },
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "558a0b512cf2bc77c3ffa862308b89d7fb86b4e48f1e0ef30f6fb64dee2610dd",
            "alg": "RS256",
            "n": "4mGTm7XBEsGGkZEWDSKlLp4tRU6R6WhVnm9Tk1mDnSvMTFl9TFLlc-e_Ue8PdSCBKkEc33jOW7H6-TMLN0VZOLG1gbHuj_JenGGIE7srSvc9dDh67P6cTPbfo_7qqfuisnKDGwH7NUyUIntpBY1SSQLgeyYhUnMFXMxDfxHN8oZrcNHYZXPmCYd4BUlCdsOkHdzZ6phDP4B_6stmPqcFHX87YvNaHvk7UNL1mydLpiCXRv0ECmfE_0TQKPjUNUlD7ttfuSUYmvY1XBgffNGU3GEoTjOPu05fnjdeSTuayxKYUY0gCDLlO8lpPqpwLBBhOzE8Jf2aysswBDcKZ_hetQ",
            "e": "AAAAAAABAAE"
        },
        {
            "use": "sig",
            "kty": "EC",
            "kid": "970a71f9979cd2f67819497f976ad006e4bdd2ff2d1dd2e7a7d1b10779bfb268",
            "crv": "P-256",
            "alg": "ES256",
            "x": "mDOfOROjwltDurdAEieXqnohButUXxyavXoF0mmtFos",
            "y": "B2rEvk135QzNVWMNj-jqOGa0IftuovnGztAkvBtGaq8"
        },
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "b18e0592925e95a8187a745e8e823dc04a1335c608899c19df6877ceec16017a",
            "alg": "RS256",
            "n": "tbGBEuLyPVEaB3vKhaJ-tR0g03sXCAvkO3GqBlVacR0xRtwLj1qhY0ZSJ6pNzcl6ItHmea8ai9HVStba9bzAaUZpZE5P8gylaUi6G9Wfl5TOEluQtLJBkFTEVz9kydxnMvnkvIqaH_1Gzpo_R2_1zXvULasWYKEvummCDcZTJua_VjYKUHiQu3iBfiehlmDKknhnwTEEN11R-ssiGsS6mmii4qJACkweT9iEZegjdeqdqNvvdhaXU1NRMIiHN_KBuDmKIFEQDRIsSKWfswEskVmJAPdDaS-YhPsPZXTkBa18IB8s5ez0ttGoThP8PnXFf37PLYeXcseIuEnALurZ6buMNS5Je_zAG8c203470VWN5unZuMA5RwXSdDgsKRA7ty3jVhkoGkWjEQFppLB4uYvUI27dvr3N8EbPbtpkH01NHg-Hss9o1OSKNdYNt5VzlsshbJpA4QI9uL4X3gn2sKTzuSSLpSTzbH17b1J-MJ8Z7qTv2w9ZkKtLAXGQHUOATlPGfa3GFTGgYbt2pWc2CD1mtfkIKCDfYcwN8nemaQEEmvUlt2_VEpRazsCxgD6shTwsa2z8WihKDzZg7rYTPsO5SRDcP3DbDCdDcC4AKzom1Y5qxle5aEVx-VpEe4nR1pvNuYTvuEj3O9UA5F2CdOgbLcysD2sa7UhP9uQg2OU",
            "e": "AAAAAAABAAE",
            "x5c": [
                "MIIFCDCCAvCgAwIBAgIgWT3ju3jtX4uE5SICTNfQ8vDED2eTCj/5QzlI2BfeioYwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAxMLU2VsZi1TaWduZWQwHhcNMjUwOTAzMTI0ODM0WhcNMzUwOTAzMTI0ODM0WjAWMRQwEgYDVQQDEwtTZWxmLVNpZ25lZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALWxgRLi8j1RGgd7yoWifrUdINN7FwgL5DtxqgZVWnEdMUbcC49aoWNGUieqTc3JeiLR5nmvGovR1UrW2vW8wGlGaWROT/IMpWlIuhvVn5eUzhJbkLSyQZBUxFc/ZMncZzL55LyKmh/9Rs6aP0dv9c171C2rFmChL7ppgg3GUybmv1Y2ClB4kLt4gX4noZZgypJ4Z8ExBDddUfrLIhrEuppoouKiQApMHk/YhGXoI3Xqnajb73YWl1NTUTCIhzfygbg5iiBREA0SLEiln7MBLJFZiQD3Q2kvmIT7D2V05AWtfCAfLOXs9LbRqE4T/D51xX9+zy2Hl3LHiLhJwC7q2em7jDUuSXv8wBvHNtN+O9FVjebp2bjAOUcF0nQ4LCkQO7ct41YZKBpFoxEBaaSweLmL1CNu3b69zfBGz27aZB9NTR4Ph7LPaNTkijXWDbeVc5bLIWyaQOECPbi+F94J9rCk87kki6Uk82x9e29SfjCfGe6k79sPWZCrSwFxkB1DgE5Txn2txhUxoGG7dqVnNgg9ZrX5CCgg32HMDfJ3pmkBBJr1Jbdv1RKUWs7AsYA+rIU8LGts/FooSg82YO62Ez7DuUkQ3D9w2wwnQ3AuACs6JtWOasZXuWhFcflaRHuJ0dabzbmE77hI9zvVAORdgnToGy3MrA9rGu1IT/bkINjlAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIFoDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQrwPWnhhCyxIoDETVsv2d1zhgk8zANBgkqhkiG9w0BAQsFAAOCAgEASdCyqhVMc0n8yfEHDY84/njVdRZ5tnOPVkhfyE74nbWMcvOOrLooSVIUoIfOdzBJh29IAA425HIoYn+pBOEhIauGpfeQRl/qX5caAdiN8IzcPYkx2GfvKANlRvRcJQ/NHe+cYs7xvyUesJEFTyK03h4pBmkwJhqAc9MvDlAjnA8DucH4lW/GB5ZnQS2wy92QwIFYIlNbxgor97URrwZrfUZ6cMGBsinhg7FcmXWZObhhVqCIdFEGTxdKkky9t4Yy5dkMNclGX3DGDfZKL/dPOBbeL+WY7LkaunoqrWdxFhEcCXQblTvKR2xfCtfV4JXktJrWKfp1EZCd8ao6oaGnhagVYIImvibA9lnNHg5BFoQqShdltDxO0xUFdxnXV1aXyqlITkQjEJrTcVdsc8gJH1zSnjmhqilbvIsTVx5SAPKXIyOfRu/qRnKdtC+Iq2Qp+iBGH5CIjqk/ITQYwzqZMUwIm7irPeB8cPYhwkeEGVcqkEj1nLH3u41rk7zp/RnzFdJPp1qiCqcFZ18z0i//zwIduencSJKDlAOM0drX6kJrVgkD7qagcjfau7Yk09dS5e85z/ekD9BDPCpUinR8dnXnRGgrttSVPJJR6OJBIs8eyc88jqC1f6mbKajkhS8RzabMCMKRSB9/Q/++Y8iz7LUSvCgmBQy0VcfGFBBl1/s="
            ]
        }
    ]
}`

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestJWKSProvider_ValidationSchemes(t *testing.T) {
	// mock http response
	http.DefaultClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 201,
			Body:       io.NopCloser(bytes.NewBufferString(jwksResponsePayload)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})
	tests := []struct {
		name     string
		in       credentials.Credentials
		wantTest func([]credentials.Scheme) error
		wantErr  bool
	}{
		{
			name: "successful execution",
			in:   credentials.JWTInput{Token: "ttt"},
			wantTest: func(schemes []credentials.Scheme) error {
				if len(schemes) < 1 {
					return errors.New("no schemes")
				}
				if len(schemes) != 1 {
					return fmt.Errorf("want 1 schemes, got %d", len(schemes))
				}
				jwtScheme, ok := schemes[0].(credentials.JWTScheme)
				if !ok {
					return errors.New("invalid scheme type, want JWTScheme")
				}
				if len(jwtScheme.Keys) != 4 {
					return fmt.Errorf("invalid number of keys: want 4, got %d", len(jwtScheme.Keys))
				}
				return nil
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p credentials.JWKSProvider
			p.JWKSURL = url.URL{}
			got, gotErr := p.ValidationSchemes(context.Background(), tt.in)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ValidationSchemes() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ValidationSchemes() succeeded unexpectedly")
			}
			if err := tt.wantTest(got); err != nil {
				t.Errorf("ValidationSchemes() failed: %v", err)
			}
		})
	}
}
