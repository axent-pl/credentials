package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

type JWKSProvider struct {
	JWKSURL url.URL
}

// --- internal types/helpers ---

// jwksResponse represents a JWKS document extended with optional fields.
// Standard JWKS uses only "keys". We also accept "valid_methods" and "issuer".
type jwksResponse struct {
	Keys         []jwkKey `json:"keys"`
	ValidMethods []string `json:"valid_methods,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
}

type jwkKey struct {
	Use       string   `json:"use,omitempty"`
	Kty       string   `json:"kty,omitempty"`
	Kid       string   `json:"kid,omitempty"`
	Crv       string   `json:"crv,omitempty"`
	Alg       string   `json:"alg,omitempty"`
	K         string   `json:"k,omitempty"`
	X         string   `json:"x,omitempty"`
	Y         string   `json:"y,omitempty"`
	N         string   `json:"n,omitempty"`
	E         string   `json:"e,omitempty"`
	X5c       []string `json:"x5c,omitempty"`
	X5u       *url.URL `json:"x5u,omitempty"`
	X5tSHA1   string   `json:"x5t,omitempty"`
	X5tSHA256 string   `json:"x5t#S256,omitempty"`
}

func b64uToBigInt(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.New("empty base64url")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func JwkToPublicKey(k jwkKey) (crypto.PublicKey, error) {
	switch strings.ToUpper(k.Kty) {
	case "RSA":
		n, err := b64uToBigInt(k.N)
		if err != nil {
			return nil, fmt.Errorf("rsa n: %w", err)
		}
		eBig, err := b64uToBigInt(k.E)
		if err != nil {
			return nil, fmt.Errorf("rsa e: %w", err)
		}
		if !eBig.IsInt64() || eBig.Int64() > int64(^uint32(0)>>1) {
			return nil, errors.New("rsa exponent too large")
		}
		e := int(eBig.Int64())
		return &rsa.PublicKey{N: n, E: e}, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %q", k.Crv)
		}
		x, err := b64uToBigInt(k.X)
		if err != nil {
			return nil, fmt.Errorf("ec x: %w", err)
		}
		y, err := b64uToBigInt(k.Y)
		if err != nil {
			return nil, fmt.Errorf("ec y: %w", err)
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported kty: %q", k.Kty)
	}
}

func (p *JWKSProvider) ValidationSchemes(ctx context.Context, in InputCredentials) ([]ValidationScheme, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.JWKSURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("jwks request build failed: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return nil, fmt.Errorf("jwks fetch failed: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("jwks fetch failed: unexpected status %s", resp.Status)
	}

	var doc jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwks decode failed: %w", err)
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("jwks contains no keys")
	}

	keys := make([]JWTSchemeKey, 0)
	allHaveKID := true
	for _, jk := range doc.Keys {
		pub, err := JwkToPublicKey(jk)
		if err != nil {
			return nil, fmt.Errorf("could not extract public key: %w", err)
		}
		if jk.Kid == "" {
			allHaveKID = false
		}
		keys = append(keys, JWTSchemeKey{
			ID:  jk.Kid,
			Key: pub,
			Alg: jk.Alg,
		})
	}

	if len(keys) == 0 {
		return nil, errors.New("no usable keys in jwks")
	}

	scheme := JWTScheme{
		MustMatchKid: allHaveKID && len(keys) > 1, // require kid only if all keys provide it and there are multiple keys
		Keys:         keys,
	}

	return []ValidationScheme{scheme}, nil
}
