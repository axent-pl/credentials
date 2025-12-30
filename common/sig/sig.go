package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// SigAlg represents a unified signature algorithm across OAuth2, SAML, jwt lib
type SigAlg int

const (
	SigAlgUnknown SigAlg = iota

	// RSA PKCS#1 v1.5
	SigAlgRS1
	SigAlgRS256
	SigAlgRS384
	SigAlgRS512

	// ECDSA over P-256/384/512 (aka P-521) with SHA-2
	SigAlgES256
	SigAlgES384
	SigAlgES512

	// RSA-PSS
	SigAlgPS256
	SigAlgPS384
	SigAlgPS512
)

func (sa SigAlg) String() string {
	mapping := map[SigAlg]string{
		SigAlgRS1:   "RS1",
		SigAlgRS256: "RS256",
		SigAlgRS384: "RS384",
		SigAlgRS512: "RS512",
		SigAlgES256: "ES256",
		SigAlgES384: "ES384",
		SigAlgES512: "ES512",
		SigAlgPS256: "PS256",
		SigAlgPS384: "PS384",
		SigAlgPS512: "PS512",
	}
	if alg, ok := mapping[sa]; ok {
		return alg
	}
	return "unknown"
}

// ---------- JWT package ---
func (sa SigAlg) ToGoJWT() (jwt.SigningMethod, error) {
	mapping := map[SigAlg]jwt.SigningMethod{
		SigAlgRS256: jwt.SigningMethodRS256,
		SigAlgRS384: jwt.SigningMethodRS384,
		SigAlgRS512: jwt.SigningMethodRS512,
		SigAlgES256: jwt.SigningMethodES256,
		SigAlgES384: jwt.SigningMethodES384,
		SigAlgES512: jwt.SigningMethodES512,
		SigAlgPS256: jwt.SigningMethodPS256,
		SigAlgPS384: jwt.SigningMethodPS384,
		SigAlgPS512: jwt.SigningMethodPS512,
	}
	if alg, ok := mapping[sa]; ok {
		return alg, nil
	}
	return nil, fmt.Errorf("unknown alg: %s", sa)
}

func FromOAuth(s string) (SigAlg, error) {
	mapping := map[string]SigAlg{
		"RS1":   SigAlgRS1,
		"RS256": SigAlgRS256,
		"RS384": SigAlgRS384,
		"RS512": SigAlgRS512,
		"ES256": SigAlgES256,
		"ES384": SigAlgES384,
		"ES512": SigAlgES512,
		"PS256": SigAlgPS256,
		"PS384": SigAlgPS384,
		"PS512": SigAlgPS512,
	}
	if alg, ok := mapping[s]; ok {
		return alg, nil
	}
	return SigAlgUnknown, fmt.Errorf("unknown alg: %s", s)
}

func (sa SigAlg) ToOAuth() (string, error) {
	mapping := map[SigAlg]string{
		SigAlgRS1:   "RS1",
		SigAlgRS256: "RS256",
		SigAlgRS384: "RS384",
		SigAlgRS512: "RS512",
		SigAlgES256: "ES256",
		SigAlgES384: "ES384",
		SigAlgES512: "ES512",
		SigAlgPS256: "PS256",
		SigAlgPS384: "PS384",
		SigAlgPS512: "PS512",
	}
	if alg, ok := mapping[sa]; ok {
		return alg, nil
	}
	return "unknown", fmt.Errorf("unknown alg: %s", sa)
}

func FromSAML(s string) (SigAlg, error) {
	mapping := map[string]SigAlg{
		"http://www.w3.org/2000/09/xmldsig#rsa-sha1":          SigAlgRS1,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   SigAlgRS256,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   SigAlgRS384,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   SigAlgRS512,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": SigAlgES256,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": SigAlgES384,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": SigAlgES512,
	}
	if alg, ok := mapping[s]; ok {
		return alg, nil
	}
	return SigAlgUnknown, fmt.Errorf("unknown alg: %s", s)
}

func (sa SigAlg) ToSAML() (string, error) {
	mapping := map[SigAlg]string{
		SigAlgRS1:   "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		SigAlgRS256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		SigAlgRS384: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
		SigAlgRS512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
		SigAlgES256: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
		SigAlgES384: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
		SigAlgES512: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
	}
	if alg, ok := mapping[sa]; ok {
		return alg, nil
	}
	return "unknown", fmt.Errorf("unknown alg: %s", sa)
}

func (sa SigAlg) ToCryptoHash() (*crypto.Hash, error) {
	mapping := map[SigAlg]crypto.Hash{
		SigAlgRS1:   crypto.SHA1,
		SigAlgRS256: crypto.SHA256,
		SigAlgRS384: crypto.SHA384,
		SigAlgRS512: crypto.SHA512,
		SigAlgES256: crypto.SHA256,
		SigAlgES384: crypto.SHA384,
		SigAlgES512: crypto.SHA512,
		SigAlgPS256: crypto.SHA256,
		SigAlgPS384: crypto.SHA384,
		SigAlgPS512: crypto.SHA512,
	}
	if alg, ok := mapping[sa]; ok {
		return &alg, nil
	}
	return nil, fmt.Errorf("unknown alg: %s", sa)
}

// ---------- crypto.Hash + key type <-> Alg ----------

type CryptoSpec struct {
	Hash  crypto.Hash
	Key   any
	IsPSS bool // true -> PS*, false -> RS* (for RSA); ignored for ECDSA
}

// ToCrypto returns the crypto.Hash, key kind, and whether RSA-PSS is required.
func (sa SigAlg) ToCrypto() (CryptoSpec, error) {
	switch sa {
	case SigAlgRS1:
		return CryptoSpec{Hash: crypto.SHA1, Key: (*rsa.PublicKey)(nil), IsPSS: false}, nil
	case SigAlgRS256:
		return CryptoSpec{Hash: crypto.SHA256, Key: (*rsa.PublicKey)(nil), IsPSS: false}, nil
	case SigAlgRS384:
		return CryptoSpec{Hash: crypto.SHA384, Key: (*rsa.PublicKey)(nil), IsPSS: false}, nil
	case SigAlgRS512:
		return CryptoSpec{Hash: crypto.SHA512, Key: (*rsa.PublicKey)(nil), IsPSS: false}, nil
	case SigAlgES256:
		return CryptoSpec{Hash: crypto.SHA256, Key: (*ecdsa.PublicKey)(nil), IsPSS: false}, nil
	case SigAlgES384:
		return CryptoSpec{Hash: crypto.SHA384, Key: (*ecdsa.PublicKey)(nil), IsPSS: false}, nil
	case SigAlgES512:
		return CryptoSpec{Hash: crypto.SHA512, Key: (*ecdsa.PublicKey)(nil), IsPSS: false}, nil
	case SigAlgPS256:
		return CryptoSpec{Hash: crypto.SHA256, Key: (*rsa.PublicKey)(nil), IsPSS: true}, nil
	case SigAlgPS384:
		return CryptoSpec{Hash: crypto.SHA384, Key: (*rsa.PublicKey)(nil), IsPSS: true}, nil
	case SigAlgPS512:
		return CryptoSpec{Hash: crypto.SHA512, Key: (*rsa.PublicKey)(nil), IsPSS: true}, nil
	default:
		return CryptoSpec{}, fmt.Errorf("no crypto mapping for %v", sa)
	}
}

// FromCrypto infers Alg from (hash + key type). For RSA it returns *RS* by default.
// Use FromCryptoPSS for RSA-PSS (PS*).
func FromCrypto(hash crypto.Hash, key any) (SigAlg, error) {
	switch key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			return SigAlgRS1, nil
		case crypto.SHA256:
			return SigAlgRS256, nil
		case crypto.SHA384:
			return SigAlgRS384, nil
		case crypto.SHA512:
			return SigAlgRS512, nil
		default:
			return SigAlgUnknown, fmt.Errorf("unsupported RSA hash %v", hash)
		}
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return SigAlgES256, nil
		case crypto.SHA384:
			return SigAlgES384, nil
		case crypto.SHA512:
			return SigAlgES512, nil
		default:
			return SigAlgUnknown, fmt.Errorf("unsupported ECDSA hash %v", hash)
		}
	default:
		return SigAlgUnknown, fmt.Errorf("unsupported key type %T", key)
	}
}

// FromCryptoPSS is identical to FromCrypto, but for RSA returns PS* (RSA-PSS).
func FromCryptoPSS(hash crypto.Hash, key any) (SigAlg, error) {
	switch key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return SigAlgPS256, nil
		case crypto.SHA384:
			return SigAlgPS384, nil
		case crypto.SHA512:
			return SigAlgPS512, nil
		case crypto.SHA1:
			// PSS with SHA-1 is theoretically possible but not recommended and
			// not defined as a JWT alg. Return an error to be safe.
			return SigAlgUnknown, fmt.Errorf("RSA-PSS with SHA-1 is not mapped to a standard alg")
		default:
			return SigAlgUnknown, fmt.Errorf("unsupported RSA-PSS hash %v", hash)
		}
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return SigAlgUnknown, fmt.Errorf("RSA-PSS requires RSA key, got ECDSA")
	default:
		return SigAlgUnknown, fmt.Errorf("unsupported key type %T", key)
	}
}
