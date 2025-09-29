package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"

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

// ---------- OAuth2 / JWT <-> SigAlg ----------

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

// ---------- SAML XMLDSIG URI <-> Alg ----------

const (
	// RSA PKCS#1 v1.5
	samlRSA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	samlRSA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	samlRSA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	samlRSA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

	// ECDSA
	samlECDSA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	samlECDSA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	samlECDSA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

	// NOTE: XMLDSIG-More also defines RSA-PSS URIs, e.g.
	//   "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
	// If you need them, add mappings similarly to PS*.
)

func FromSAML(uri string) (SigAlg, error) {
	switch strings.TrimSpace(uri) {
	case samlRSA1:
		return SigAlgRS1, nil
	case samlRSA256:
		return SigAlgRS256, nil
	case samlRSA384:
		return SigAlgRS384, nil
	case samlRSA512:
		return SigAlgRS512, nil
	case samlECDSA256:
		return SigAlgES256, nil
	case samlECDSA384:
		return SigAlgES384, nil
	case samlECDSA512:
		return SigAlgES512, nil
	default:
		return SigAlgUnknown, fmt.Errorf("unknown or unsupported SAML XMLDSIG URI %q", uri)
	}
}

func (sa SigAlg) ToSAML() (string, error) {
	switch sa {
	case SigAlgRS1:
		return samlRSA1, nil
	case SigAlgRS256:
		return samlRSA256, nil
	case SigAlgRS384:
		return samlRSA384, nil
	case SigAlgRS512:
		return samlRSA512, nil
	case SigAlgES256:
		return samlECDSA256, nil
	case SigAlgES384:
		return samlECDSA384, nil
	case SigAlgES512:
		return samlECDSA512, nil
	default:
		return "", fmt.Errorf("no SAML XMLDSIG mapping for %v", sa)
	}
}

// ---------- crypto.Hash + key type <-> Alg ----------

type KeyKind int

const (
	KeyUnknown KeyKind = iota
	KeyRSA
	KeyECDSA
)

type CryptoSpec struct {
	Hash  crypto.Hash
	Key   KeyKind
	IsPSS bool // true -> PS*, false -> RS* (for RSA); ignored for ECDSA
}

// ToCrypto returns the crypto.Hash, key kind, and whether RSA-PSS is required.
func (sa SigAlg) ToCrypto() (CryptoSpec, error) {
	switch sa {
	case SigAlgRS1:
		return CryptoSpec{Hash: crypto.SHA1, Key: KeyRSA, IsPSS: false}, nil
	case SigAlgRS256:
		return CryptoSpec{Hash: crypto.SHA256, Key: KeyRSA, IsPSS: false}, nil
	case SigAlgRS384:
		return CryptoSpec{Hash: crypto.SHA384, Key: KeyRSA, IsPSS: false}, nil
	case SigAlgRS512:
		return CryptoSpec{Hash: crypto.SHA512, Key: KeyRSA, IsPSS: false}, nil
	case SigAlgES256:
		return CryptoSpec{Hash: crypto.SHA256, Key: KeyECDSA, IsPSS: false}, nil
	case SigAlgES384:
		return CryptoSpec{Hash: crypto.SHA384, Key: KeyECDSA, IsPSS: false}, nil
	case SigAlgES512:
		return CryptoSpec{Hash: crypto.SHA512, Key: KeyECDSA, IsPSS: false}, nil
	case SigAlgPS256:
		return CryptoSpec{Hash: crypto.SHA256, Key: KeyRSA, IsPSS: true}, nil
	case SigAlgPS384:
		return CryptoSpec{Hash: crypto.SHA384, Key: KeyRSA, IsPSS: true}, nil
	case SigAlgPS512:
		return CryptoSpec{Hash: crypto.SHA512, Key: KeyRSA, IsPSS: true}, nil
	default:
		return CryptoSpec{}, fmt.Errorf("no crypto mapping for %v", sa)
	}
}

// FromCrypto infers Alg from (hash + key type). For RSA it returns *RS* by default.
// Use FromCryptoPSS for RSA-PSS (PS*).
func FromCrypto(hash crypto.Hash, key interface{}) (SigAlg, error) {
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
func FromCryptoPSS(hash crypto.Hash, key interface{}) (SigAlg, error) {
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
