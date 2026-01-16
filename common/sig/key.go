package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
)

// structure to hold a key used to validate the signature
type SignatureVerificationKey struct {
	Kid string
	Key crypto.PublicKey
	Alg SigAlg
}

type SignatureKeyer interface {
	GetKid() string
	GetKey() crypto.PrivateKey
	GetAlg() SigAlg
	GetJWK() (JSONWebKey, error)
}

type SignatureKey struct {
	Kid string
	Key crypto.PrivateKey
	Alg SigAlg
}

func (k *SignatureKey) GetKid() string            { return k.Kid }
func (k *SignatureKey) GetKey() crypto.PrivateKey { return k.Key }
func (k *SignatureKey) GetAlg() SigAlg            { return k.Alg }
func (k *SignatureKey) GetJWK() (JSONWebKey, error) {
	if k.Key == nil {
		return JSONWebKey{}, errors.New("nil key")
	}

	jwk := JSONWebKey{
		Use: "sig",
		Kid: k.Kid,
		Alg: k.Alg.String(),
	}

	switch pk := k.Key.(type) {
	case *rsa.PrivateKey:
		jwk.Kty = "RSA"
		jwk.N = &byteBuffer{data: pk.N.Bytes()}
		jwk.E = &byteBuffer{data: big.NewInt(int64(pk.E)).Bytes()}

	case *ecdsa.PrivateKey:
		jwk.Kty = "EC"
		crv, size := curveNameAndSize(pk.Curve)
		if crv == "" {
			return JSONWebKey{}, fmt.Errorf("unsupported elliptic curve: %T", pk.Curve)
		}
		jwk.Crv = crv

		jwk.X = &byteBuffer{data: make([]byte, size)}
		padX := make([]byte, size-len(pk.X.Bytes()))
		jwk.X.data = append(padX, pk.X.Bytes()...)

		jwk.Y = &byteBuffer{data: make([]byte, size)}
		padY := make([]byte, size-len(pk.Y.Bytes()))
		jwk.Y.data = append(padY, pk.Y.Bytes()...)

	default:
		return JSONWebKey{}, fmt.Errorf("unsupported key type: %T", pk)
	}

	return jwk, nil
}

// FindSignatureVerificationKey returns a matching key by kid, or the only key if kid is empty and len(keys)==1.
func FindSignatureVerificationKey(keys []SignatureVerificationKey, kid string) (*SignatureVerificationKey, bool) {
	if kid == "" {
		if len(keys) == 1 {
			return &keys[0], true
		}
		return nil, false
	}

	for i := range keys {
		if keys[i].Kid == kid {
			return &keys[i], true
		}
	}
	return nil, false
}

func curveNameAndSize(c elliptic.Curve) (name string, sizeBytes int) {
	switch c {
	case elliptic.P256():
		return "P-256", 32
	case elliptic.P384():
		return "P-384", 48
	case elliptic.P521():
		return "P-521", 66
	default:
		return "", 0
	}
}
