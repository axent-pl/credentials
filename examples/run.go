package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/axent-pl/credentials/common/sig"
)

func main() {
	rsaKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKeyP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// ecdsaKeyP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	// ecdsaKeyP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	rsaKey := sig.SignatureKey{
		Kid: "zxc",
		Key: rsaKey2048,
		Alg: sig.SigAlgRS256,
	}
	IssueJWT(&rsaKey)
	IssueJWKS(&rsaKey)

	ecdsaKey := sig.SignatureKey{
		Kid: "zxcs",
		Key: ecdsaKeyP256,
		Alg: sig.SigAlgES256,
	}
	IssueJWT(&ecdsaKey)
	IssueJWKS(&ecdsaKey)
}
