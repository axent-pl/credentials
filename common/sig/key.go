package sig

import "crypto"

// structure to hold a key used to validate the signature
type SignatureVerificationKey struct {
	Kid string
	Key crypto.PublicKey
	Alg SigAlg
}

// structure to hold a key used to sign data
type SignatureKey struct {
	Kid string
	Key crypto.PrivateKey
	Alg SigAlg
}
