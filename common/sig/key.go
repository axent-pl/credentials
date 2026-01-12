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
