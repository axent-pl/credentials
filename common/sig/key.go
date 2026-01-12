package sig

import "crypto"

type SignatureKey struct {
	Kid string
	Key crypto.PublicKey
	Alg SigAlg
}
