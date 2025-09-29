package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// Verify checks if signature is valid for the given digest, public key, and SigAlg.
// - digest must already be hashed with the algorithm implied by sigAlg.
// - For ECDSA, signature may be in JOSE raw R||S or ASN.1 DER form.
func Verify(signature, digest []byte, pubKey crypto.PublicKey, sigAlg SigAlg) error {
	spec, err := sigAlg.ToCrypto()
	if err != nil {
		return err
	}
	if !spec.Hash.Available() {
		return fmt.Errorf("hash %v not available", spec.Hash)
	}
	if got, want := len(digest), spec.Hash.Size(); got != want {
		return fmt.Errorf("digest length %d does not match hash %v size %d", got, spec.Hash, want)
	}

	switch k := pubKey.(type) {
	case rsa.PublicKey:
		if spec.Key != KeyRSA {
			return fmt.Errorf("algorithm %v expects non-RSA key", sigAlg)
		}
		if spec.IsPSS {
			// JOSE requires salt length = hash size.
			opts := &rsa.PSSOptions{SaltLength: spec.Hash.Size(), Hash: spec.Hash}
			if err := rsa.VerifyPSS(&k, spec.Hash, digest, signature, opts); err != nil {
				return fmt.Errorf("rsa-pss verify failed: %w", err)
			}
			return nil
		}
		// PKCS#1 v1.5
		if err := rsa.VerifyPKCS1v15(&k, spec.Hash, digest, signature); err != nil {
			return fmt.Errorf("rsa-pkcs1v15 verify failed: %w", err)
		}
		return nil

	case ecdsa.PublicKey:
		if spec.Key != KeyECDSA {
			return fmt.Errorf("algorithm %v expects non-ECDSA key", sigAlg)
		}
		R, S, err := parseECDSASignature(signature, k.Params().BitSize)
		if err != nil {
			return err
		}
		ok := ecdsa.Verify(&k, digest, R, S)
		if !ok {
			return errors.New("ecdsa verify failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type %T", pubKey)
	}
}

// parseECDSASignature accepts either ASN.1 DER-encoded ECDSA signature or JOSE raw R||S.
// For raw form, curveBits should be the curve bit size (e.g., 256, 384, 521).
func parseECDSASignature(sig []byte, curveBits int) (*big.Int, *big.Int, error) {
	type ecdsaSig struct {
		R, S *big.Int
	}
	// Heuristic: DER signatures start with 0x30 (SEQUENCE)
	if len(sig) > 0 && sig[0] == 0x30 {
		var esig ecdsaSig
		if _, err := asn1.Unmarshal(sig, &esig); err != nil {
			return nil, nil, fmt.Errorf("ecdsa der parse: %w", err)
		}
		if esig.R == nil || esig.S == nil {
			return nil, nil, errors.New("ecdsa der parse: nil R/S")
		}
		return esig.R, esig.S, nil
	}

	// Raw JOSE form: fixed-width big-endian R || S (each padded to curve byte length)
	curveBytes := (curveBits + 7) / 8
	if len(sig) != 2*curveBytes {
		return nil, nil, fmt.Errorf("ecdsa raw length %d does not match expected %d", len(sig), 2*curveBytes)
	}
	r := new(big.Int).SetBytes(sig[:curveBytes])
	s := new(big.Int).SetBytes(sig[curveBytes:])
	return r, s, nil
}
