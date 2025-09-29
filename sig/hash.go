package sig

import (
	"crypto"
	"errors"
)

func Hash(data []byte, hashAlg crypto.Hash) (digest []byte, _ error) {
	if !hashAlg.Available() {
		return nil, errors.New("unsupported hash")
	}
	h := hashAlg.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
