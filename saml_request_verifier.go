package auth

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"math/big"
	"net/url"
	"strings"

	"github.com/axent-pl/auth/logx"
)

type SAMLRequestVerifier struct{}

func (v *SAMLRequestVerifier) Kind() Kind { return CredSAMLRequest }

func (v *SAMLRequestVerifier) Verify(ctx context.Context, in Credentials, schemes []Scheme) (Principal, error) {
	samlRequestInput, ok := in.(SAMLRequestInput)
	if !ok {
		logx.L().Debug("could not cast Input to SAMLRequestInput", "context", ctx)
		return Principal{}, ErrInvalidInput
	}
	if samlRequestInput.SAMLRequest == "" {
		logx.L().Debug("empty request", "context", ctx)
		return Principal{}, ErrInvalidInput
	}
	samlRequestXML, err := v.ParseSAMLRequest(samlRequestInput.SAMLRequest)
	if err != nil {
		logx.L().Debug("could not parse SAML request", "context", ctx, "error", err)
		return Principal{}, ErrInvalidInput
	}

	for _, s := range schemes {
		scheme, ok := s.(SAMLRequestScheme)
		if !ok {
			continue
		}
		if err := v.VerifySignature(samlRequestInput, scheme); err != nil {
			continue
		}
		if samlRequestXML.Issuer.Value == "" {
			continue
		}
	}

	return Principal{}, nil
}

func (v *SAMLRequestVerifier) VerifySignature(r SAMLRequestInput, s SAMLRequestScheme) error {
	// no keys in scheme => no signature verification
	if len(s.Keys) == 0 {
		return nil
	}
	// keys in scheme => require signature algorithm
	if r.SigAlg == "" {
		return errors.New("missing signature algorithm")
	}
	// keys in scheme => require signature
	if r.Signature == "" {
		return errors.New("missing signature")
	}
	// parse signature algorithm (keyType, hashAlg)
	keyType, hashAlg, err := parseSigAlg(r.SigAlg)
	if err != nil {
		return err
	}
	// parse signature (signature, digest)
	signature, digest, err := parseSignature(r, hashAlg)
	if err != nil {
		return err
	}

	for _, k := range s.Keys {
		// only consider keys that declare the same SigAlg
		if k.SigAlg == "" || k.SigAlg != r.SigAlg {
			continue
		}

		switch keyType {
		case "rsa":
			pub, ok := k.Key.(*rsa.PublicKey)
			if !ok {
				// sometimes keys might be x509.PublicKey from certs; try to extract
				switch pk := k.Key.(type) {
				case *x509.Certificate:
					if rsaPub, ok := pk.PublicKey.(*rsa.PublicKey); ok {
						pub = rsaPub
					} else {
						continue
					}
				default:
					continue
				}
			}
			if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, signature); err == nil {
				return nil
			}

		case "ecdsa":
			pub, ok := k.Key.(*ecdsa.PublicKey)
			if !ok {
				switch pk := k.Key.(type) {
				case *x509.Certificate:
					if ecPub, ok := pk.PublicKey.(*ecdsa.PublicKey); ok {
						pub = ecPub
					} else {
						continue
					}
				default:
					continue
				}
			}
			// ECDSA signatures are DER-encoded (r,s)
			var esig struct {
				R, S *big.Int
			}
			if _, err := asn1.Unmarshal(signature, &esig); err != nil || esig.R == nil || esig.S == nil {
				continue
			}
			if ecdsa.Verify(pub, digest, esig.R, esig.S) {
				return nil
			}
		}
	}

	return errors.New("invalid signature")
}

func (v *SAMLRequestVerifier) ParseSAMLRequest(enc string) (*SAMLRequestXML, error) {
	// 1) Base64 decode
	compressed, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		// Try URL-safe alphabet just in case
		compressed, err = base64.URLEncoding.DecodeString(enc)
		if err != nil {
			return nil, errors.New("invalid base64 in SAMLRequest")
		}
	}

	// 2) Inflate (Redirect binding uses raw DEFLATE; some stacks use zlib wrapper)
	xmlBytes, inflateErr := v.inflateRawDeflate(compressed)
	if inflateErr != nil {
		// fallback to zlib (RFC1950)
		if xmlBytes, err = v.inflateZlib(compressed); err != nil {
			// If both fail, it might be POST binding (no compression) — accept as-is if it looks like XML
			if v.looksLikeXML(compressed) {
				xmlBytes = compressed
			} else {
				return nil, errors.New("unable to inflate SAMLRequest (tried DEFLATE and zlib)")
			}
		}
	}

	// 3) Unmarshal XML
	var req SAMLRequestXML
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func (v *SAMLRequestVerifier) inflateRawDeflate(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	return io.ReadAll(r)
}

func (v *SAMLRequestVerifier) inflateZlib(b []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func (v *SAMLRequestVerifier) looksLikeXML(b []byte) bool {
	// Trim a tiny bit of whitespace and check for '<'
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	return i < len(b) && b[i] == '<'
}

// parse Signature
func parseSignature(r SAMLRequestInput, hashAlg crypto.Hash) (signature []byte, digest []byte, _ error) {
	signedData := buildSignedQuery(r)
	signature, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return nil, nil, errors.New("invalid signature encoding")
	}
	switch hashAlg {
	case crypto.SHA1:
		sum := sha1.Sum(signedData)
		digest = sum[:]
	case crypto.SHA224:
		h := sha256.New224()
		h.Write(signedData)
		digest = h.Sum(nil)
	case crypto.SHA256:
		sum := sha256.Sum256(signedData)
		digest = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(signedData)
		digest = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(signedData)
		digest = sum[:]
	default:
		return nil, nil, errors.New("unsupported hash")
	}
	return signature, digest, nil
}

// map SigAlg URI -> (scheme, hash)
func parseSigAlg(uri string) (keyType string, hashAlg crypto.Hash, _ error) {
	switch uri {
	// RSA PKCS#1 v1.5
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		return "rsa", crypto.SHA1, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		return "rsa", crypto.SHA256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
		return "rsa", crypto.SHA384, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
		return "rsa", crypto.SHA512, nil

	// ECDSA
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":
		return "ecdsa", crypto.SHA256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":
		return "ecdsa", crypto.SHA384, nil
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":
		return "ecdsa", crypto.SHA512, nil
	default:
		return "", 0, errors.New("unsupported SigAlg")
	}
}

// buildSignedQuery recreates the exact byte sequence signed for Redirect binding:
// "SAMLRequest=<val>[&RelayState=<val>]&SigAlg=<val>"
// Each value must be percent-encoded per RFC 3986 (same as url.QueryEscape).
func buildSignedQuery(r SAMLRequestInput) []byte {
	var b strings.Builder
	b.WriteString("SAMLRequest=")
	b.WriteString(url.QueryEscape(r.SAMLRequest))
	if r.RelayState != "" {
		b.WriteString("&RelayState=")
		b.WriteString(url.QueryEscape(r.RelayState))
	}
	b.WriteString("&SigAlg=")
	b.WriteString(url.QueryEscape(r.SigAlg))
	return []byte(b.String())
}
