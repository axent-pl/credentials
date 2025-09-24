package auth

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"

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
		if len(scheme.Keys) == 0 { // temporary -> will have to implement all the logic
			continue
		}
		if samlRequestXML.Issuer.Value == "" {
			continue
		}
	}

	return Principal{}, nil
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
