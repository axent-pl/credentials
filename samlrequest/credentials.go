package samlrequest

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
)

// SAMLRequestCredentials represents the HTTP request parameters typically passed
// in a SAML AuthnRequest (usually sent via Redirect or POST binding).
type SAMLRequestCredentials struct {
	// SAMLRequest: Required.
	// The actual base64-encoded (and often deflated) XML AuthnRequest message.
	SAMLRequest string

	// RelayState: Optional (but commonly used).
	// An opaque value sent by the Service Provider (SP) and returned unchanged
	// by the Identity Provider (IdP). Typically used for preserving state (e.g. return URL).
	RelayState string

	// SigAlg: Optional.
	// The signature algorithm URI (e.g., RSA-SHA256) used when the SAMLRequest
	// is signed in HTTP-Redirect binding. Required if "Signature" is present.
	SigAlg string

	// Signature: Optional.
	// The base64-encoded signature computed over the query parameters.
	// Used only with signed Redirect binding requests.
	Signature string
}

func (SAMLRequestCredentials) Kind() common.Kind { return common.SAMLRequest }

// SAMLRequestXML represents the XML <AuthnRequest> element
// defined in SAML 2.0 Core specification (protocol namespace).
type SAMLRequestXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`

	// ID: Required.
	// Unique identifier for the request, must be a unique string.
	ID string `xml:"ID,attr"`

	// Version: Required.
	// SAML protocol version (must be "2.0").
	Version string `xml:"Version,attr"`

	// IssueInstant: Required.
	// The time instant when the request was created, in UTC ISO8601 format.
	IssueInstant string `xml:"IssueInstant,attr"`

	// Destination: Optional.
	// URI of the IdP endpoint where the AuthnRequest is being sent.
	Destination string `xml:"Destination,attr,omitempty"`

	// AssertionConsumerServiceURL: Optional (but usually required by SPs).
	// The URL at the SP to which the IdP should send the SAML Response.
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr,omitempty"`

	// ProtocolBinding: Optional.
	// URI specifying the binding (e.g., HTTP-POST, HTTP-Artifact) expected for the response.
	ProtocolBinding string `xml:"ProtocolBinding,attr,omitempty"`

	// ForceAuthn: Optional.
	// If true, IdP must re-authenticate the user (ignore existing SSO session).
	ForceAuthn *bool `xml:"ForceAuthn,attr,omitempty"`

	// IsPassive: Optional.
	// If true, IdP must not interact with the user (silent authentication only).
	IsPassive *bool `xml:"IsPassive,attr,omitempty"`

	// Issuer: Required.
	// Identifies the SP making the request, usually an entityID (URI).
	Issuer *SAMLRequestIssuerXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`

	// NameIDPolicy: Optional.
	// Specifies constraints on the NameID (e.g., email format) and whether a new
	// identifier can be created if none exists.
	NameIDPolicy *SAMLRequestNameIDPolicyXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy,omitempty"`
}

// SAMLRequestIssuerXML represents the <Issuer> element inside an AuthnRequest.
type SAMLRequestIssuerXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`

	// Value: Required.
	// The actual entityID string (usually a URI) identifying the Service Provider.
	Value string `xml:",chardata"`
}

// SAMLRequestNameIDPolicyXML represents the <NameIDPolicy> element,
// which tells the IdP how the subject identifier should be constructed.
type SAMLRequestNameIDPolicyXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`

	// Format: Optional.
	// Specifies the desired NameID format (e.g., emailAddress, persistent, transient).
	Format string `xml:"Format,attr,omitempty"`

	// AllowCreate: Optional.
	// If true, IdP is allowed to create a new identifier for the subject
	// if no suitable existing identifier is found.
	AllowCreate *bool `xml:"AllowCreate,attr,omitempty"`
}

// ----

// SignedQuery creates the exact byte sequence signed for Redirect binding:
// "SAMLRequest=<val>[&RelayState=<val>]&SigAlg=<val>"
// Each value must be percent-encoded per RFC 3986 (same as url.QueryEscape).
func (r *SAMLRequestCredentials) SignedQuery() []byte {
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

func (r *SAMLRequestCredentials) MarshalSAMLRequest(x SAMLRequestXML) error {
	xmlBytes, err := xml.Marshal(x) // compact; keep it deterministic
	if err != nil {
		return err
	}
	var deflated bytes.Buffer
	// HTTP-Redirect uses raw DEFLATE (RFC1951) (no zlib header/footer),
	// which compress/flate writes by default.
	w, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	if err != nil {
		return err
	}
	if _, err := w.Write(xmlBytes); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	r.SAMLRequest = base64.StdEncoding.EncodeToString(deflated.Bytes())
	return nil
}

func (r *SAMLRequestCredentials) UnmarshalSAMLRequest() (*SAMLRequestXML, error) {
	// 1) Base64 decode
	compressed, err := base64.StdEncoding.DecodeString(r.SAMLRequest)
	if err != nil {
		// Try URL-safe alphabet just in case
		compressed, err = base64.URLEncoding.DecodeString(r.SAMLRequest)
		if err != nil {
			return nil, errors.New("invalid base64 in SAMLRequest")
		}
	}

	// 2) Inflate (Redirect binding uses raw DEFLATE; some stacks use zlib wrapper)
	xmlBytes, inflateErr := r.inflateRawDeflate(compressed)
	if inflateErr != nil {
		// fallback to zlib (RFC1950)
		if xmlBytes, err = r.inflateZlib(compressed); err != nil {
			// If both fail, it might be POST binding (no compression) — accept as-is if it looks like XML
			if r.looksLikeXML(compressed) {
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

func (v *SAMLRequestCredentials) inflateRawDeflate(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer func() {
		if err := r.Close(); err != nil {
			logx.L().Error("could not close io.RaadCloser")
		}
	}()
	return io.ReadAll(r)
}

func (v *SAMLRequestCredentials) inflateZlib(b []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := r.Close(); err != nil {
			logx.L().Error("could not close io.RaadCloser")
		}
	}()
	return io.ReadAll(r)
}

func (r *SAMLRequestCredentials) looksLikeXML(b []byte) bool {
	// Trim a tiny bit of whitespace and check for '<'
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	return i < len(b) && b[i] == '<'
}
