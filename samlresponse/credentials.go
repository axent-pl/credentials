package samlresponse

import (
	"encoding/base64"
	"encoding/xml"
	"errors"

	"github.com/axent-pl/credentials/common"
)

// SAMLResponseCredentials represents the HTTP response parameters typically passed
// in a SAML Response (usually sent via POST binding).
type SAMLResponseCredentials struct {
	// SAMLResponse: Required.
	// The base64-encoded XML Response message.
	SAMLResponse string

	// RelayState: Optional (but commonly used).
	// An opaque value sent by the Service Provider (SP) and returned unchanged
	// by the Identity Provider (IdP). Typically used for preserving state (e.g. return URL).
	RelayState string
}

func (SAMLResponseCredentials) Kind() common.Kind { return common.SAMLResponse }

// SAMLResponseXML represents the XML <Response> element
// defined in SAML 2.0 Core specification (protocol namespace).
type SAMLResponseXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`

	// ID: Required.
	// Unique identifier for the response, must be a unique string.
	ID string `xml:"ID,attr"`

	// Version: Required.
	// SAML protocol version (must be "2.0").
	Version string `xml:"Version,attr"`

	// IssueInstant: Required.
	// The time instant when the response was created, in UTC ISO8601 format.
	IssueInstant string `xml:"IssueInstant,attr"`

	// Destination: Optional.
	// URI of the SP endpoint where the response is being sent.
	Destination string `xml:"Destination,attr,omitempty"`

	// InResponseTo: Optional.
	// ID of the AuthnRequest that this response corresponds to.
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`

	// Issuer: Required.
	// Identifies the IdP issuing the response, usually an entityID (URI).
	Issuer *SAMLResponseIssuerXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`

	// Signature: Optional.
	// XML DSig Signature for the response.
	Signature *SAMLResponseSignatureXML `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`

	// Status: Required.
	// Indicates success or failure of the SSO attempt.
	Status *SAMLResponseStatusXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status,omitempty"`

	// Assertion: Optional.
	// Assertion containing authentication statements and attributes.
	Assertion *SAMLResponseAssertionXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion,omitempty"`
}

// SAMLResponseIssuerXML represents the <Issuer> element inside a Response.
type SAMLResponseIssuerXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`

	// Value: Required.
	// The actual entityID string (usually a URI) identifying the Identity Provider.
	Value string `xml:",chardata"`
}

// SAMLResponseStatusXML represents the <Status> element inside a Response.
type SAMLResponseStatusXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

	// StatusCode: Required.
	// Indicates the top-level status code (e.g., Success).
	StatusCode *SAMLResponseStatusCodeXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode,omitempty"`

	// StatusMessage: Optional.
	// Human-readable description of the status.
	StatusMessage string `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusMessage,omitempty"`
}

// SAMLResponseStatusCodeXML represents the <StatusCode> element inside <Status>.
type SAMLResponseStatusCodeXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`

	// Value: Required.
	// Status code URI (e.g., "urn:oasis:names:tc:SAML:2.0:status:Success").
	Value string `xml:"Value,attr"`
}

// SAMLResponseAssertionXML represents the <Assertion> element inside a Response.
type SAMLResponseAssertionXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

	// ID: Required.
	// Unique identifier for the assertion.
	ID string `xml:"ID,attr"`

	// Version: Required.
	// SAML protocol version (must be "2.0").
	Version string `xml:"Version,attr"`

	// IssueInstant: Required.
	// The time instant when the assertion was created, in UTC ISO8601 format.
	IssueInstant string `xml:"IssueInstant,attr"`

	// Subject: Optional.
	// Subject information about the principal.
	Subject *SAMLResponseSubjectXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject,omitempty"`

	// Signature: Optional.
	// XML DSig Signature for the assertion.
	Signature *SAMLResponseSignatureXML `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`

	// Conditions: Optional.
	// Constraints on the validity of the assertion (audience, time).
	Conditions *SAMLResponseConditionsXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions,omitempty"`

	// AuthnStatement: Optional.
	// Authentication statement describing how and when the user was authenticated.
	AuthnStatement *SAMLResponseAuthnStatementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement,omitempty"`

	// AttributeStatement: Optional.
	// Attributes about the subject.
	AttributeStatement *SAMLResponseAttributeStatementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement,omitempty"`
}

// SAMLResponseSubjectXML represents the <Subject> element inside an Assertion.
type SAMLResponseSubjectXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`

	// NameID: Optional.
	// Identifier for the subject.
	NameID *SAMLResponseNameIDXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID,omitempty"`
}

// SAMLResponseNameIDXML represents the <NameID> element.
type SAMLResponseNameIDXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`

	// Format: Optional.
	// NameID format URI.
	Format string `xml:"Format,attr,omitempty"`

	// Value: Required.
	// Subject identifier value.
	Value string `xml:",chardata"`
}

// SAMLResponseSignatureXML represents the XML DSig <Signature> element.
type SAMLResponseSignatureXML struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`

	// SignedInfo: Required.
	SignedInfo *SAMLResponseSignedInfoXML `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo,omitempty"`

	// SignatureValue: Required.
	SignatureValue string `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue,omitempty"`
}

// SAMLResponseSignedInfoXML represents the <SignedInfo> element.
type SAMLResponseSignedInfoXML struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`

	// CanonicalizationMethod: Required.
	CanonicalizationMethod *SAMLResponseCanonicalizationMethodXML `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod,omitempty"`

	// SignatureMethod: Required.
	SignatureMethod *SAMLResponseSignatureMethodXML `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod,omitempty"`

	// Reference: Optional.
	Reference *SAMLResponseReferenceXML `xml:"http://www.w3.org/2000/09/xmldsig# Reference,omitempty"`
}

// SAMLResponseCanonicalizationMethodXML represents the <CanonicalizationMethod> element.
type SAMLResponseCanonicalizationMethodXML struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`

	// Algorithm: Required.
	Algorithm string `xml:"Algorithm,attr"`
}

// SAMLResponseSignatureMethodXML represents the <SignatureMethod> element.
type SAMLResponseSignatureMethodXML struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`

	// Algorithm: Required.
	Algorithm string `xml:"Algorithm,attr"`
}

// SAMLResponseReferenceXML represents the <Reference> element.
type SAMLResponseReferenceXML struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`

	// URI: Optional.
	URI string `xml:"URI,attr,omitempty"`

	// Transforms: Optional.
	Transforms *SAMLResponseTransformsXML `xml:"http://www.w3.org/2000/09/xmldsig# Transforms,omitempty"`

	// DigestMethod: Required.
	DigestMethod *SAMLResponseDigestMethodXML `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod,omitempty"`

	// DigestValue: Required.
	DigestValue string `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue,omitempty"`
}

// SAMLResponseTransformsXML represents the <Transforms> element.
type SAMLResponseTransformsXML struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`

	// Transform: Optional.
	Transform []SAMLResponseTransformXML `xml:"http://www.w3.org/2000/09/xmldsig# Transform,omitempty"`
}

// SAMLResponseTransformXML represents the <Transform> element.
type SAMLResponseTransformXML struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`

	// Algorithm: Required.
	Algorithm string `xml:"Algorithm,attr"`
}

// SAMLResponseDigestMethodXML represents the <DigestMethod> element.
type SAMLResponseDigestMethodXML struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`

	// Algorithm: Required.
	Algorithm string `xml:"Algorithm,attr"`
}

// SAMLResponseConditionsXML represents the <Conditions> element inside an Assertion.
type SAMLResponseConditionsXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`

	// NotBefore: Optional.
	// Earliest time instant at which the assertion is valid.
	NotBefore string `xml:"NotBefore,attr,omitempty"`

	// NotOnOrAfter: Optional.
	// Time instant at which the assertion expires.
	NotOnOrAfter string `xml:"NotOnOrAfter,attr,omitempty"`
}

// SAMLResponseAuthnStatementXML represents the <AuthnStatement> element.
type SAMLResponseAuthnStatementXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`

	// AuthnInstant: Required.
	// Time instant when the user was authenticated.
	AuthnInstant string `xml:"AuthnInstant,attr"`

	// SessionIndex: Optional.
	// Session index assigned by the IdP.
	SessionIndex string `xml:"SessionIndex,attr,omitempty"`

	// AuthnContext: Optional.
	// Describes the context class or declaration.
	AuthnContext *SAMLResponseAuthnContextXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext,omitempty"`
}

// SAMLResponseAuthnContextXML represents the <AuthnContext> element.
type SAMLResponseAuthnContextXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`

	// AuthnContextClassRef: Optional.
	// URI identifying the authentication context.
	AuthnContextClassRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef,omitempty"`
}

// SAMLResponseAttributeStatementXML represents the <AttributeStatement> element.
type SAMLResponseAttributeStatementXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`

	// Attributes: Optional.
	// Subject attributes such as email, roles, etc.
	Attributes []SAMLResponseAttributeXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute,omitempty"`
}

// SAMLResponseAttributeXML represents the <Attribute> element.
type SAMLResponseAttributeXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`

	// Name: Required.
	// Attribute name (e.g., "email").
	Name string `xml:"Name,attr"`

	// Values: Optional.
	// One or more values for the attribute.
	Values []SAMLResponseAttributeValueXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue,omitempty"`
}

// SAMLResponseAttributeValueXML represents the <AttributeValue> element.
type SAMLResponseAttributeValueXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`

	// Value: Required.
	// Attribute value.
	Value string `xml:",chardata"`
}

// ----

func (r *SAMLResponseCredentials) MarshalSAMLResponse(x SAMLResponseXML) error {
	xmlBytes, err := xml.Marshal(x) // compact; keep it deterministic
	if err != nil {
		return err
	}
	r.SAMLResponse = base64.StdEncoding.EncodeToString(xmlBytes)
	return nil
}

func (r *SAMLResponseCredentials) UnmarshalSAMLResponse() (*SAMLResponseXML, error) {
	decoded, err := base64.StdEncoding.DecodeString(r.SAMLResponse)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(r.SAMLResponse)
		if err != nil {
			if r.looksLikeXML([]byte(r.SAMLResponse)) {
				decoded = []byte(r.SAMLResponse)
			} else {
				return nil, errors.New("invalid base64 in SAMLResponse")
			}
		}
	}

	var resp SAMLResponseXML
	if err := xml.Unmarshal(decoded, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (r *SAMLResponseCredentials) looksLikeXML(b []byte) bool {
	// Trim a tiny bit of whitespace and check for '<'
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	return i < len(b) && b[i] == '<'
}
