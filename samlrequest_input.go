package auth

import "encoding/xml"

// SAML request is used to authenticate the issuer (client) which requests user credentials (a SAMLResponse with Assertion)

type SAMLRequestInput struct {
	SAMLRequest string
	RelayState  string
	SigAlg      string
	Signature   string
}

func (SAMLRequestInput) Kind() Kind { return CredSAMLRequest }

type SAMLRequestXML struct {
	XMLName                     xml.Name                    `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string                      `xml:"ID,attr"`
	Version                     string                      `xml:"Version,attr"`
	IssueInstant                string                      `xml:"IssueInstant,attr"`
	Destination                 string                      `xml:"Destination,attr,omitempty"`
	AssertionConsumerServiceURL string                      `xml:"AssertionConsumerServiceURL,attr,omitempty"`
	ProtocolBinding             string                      `xml:"ProtocolBinding,attr,omitempty"`
	ForceAuthn                  *bool                       `xml:"ForceAuthn,attr,omitempty"`
	IsPassive                   *bool                       `xml:"IsPassive,attr,omitempty"`
	Issuer                      *SAMLRequestIssuerXML       `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	NameIDPolicy                *SAMLRequestNameIDPolicyXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy,omitempty"`
}

type SAMLRequestIssuerXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

type SAMLRequestNameIDPolicyXML struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format      string   `xml:"Format,attr,omitempty"`
	AllowCreate *bool    `xml:"AllowCreate,attr,omitempty"`
}
