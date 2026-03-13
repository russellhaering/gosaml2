// Copyright 2016 Russell Haering et al.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"encoding/xml"
	"time"
)

// EntityDescriptor represents a SAML 2.0 metadata EntityDescriptor element.
type EntityDescriptor struct {
	XMLName    xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	ValidUntil time.Time `xml:"validUntil,attr"`
	// SAML 2.0 8.3.6 Entity Identifier could be used to represent issuer
	EntityID         string            `xml:"entityID,attr"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor,omitempty"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor,omitempty"`
    Extensions       *Extensions       `xml:"Extensions,omitempty"`
}

// Endpoint represents a SAML metadata endpoint (e.g. SingleLogoutService).
type Endpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}

// IndexedEndpoint represents an indexed SAML metadata endpoint (e.g. AssertionConsumerService).
type IndexedEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
}

// SPSSODescriptor represents a SAML metadata SPSSODescriptor element.
type SPSSODescriptor struct {
	XMLName                    xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	AuthnRequestsSigned        bool              `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool              `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string            `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []KeyDescriptor   `xml:"KeyDescriptor"`
	SingleLogoutServices       []Endpoint        `xml:"SingleLogoutService"`
	NameIDFormats              []string          `xml:"NameIDFormat"`
	AssertionConsumerServices  []IndexedEndpoint `xml:"AssertionConsumerService"`
    Extensions                 *Extensions       `xml:"Extensions,omitempty"`
}

// IDPSSODescriptor represents a SAML metadata IDPSSODescriptor element.
type IDPSSODescriptor struct {
	XMLName                    xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	ProtocolSupportEnumeration string                `xml:"protocolSupportEnumeration,attr"`
	WantAuthnRequestsSigned    bool                  `xml:"WantAuthnRequestsSigned,attr"`
	KeyDescriptors             []KeyDescriptor       `xml:"KeyDescriptor"`
	NameIDFormats           []NameIDFormat        `xml:"NameIDFormat"`
	SingleSignOnServices    []SingleSignOnService `xml:"SingleSignOnService"`
    SingleLogoutServices    []SingleLogoutService `xml:"SingleLogoutService"`
	Attributes              []Attribute           `xml:"Attribute"`
    Extensions              *Extensions           `xml:"Extensions,omitempty"`
}

// KeyDescriptor represents a SAML metadata KeyDescriptor element.
type KeyDescriptor struct {
	XMLName           xml.Name           `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	Use               string             `xml:"use,attr"`
	KeyInfo           KeyInfo            `xml:"KeyInfo"`
	EncryptionMethods []EncryptionMethod `xml:"EncryptionMethod"`
}

// KeyInfo represents a ds:KeyInfo element.
type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data X509Data `xml:"X509Data"`
}

// X509Data represents a ds:X509Data element.
type X509Data struct {
	XMLName          xml.Name          `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificates []X509Certificate `xml:"X509Certificate"`
}

// X509Certificate represents a ds:X509Certificate element.
type X509Certificate struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
	Data    string   `xml:",chardata"`
}

// NameIDFormat represents a SAML metadata NameIDFormat element.
type NameIDFormat struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	Value   string   `xml:",chardata"`
}

// SingleSignOnService represents a SAML metadata SingleSignOnService element.
type SingleSignOnService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// SingleLogoutService represents a SAML metadata SingleLogoutService element.
type SingleLogoutService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// SigningMethod represents a metadata Extensions SigningMethod element.
type SigningMethod struct {
    Algorithm           string       `xml:",attr"`
    MinKeySize          string       `xml:"MinKeySize,attr,omitempty"`
    MaxKeySize          string       `xml:"MaxKeySize,attr,omitempty"`
}

// Extensions represents a SAML metadata Extensions element.
type Extensions struct {
    DigestMethod        *DigestMethod   `xml:",omitempty"`
    SigningMethod       *SigningMethod  `xml:",omitempty"`
}
