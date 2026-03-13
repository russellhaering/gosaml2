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

// UnverifiedBaseResponse extracts several basic attributes of a SAML Response
// which may be useful in deciding how to validate the Response. An UnverifiedBaseResponse
// is parsed by this library prior to any validation of the Response, so the
// values it contains may have been supplied by an attacker and should not be
// trusted as authoritative from the IdP.
type UnverifiedBaseResponse struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string   `xml:"ID,attr"`
	InResponseTo string   `xml:"InResponseTo,attr"`
	Destination  string   `xml:"Destination,attr"`
	Version      string   `xml:"Version,attr"`
	Issuer       *Issuer  `xml:"Issuer"`
	Audiences    []string `xml:"-"` // populated after parsing
}

// Response represents a SAML 2.0 Response protocol message.
type Response struct {
	XMLName             xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID                  string               `xml:"ID,attr"`
	InResponseTo        string               `xml:"InResponseTo,attr"`
	Destination         string               `xml:"Destination,attr"`
	Version             string               `xml:"Version,attr"`
	IssueInstant        time.Time            `xml:"IssueInstant,attr"`
	Status              *Status              `xml:"Status"`
	Issuer              *Issuer              `xml:"Issuer"`
	Assertions          []Assertion          `xml:"Assertion"`
	EncryptedAssertions []EncryptedAssertion `xml:"EncryptedAssertion"`
	SignatureValidated  bool                 `xml:"-"` // not read, not dumped
}

// LogoutResponse represents a SAML 2.0 LogoutResponse protocol message.
type LogoutResponse struct {
	XMLName            xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	ID                 string    `xml:"ID,attr"`
	InResponseTo       string    `xml:"InResponseTo,attr"`
	Destination        string    `xml:"Destination,attr"`
	Version            string    `xml:"Version,attr"`
	IssueInstant       time.Time `xml:"IssueInstant,attr"`
	Status             *Status   `xml:"Status"`
	Issuer             *Issuer   `xml:"Issuer"`
	SignatureValidated bool      `xml:"-"` // not read, not dumped
}

// Status represents a samlp:Status element.
type Status struct {
	XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode *StatusCode `xml:"StatusCode"`
}

// StatusCode represents a samlp:StatusCode element.
type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:"Value,attr"`
}

// Issuer represents a saml:Issuer element.
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

// Signature represents an XML-DSig Signature element within a SAML message.
type Signature struct {
	SignatureDocument []byte `xml:",innerxml"`
}

// Assertion represents a saml:Assertion element.
type Assertion struct {
	XMLName            xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	Version            string              `xml:"Version,attr"`
	ID                 string              `xml:"ID,attr"`
	IssueInstant       time.Time           `xml:"IssueInstant,attr"`
	Issuer             *Issuer             `xml:"Issuer"`
	Signature          *Signature          `xml:"Signature"`
	Subject            *Subject            `xml:"Subject"`
	Conditions         *Conditions         `xml:"Conditions"`
	AttributeStatements []AttributeStatement `xml:"AttributeStatement"`
	AuthnStatement     *AuthnStatement     `xml:"AuthnStatement"`
	SignatureValidated bool                `xml:"-"` // not read, not dumped
}

// Subject represents a saml:Subject element.
type Subject struct {
	XMLName             xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              *NameID              `xml:"NameID"`
	SubjectConfirmation *SubjectConfirmation `xml:"SubjectConfirmation"`
}

// AuthnContext represents a saml:AuthnContext element.
type AuthnContext struct {
	XMLName              xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
	AuthnContextClassRef *AuthnContextClassRef `xml:"AuthnContextClassRef"`
}

// AuthnContextClassRef represents a saml:AuthnContextClassRef element.
type AuthnContextClassRef struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
	Value   string   `xml:",chardata"`
}

// NameID represents a saml:NameID element identifying the subject.
type NameID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format  string   `xml:"Format,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// SubjectConfirmation represents a saml:SubjectConfirmation element.
type SubjectConfirmation struct {
	XMLName                 xml.Name                 `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
	Method                  string                   `xml:"Method,attr"`
	SubjectConfirmationData *SubjectConfirmationData `xml:"SubjectConfirmationData"`
}

// SubjectConfirmationData represents a saml:SubjectConfirmationData element.
type SubjectConfirmationData struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
	NotBefore    string   `xml:"NotBefore,attr"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
	Recipient    string   `xml:"Recipient,attr"`
	InResponseTo string   `xml:"InResponseTo,attr"`
}

// Conditions represents a saml:Conditions element containing validity constraints.
type Conditions struct {
	XMLName              xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	NotBefore            string                `xml:"NotBefore,attr"`
	NotOnOrAfter         string                `xml:"NotOnOrAfter,attr"`
	AudienceRestrictions []AudienceRestriction `xml:"AudienceRestriction"`
	OneTimeUse           *OneTimeUse           `xml:"OneTimeUse"`
	ProxyRestriction     *ProxyRestriction     `xml:"ProxyRestriction"`
}

// AudienceRestriction represents a saml:AudienceRestriction element.
type AudienceRestriction struct {
	XMLName   xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	Audiences []Audience `xml:"Audience"`
}

// Audience represents a saml:Audience element.
type Audience struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
	Value   string   `xml:",chardata"`
}

// OneTimeUse represents a saml:OneTimeUse condition element.
type OneTimeUse struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion OneTimeUse"`
}

// ProxyRestriction represents a saml:ProxyRestriction condition element.
type ProxyRestriction struct {
	XMLName  xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:assertion ProxyRestriction"`
	Count    int        `xml:"Count,attr"`
	Audience []Audience `xml:"Audience"`
}

// AttributeStatement represents a saml:AttributeStatement element.
type AttributeStatement struct {
	XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attributes []Attribute `xml:"Attribute"`
}

// Attribute represents a saml:Attribute element containing one or more values.
type Attribute struct {
	XMLName      xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	FriendlyName string           `xml:"FriendlyName,attr"`
	Name         string           `xml:"Name,attr"`
	NameFormat   string           `xml:"NameFormat,attr"`
	Values       []AttributeValue `xml:"AttributeValue"`
}

// AttributeValue represents a saml:AttributeValue element.
type AttributeValue struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	Type    string   `xml:"xsi:type,attr"`
	Value   string   `xml:",chardata"`
}

// AuthnStatement represents a saml:AuthnStatement element.
type AuthnStatement struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	//Section 4.1.4.2 - https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
	//If the identity provider supports the Single Logout profile, defined in Section 4.4
	//, any such authentication statements MUST include a SessionIndex attribute to enable
	//per-session logout requests by the service provider.
	SessionIndex        string        `xml:"SessionIndex,attr,omitempty"`
	AuthnInstant        *time.Time    `xml:"AuthnInstant,attr,omitempty"`
	SessionNotOnOrAfter *time.Time    `xml:"SessionNotOnOrAfter,attr,omitempty"`
	AuthnContext        *AuthnContext `xml:"AuthnContext"`
}
