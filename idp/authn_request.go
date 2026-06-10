// Copyright 2025 Russell Haering et al.
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

package idp

import "encoding/xml"

// ReceivedAuthnRequest represents an AuthnRequest received by an IdP.
type ReceivedAuthnRequest struct {
	XMLName                       xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                            string        `xml:"ID,attr"`
	Version                       string        `xml:"Version,attr"`
	IssueInstant                  string        `xml:"IssueInstant,attr"`
	Destination                   string        `xml:"Destination,attr,omitempty"`
	AssertionConsumerServiceURL   string        `xml:"AssertionConsumerServiceURL,attr,omitempty"`
	AssertionConsumerServiceIndex string        `xml:"AssertionConsumerServiceIndex,attr,omitempty"`
	ProtocolBinding               string        `xml:"ProtocolBinding,attr,omitempty"`
	ForceAuthn                    string        `xml:"ForceAuthn,attr,omitempty"`
	IsPassive                     string        `xml:"IsPassive,attr,omitempty"`
	Issuer                        string        `xml:"Issuer"`
	NameIDPolicy                  *NameIDPolicy `xml:"NameIDPolicy,omitempty"`
}

// NameIDPolicy represents a NameIDPolicy element in an AuthnRequest.
type NameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	AllowCreate string   `xml:"AllowCreate,attr,omitempty"`
	Format      string   `xml:"Format,attr,omitempty"`
}
