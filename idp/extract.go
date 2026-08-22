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

import (
	"encoding/xml"
	"fmt"

	saml2 "github.com/russellhaering/gosaml2/v2"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// receivedAuthnRequestFromElement extracts a ReceivedAuthnRequest from a
// samlp:AuthnRequest element.
func receivedAuthnRequestFromElement(el *xmltree.Element) (*ReceivedAuthnRequest, error) {
	if el.Tag != "AuthnRequest" {
		return nil, fmt.Errorf("expected element AuthnRequest, got %s", el.Tag)
	}
	req := &ReceivedAuthnRequest{
		XMLName:                       xml.Name{Space: saml2.SAMLProtocolNamespace, Local: "AuthnRequest"},
		ID:                            el.SelectAttrValue("ID", ""),
		Version:                       el.SelectAttrValue("Version", ""),
		IssueInstant:                  el.SelectAttrValue("IssueInstant", ""),
		Destination:                   el.SelectAttrValue("Destination", ""),
		AssertionConsumerServiceURL:   el.SelectAttrValue("AssertionConsumerServiceURL", ""),
		AssertionConsumerServiceIndex: el.SelectAttrValue("AssertionConsumerServiceIndex", ""),
		ProtocolBinding:               el.SelectAttrValue("ProtocolBinding", ""),
		ForceAuthn:                    el.SelectAttrValue("ForceAuthn", ""),
		IsPassive:                     el.SelectAttrValue("IsPassive", ""),
	}
	issuer, err := el.SingleElement("Issuer")
	if err != nil {
		return nil, err
	}
	if issuer != nil {
		req.Issuer = issuer.Text()
	}
	nip, err := el.SingleElement("NameIDPolicy")
	if err != nil {
		return nil, err
	}
	if nip != nil {
		req.NameIDPolicy = &NameIDPolicy{
			XMLName:     xml.Name{Space: saml2.SAMLProtocolNamespace, Local: "NameIDPolicy"},
			AllowCreate: nip.SelectAttrValue("AllowCreate", ""),
			Format:      nip.SelectAttrValue("Format", ""),
		}
	}
	return req, nil
}

// receivedLogoutRequestFromElement extracts a ReceivedLogoutRequest from a
// samlp:LogoutRequest element.
func receivedLogoutRequestFromElement(el *xmltree.Element) (*ReceivedLogoutRequest, error) {
	if el.Tag != "LogoutRequest" {
		return nil, fmt.Errorf("expected element LogoutRequest, got %s", el.Tag)
	}
	req := &ReceivedLogoutRequest{
		XMLName:      xml.Name{Space: saml2.SAMLProtocolNamespace, Local: "LogoutRequest"},
		ID:           el.SelectAttrValue("ID", ""),
		Version:      el.SelectAttrValue("Version", ""),
		IssueInstant: el.SelectAttrValue("IssueInstant", ""),
		NotOnOrAfter: el.SelectAttrValue("NotOnOrAfter", ""),
		Destination:  el.SelectAttrValue("Destination", ""),
	}
	issuer, err := el.SingleElement("Issuer")
	if err != nil {
		return nil, err
	}
	if issuer != nil {
		req.Issuer = issuer.Text()
	}
	nameID, err := el.SingleElement("NameID")
	if err != nil {
		return nil, err
	}
	if nameID != nil {
		req.NameID.Format = nameID.SelectAttrValue("Format", "")
		req.NameID.Value = nameID.Text()
	}
	si, err := el.SingleElement("SessionIndex")
	if err != nil {
		return nil, err
	}
	if si != nil {
		req.SessionIndex = si.Text()
	}
	return req, nil
}
