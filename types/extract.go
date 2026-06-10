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

package types

import (
	"encoding/xml"
	"fmt"
	"time"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// This file hand-extracts SAML structs from xmltree elements, replacing
// encoding/xml unmarshaling on the trusted path. Extraction matches the
// encoding/xml behavior the structs were written for: the root element's
// local name and namespace are checked; nested elements are matched by
// local name (any prefix); text values concatenate all character data of an
// element; time attributes are RFC 3339.

const (
	ProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
)

// resolveNamespace resolves el's namespace prefix against the declarations
// on el and its ancestors. It returns "" for an undeclared prefix or
// unprefixed element with no default namespace in scope.
func resolveNamespace(el *xmltree.Element) string {
	prefix := el.Space
	for cur := el; cur != nil; cur = cur.Parent() {
		for _, a := range cur.Attr {
			if prefix == "" && a.Space == "" && a.Key == "xmlns" {
				return a.Value
			}
			if prefix != "" && a.Space == "xmlns" && a.Key == prefix {
				return a.Value
			}
		}
	}
	if prefix == "xml" {
		return "http://www.w3.org/XML/1998/namespace"
	}
	return ""
}

// requireElement checks the root element's local name and namespace, like
// encoding/xml did for the struct XMLName fields.
func requireElement(el *xmltree.Element, namespace, local string) error {
	if el == nil {
		return fmt.Errorf("saml: missing element %s", local)
	}
	if el.Tag != local {
		return fmt.Errorf("saml: expected element %s, got %s", local, el.Tag)
	}
	if ns := resolveNamespace(el); ns != namespace {
		return fmt.Errorf("saml: expected element %s in namespace %s, got %q", local, namespace, ns)
	}
	return nil
}

func xmlName(namespace, local string) xml.Name {
	return xml.Name{Space: namespace, Local: local}
}

// parseTimeAttr parses an RFC 3339 time attribute; a missing attribute
// yields the zero time.
func parseTimeAttr(el *xmltree.Element, key string) (time.Time, error) {
	v := el.SelectAttrValue(key, "")
	if v == "" {
		return time.Time{}, nil
	}
	ts, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("saml: invalid %s timestamp: %v", key, err)
	}
	return ts, nil
}

// parseTimePtrAttr parses an optional RFC 3339 time attribute.
func parseTimePtrAttr(el *xmltree.Element, key string) (*time.Time, error) {
	v := el.SelectAttrValue(key, "")
	if v == "" {
		return nil, nil
	}
	ts, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, fmt.Errorf("saml: invalid %s timestamp: %v", key, err)
	}
	return &ts, nil
}

// ResponseFromElement extracts a Response from a samlp:Response element.
func ResponseFromElement(el *xmltree.Element) (*Response, error) {
	if err := requireElement(el, ProtocolNamespace, "Response"); err != nil {
		return nil, err
	}
	issueInstant, err := parseTimeAttr(el, "IssueInstant")
	if err != nil {
		return nil, err
	}
	resp := &Response{
		XMLName:      xmlName(ProtocolNamespace, "Response"),
		ID:           el.SelectAttrValue("ID", ""),
		InResponseTo: el.SelectAttrValue("InResponseTo", ""),
		Destination:  el.SelectAttrValue("Destination", ""),
		Version:      el.SelectAttrValue("Version", ""),
		IssueInstant: issueInstant,
	}
	for _, child := range el.ChildElements() {
		switch child.Tag {
		case "Status":
			resp.Status = statusFromElement(child)
		case "Issuer":
			resp.Issuer = issuerFromElement(child)
		case "Assertion":
			assertion, err := assertionFromElementNoNSCheck(child)
			if err != nil {
				return nil, err
			}
			resp.Assertions = append(resp.Assertions, *assertion)
		case "EncryptedAssertion":
			ea, err := EncryptedAssertionFromElement(child)
			if err != nil {
				return nil, err
			}
			resp.EncryptedAssertions = append(resp.EncryptedAssertions, *ea)
		}
	}
	return resp, nil
}

// LogoutResponseFromElement extracts a LogoutResponse from a
// samlp:LogoutResponse element.
func LogoutResponseFromElement(el *xmltree.Element) (*LogoutResponse, error) {
	if err := requireElement(el, ProtocolNamespace, "LogoutResponse"); err != nil {
		return nil, err
	}
	issueInstant, err := parseTimeAttr(el, "IssueInstant")
	if err != nil {
		return nil, err
	}
	resp := &LogoutResponse{
		XMLName:      xmlName(ProtocolNamespace, "LogoutResponse"),
		ID:           el.SelectAttrValue("ID", ""),
		InResponseTo: el.SelectAttrValue("InResponseTo", ""),
		Destination:  el.SelectAttrValue("Destination", ""),
		Version:      el.SelectAttrValue("Version", ""),
		IssueInstant: issueInstant,
	}
	if status := el.SelectLastElement("Status"); status != nil {
		resp.Status = statusFromElement(status)
	}
	if issuer := el.SelectLastElement("Issuer"); issuer != nil {
		resp.Issuer = issuerFromElement(issuer)
	}
	return resp, nil
}

// AssertionFromElement extracts an Assertion from a saml:Assertion element.
func AssertionFromElement(el *xmltree.Element) (*Assertion, error) {
	if err := requireElement(el, AssertionNamespace, "Assertion"); err != nil {
		return nil, err
	}
	return assertionFromElementNoNSCheck(el)
}

// assertionFromElementNoNSCheck extracts an Assertion matched by local name,
// mirroring encoding/xml's local-name matching for nested elements.
func assertionFromElementNoNSCheck(el *xmltree.Element) (*Assertion, error) {
	issueInstant, err := parseTimeAttr(el, "IssueInstant")
	if err != nil {
		return nil, err
	}
	assertion := &Assertion{
		XMLName:      xmlName(AssertionNamespace, "Assertion"),
		Version:      el.SelectAttrValue("Version", ""),
		ID:           el.SelectAttrValue("ID", ""),
		IssueInstant: issueInstant,
	}
	for _, child := range el.ChildElements() {
		switch child.Tag {
		case "Issuer":
			assertion.Issuer = issuerFromElement(child)
		case "Signature":
			assertion.Signature = &Signature{SignatureDocument: innerXML(child)}
		case "Subject":
			assertion.Subject = subjectFromElement(child)
		case "Conditions":
			assertion.Conditions = conditionsFromElement(child)
		case "AttributeStatement":
			assertion.AttributeStatements = append(assertion.AttributeStatements,
				*attributeStatementFromElement(child))
		case "AuthnStatement":
			authn, err := authnStatementFromElement(child)
			if err != nil {
				return nil, err
			}
			assertion.AuthnStatement = authn
		}
	}
	return assertion, nil
}

// innerXML serializes an element's children (the equivalent of
// encoding/xml's ",innerxml" capture; the bytes are a re-serialization, not
// the original input bytes).
func innerXML(el *xmltree.Element) []byte {
	var out []byte
	for _, child := range el.ChildElements() {
		out = append(out, child.WriteToBytes()...)
	}
	return out
}

func statusFromElement(el *xmltree.Element) *Status {
	status := &Status{XMLName: xmlName(ProtocolNamespace, "Status")}
	if sc := el.SelectLastElement("StatusCode"); sc != nil {
		status.StatusCode = &StatusCode{
			XMLName: xmlName(ProtocolNamespace, "StatusCode"),
			Value:   sc.SelectAttrValue("Value", ""),
		}
	}
	return status
}

func issuerFromElement(el *xmltree.Element) *Issuer {
	return &Issuer{
		XMLName: xmlName(AssertionNamespace, "Issuer"),
		Value:   el.Text(),
	}
}

func subjectFromElement(el *xmltree.Element) *Subject {
	subject := &Subject{XMLName: xmlName(AssertionNamespace, "Subject")}
	if nameID := el.SelectLastElement("NameID"); nameID != nil {
		subject.NameID = &NameID{
			XMLName: xmlName(AssertionNamespace, "NameID"),
			Format:  nameID.SelectAttrValue("Format", ""),
			Value:   nameID.Text(),
		}
	}
	if sc := el.SelectLastElement("SubjectConfirmation"); sc != nil {
		subject.SubjectConfirmation = &SubjectConfirmation{
			XMLName: xmlName(AssertionNamespace, "SubjectConfirmation"),
			Method:  sc.SelectAttrValue("Method", ""),
		}
		if scd := sc.SelectLastElement("SubjectConfirmationData"); scd != nil {
			subject.SubjectConfirmation.SubjectConfirmationData = &SubjectConfirmationData{
				XMLName:      xmlName(AssertionNamespace, "SubjectConfirmationData"),
				NotBefore:    scd.SelectAttrValue("NotBefore", ""),
				NotOnOrAfter: scd.SelectAttrValue("NotOnOrAfter", ""),
				Recipient:    scd.SelectAttrValue("Recipient", ""),
				InResponseTo: scd.SelectAttrValue("InResponseTo", ""),
			}
		}
	}
	return subject
}

func conditionsFromElement(el *xmltree.Element) *Conditions {
	conditions := &Conditions{
		XMLName:      xmlName(AssertionNamespace, "Conditions"),
		NotBefore:    el.SelectAttrValue("NotBefore", ""),
		NotOnOrAfter: el.SelectAttrValue("NotOnOrAfter", ""),
	}
	for _, child := range el.ChildElements() {
		switch child.Tag {
		case "AudienceRestriction":
			ar := AudienceRestriction{XMLName: xmlName(AssertionNamespace, "AudienceRestriction")}
			for _, aud := range child.SelectElements("Audience") {
				ar.Audiences = append(ar.Audiences, Audience{
					XMLName: xmlName(AssertionNamespace, "Audience"),
					Value:   aud.Text(),
				})
			}
			conditions.AudienceRestrictions = append(conditions.AudienceRestrictions, ar)
		case "OneTimeUse":
			conditions.OneTimeUse = &OneTimeUse{XMLName: xmlName(AssertionNamespace, "OneTimeUse")}
		case "ProxyRestriction":
			pr := &ProxyRestriction{XMLName: xmlName(AssertionNamespace, "ProxyRestriction")}
			if count := child.SelectAttrValue("Count", ""); count != "" {
				fmt.Sscanf(count, "%d", &pr.Count)
			}
			for _, aud := range child.SelectElements("Audience") {
				pr.Audience = append(pr.Audience, Audience{
					XMLName: xmlName(AssertionNamespace, "Audience"),
					Value:   aud.Text(),
				})
			}
			conditions.ProxyRestriction = pr
		}
	}
	return conditions
}

func attributeStatementFromElement(el *xmltree.Element) *AttributeStatement {
	stmt := &AttributeStatement{XMLName: xmlName(AssertionNamespace, "AttributeStatement")}
	for _, attrEl := range el.SelectElements("Attribute") {
		attr := Attribute{
			XMLName:      xmlName(AssertionNamespace, "Attribute"),
			FriendlyName: attrEl.SelectAttrValue("FriendlyName", ""),
			Name:         attrEl.SelectAttrValue("Name", ""),
			NameFormat:   attrEl.SelectAttrValue("NameFormat", ""),
		}
		for _, valEl := range attrEl.SelectElements("AttributeValue") {
			attr.Values = append(attr.Values, AttributeValue{
				XMLName: xmlName(AssertionNamespace, "AttributeValue"),
				Type:    valEl.SelectAttrValue("xsi:type", ""),
				Value:   valEl.Text(),
			})
		}
		stmt.Attributes = append(stmt.Attributes, attr)
	}
	return stmt
}

func authnStatementFromElement(el *xmltree.Element) (*AuthnStatement, error) {
	authnInstant, err := parseTimePtrAttr(el, "AuthnInstant")
	if err != nil {
		return nil, err
	}
	sessionNotOnOrAfter, err := parseTimePtrAttr(el, "SessionNotOnOrAfter")
	if err != nil {
		return nil, err
	}
	stmt := &AuthnStatement{
		XMLName:             xmlName(AssertionNamespace, "AuthnStatement"),
		SessionIndex:        el.SelectAttrValue("SessionIndex", ""),
		AuthnInstant:        authnInstant,
		SessionNotOnOrAfter: sessionNotOnOrAfter,
	}
	if ac := el.SelectLastElement("AuthnContext"); ac != nil {
		stmt.AuthnContext = &AuthnContext{XMLName: xmlName(AssertionNamespace, "AuthnContext")}
		if ref := ac.SelectLastElement("AuthnContextClassRef"); ref != nil {
			stmt.AuthnContext.AuthnContextClassRef = &AuthnContextClassRef{
				XMLName: xmlName(AssertionNamespace, "AuthnContextClassRef"),
				Value:   ref.Text(),
			}
		}
	}
	return stmt, nil
}

// UnverifiedBaseResponseFromElement extracts the pre-validation routing
// attributes of a Response, including all assertion audiences.
func UnverifiedBaseResponseFromElement(el *xmltree.Element) (*UnverifiedBaseResponse, error) {
	if err := requireElement(el, ProtocolNamespace, "Response"); err != nil {
		return nil, err
	}
	resp := &UnverifiedBaseResponse{
		XMLName:      xmlName(ProtocolNamespace, "Response"),
		ID:           el.SelectAttrValue("ID", ""),
		InResponseTo: el.SelectAttrValue("InResponseTo", ""),
		Destination:  el.SelectAttrValue("Destination", ""),
		Version:      el.SelectAttrValue("Version", ""),
	}
	if issuer := el.SelectLastElement("Issuer"); issuer != nil {
		resp.Issuer = issuerFromElement(issuer)
	}
	seen := make(map[string]bool)
	for _, assertion := range el.SelectElements("Assertion") {
		if conditions := assertion.SelectLastElement("Conditions"); conditions != nil {
			for _, ar := range conditions.SelectElements("AudienceRestriction") {
				for _, aud := range ar.SelectElements("Audience") {
					if v := aud.Text(); v != "" && !seen[v] {
						seen[v] = true
						resp.Audiences = append(resp.Audiences, v)
					}
				}
			}
		}
	}
	return resp, nil
}

// EncryptedAssertionFromElement extracts an EncryptedAssertion's encryption
// metadata and ciphertext from a saml:EncryptedAssertion element.
func EncryptedAssertionFromElement(el *xmltree.Element) (*EncryptedAssertion, error) {
	if el.Tag != "EncryptedAssertion" {
		return nil, fmt.Errorf("saml: expected element EncryptedAssertion, got %s", el.Tag)
	}
	ea := &EncryptedAssertion{
		XMLName: xmlName(AssertionNamespace, "EncryptedAssertion"),
	}

	encryptedData := el.SelectLastElement("EncryptedData")
	if encryptedData != nil {
		if em := encryptedData.SelectLastElement("EncryptionMethod"); em != nil {
			ea.EncryptionMethod = *encryptionMethodFromElement(em)
		}
		if keyInfo := encryptedData.SelectLastElement("KeyInfo"); keyInfo != nil {
			if ek := keyInfo.SelectLastElement("EncryptedKey"); ek != nil {
				ea.EncryptedKey = *encryptedKeyFromElement(ek)
			}
		}
		if cd := encryptedData.SelectLastElement("CipherData"); cd != nil {
			if cv := cd.SelectLastElement("CipherValue"); cv != nil {
				ea.CipherValue = cv.Text()
			}
		}
	}

	// A detached EncryptedKey is a sibling of EncryptedData.
	if det := el.SelectLastElement("EncryptedKey"); det != nil {
		ea.DetEncryptedKey = *encryptedKeyFromElement(det)
	}
	return ea, nil
}

func encryptionMethodFromElement(el *xmltree.Element) *EncryptionMethod {
	em := &EncryptionMethod{
		Algorithm: el.SelectAttrValue("Algorithm", ""),
	}
	if dm := el.SelectLastElement("DigestMethod"); dm != nil {
		em.DigestMethod = &DigestMethod{Algorithm: dm.SelectAttrValue("Algorithm", "")}
	}
	return em
}

func encryptedKeyFromElement(el *xmltree.Element) *EncryptedKey {
	ek := &EncryptedKey{}
	if keyInfo := el.SelectLastElement("KeyInfo"); keyInfo != nil {
		if x509Data := keyInfo.SelectLastElement("X509Data"); x509Data != nil {
			if cert := x509Data.SelectLastElement("X509Certificate"); cert != nil {
				ek.X509Data = cert.Text()
			}
		}
	}
	if cd := el.SelectLastElement("CipherData"); cd != nil {
		if cv := cd.SelectLastElement("CipherValue"); cv != nil {
			ek.CipherValue = cv.Text()
		}
	}
	if em := el.SelectLastElement("EncryptionMethod"); em != nil {
		ek.EncryptionMethod = *encryptionMethodFromElement(em)
	}
	return ek
}
