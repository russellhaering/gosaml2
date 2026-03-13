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

package saml2

import (
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/russellhaering/gosaml2/v2/uuid"
)

// AssertionParams contains the parameters for building a SAML assertion.
type AssertionParams struct {
	NameID               string
	NameIDFormat         string
	AuthnContext         string
	SessionIndex         string
	Attributes           []types.Attribute
	InResponseTo         string
	Recipient            string
	AudienceRestrictions []string
}

// BuildResponseDocument builds a signed SAML Response document for the given SP.
func (idp *IdentityProvider) BuildResponseDocument(spEntityID string, params *AssertionParams) (*etree.Document, string, error) {
	sp, err := idp.lookupSP(spEntityID)
	if err != nil {
		return nil, "", err
	}

	acsURL := params.Recipient
	if acsURL == "" && len(sp.ACSURLs) > 0 {
		acsURL = sp.ACSURLs[0]
	}
	if acsURL == "" {
		return nil, "", &ValidationError{
			Reason: ErrBadACSURL,
			Detail: "no ACS URL specified and none configured for SP",
		}
	}

	assertionEl := idp.buildAssertion(sp, params, acsURL)

	responseEl := idp.buildResponse(params.InResponseTo, acsURL)

	// Sign assertion if configured. We must add the Response's namespace
	// declarations to the assertion before signing because the SP's verifier
	// uses NSDetach which copies parent namespace context onto the assertion.
	// The canonical form at signing time must match what the SP will see.
	if idp.SignAssertions {
		assertionEl.CreateAttr("xmlns:samlp", SAMLProtocolNamespace)
		assertionEl, err = idp.signElement(assertionEl)
		if err != nil {
			return nil, "", fmt.Errorf("error signing assertion: %w", err)
		}
	}

	// Either encrypt or embed the assertion directly
	if sp.EncryptAssertions {
		encryptedEl, err := idp.encryptAssertion(assertionEl, sp)
		if err != nil {
			return nil, "", err
		}
		responseEl.AddChild(encryptedEl)
	} else {
		responseEl.AddChild(assertionEl)
	}

	// Sign response if configured
	if idp.SignResponses {
		responseEl, err = idp.signElement(responseEl)
		if err != nil {
			return nil, "", fmt.Errorf("error signing response: %w", err)
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(responseEl)

	return doc, acsURL, nil
}

// BuildResponseBodyPost builds the POST form body for submitting a SAML Response.
func (idp *IdentityProvider) BuildResponseBodyPost(spEntityID string, params *AssertionParams, relayState string) ([]byte, error) {
	doc, acsURL, err := idp.BuildResponseDocument(spEntityID, params)
	if err != nil {
		return nil, err
	}

	docBytes, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("error serializing response: %w", err)
	}

	return buildPOSTForm(acsURL, "SAMLResponse", base64.StdEncoding.EncodeToString(docBytes), relayState)
}

// BuildErrorResponseDocument builds a SAML Response with an error status.
func (idp *IdentityProvider) BuildErrorResponseDocument(spEntityID, statusCode, inResponseTo, destination string) (*etree.Document, error) {
	if _, err := idp.lookupSP(spEntityID); err != nil {
		return nil, err
	}

	responseEl := idp.buildResponse(inResponseTo, destination)

	// Replace the success status with the error status
	statusEl := responseEl.SelectElement("samlp:Status")
	if statusEl != nil {
		responseEl.RemoveChild(statusEl)
	}
	statusEl = responseEl.CreateElement("samlp:Status")
	statusCodeEl := statusEl.CreateElement("samlp:StatusCode")
	statusCodeEl.CreateAttr("Value", statusCode)

	if idp.SignResponses {
		var err error
		responseEl, err = idp.signElement(responseEl)
		if err != nil {
			return nil, fmt.Errorf("error signing error response: %w", err)
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(responseEl)
	return doc, nil
}

func (idp *IdentityProvider) buildAssertion(sp *SPConfig, params *AssertionParams, acsURL string) *etree.Element {
	now := idp.now().UTC()
	assertionLifetime := idp.assertionLifetime()
	sessionLifetime := idp.sessionLifetime()

	assertionID := "_" + uuid.NewV4().String()

	assertionEl := etree.NewElement("saml:Assertion")
	assertionEl.CreateAttr("xmlns:saml", SAMLAssertionNamespace)
	assertionEl.CreateAttr("Version", "2.0")
	assertionEl.CreateAttr("ID", assertionID)
	assertionEl.CreateAttr("IssueInstant", now.Format(issueInstantFormat))

	assertionEl.CreateElement("saml:Issuer").SetText(idp.EntityID)

	// Subject
	subjectEl := assertionEl.CreateElement("saml:Subject")
	nameIDEl := subjectEl.CreateElement("saml:NameID")
	nameIDFormat := params.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = NameIdFormatTransient
	}
	nameIDEl.CreateAttr("Format", nameIDFormat)
	nameIDEl.SetText(params.NameID)

	subjectConfEl := subjectEl.CreateElement("saml:SubjectConfirmation")
	subjectConfEl.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	subjectConfDataEl := subjectConfEl.CreateElement("saml:SubjectConfirmationData")
	if params.InResponseTo != "" {
		subjectConfDataEl.CreateAttr("InResponseTo", params.InResponseTo)
	}
	subjectConfDataEl.CreateAttr("NotOnOrAfter", now.Add(assertionLifetime).Format(issueInstantFormat))
	subjectConfDataEl.CreateAttr("Recipient", acsURL)

	// Conditions
	conditionsEl := assertionEl.CreateElement("saml:Conditions")
	conditionsEl.CreateAttr("NotBefore", now.Format(issueInstantFormat))
	conditionsEl.CreateAttr("NotOnOrAfter", now.Add(assertionLifetime).Format(issueInstantFormat))

	audiences := params.AudienceRestrictions
	if len(audiences) == 0 {
		audiences = []string{sp.EntityID}
	}
	audienceRestrictionEl := conditionsEl.CreateElement("saml:AudienceRestriction")
	for _, aud := range audiences {
		audienceRestrictionEl.CreateElement("saml:Audience").SetText(aud)
	}

	// AuthnStatement
	authnStatementEl := assertionEl.CreateElement("saml:AuthnStatement")
	authnStatementEl.CreateAttr("AuthnInstant", now.Format(issueInstantFormat))
	authnStatementEl.CreateAttr("SessionNotOnOrAfter", now.Add(sessionLifetime).Format(issueInstantFormat))
	sessionIndex := params.SessionIndex
	if sessionIndex == "" {
		sessionIndex = "_" + uuid.NewV4().String()
	}
	authnStatementEl.CreateAttr("SessionIndex", sessionIndex)

	authnContextEl := authnStatementEl.CreateElement("saml:AuthnContext")
	authnContextClassRef := params.AuthnContext
	if authnContextClassRef == "" {
		authnContextClassRef = AuthnContextPasswordProtectedTransport
	}
	authnContextEl.CreateElement("saml:AuthnContextClassRef").SetText(authnContextClassRef)

	// AttributeStatement
	if len(params.Attributes) > 0 {
		attrStatementEl := assertionEl.CreateElement("saml:AttributeStatement")
		for _, attr := range params.Attributes {
			attrEl := attrStatementEl.CreateElement("saml:Attribute")
			attrEl.CreateAttr("Name", attr.Name)
			if attr.FriendlyName != "" {
				attrEl.CreateAttr("FriendlyName", attr.FriendlyName)
			}
			if attr.NameFormat != "" {
				attrEl.CreateAttr("NameFormat", attr.NameFormat)
			}
			for _, val := range attr.Values {
				valEl := attrEl.CreateElement("saml:AttributeValue")
				valEl.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
				if val.Type != "" {
					valEl.CreateAttr("xsi:type", val.Type)
				} else {
					valEl.CreateAttr("xsi:type", "xs:string")
				}
				valEl.SetText(val.Value)
			}
		}
	}

	return assertionEl
}

func (idp *IdentityProvider) buildResponse(inResponseTo, destination string) *etree.Element {
	now := idp.now().UTC()
	responseID := "_" + uuid.NewV4().String()

	responseEl := etree.NewElement("samlp:Response")
	responseEl.CreateAttr("xmlns:samlp", SAMLProtocolNamespace)
	responseEl.CreateAttr("xmlns:saml", SAMLAssertionNamespace)
	responseEl.CreateAttr("ID", responseID)
	responseEl.CreateAttr("Version", "2.0")
	responseEl.CreateAttr("IssueInstant", now.Format(issueInstantFormat))
	responseEl.CreateAttr("Destination", destination)
	if inResponseTo != "" {
		responseEl.CreateAttr("InResponseTo", inResponseTo)
	}

	responseEl.CreateElement("saml:Issuer").SetText(idp.EntityID)

	statusEl := responseEl.CreateElement("samlp:Status")
	statusCodeEl := statusEl.CreateElement("samlp:StatusCode")
	statusCodeEl.CreateAttr("Value", StatusCodeSuccess)

	return responseEl
}
