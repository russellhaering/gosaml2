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
	"context"
	"encoding/base64"
	"fmt"

	saml2 "github.com/russellhaering/gosaml2/v2"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
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

// BuildResponseDocument builds a SAML Response XML document for the given SP,
// including a signed assertion with the provided parameters. It returns the
// document, the resolved ACS URL, and any error.
func (idp *IdentityProvider) BuildResponseDocument(spEntityID string, params *AssertionParams) (*xmltree.Document, string, error) {
	return idp.BuildResponseDocumentContext(context.Background(), spEntityID, params)
}

// BuildResponseDocumentContext builds a SAML Response XML document for the
// given SP using the Service Provider resolved with ctx. A supplied Recipient
// must be a currently registered ACS URL for the resolved Service Provider.
func (idp *IdentityProvider) BuildResponseDocumentContext(ctx context.Context, spEntityID string, params *AssertionParams) (*xmltree.Document, string, error) {
	sp, err := idp.lookupSPContext(ctx, spEntityID)
	if err != nil {
		return nil, "", err
	}

	acsURL := params.Recipient
	if acsURL == "" && len(sp.ACSURLs) > 0 {
		acsURL = sp.ACSURLs[0]
	}
	if acsURL == "" {
		return nil, "", &saml2.ValidationError{
			Reason: saml2.ErrBadACSURL,
			Detail: "no ACS URL specified and none configured for SP",
		}
	}
	if !sp.hasACSURL(acsURL) {
		return nil, "", &saml2.ValidationError{
			Reason: saml2.ErrBadACSURL,
			Detail: fmt.Sprintf("ACS URL %s is not registered for SP %s", acsURL, sp.EntityID),
		}
	}

	assertionEl := idp.buildAssertion(sp, params, acsURL)

	responseEl := idp.buildResponse(params.InResponseTo, acsURL)

	if idp.SignAssertions {
		assertionEl.CreateAttr("xmlns:samlp", saml2.SAMLProtocolNamespace)
		assertionEl, err = idp.signElement(assertionEl)
		if err != nil {
			return nil, "", fmt.Errorf("error signing assertion: %w", err)
		}
	}

	if sp.EncryptAssertions {
		encryptedEl, err := idp.encryptAssertion(assertionEl, sp)
		if err != nil {
			return nil, "", err
		}
		responseEl.AddChild(encryptedEl)
	} else {
		responseEl.AddChild(assertionEl)
	}

	if idp.SignResponses {
		responseEl, err = idp.signElement(responseEl)
		if err != nil {
			return nil, "", fmt.Errorf("error signing response: %w", err)
		}
	}

	doc := xmltree.NewDocument()
	doc.SetRoot(responseEl)

	return doc, acsURL, nil
}

// BuildResponseBodyPost builds a SAML Response and returns an HTML auto-submit
// POST form targeting the SP's ACS URL. This is the typical way to deliver a
// SAML response via the HTTP-POST binding.
func (idp *IdentityProvider) BuildResponseBodyPost(spEntityID string, params *AssertionParams, relayState string) ([]byte, error) {
	return idp.BuildResponseBodyPostContext(context.Background(), spEntityID, params, relayState)
}

// BuildResponseBodyPostContext builds a SAML Response using the Service
// Provider resolved with ctx and returns an auto-submit HTTP-POST form.
func (idp *IdentityProvider) BuildResponseBodyPostContext(ctx context.Context, spEntityID string, params *AssertionParams, relayState string) ([]byte, error) {
	doc, acsURL, err := idp.BuildResponseDocumentContext(ctx, spEntityID, params)
	if err != nil {
		return nil, err
	}

	docBytes, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("error serializing response: %w", err)
	}

	return saml2.BuildPOSTForm(acsURL, "SAMLResponse", base64.StdEncoding.EncodeToString(docBytes), relayState)
}

// BuildErrorResponseDocument builds a SAML Response document with an error
// status code (e.g. StatusCodeResponder). Use this to communicate authentication
// failures back to the SP.
func (idp *IdentityProvider) BuildErrorResponseDocument(spEntityID, statusCode, inResponseTo, destination string) (*xmltree.Document, error) {
	if _, err := idp.lookupSP(spEntityID); err != nil {
		return nil, err
	}

	responseEl := idp.buildResponse(inResponseTo, destination)

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

	doc := xmltree.NewDocument()
	doc.SetRoot(responseEl)
	return doc, nil
}

func (sp *SPConfig) hasACSURL(acsURL string) bool {
	for _, allowed := range sp.ACSURLs {
		if acsURL == allowed {
			return true
		}
	}
	return false
}

func (idp *IdentityProvider) buildAssertion(sp *SPConfig, params *AssertionParams, acsURL string) *xmltree.Element {
	now := idp.now().UTC()
	assertionLifetime := idp.assertionLifetime()
	sessionLifetime := idp.sessionLifetime()

	assertionID := "_" + uuid.NewV4().String()

	assertionEl := xmltree.NewElement("saml:Assertion")
	assertionEl.CreateAttr("xmlns:saml", saml2.SAMLAssertionNamespace)
	assertionEl.CreateAttr("Version", "2.0")
	assertionEl.CreateAttr("ID", assertionID)
	assertionEl.CreateAttr("IssueInstant", now.Format(saml2.IssueInstantFormat))

	assertionEl.CreateElement("saml:Issuer").SetText(idp.EntityID)

	subjectEl := assertionEl.CreateElement("saml:Subject")
	nameIDEl := subjectEl.CreateElement("saml:NameID")
	nameIDFormat := params.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = saml2.NameIdFormatTransient
	}
	nameIDEl.CreateAttr("Format", nameIDFormat)
	nameIDEl.SetText(params.NameID)

	subjectConfEl := subjectEl.CreateElement("saml:SubjectConfirmation")
	subjectConfEl.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	subjectConfDataEl := subjectConfEl.CreateElement("saml:SubjectConfirmationData")
	if params.InResponseTo != "" {
		subjectConfDataEl.CreateAttr("InResponseTo", params.InResponseTo)
	}
	subjectConfDataEl.CreateAttr("NotOnOrAfter", now.Add(assertionLifetime).Format(saml2.IssueInstantFormat))
	subjectConfDataEl.CreateAttr("Recipient", acsURL)

	conditionsEl := assertionEl.CreateElement("saml:Conditions")
	conditionsEl.CreateAttr("NotBefore", now.Format(saml2.IssueInstantFormat))
	conditionsEl.CreateAttr("NotOnOrAfter", now.Add(assertionLifetime).Format(saml2.IssueInstantFormat))

	audiences := params.AudienceRestrictions
	if len(audiences) == 0 {
		audiences = []string{sp.EntityID}
	}
	audienceRestrictionEl := conditionsEl.CreateElement("saml:AudienceRestriction")
	for _, aud := range audiences {
		audienceRestrictionEl.CreateElement("saml:Audience").SetText(aud)
	}

	authnStatementEl := assertionEl.CreateElement("saml:AuthnStatement")
	authnStatementEl.CreateAttr("AuthnInstant", now.Format(saml2.IssueInstantFormat))
	authnStatementEl.CreateAttr("SessionNotOnOrAfter", now.Add(sessionLifetime).Format(saml2.IssueInstantFormat))
	sessionIndex := params.SessionIndex
	if sessionIndex == "" {
		sessionIndex = "_" + uuid.NewV4().String()
	}
	authnStatementEl.CreateAttr("SessionIndex", sessionIndex)

	authnContextEl := authnStatementEl.CreateElement("saml:AuthnContext")
	authnContextClassRef := params.AuthnContext
	if authnContextClassRef == "" {
		authnContextClassRef = saml2.AuthnContextPasswordProtectedTransport
	}
	authnContextEl.CreateElement("saml:AuthnContextClassRef").SetText(authnContextClassRef)

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

func (idp *IdentityProvider) buildResponse(inResponseTo, destination string) *xmltree.Element {
	now := idp.now().UTC()
	responseID := "_" + uuid.NewV4().String()

	responseEl := xmltree.NewElement("samlp:Response")
	responseEl.CreateAttr("xmlns:samlp", saml2.SAMLProtocolNamespace)
	responseEl.CreateAttr("xmlns:saml", saml2.SAMLAssertionNamespace)
	responseEl.CreateAttr("ID", responseID)
	responseEl.CreateAttr("Version", "2.0")
	responseEl.CreateAttr("IssueInstant", now.Format(saml2.IssueInstantFormat))
	responseEl.CreateAttr("Destination", destination)
	if inResponseTo != "" {
		responseEl.CreateAttr("InResponseTo", inResponseTo)
	}

	responseEl.CreateElement("saml:Issuer").SetText(idp.EntityID)

	statusEl := responseEl.CreateElement("samlp:Status")
	statusCodeEl := statusEl.CreateElement("samlp:StatusCode")
	statusCodeEl.CreateAttr("Value", saml2.StatusCodeSuccess)

	return responseEl
}
