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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"

	"github.com/beevik/etree"
	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/uuid"
)

// ReceivedLogoutRequest represents a received SAML LogoutRequest for IdP-side processing.
type ReceivedLogoutRequest struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr,omitempty"`
	Issuer       string   `xml:"Issuer"`
	NameID       struct {
		Format string `xml:"Format,attr,omitempty"`
		Value  string `xml:",chardata"`
	} `xml:"NameID"`
	SessionIndex string `xml:"SessionIndex,omitempty"`
}

func (idp *IdentityProvider) ValidateEncodedLogoutRequestPOST(_ context.Context, encoded string) (*ReceivedLogoutRequest, *SPConfig, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("base64 decode error: %v", err),
		}
	}

	return idp.decodeAndValidateLogoutRequest(raw)
}

func (idp *IdentityProvider) ValidateEncodedLogoutRequestRedirect(_ context.Context, samlRequest, relayState, sigAlg, signature string) (*ReceivedLogoutRequest, *SPConfig, error) {
	raw, err := idp.decodeRedirectRequest(samlRequest)
	if err != nil {
		return nil, nil, err
	}

	req, sp, err := idp.decodeAndValidateLogoutRequest(raw)
	if err != nil {
		return nil, nil, err
	}

	if sp.RequireSignedAuthnRequests || signature != "" {
		if signature == "" {
			return nil, nil, &saml2.ValidationError{
				Reason: saml2.ErrMissingSignature,
				Detail: "SP is required to sign requests but no signature was provided",
			}
		}
		if err := idp.verifyRedirectSignature(sp, samlRequest, relayState, sigAlg, signature); err != nil {
			return nil, nil, err
		}
	}

	return req, sp, nil
}

func (idp *IdentityProvider) decodeAndValidateLogoutRequest(raw []byte) (*ReceivedLogoutRequest, *SPConfig, error) {
	if err := rtvalidator.Validate(bytes.NewReader(raw)); err != nil {
		return nil, nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("XML roundtrip validation failed: %v", err),
		}
	}

	req := &ReceivedLogoutRequest{}
	if err := xml.Unmarshal(raw, req); err != nil {
		return nil, nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("XML unmarshal error: %v", err),
		}
	}

	if req.ID == "" {
		return nil, nil, &saml2.ValidationError{
			Reason: saml2.ErrMissingElement,
			Detail: "LogoutRequest missing ID attribute",
		}
	}

	if req.Version != "2.0" {
		return nil, nil, &saml2.ValidationError{
			Reason: saml2.ErrBadVersion,
			Detail: fmt.Sprintf("expected 2.0, got %s", req.Version),
		}
	}

	if req.Issuer == "" {
		return nil, nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: "LogoutRequest missing Issuer",
		}
	}

	if req.Destination != "" && req.Destination != idp.SLOURL {
		return nil, nil, &saml2.ValidationError{
			Reason: saml2.ErrBadDestination,
			Detail: fmt.Sprintf("expected %s, got %s", idp.SLOURL, req.Destination),
		}
	}

	sp, err := idp.lookupSP(req.Issuer)
	if err != nil {
		return nil, nil, err
	}

	return req, sp, nil
}

func (idp *IdentityProvider) BuildLogoutResponseDocument(spEntityID, statusCode, inResponseTo, destination string) (*etree.Document, error) {
	if _, err := idp.lookupSP(spEntityID); err != nil {
		return nil, err
	}

	responseEl := idp.buildLogoutResponse(statusCode, inResponseTo, destination)

	if idp.SignResponses {
		var err error
		responseEl, err = idp.signElement(responseEl)
		if err != nil {
			return nil, fmt.Errorf("error signing logout response: %w", err)
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(responseEl)
	return doc, nil
}

func (idp *IdentityProvider) BuildLogoutResponseBodyPost(spEntityID, statusCode, inResponseTo, destination, relayState string) ([]byte, error) {
	doc, err := idp.BuildLogoutResponseDocument(spEntityID, statusCode, inResponseTo, destination)
	if err != nil {
		return nil, err
	}

	docBytes, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("error serializing logout response: %w", err)
	}

	return saml2.BuildPOSTForm(destination, "SAMLResponse", base64.StdEncoding.EncodeToString(docBytes), relayState)
}

func (idp *IdentityProvider) BuildLogoutRequestDocument(spEntityID, nameID, nameIDFormat, sessionIndex string) (*etree.Document, error) {
	sp, err := idp.lookupSP(spEntityID)
	if err != nil {
		return nil, err
	}

	destination := ""
	if len(sp.SLOURLs) > 0 {
		destination = sp.SLOURLs[0]
	}

	now := idp.now().UTC()
	requestID := "_" + uuid.NewV4().String()

	logoutRequestEl := etree.NewElement("samlp:LogoutRequest")
	logoutRequestEl.CreateAttr("xmlns:samlp", saml2.SAMLProtocolNamespace)
	logoutRequestEl.CreateAttr("xmlns:saml", saml2.SAMLAssertionNamespace)
	logoutRequestEl.CreateAttr("ID", requestID)
	logoutRequestEl.CreateAttr("Version", "2.0")
	logoutRequestEl.CreateAttr("IssueInstant", now.Format(saml2.IssueInstantFormat))
	if destination != "" {
		logoutRequestEl.CreateAttr("Destination", destination)
	}

	logoutRequestEl.CreateElement("saml:Issuer").SetText(idp.EntityID)

	nameIDEl := logoutRequestEl.CreateElement("saml:NameID")
	if nameIDFormat != "" {
		nameIDEl.CreateAttr("Format", nameIDFormat)
	}
	nameIDEl.SetText(nameID)

	if sessionIndex != "" {
		logoutRequestEl.CreateElement("samlp:SessionIndex").SetText(sessionIndex)
	}

	if idp.SignResponses {
		logoutRequestEl, err = idp.signElement(logoutRequestEl)
		if err != nil {
			return nil, fmt.Errorf("error signing logout request: %w", err)
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(logoutRequestEl)
	return doc, nil
}

func (idp *IdentityProvider) buildLogoutResponse(statusCode, inResponseTo, destination string) *etree.Element {
	now := idp.now().UTC()
	responseID := "_" + uuid.NewV4().String()

	responseEl := etree.NewElement("samlp:LogoutResponse")
	responseEl.CreateAttr("xmlns:samlp", saml2.SAMLProtocolNamespace)
	responseEl.CreateAttr("xmlns:saml", saml2.SAMLAssertionNamespace)
	responseEl.CreateAttr("ID", responseID)
	responseEl.CreateAttr("Version", "2.0")
	responseEl.CreateAttr("IssueInstant", now.Format(saml2.IssueInstantFormat))
	if destination != "" {
		responseEl.CreateAttr("Destination", destination)
	}
	if inResponseTo != "" {
		responseEl.CreateAttr("InResponseTo", inResponseTo)
	}

	responseEl.CreateElement("saml:Issuer").SetText(idp.EntityID)

	statusEl := responseEl.CreateElement("samlp:Status")
	statusCodeEl := statusEl.CreateElement("samlp:StatusCode")
	statusCodeEl.CreateAttr("Value", statusCode)

	return responseEl
}
