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

package sp

import (
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/uuid"
)

func (sp *ServiceProvider) buildLogoutResponse(statusCodeValue string, reqID string, includeSig bool) (*etree.Document, error) {
	if sp.EntityID == "" {
		return nil, fmt.Errorf("EntityID must not be empty")
	}

	logoutResponse := &etree.Element{
		Space: "samlp",
		Tag:   "LogoutResponse",
	}

	logoutResponse.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	logoutResponse.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")

	arId := uuid.NewV4()

	logoutResponse.CreateAttr("ID", "_"+arId.String())
	logoutResponse.CreateAttr("Version", "2.0")
	logoutResponse.CreateAttr("IssueInstant", sp.now().UTC().Format(saml2.IssueInstantFormat))
	logoutResponse.CreateAttr("Destination", sp.IDPSLOURL)
	logoutResponse.CreateAttr("InResponseTo", reqID)

	logoutResponse.CreateElement("saml:Issuer").SetText(sp.EntityID)

	status := logoutResponse.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", statusCodeValue)

	doc := etree.NewDocument()

	if includeSig {
		signed, err := sp.SignLogoutResponse(logoutResponse)
		if err != nil {
			return nil, err
		}

		doc.SetRoot(signed)
	} else {
		doc.SetRoot(logoutResponse)
	}
	return doc, nil
}
// BuildLogoutResponseDocument builds a signed LogoutResponse XML document
// with the given status code and InResponseTo value.
func (sp *ServiceProvider) BuildLogoutResponseDocument(status string, reqID string) (*etree.Document, error) {
	return sp.buildLogoutResponse(status, reqID, true)
}

// BuildLogoutResponseDocumentNoSig builds a LogoutResponse XML document
// without an embedded signature.
func (sp *ServiceProvider) BuildLogoutResponseDocumentNoSig(status string, reqID string) (*etree.Document, error) {
	return sp.buildLogoutResponse(status, reqID, false)
}

// SignLogoutResponse signs a LogoutResponse element, placing the Signature
// element after the Issuer per the SAML schema.
func (sp *ServiceProvider) SignLogoutResponse(el *etree.Element) (*etree.Element, error) {
	signer, err := sp.Signer()
	if err != nil {
		return nil, err
	}
	signed, err := signer.SignEnveloped(el)
	if err != nil {
		return nil, err
	}

	// SignEnveloped appends the signature as the last child.
	// Per the SAML schema, signature must come right after the Issuer.
	children := signed.ChildElements()
	if len(children) >= 2 {
		sigEl := children[len(children)-1]
		signed.RemoveChild(sigEl)

		var newChildren []etree.Token
		newChildren = append(newChildren, signed.Child[0])
		newChildren = append(newChildren, sigEl)
		newChildren = append(newChildren, signed.Child[1:]...)
		signed.Child = newChildren
	}

	return signed, nil
}

func (sp *ServiceProvider) buildLogoutResponseBodyPostFromDocument(relayState string, doc *etree.Document) ([]byte, error) {
	respBuf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return saml2.BuildPOSTForm(sp.IDPSLOURL, "SAMLResponse", base64.StdEncoding.EncodeToString(respBuf), relayState)
}

// BuildLogoutResponseBodyPostFromDocument builds an HTML auto-submit POST form
// containing the LogoutResponse for the HTTP-POST binding.
func (sp *ServiceProvider) BuildLogoutResponseBodyPostFromDocument(relayState string, doc *etree.Document) ([]byte, error) {
	return sp.buildLogoutResponseBodyPostFromDocument(relayState, doc)
}
