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
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/uuid"
)

func (sp *ServiceProvider) buildAuthnRequest(includeSig bool) (*etree.Document, error) {
	if sp.EntityID == "" {
		return nil, fmt.Errorf("EntityID must not be empty")
	}

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	authnRequest.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	authnRequest.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")

	arId := uuid.NewV4()

	authnRequest.CreateAttr("ID", "_"+arId.String())
	authnRequest.CreateAttr("Version", "2.0")
	authnRequest.CreateAttr("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
	authnRequest.CreateAttr("AssertionConsumerServiceURL", sp.ACSURL)
	authnRequest.CreateAttr("IssueInstant", sp.now().UTC().Format(saml2.IssueInstantFormat))
	authnRequest.CreateAttr("Destination", sp.IDPSSOURL)
	if sp.ForceAuthn {
		authnRequest.CreateAttr("ForceAuthn", "true")
	}
	if sp.IsPassive {
		authnRequest.CreateAttr("IsPassive", "true")
	}

	authnRequest.CreateElement("saml:Issuer").SetText(sp.EntityID)

	nameIdPolicy := authnRequest.CreateElement("samlp:NameIDPolicy")
	nameIdPolicy.CreateAttr("AllowCreate", "true")
	if sp.NameIDFormat != "" {
		nameIdPolicy.CreateAttr("Format", sp.NameIDFormat)
	}

	if sp.RequestedAuthnContext != nil {
		requestedAuthnContext := authnRequest.CreateElement("samlp:RequestedAuthnContext")
		requestedAuthnContext.CreateAttr("Comparison", sp.RequestedAuthnContext.Comparison)

		for _, context := range sp.RequestedAuthnContext.Contexts {
			authnContextClassRef := requestedAuthnContext.CreateElement("saml:AuthnContextClassRef")
			authnContextClassRef.SetText(context)
		}
	}

	doc := etree.NewDocument()

	// Only POST binding includes <Signature> in <AuthnRequest> (includeSig)
	if sp.SignAuthnRequests && includeSig {
		signed, err := sp.SignAuthnRequest(authnRequest)
		if err != nil {
			return nil, err
		}

		doc.SetRoot(signed)
	} else {
		doc.SetRoot(authnRequest)
	}
	return doc, nil
}

func (sp *ServiceProvider) BuildAuthRequestDocument() (*etree.Document, error) {
	return sp.buildAuthnRequest(true)
}

func (sp *ServiceProvider) BuildAuthRequestDocumentNoSig() (*etree.Document, error) {
	return sp.buildAuthnRequest(false)
}

// SignAuthnRequest takes a document, builds a signature, creates another document
// and inserts the signature in it. According to the schema, the position of the
// signature is right after the Issuer [1] then all other children.
//
// [1] https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd
func (sp *ServiceProvider) SignAuthnRequest(el *etree.Element) (*etree.Element, error) {
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
	// Rearrange: [issuer, sig, ...rest]
	children := signed.ChildElements()
	if len(children) >= 2 {
		// Find the Signature element (last child added by SignEnveloped)
		sigEl := children[len(children)-1]
		signed.RemoveChild(sigEl)

		// Rebuild: issuer first, then sig, then rest
		var newChildren []etree.Token
		newChildren = append(newChildren, signed.Child[0]) // issuer
		newChildren = append(newChildren, sigEl)           // signature
		newChildren = append(newChildren, signed.Child[1:]...) // rest
		signed.Child = newChildren
	}

	return signed, nil
}

// BuildAuthRequest builds <AuthnRequest> for identity provider
func (sp *ServiceProvider) BuildAuthRequest() (string, error) {
	doc, err := sp.BuildAuthRequestDocument()
	if err != nil {
		return "", err
	}
	return doc.WriteToString()
}

func (sp *ServiceProvider) buildAuthURLFromDocument(relayState, binding string, doc *etree.Document) (string, error) {
	parsedUrl, err := url.Parse(sp.IDPSSOURL)
	if err != nil {
		return "", err
	}

	authnRequest, err := doc.WriteToString()
	if err != nil {
		return "", err
	}

	buf := &bytes.Buffer{}

	fw, err := flate.NewWriter(buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("flate NewWriter error: %v", err)
	}

	_, err = fw.Write([]byte(authnRequest))
	if err != nil {
		return "", fmt.Errorf("flate.Writer Write error: %v", err)
	}

	err = fw.Close()
	if err != nil {
		return "", fmt.Errorf("flate.Writer Close error: %v", err)
	}

	qs := parsedUrl.Query()

	qs.Add("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))

	if relayState != "" {
		qs.Add("RelayState", relayState)
	}

	if sp.SignAuthnRequests && binding == saml2.BindingHttpRedirect {
		// Sign URL encoded query (see Section 3.4.4.1 DEFLATE Encoding of saml-bindings-2.0-os.pdf)
		signer, err := sp.Signer()
		if err != nil {
			return "", fmt.Errorf("unable to get signer: %v", err)
		}
		sigAlg := saml2.SignatureMethodIdentifier(signer.Key, signer.Hash)
		qs.Add("SigAlg", sigAlg)
		var rawSignature []byte
		if rawSignature, err = signer.SignString(saml2.SignatureInputString(qs.Get("SAMLRequest"), qs.Get("RelayState"), qs.Get("SigAlg"))); err != nil {
			return "", fmt.Errorf("unable to sign query string of redirect URL: %v", err)
		}

		// Now add base64 encoded Signature
		qs.Add("Signature", base64.StdEncoding.EncodeToString(rawSignature))
	}

	//Here the parameters may appear in any order.
	parsedUrl.RawQuery = qs.Encode()
	return parsedUrl.String(), nil
}

func (sp *ServiceProvider) BuildAuthURLFromDocument(relayState string, doc *etree.Document) (string, error) {
	return sp.buildAuthURLFromDocument(relayState, saml2.BindingHttpPost, doc)
}

func (sp *ServiceProvider) BuildAuthURLRedirect(relayState string, doc *etree.Document) (string, error) {
	return sp.buildAuthURLFromDocument(relayState, saml2.BindingHttpRedirect, doc)
}

func (sp *ServiceProvider) buildAuthBodyPostFromDocument(relayState string, doc *etree.Document) ([]byte, error) {
	reqBuf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return saml2.BuildPOSTForm(sp.IDPSSOURL, "SAMLRequest", base64.StdEncoding.EncodeToString(reqBuf), relayState)
}

//BuildAuthBodyPost builds the POST body to be sent to IDP.
func (sp *ServiceProvider) BuildAuthBodyPost(relayState string) ([]byte, error) {
	var doc *etree.Document
	var err error

	if sp.SignAuthnRequests {
		doc, err = sp.BuildAuthRequestDocument()
	} else {
		doc, err = sp.BuildAuthRequestDocumentNoSig()
	}

	if err != nil {
		return nil, err
	}

	return sp.buildAuthBodyPostFromDocument(relayState, doc)
}

//BuildAuthBodyPostFromDocument builds the POST body to be sent to IDP.
//It takes the AuthnRequest xml as input.
func (sp *ServiceProvider) BuildAuthBodyPostFromDocument(relayState string, doc *etree.Document) ([]byte, error) {
	return sp.buildAuthBodyPostFromDocument(relayState, doc)
}

// BuildAuthURL builds redirect URL to be sent to principal
func (sp *ServiceProvider) BuildAuthURL(relayState string) (string, error) {
	doc, err := sp.BuildAuthRequestDocument()
	if err != nil {
		return "", err
	}
	return sp.BuildAuthURLFromDocument(relayState, doc)
}

// AuthRedirect takes a ResponseWriter and Request from an http interaction and
// redirects to the ServiceProvider's configured IdP, including the
// relayState provided, if any.
func (sp *ServiceProvider) AuthRedirect(w http.ResponseWriter, r *http.Request, relayState string) (err error) {
	url, err := sp.BuildAuthURL(relayState)
	if err != nil {
		return err
	}

	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

func (sp *ServiceProvider) buildLogoutRequest(includeSig bool, nameID string, sessionIndex string) (*etree.Document, error) {
	if sp.EntityID == "" {
		return nil, fmt.Errorf("EntityID must not be empty")
	}

	logoutRequest := &etree.Element{
		Space: "samlp",
		Tag:   "LogoutRequest",
	}

	logoutRequest.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	logoutRequest.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")

	arId := uuid.NewV4()

	logoutRequest.CreateAttr("ID", "_"+arId.String())
	logoutRequest.CreateAttr("Version", "2.0")
	logoutRequest.CreateAttr("IssueInstant", sp.now().UTC().Format(saml2.IssueInstantFormat))
	logoutRequest.CreateAttr("Destination", sp.IDPSLOURL)

	logoutRequest.CreateElement("saml:Issuer").SetText(sp.EntityID)

	nameIdEl := logoutRequest.CreateElement("saml:NameID")
	nameIdEl.SetText(nameID)
	nameIdEl.CreateAttr("Format", sp.NameIDFormat)

	nameIdEl = logoutRequest.CreateElement("samlp:SessionIndex")
	nameIdEl.SetText(sessionIndex)

	doc := etree.NewDocument()

	if includeSig {
		signed, err := sp.SignLogoutRequest(logoutRequest)
		if err != nil {
			return nil, err
		}

		doc.SetRoot(signed)
	} else {
		doc.SetRoot(logoutRequest)
	}

	return doc, nil
}

func (sp *ServiceProvider) SignLogoutRequest(el *etree.Element) (*etree.Element, error) {
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

func (sp *ServiceProvider) BuildLogoutRequestDocumentNoSig(nameID string, sessionIndex string) (*etree.Document, error) {
	return sp.buildLogoutRequest(false, nameID, sessionIndex)
}

func (sp *ServiceProvider) BuildLogoutRequestDocument(nameID string, sessionIndex string) (*etree.Document, error) {
	return sp.buildLogoutRequest(true, nameID, sessionIndex)
}

//BuildLogoutBodyPostFromDocument builds the POST body to be sent to IDP.
//It takes the LogoutRequest xml as input.
func (sp *ServiceProvider) BuildLogoutBodyPostFromDocument(relayState string, doc *etree.Document) ([]byte, error) {
	return sp.buildLogoutBodyPostFromDocument(relayState, doc)
}

func (sp *ServiceProvider) buildLogoutBodyPostFromDocument(relayState string, doc *etree.Document) ([]byte, error) {
	reqBuf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return saml2.BuildPOSTForm(sp.IDPSLOURL, "SAMLRequest", base64.StdEncoding.EncodeToString(reqBuf), relayState)
}

func (sp *ServiceProvider) BuildLogoutURLRedirect(relayState string, doc *etree.Document) (string, error) {
	return sp.buildLogoutURLFromDocument(relayState, saml2.BindingHttpRedirect, doc)
}

func (sp *ServiceProvider) buildLogoutURLFromDocument(relayState, binding string, doc *etree.Document) (string, error) {
	parsedUrl, err := url.Parse(sp.IDPSLOURL)
	if err != nil {
		return "", err
	}

	logoutRequest, err := doc.WriteToString()
	if err != nil {
		return "", err
	}

	buf := &bytes.Buffer{}

	fw, err := flate.NewWriter(buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("flate NewWriter error: %v", err)
	}

	_, err = fw.Write([]byte(logoutRequest))
	if err != nil {
		return "", fmt.Errorf("flate.Writer Write error: %v", err)
	}

	err = fw.Close()
	if err != nil {
		return "", fmt.Errorf("flate.Writer Close error: %v", err)
	}

	qs := parsedUrl.Query()

	qs.Add("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))

	if relayState != "" {
		qs.Add("RelayState", relayState)
	}

	if binding == saml2.BindingHttpRedirect {
		// Sign URL encoded query (see Section 3.4.4.1 DEFLATE Encoding of saml-bindings-2.0-os.pdf)
		signer, err := sp.Signer()
		if err != nil {
			return "", fmt.Errorf("unable to get signer: %v", err)
		}
		sigAlg := saml2.SignatureMethodIdentifier(signer.Key, signer.Hash)
		qs.Add("SigAlg", sigAlg)
		var rawSignature []byte
		var orderedParams = []string{"SAMLRequest", "RelayState", "SigAlg"}

		var paramValueMap = make(map[string]string)
		paramValueMap["SAMLRequest"] = base64.StdEncoding.EncodeToString(buf.Bytes())
		if relayState != "" {
			paramValueMap["RelayState"] = relayState
		}
		paramValueMap["SigAlg"] = sigAlg

		ss := ""

		for _, k := range orderedParams {
			v, ok := paramValueMap[k]
			if ok {
				u := url.Values{}
				u.Add(k, v)
				e := u.Encode()
				if ss != "" {
					ss += "&" + e
				} else {
					ss = e
				}
			}
		}

		if rawSignature, err = signer.SignString(ss); err != nil {
			return "", fmt.Errorf("unable to sign query string of redirect URL: %v", err)
		}

		// Now add base64 encoded Signature
		qs.Add("Signature", base64.StdEncoding.EncodeToString(rawSignature))
	}

	//Here the parameters may appear in any order.
	parsedUrl.RawQuery = qs.Encode()
	return parsedUrl.String(), nil
}
