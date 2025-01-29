package saml2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/beevik/etree"
	"github.com/frozenchickenx/gosaml2/uuid"
	"github.com/frozenchickenx/gosaml2/xmlenc"
	"html/template"
	"time"
)

type SAMLResponseData struct {
	AssertionConsumerURL string
	ConcurrencyRule      string
	Email                string
	EToken               string
	FirstName            string
	IssuerName           string
	LastName             string
	NameID               string
	Picker               string
	RequestID            string
	SiteID               string
	SPID                 string
	ZipCode              string
	IsLegacyIssuerFormat bool
	NotAfter             time.Time
}

const (
	_attrFirstName       = "firstName"
	_attrLastName        = "lastName"
	_attrEmail           = "email"
	_attrEToken          = "eToken"
	_attrPicker          = "picker"
	_attrSPID            = "SPID"
	_attrZipCode         = "ZipCode"
	_attrConcurrencyRule = "concurrency_rule"
)

// todo godocs and break into smaller functions
func (sp *SAMLServiceProvider) buildResponse(respData SAMLResponseData) (*etree.Document, error) {
	resp := &etree.Element{
		Space: "saml2p",
		Tag:   ResponseTag,
	}

	responseUUID := uuid.NewV4().String()
	instant := sp.Clock.Now().UTC().Format(issueInstantFormat)

	resp.CreateAttr("xmlns:saml2p", SAMLProtocolNamespace)

	resp.CreateAttr(IDAttr, "_"+responseUUID)
	resp.CreateAttr(VersionAttr, "2.0")
	resp.CreateAttr(DestinationAttr, respData.AssertionConsumerURL)
	resp.CreateAttr(IssueInstantAttr, instant)
	resp.CreateAttr(InResponseToAttr, respData.RequestID)

	issuer := resp.CreateElement("saml2:Issuer")
	issuer.CreateAttr("xmlns:saml2", SAMLAssertionNamespace)
	issuer.SetText(respData.IssuerName)
	if respData.IsLegacyIssuerFormat {
		issuer.CreateAttr(FormatAttr, NameIDFormatEntity)
	}

	status := resp.CreateElement("saml2p:Status")
	statusCode := status.CreateElement("saml2p:StatusCode")
	statusCode.CreateAttr(ValueAttr, StatusCodeSuccess)

	// assertion
	assertion := etree.NewElement("saml2:Assertion")
	assertion.CreateAttr("xmlns:saml2", SAMLAssertionNamespace)
	assertion.CreateAttr(IDAttr, "_"+responseUUID)
	assertion.CreateAttr(IssueInstantAttr, instant)
	assertion.CreateAttr(VersionAttr, "2.0")
	assertion.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	issuer.SetText(respData.IssuerName)
	if respData.IsLegacyIssuerFormat {
		issuer.CreateAttr(FormatAttr, NameIDFormatEntity)
	}
	// subject
	subject := assertion.CreateElement("saml2:Subject")
	nameID := subject.CreateElement("saml2:NameID")
	nameID.CreateAttr(FormatAttr, NameIDFormatPersistent)
	nameID.SetText(respData.NameID)
	subjectConfirmation := subject.CreateElement("saml2:SubjectConfirmation")
	subjectConfirmation.CreateAttr(MethodAttr, MethodBearer)
	scData := subjectConfirmation.CreateElement("saml2:SubjectConfirmationData")
	scData.CreateAttr(InResponseToAttr, respData.RequestID)
	scData.CreateAttr(NotOnOrAfterAttr, respData.NotAfter.UTC().Format(issueInstantFormat))
	scData.CreateAttr(RecipientAttr, respData.AssertionConsumerURL)

	//conditions
	conditions := assertion.CreateElement("saml2:Conditions")
	conditions.CreateAttr(NotBeforeAttr, instant)
	conditions.CreateAttr(NotOnOrAfterAttr, respData.NotAfter.UTC().Format(issueInstantFormat))
	audienceRestriction := conditions.CreateElement("saml2:AudienceRestriction")
	audience := audienceRestriction.CreateElement("saml2:Audience")
	audience.SetText(respData.SiteID)

	//statements
	authnStatement := assertion.CreateElement("saml2:AuthnStatement")
	authnStatement.CreateAttr(AuthnInstantAttr, instant)
	authnStatement.CreateAttr(SessionNotOnOrAfterAttr, respData.NotAfter.UTC().Format(issueInstantFormat))
	authnCtx := authnStatement.CreateElement("saml2:AuthnContext")
	authnCtxClassRef := authnCtx.CreateElement("saml2:AuthnContextClassRef")
	authnCtxClassRef.SetText(ClassesAuthnContextPassword)

	attributeStatements := assertion.CreateElement("saml2:AttributeStatement")
	attributeStatements.AddChild(buildAttribute(attributeStatements, _attrFirstName, respData.FirstName))
	attributeStatements.AddChild(buildAttribute(attributeStatements, _attrLastName, respData.LastName))
	attributeStatements.AddChild(buildAttribute(attributeStatements, _attrZipCode, respData.ZipCode))
	attributeStatements.AddChild(buildAttribute(attributeStatements, _attrEToken, respData.EToken))
	attributeStatements.AddChild(buildAttribute(attributeStatements, _attrPicker, respData.Picker))
	attributeStatements.AddChild(buildAttribute(attributeStatements, _attrConcurrencyRule, respData.ConcurrencyRule))
	attributeStatements.AddChild(buildAttribute(attributeStatements, _attrSPID, respData.SPID))
	attributeStatements.AddChild(buildAttribute(attributeStatements, _attrEmail, respData.Email))

	signedAssertion, err := sp.SignResponse(assertion)
	if err != nil {
		return nil, err
	}

	certs, err := sp.IDPCertificateStore.Certificates()
	if err != nil {
		return nil, err
	}

	if len(certs) <= 0 {
		return nil, fmt.Errorf("no certificates found in IDPCertificateStore")
	}

	assertionDoc := etree.NewDocument()
	assertionDoc.SetRoot(signedAssertion)
	assertionBytes, err := assertionDoc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	encryptedDataAndKey, err := xmlenc.PKCS1v15().Encrypt(certs[0], assertionBytes, nil)
	if err != nil {
		return nil, err
	}

	encryptedAssertion := etree.NewElement("saml2:EncryptedAssertion")
	encryptedAssertion.CreateAttr("xmlns:saml2", SAMLAssertionNamespace)
	for _, el := range encryptedDataAndKey {
		encryptedAssertion.AddChild(el)
	}

	resp.AddChild(encryptedAssertion)

	doc := etree.NewDocument()
	doc.SetRoot(resp)

	return doc, nil
}
func (sp *SAMLServiceProvider) BuildResponseDocument(respData SAMLResponseData) (*etree.Document, error) {
	return sp.buildResponse(respData)
}

func (sp *SAMLServiceProvider) BuildResponseBodyPostFromDocument(relayState string, endpointURL string, doc *etree.Document) ([]byte, error) {
	respBuf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	encodedRespBuf := base64.StdEncoding.EncodeToString(respBuf)

	var tmpl *template.Template
	var rv bytes.Buffer

	if relayState != "" {
		// this is based on the template from java org.opensaml library saml2-post-binding.vm
		tmpl = template.Must(template.New("saml-post-form").Parse(
			`<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">` +
				`<body onload="document.forms[0].submit()">` +
				`<noscript><p>` +
				`<strong>Note:</strong>` +
				`Since your browser does not support JavaScript,you must press the Continue button once to proceed.` +
				`</p></noscript>` +
				`<form method="post" action="{{.URL}}">` +
				`<div>` +
				`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
				`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
				`</div>` +
				`<noscript>` +
				`<div>` +
				`<input type="submit" value="Continue"/>` +
				`</div>` +
				`</noscript>` +
				`</form>` +
				`</body>` +
				`</html>`))
		data := struct {
			URL          string
			SAMLResponse string
			RelayState   string
		}{
			URL:          endpointURL,
			SAMLResponse: encodedRespBuf,
			RelayState:   relayState,
		}
		if err = tmpl.Execute(&rv, data); err != nil {
			return nil, err
		}
	} else {
		tmpl = template.Must(template.New("saml-post-form").Parse(
			`<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">` +
				`<body onload="document.forms[0].submit()">` +
				`<noscript><p>` +
				`<strong>Note:</strong>` +
				`Since your browser does not support JavaScript,you must press the Continue button once to proceed.` +
				`</p></noscript>` +
				`<form method="post" action="{{.URL}}">` +
				`<div>` +
				`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
				`</div>` +
				`<noscript>` +
				`<div>` +
				`<input type="submit" value="Continue"/>` +
				`</div>` +
				`</noscript>` +
				`</form>` +
				`</body>` +
				`</html>`))
		data := struct {
			URL          string
			SAMLResponse string
		}{
			URL:          sp.IdentityProviderSLOURL,
			SAMLResponse: encodedRespBuf,
		}

		if err = tmpl.Execute(&rv, data); err != nil {
			return nil, err
		}
	}

	return rv.Bytes(), nil
}

func buildAttribute(e *etree.Element, attrName, attrValue string) *etree.Element {
	attr := e.CreateElement("saml2:Attribute")
	attr.CreateAttr("Name", attrName)
	av := attr.CreateElement("saml2:AttributeValue")
	av.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	av.CreateAttr("xsi:type", "xs:string")
	av.SetText(attrValue)

	return attr
}
