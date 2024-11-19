package saml2

import (
	"bytes"
	"encoding/base64"
	"github.com/beevik/etree"
	"github.com/frozenchickenx/gosaml2/uuid"
	"html/template"
)

type SAMLErrorResponseData struct {
	AssertionConsumerURL string
	ErrorMessage         string
	IssuerName           string
	RequestID            string
	IsRequesterError     bool
	IsLegacyFormat       bool
}

func (sp *SAMLServiceProvider) buildErrorResponse(errorRespData SAMLErrorResponseData, includeSig bool) (*etree.Document, error) {
	errorResponse := &etree.Element{
		Space: "saml2p",
		Tag:   ResponseTag,
	}

	errorResponse.CreateAttr("xmlns:saml2p", SAMLProtocolNamespace)

	errorResponse.CreateAttr(IDAttr, "_"+uuid.NewV4().String())
	errorResponse.CreateAttr(VersionAttr, "2.0")
	errorResponse.CreateAttr(DestinationAttr, errorRespData.AssertionConsumerURL)
	errorResponse.CreateAttr(IssueInstantAttr, sp.Clock.Now().UTC().Format(issueInstantFormat))
	errorResponse.CreateAttr(InResponseToAttr, errorRespData.RequestID)

	issuer := errorResponse.CreateElement("saml2:Issuer")
	issuer.CreateAttr("xmlns:saml2", SAMLAssertionNamespace)
	issuer.SetText(errorRespData.IssuerName)
	if errorRespData.IsLegacyFormat {
		issuer.CreateAttr(FormatAttr, NameIDFormatEntity)
	}

	status := errorResponse.CreateElement("saml2p:Status")
	responder := status.CreateElement("saml2p:StatusCode")
	if errorRespData.IsRequesterError {
		responder.CreateAttr(ValueAttr, StatusCodeRequester)
	} else {
		responder.CreateAttr(ValueAttr, StatusCodeResponder)
	}
	statusCode := responder.CreateElement("saml2p:StatusCode")
	statusCode.CreateAttr(ValueAttr, StatusCodeDenied)

	statusMessage := status.CreateElement("saml2p:StatusMessage")
	statusMessage.SetText(errorRespData.ErrorMessage)

	doc := etree.NewDocument()

	if includeSig {
		signed, err := sp.SignResponse(errorResponse)
		if err != nil {
			return nil, err
		}

		doc.SetRoot(signed)
	} else {
		doc.SetRoot(errorResponse)
	}
	return doc, nil
}
func (sp *SAMLServiceProvider) BuildErrorResponseDocument(errorRespData SAMLErrorResponseData) (*etree.Document, error) {
	return sp.buildErrorResponse(errorRespData, true)
}

func (sp *SAMLServiceProvider) BuildErrorResponseDocumentNoSig(errorRespData SAMLErrorResponseData) (*etree.Document, error) {
	return sp.buildErrorResponse(errorRespData, false)
}

func (sp *SAMLServiceProvider) BuildErrorResponseBodyPostFromDocument(relayState string, endpointURL string, doc *etree.Document) ([]byte, error) {
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
