package saml2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/beevik/etree"
	"github.com/russellhaering/gosaml2/uuid"
)

func (sp *SAMLServiceProvider) ResolveArtifact(artifact string) (*AssertionInfo, error) {
	if sp.HTTPClient == nil {
		return nil, errors.New("HTTPClient must be set for artifact binding")
	}
	request, err := sp.buildResolveRequest(artifact)
	if err != nil {
		return nil, err
	}
	post, err := http.NewRequest("POST", sp.IdentityProviderArtifactResolutionServiceURL, request)
	if err != nil {
		return nil, err
	}
	post.Header.Add("Content-Type", "text/xml")
	post.Header.Add("SOAPAction", "http://www.oasis-open.org/committees/security")
	resp, err := sp.HTTPClient.Do(post)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code from artifact resolve request %d", resp.StatusCode)
	}
	// Buffer the response and base64 encode it.
	// It's not ideal, but existing parsing methods expect it to be encoded.
	// Attempting to minimize change for now.
	doc := etree.NewDocument()
	doc.ReadFrom(resp.Body)
	el := doc.FindElement("./Envelope/Body/ArtifactResponse/Response")
	doc = etree.NewDocument()
	doc.SetRoot(el)
	var buffer bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buffer)
	doc.WriteTo(encoder)
	encoder.Close()
	return sp.RetrieveAssertionInfo(buffer.String())
}

func (sp *SAMLServiceProvider) buildResolveRequest(artifact string) (io.Reader, error) {
	envelope := &etree.Element{
		Space: "soap-env",
		Tag:   "Envelope",
	}
	envelope.CreateAttr("xmlns:soap-env", "http://schemas.xmlsoap.org/soap/envelope/")
	body := envelope.CreateElement("soap-env:Body")
	artifactResolve := &etree.Element{
		Space: "samlp",
		Tag:   "ArtifactResolve",
	}
	artifactResolve.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	artifactResolve.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")

	arID := uuid.NewV4()
	artifactResolve.CreateAttr("ID", "_"+arID.String())
	artifactResolve.CreateAttr("Version", "2.0")
	artifactResolve.CreateAttr("IssueInstant", sp.Clock.Now().UTC().Format(issueInstantFormat))

	// NOTE(russell_h): In earlier versions we mistakenly sent the IdentityProviderIssuer
	// in the AuthnRequest. For backwards compatibility we will fall back to that
	// behavior when ServiceProviderIssuer isn't set.
	if sp.ServiceProviderIssuer != "" {
		artifactResolve.CreateElement("saml:Issuer").SetText(sp.ServiceProviderIssuer)
	} else {
		artifactResolve.CreateElement("saml:Issuer").SetText(sp.IdentityProviderIssuer)
	}

	artifactResolve.CreateElement("samlp:Artifact").SetText(artifact)

	// TODO should really change this method name
	signed, err := sp.SignAuthnRequest(artifactResolve)
	if err != nil {
		return nil, err
	}

	body.AddChild(signed)
	doc := etree.NewDocument()
	doc.SetRoot(envelope)
	message, err := doc.WriteToString()
	if err != nil {
		return nil, err
	}

	return strings.NewReader(message), nil
}
