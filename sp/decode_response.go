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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"

	"encoding/xml"

	"github.com/beevik/etree"
	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/types"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
)

const (
	defaultMaxDecompressedResponseSize = 5 * 1024 * 1024
)

func (sp *ServiceProvider) verifier() *dsig.Verifier {
	v := &dsig.Verifier{
		TrustedCerts: sp.IDPCertificates,
		AllowSHA1:    sp.AllowSHA1,
	}
	if sp.Clock != nil {
		v.Clock = sp.Clock
	}
	return v
}

// validateResponseAttributes validates a SAML Response's tag and attributes. It does
// not inspect child elements of the Response at all.
func (sp *ServiceProvider) validateResponseAttributes(response *types.Response) error {
	if response.Destination != "" && response.Destination != sp.ACSURL {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadDestination,
			Detail: fmt.Sprintf("expected %s, got %s", sp.ACSURL, response.Destination),
		}
	}

	if response.Version != "2.0" {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadVersion,
			Detail: fmt.Sprintf("expected 2.0, got %s", response.Version),
		}
	}

	return nil
}

// validateLogoutResponseAttributes validates a SAML Response's tag and attributes. It does
// not inspect child elements of the Response at all.
func (sp *ServiceProvider) validateLogoutResponseAttributes(response *types.LogoutResponse) error {
	if response.Destination != "" && response.Destination != sp.SLOURL {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadDestination,
			Detail: fmt.Sprintf("expected %s, got %s", sp.SLOURL, response.Destination),
		}
	}

	if response.Version != "2.0" {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadVersion,
			Detail: fmt.Sprintf("expected 2.0, got %s", response.Version),
		}
	}

	return nil
}

func xmlUnmarshalElement(el *etree.Element, obj interface{}) error {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	data, err := doc.WriteToBytes()
	if err != nil {
		return err
	}

	err = xml.Unmarshal(data, obj)
	if err != nil {
		return err
	}
	return nil
}

func (sp *ServiceProvider) getDecryptCert() (*tls.Certificate, error) {
	if sp.SPKeyStore == nil {
		return nil, fmt.Errorf("no decryption certs available")
	}

	decryptCert := tls.Certificate{
		Certificate: [][]byte{sp.SPKeyStore.Cert},
		PrivateKey:  sp.SPKeyStore.Signer,
	}

	if sp.ValidateEncryptionCert {
		// Check Validity period of certificate
		if len(decryptCert.Certificate) < 1 || len(decryptCert.Certificate[0]) < 1 {
			return nil, fmt.Errorf("empty decryption cert")
		} else if cert, err := x509.ParseCertificate(decryptCert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("invalid x509 decryption cert: %v", err)
		} else {
			now := sp.now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return nil, fmt.Errorf("decryption cert is not valid at this time")
			}
		}
	}

	return &decryptCert, nil
}

func (sp *ServiceProvider) decryptAssertions(el *etree.Element) error {
	var decryptCert *tls.Certificate

	decryptAssertion := func(ctx dsig.NSContext, encryptedElement *etree.Element) error {
		if encryptedElement.Parent() != el {
			return fmt.Errorf("found encrypted assertion with unexpected parent element: %s", encryptedElement.Parent().Tag)
		}

		detached, err := dsig.NSDetach(ctx, encryptedElement) // make a detached copy
		if err != nil {
			return fmt.Errorf("unable to detach encrypted assertion: %v", err)
		}

		encryptedAssertion := &types.EncryptedAssertion{}
		err = xmlUnmarshalElement(detached, encryptedAssertion)
		if err != nil {
			return fmt.Errorf("unable to unmarshal encrypted assertion: %v", err)
		}

		if decryptCert == nil {
			decryptCert, err = sp.getDecryptCert()
			if err != nil {
				return fmt.Errorf("unable to get decryption certificate: %v", err)
			}
		}

		raw, derr := encryptedAssertion.DecryptBytes(decryptCert)
		if derr != nil {
			return fmt.Errorf("unable to decrypt encrypted assertion: %v", derr)
		}

		doc, _, err := parseResponse(raw, sp.MaximumDecompressedBodySize)
		if err != nil {
			return fmt.Errorf("unable to create element from decrypted assertion bytes: %v", err)
		}

		// Replace the original encrypted assertion with the decrypted one.
		if el.RemoveChild(encryptedElement) == nil {
			return fmt.Errorf("unable to remove encrypted assertion element")
		}

		el.AddChild(doc.Root())
		return nil
	}

	if err := dsig.NSFindIterate(el, saml2.SAMLAssertionNamespace, saml2.EncryptedAssertionTag, decryptAssertion); err != nil {
		return err
	} else {
		return nil
	}
}

func (sp *ServiceProvider) validateElementSignature(el *etree.Element) (*etree.Element, error) {
	result, err := sp.verifier().Verify(el)
	if err != nil {
		return nil, err
	}
	return result.Element, nil
}

// verifyAssertionSignaturesIfPresent iterates through assertions within a
// signed Response and verifies any that carry their own signatures.
func (sp *ServiceProvider) verifyAssertionSignaturesIfPresent(responseEl *etree.Element) error {
	verifyAssertion := func(ctx dsig.NSContext, assertionEl *etree.Element) error {
		if assertionEl.Parent() != responseEl {
			return nil
		}

		detached, err := dsig.NSDetach(ctx, assertionEl)
		if err != nil {
			return fmt.Errorf("unable to detach assertion for signature verification: %v", err)
		}

		result, err := sp.verifier().Verify(detached)
		if missing, err := saml2.IsSignatureMissing(err); missing {
			return nil
		} else if err != nil {
			return fmt.Errorf("assertion signature verification failed: %v", err)
		}

		if responseEl.RemoveChild(assertionEl) == nil {
			return fmt.Errorf("unable to remove unverified assertion element")
		}
		responseEl.AddChild(result.Element)
		return nil
	}

	return dsig.NSFindIterate(responseEl, saml2.SAMLAssertionNamespace, saml2.AssertionTag, verifyAssertion)
}

// ValidateEncodedResponse both decodes and validates, based on SP
// configuration, an encoded, signed response.
func (sp *ServiceProvider) ValidateEncodedResponse(ctx context.Context, encodedResponse string) (*types.Response, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}

	doc, unverifiedResponse, err := parseResponse(raw, sp.MaximumDecompressedBodySize)
	if err != nil {
		return nil, err
	}

	var responseSignatureValidated bool
	decodedResponse := &types.Response{}

	if sp.InsecureSkipSignatureValidation {
		err = xmlUnmarshalElement(unverifiedResponse, decodedResponse)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal response: %v", err)
		}

		decodedResponse.SignatureValidated = false
		if err := sp.Validate(decodedResponse); err != nil {
			return nil, err
		}
		if err := sp.validateInResponseTo(ctx, decodedResponse); err != nil {
			return nil, err
		}
		return decodedResponse, nil
	}

	signedResponseEl, err := sp.validateElementSignature(unverifiedResponse)

	if missing, err := saml2.IsSignatureMissing(err); missing {
		unverifiedResponse = doc.Root()
	} else if err != nil {
		return nil, err
	} else if signedResponseEl == nil {
		return nil, fmt.Errorf("missing transformed response")
	} else {
		err = sp.decryptAssertions(signedResponseEl)
		if err != nil {
			return nil, err
		}

		err = sp.verifyAssertionSignaturesIfPresent(signedResponseEl)
		if err != nil {
			return nil, err
		}

		responseSignatureValidated = true

		err = xmlUnmarshalElement(signedResponseEl, decodedResponse)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal response: %v", err)
		}
		decodedResponse.SignatureValidated = responseSignatureValidated

		if err := sp.Validate(decodedResponse); err != nil {
			return nil, err
		}
		if err := sp.validateInResponseTo(ctx, decodedResponse); err != nil {
			return nil, err
		}
		return decodedResponse, nil
	}

	err = xmlUnmarshalElement(unverifiedResponse, decodedResponse)
	if err != nil {
		return nil, err
	}

	decodedResponse.SignatureValidated = false
	decodedResponse.Assertions = []types.Assertion{}
	decodedResponse.EncryptedAssertions = []types.EncryptedAssertion{}

	err = sp.decryptAssertions(unverifiedResponse)
	if err != nil {
		return nil, err
	}

	addSignedAssertion := func(ctx dsig.NSContext, unverifiedAssertion *etree.Element) error {
		parent := unverifiedAssertion.Parent()
		if parent == nil {
			return fmt.Errorf("parent is nil")
		}
		if parent != unverifiedResponse {
			return fmt.Errorf("found assertion with unexpected parent element: %s", unverifiedAssertion.Parent().Tag)
		}

		detached, err := dsig.NSDetach(ctx, unverifiedAssertion)
		if err != nil {
			return fmt.Errorf("unable to detach unverified assertion: %v", err)
		}

		result, err := sp.verifier().Verify(detached)

		if err != nil {
			return err
		}

		decodedAssertion := &types.Assertion{}

		err = xmlUnmarshalElement(result.Element, decodedAssertion)
		if err != nil {
			return fmt.Errorf("unable to unmarshal assertion: %v", err)
		}

		decodedAssertion.SignatureValidated = true

		decodedResponse.Assertions = append(decodedResponse.Assertions, *decodedAssertion)

		return nil
	}

	if err := dsig.NSFindIterate(unverifiedResponse, saml2.SAMLAssertionNamespace, saml2.AssertionTag, addSignedAssertion); err != nil {
		return nil, err
	}

	if err := sp.Validate(decodedResponse); err != nil {
		return nil, err
	}
	if err := sp.validateInResponseTo(ctx, decodedResponse); err != nil {
		return nil, err
	}

	return decodedResponse, nil
}

// DecodeUnverifiedBaseResponse decodes several attributes from a SAML response for the purpose
// of determining how to validate the response.
func DecodeUnverifiedBaseResponse(encodedResponse string) (*types.UnverifiedBaseResponse, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}

	var response *types.UnverifiedBaseResponse
	var rawXML []byte

	err = maybeDeflate(raw, defaultMaxDecompressedResponseSize, func(maybeXML []byte) error {
		response = &types.UnverifiedBaseResponse{}
		rawXML = maybeXML
		return xml.Unmarshal(maybeXML, response)
	})
	if err != nil {
		return nil, err
	}

	response.Audiences = extractAudiences(rawXML)

	return response, nil
}

type unverifiedAudiences struct {
	Assertions []struct {
		Conditions struct {
			AudienceRestrictions []struct {
				Audiences []struct {
					Value string `xml:",chardata"`
				} `xml:"Audience"`
			} `xml:"AudienceRestriction"`
		} `xml:"Conditions"`
	} `xml:"Assertion"`
}

func extractAudiences(rawXML []byte) []string {
	var ua unverifiedAudiences
	_ = xml.Unmarshal(rawXML, &ua)

	seen := make(map[string]bool)
	var audiences []string
	for _, a := range ua.Assertions {
		for _, ar := range a.Conditions.AudienceRestrictions {
			for _, aud := range ar.Audiences {
				if aud.Value != "" && !seen[aud.Value] {
					seen[aud.Value] = true
					audiences = append(audiences, aud.Value)
				}
			}
		}
	}
	return audiences
}

func maybeDeflate(data []byte, maxSize int64, decoder func([]byte) error) error {
	err := decoder(data)
	if err == nil {
		return nil
	}

	if maxSize == 0 {
		maxSize = defaultMaxDecompressedResponseSize
	}

	lr := io.LimitReader(flate.NewReader(bytes.NewReader(data)), maxSize+1)

	deflated, err := io.ReadAll(lr)
	if err != nil {
		return err
	}

	if int64(len(deflated)) > maxSize {
		return fmt.Errorf("deflated response exceeds maximum size of %d bytes", maxSize)
	}

	return decoder(deflated)
}

func parseResponse(xml []byte, maxSize int64) (*etree.Document, *etree.Element, error) {
	var doc *etree.Document
	var rawXML []byte

	err := maybeDeflate(xml, maxSize, func(xml []byte) error {
		doc = etree.NewDocument()
		rawXML = xml
		return doc.ReadFromBytes(xml)
	})
	if err != nil {
		return nil, nil, err
	}

	el := doc.Root()
	if el == nil {
		return nil, nil, fmt.Errorf("unable to parse response")
	}

	err = rtvalidator.Validate(bytes.NewReader(rawXML))
	if err != nil {
		return nil, nil, err
	}

	return doc, el, nil
}

// DecodeUnverifiedLogoutResponse decodes several attributes from a SAML Logout response, without doing any verifications.
func DecodeUnverifiedLogoutResponse(encodedResponse string) (*types.LogoutResponse, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}

	var response *types.LogoutResponse

	err = maybeDeflate(raw, defaultMaxDecompressedResponseSize, func(maybeXML []byte) error {
		response = &types.LogoutResponse{}
		return xml.Unmarshal(maybeXML, response)
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (sp *ServiceProvider) ValidateEncodedLogoutResponsePOST(ctx context.Context, encodedResponse string) (*types.LogoutResponse, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}

	_, el, err := parseResponse(raw, sp.MaximumDecompressedBodySize)
	if err != nil {
		return nil, err
	}

	var responseSignatureValidated bool
	if !sp.InsecureSkipSignatureValidation {
		el, err = sp.validateElementSignature(el)
		if missing, err := saml2.IsSignatureMissing(err); missing {
			return nil, fmt.Errorf("logout response has no signature")
		} else if err != nil {
			return nil, err
		} else if el == nil {
			return nil, fmt.Errorf("missing transformed logout response")
		} else {
			responseSignatureValidated = true
		}
	}

	decodedResponse := &types.LogoutResponse{}
	err = xmlUnmarshalElement(el, decodedResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal logout response: %v", err)
	}
	decodedResponse.SignatureValidated = responseSignatureValidated

	err = sp.ValidateDecodedLogoutResponse(decodedResponse)
	if err != nil {
		return nil, err
	}

	return decodedResponse, nil
}
