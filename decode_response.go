package saml2

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func (sp *SAMLServiceProvider) validationContext() *dsig.ValidationContext {
	ctx := dsig.NewDefaultValidationContext(sp.IDPCertificateStore)
	ctx.Clock = sp.Clock
	return ctx
}

//ValidateEncodedResponse both decodes and validates, based on SP
//configuration, an encoded, signed response. It will also appropriately
//decrypt a response if the assertion was encrypted
func (sp *SAMLServiceProvider) ValidateEncodedResponse(encodedResponse string) (*etree.Element, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	err = doc.ReadFromBytes(raw)
	if err != nil {
		return nil, err
	}

	response, err := sp.validationContext().Validate(doc.Root())
	if err != nil && !sp.SkipSignatureValidation || response == nil {
		// Attempt to verify the assertion's signature
		assertionElement := doc.Root().FindElement(AssertionTag)
		if assertionElement == nil {
			return nil, err
		}

		response, err = sp.validationContext().Validate(assertionElement)
		if err != nil && !sp.SkipSignatureValidation || response == nil {
			return nil, err
		}

		doc.RemoveChild(assertionElement)
		doc.AddChild(response)
		response = doc.Root()
	}

	err = sp.Validate(response)
	if err == nil {
		//If there was no error, then return the response
		return response, nil
	}

	//If an error aside from missing assertion, return it.
	if err != ErrMissingAssertion {
		return nil, err
	}

	//If the error indicated a missing assertion, proceed to attempt decryption
	//of encrypted assertion.
	res, err := NewResponseFromReader(bytes.NewReader(raw))

	if err != nil {
		return nil, fmt.Errorf("Error getting response: %v", err)
	}

	//This is the tls.Certificate we'll use to decrypt
	var decryptCert tls.Certificate

	switch crt := sp.SPKeyStore.(type) {
	case dsig.TLSCertKeyStore:
		//Get the tls.Certificate directly if possible
		decryptCert = tls.Certificate(crt)
	default:
		//Otherwise, construct one from the results of GetKeyPair
		pk, cert, err := sp.SPKeyStore.GetKeyPair()
		if err != nil {
			return nil, fmt.Errorf("error getting keypair: %v", err)
		}

		decryptCert = tls.Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  pk,
		}
	}

	//Decrypt the xml contents of the assertion
	docBytes, err := res.Decrypt(decryptCert)

	if err != nil {
		return nil, fmt.Errorf("Error decrypting assertion: %v", err)
	}

	//Read the assertion and return it
	resDoc := etree.NewDocument()
	err = resDoc.ReadFromBytes(docBytes)

	if err != nil {
		return nil, fmt.Errorf("Error reading decrypted assertion: %v", err)
	}

	el := etree.NewElement("DecryptedAssertion")
	el.AddChild(resDoc.Root())

	return el, nil
}
