package saml2

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	dsig "github.com/russellhaering/goxmldsig"
)

// GetKeyNameFromAuthNRequest takes a base 64 encoded SAML AuthNRequest and returns the key name.
func GetKeyNameFromAuthNRequest(encodedRequest string) (string, error) {
	var err error
	if strings.Contains(encodedRequest, "%") {
		encodedRequest, err = url.QueryUnescape(encodedRequest)
		if err != nil {
			return "", err
		}
	}

	raw, err := base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		return "", err
	}

	// Parse the raw request - parseResponse is generic
	_, el, err := parseResponse(raw, 0) // setting maxSize to 0 to use default value - 5 * 1024 * 1024
	if err != nil {
		return "", err
	}

	decodedRequest := &AuthNRequest{}
	err = xmlUnmarshalElement(el, decodedRequest)
	if err != nil {
		return "", fmt.Errorf("unable to unmarshal authn request: %v", err)
	}

	// attempt to extract key name from the request
	if decodedRequest.Signature != nil &&
		decodedRequest.Signature.KeyInfo != nil {
		return decodedRequest.Signature.KeyInfo.KeyName, nil
	}

	return "", fmt.Errorf("key name not found in the request")
}

// ParseAndValidateAuthNRequest takes a base64 encoded SAML AuthNRequest, decodes and validates it (including signature) and returns the parsed AuthNRequest.
func (sp *SAMLServiceProvider) ParseAndValidateAuthNRequest(encodedRequest string) (*AuthNRequest, error) {

	var err error
	if strings.Contains(encodedRequest, "%") {
		encodedRequest, err = url.QueryUnescape(encodedRequest)
		if err != nil {
			return nil, err
		}
	}

	raw, err := base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		return nil, err
	}

	// Parse the raw request - parseResponse is generic
	doc, el, err := parseResponse(raw, sp.MaximumDecompressedBodySize)
	if err != nil {
		return nil, err
	}

	if !sp.SkipSignatureValidation {
		el, err = sp.validateElementSignature(el)
		if errors.Is(err, dsig.ErrMissingSignature) {
			// Unfortunately we just blew away our Response
			el = doc.Root()
		} else if err != nil {
			return nil, err
		} else if el == nil {
			return nil, fmt.Errorf("missing transformed authn request")
		}
	}

	decodedRequest := &AuthNRequest{}
	err = xmlUnmarshalElement(el, decodedRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal authn request: %v", err)
	}

	err = sp.ValidateDecodedAuthNRequest(decodedRequest)
	if err != nil {
		return nil, err
	}

	return decodedRequest, nil
}

func (sp *SAMLServiceProvider) validateAuthNRequestAttributes(request *AuthNRequest) error {
	if request.AssertionConsumerServiceURL == "" {
		return ErrInvalidValue{
			Key:    AssertionConsumerServiceURLAttr,
			Reason: "AssertionConsumerServiceURL is required",
		}
	}

	return nil
}
