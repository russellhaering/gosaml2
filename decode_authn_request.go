package saml2

import (
	"encoding/base64"
	"errors"
	"fmt"
	dsig "github.com/russellhaering/goxmldsig"
	"net/url"
	"strings"
)

func (sp *SAMLServiceProvider) ValidateEncodedAuthNRequest(encodedRequest string) (*AuthNRequest, error) {

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
