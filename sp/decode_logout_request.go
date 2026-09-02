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
	"context"
	"encoding/base64"
	"fmt"

	saml2 "github.com/russellhaering/gosaml2/v2"
)

func (sp *ServiceProvider) validateLogoutRequestAttributes(request *saml2.LogoutRequest) error {
	if err := sp.validateLogoutDestination("LogoutRequest", request.Destination, request.SignatureValidated); err != nil {
		return err
	}

	if request.Version != "2.0" {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadVersion,
			Detail: fmt.Sprintf("expected 2.0, got %s", request.Version),
		}
	}

	return nil
}

// ValidateEncodedLogoutRequestPOST decodes and validates a base64-encoded
// LogoutRequest received via the HTTP-POST binding. It verifies the signature
// (unless InsecureSkipSignatureValidation is set) and validates request attributes.
func (sp *ServiceProvider) ValidateEncodedLogoutRequestPOST(ctx context.Context, encodedRequest string) (*saml2.LogoutRequest, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		return nil, err
	}

	// Parse the raw request - parseResponse is generic
	_, el, err := parseResponse(raw, sp.MaximumDecompressedBodySize)
	if err != nil {
		return nil, err
	}

	var requestSignatureValidated bool
	if !sp.InsecureSkipSignatureValidation {
		el, err = sp.validateElementSignature(el)
		if missing, err := saml2.IsSignatureMissing(err); missing {
			return nil, fmt.Errorf("logout request has no signature")
		} else if err != nil {
			return nil, err
		} else if el == nil {
			return nil, fmt.Errorf("missing transformed logout request")
		} else {
			requestSignatureValidated = true
		}
	}

	decodedRequest, err := saml2.LogoutRequestFromElement(el)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal logout request: %v", err)
	}
	decodedRequest.SignatureValidated = requestSignatureValidated

	err = sp.ValidateDecodedLogoutRequest(decodedRequest)
	if err != nil {
		return nil, err
	}

	return decodedRequest, nil
}
