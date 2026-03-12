// Copyright 2025 Russell Haering et al.
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

package saml2

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"

	"github.com/russellhaering/gosaml2/v2/types"
)

// verifyRedirectSignature verifies the signature on an HTTP-Redirect binding
// message per SAML Bindings §3.4.4.1. The signature covers the query string
// parameters in a specific order, not the XML content directly.
//
// Parameters are raw query parameter values (not URL-encoded).
func (sp *ServiceProvider) verifyRedirectSignature(
	paramName, encodedMessage, relayState, sigAlg, signature string,
) error {
	if sp.InsecureSkipSignatureValidation {
		return nil
	}

	if sigAlg == "" || signature == "" {
		return fmt.Errorf("redirect binding message has no signature")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("cannot decode redirect signature: %v", err)
	}

	// Build the signed string in the required parameter order.
	var buf bytes.Buffer
	buf.WriteString(url.QueryEscape(paramName) + "=" + url.QueryEscape(encodedMessage))
	if relayState != "" {
		buf.WriteString("&" + url.QueryEscape("RelayState") + "=" + url.QueryEscape(relayState))
	}
	buf.WriteString("&" + url.QueryEscape("SigAlg") + "=" + url.QueryEscape(sigAlg))
	signedContent := buf.Bytes()

	// Determine hash algorithm from SigAlg URI.
	hash := signatureAlgorithmHash(sigAlg)
	if hash == 0 {
		hash = crypto.SHA256
	}
	if !hash.Available() {
		return fmt.Errorf("hash algorithm %v not available", hash)
	}

	hashed := hash.New()
	hashed.Write(signedContent)
	digest := hashed.Sum(nil)

	// Try each trusted certificate.
	var lastErr error
	for _, cert := range sp.IDPCertificates {
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			lastErr = rsa.VerifyPKCS1v15(pub, hash, digest, sigBytes)
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(pub, digest, sigBytes) {
				lastErr = nil
			} else {
				lastErr = fmt.Errorf("ECDSA signature verification failed")
			}
		default:
			lastErr = fmt.Errorf("unsupported public key type: %T", pub)
			continue
		}
		if lastErr == nil {
			return nil
		}
	}

	if lastErr != nil {
		return fmt.Errorf("redirect binding signature verification failed: %v", lastErr)
	}
	return fmt.Errorf("no trusted certificates configured")
}

// decodeRedirectMessage decodes a DEFLATE-compressed, base64-encoded SAML message
// from an HTTP-Redirect binding.
func (sp *ServiceProvider) decodeRedirectMessage(encoded string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("cannot base64-decode redirect message: %v", err)
	}

	maxSize := sp.MaximumDecompressedBodySize
	if maxSize == 0 {
		maxSize = defaultMaxDecompressedResponseSize
	}

	lr := io.LimitReader(flate.NewReader(bytes.NewReader(compressed)), maxSize+1)
	raw, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("cannot inflate redirect message: %v", err)
	}
	if int64(len(raw)) > maxSize {
		return nil, fmt.Errorf("inflated redirect message exceeds maximum size of %d bytes", maxSize)
	}
	return raw, nil
}

// ValidateEncodedLogoutResponseRedirect validates a SAML LogoutResponse
// received via HTTP-Redirect binding. Parameters are raw query parameter values.
func (sp *ServiceProvider) ValidateEncodedLogoutResponseRedirect(
	ctx context.Context, samlResponse, relayState, sigAlg, signature string,
) (*types.LogoutResponse, error) {
	if err := sp.verifyRedirectSignature("SAMLResponse", samlResponse, relayState, sigAlg, signature); err != nil {
		return nil, err
	}

	raw, err := sp.decodeRedirectMessage(samlResponse)
	if err != nil {
		return nil, err
	}

	response := &types.LogoutResponse{}
	if err := xml.Unmarshal(raw, response); err != nil {
		return nil, fmt.Errorf("unable to unmarshal logout response: %v", err)
	}
	response.SignatureValidated = !sp.InsecureSkipSignatureValidation

	if err := sp.ValidateDecodedLogoutResponse(response); err != nil {
		return nil, err
	}

	return response, nil
}

// ValidateEncodedLogoutRequestRedirect validates a SAML LogoutRequest
// received via HTTP-Redirect binding. Parameters are raw query parameter values.
func (sp *ServiceProvider) ValidateEncodedLogoutRequestRedirect(
	ctx context.Context, samlRequest, relayState, sigAlg, signature string,
) (*LogoutRequest, error) {
	if err := sp.verifyRedirectSignature("SAMLRequest", samlRequest, relayState, sigAlg, signature); err != nil {
		return nil, err
	}

	raw, err := sp.decodeRedirectMessage(samlRequest)
	if err != nil {
		return nil, err
	}

	request := &LogoutRequest{}
	if err := xml.Unmarshal(raw, request); err != nil {
		return nil, fmt.Errorf("unable to unmarshal logout request: %v", err)
	}
	request.SignatureValidated = !sp.InsecureSkipSignatureValidation

	if err := sp.ValidateDecodedLogoutRequest(request); err != nil {
		return nil, err
	}

	return request, nil
}
