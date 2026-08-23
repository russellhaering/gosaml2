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

package sp

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"

	saml2 "github.com/russellhaering/gosaml2/v2"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/russellhaering/gosaml2/v2/types"
)

// verifyRedirectSignature verifies the signature on an HTTP-Redirect binding
// message per SAML Bindings §3.4.4.1.
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
	hash := saml2.SignatureAlgorithmHash(sigAlg)
	if hash == 0 {
		return fmt.Errorf("unsupported or unrecognized signature algorithm: %s", sigAlg)
	}

	// Reject SHA1 unless explicitly allowed, matching the POST binding behavior.
	if (hash == crypto.SHA1) && !sp.AllowSHA1 {
		return fmt.Errorf("SHA1 signature algorithm is not allowed (set AllowSHA1 to enable)")
	}

	if !hash.Available() {
		return fmt.Errorf("hash algorithm %v not available", hash)
	}

	// The SigAlg URI declares both a hash and a key family (RSA vs ECDSA). Bind
	// to the declared key family so a signature is only ever verified against a
	// certificate of the matching key type.
	expectedKeyType := saml2.SignatureAlgorithmKeyType(sigAlg)
	if expectedKeyType == x509.UnknownPublicKeyAlgorithm {
		return fmt.Errorf("unsupported or unrecognized signature algorithm: %s", sigAlg)
	}

	hashed := hash.New()
	hashed.Write(signedContent)
	digest := hashed.Sum(nil)

	now := sp.now()

	// Try each trusted certificate.
	var lastErr error
	for _, cert := range sp.IDPCertificates {
		// Skip certificates whose key type doesn't match the declared SigAlg.
		if cert.PublicKeyAlgorithm != expectedKeyType {
			lastErr = fmt.Errorf("certificate key type %v does not match signature algorithm %s", cert.PublicKeyAlgorithm, sigAlg)
			continue
		}

		// Check certificate validity period.
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			lastErr = fmt.Errorf("IDP certificate is not valid at this time (notBefore=%s, notAfter=%s)",
				cert.NotBefore, cert.NotAfter)
			continue
		}

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
// received via HTTP-Redirect binding.
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

	doc, err := xmltree.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("redirect logout response XML validation failed: %v", err)
	}

	response, err := types.LogoutResponseFromElement(doc.Root())
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal logout response: %v", err)
	}
	response.SignatureValidated = !sp.InsecureSkipSignatureValidation

	if err := sp.ValidateDecodedLogoutResponse(response); err != nil {
		return nil, err
	}

	if err := sp.validateLogoutResponseInResponseTo(ctx, response); err != nil {
		return nil, err
	}

	return response, nil
}

// ValidateEncodedLogoutRequestRedirect validates a SAML LogoutRequest
// received via HTTP-Redirect binding.
func (sp *ServiceProvider) ValidateEncodedLogoutRequestRedirect(
	ctx context.Context, samlRequest, relayState, sigAlg, signature string,
) (*saml2.LogoutRequest, error) {
	if err := sp.verifyRedirectSignature("SAMLRequest", samlRequest, relayState, sigAlg, signature); err != nil {
		return nil, err
	}

	raw, err := sp.decodeRedirectMessage(samlRequest)
	if err != nil {
		return nil, err
	}

	doc, err := xmltree.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("redirect logout request XML validation failed: %v", err)
	}

	request, err := saml2.LogoutRequestFromElement(doc.Root())
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal logout request: %v", err)
	}
	request.SignatureValidated = !sp.InsecureSkipSignatureValidation

	if err := sp.ValidateDecodedLogoutRequest(request); err != nil {
		return nil, err
	}

	return request, nil
}
