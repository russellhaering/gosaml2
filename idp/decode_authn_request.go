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

package idp

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

	saml2 "github.com/russellhaering/gosaml2/v2"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// ValidateEncodedAuthnRequestPOST decodes and validates a base64-encoded
// AuthnRequest received via the HTTP-POST binding. It resolves the SP from
// the request's Issuer, validates attributes, and resolves the ACS URL.
func (idp *IdentityProvider) ValidateEncodedAuthnRequestPOST(_ context.Context, encodedRequest string) (*AuthnRequestInfo, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("base64 decode error: %v", err),
		}
	}

	el, req, err := idp.decodeAuthnRequest(raw)
	if err != nil {
		return nil, err
	}

	// The Issuer is needed to find the SP whose certificates verify the
	// signature, so it is necessarily read before verification. Everything
	// used for an access decision is re-read from the verified element below.
	sp, err := idp.lookupSP(req.Issuer)
	if err != nil {
		return nil, err
	}

	verified, err := idp.verifyPOSTSignature(sp, el, sp.RequireSignedAuthnRequests)
	if err != nil {
		return nil, err
	}

	if verified != nil {
		if _, req, err = idp.decodeAuthnRequestElement(verified); err != nil {
			return nil, err
		}
		// A signature only vouches for the SP that produced it: reject a
		// message whose signed Issuer is not the one whose key signed it.
		if req.Issuer != sp.EntityID {
			return nil, &saml2.ValidationError{
				Reason: saml2.ErrBadIssuer,
				Detail: fmt.Sprintf("signed AuthnRequest Issuer %s does not match signing SP %s", req.Issuer, sp.EntityID),
			}
		}
	}

	if err := idp.validateAuthnRequestAttributes(req); err != nil {
		return nil, err
	}

	acsURL, err := idp.resolveACSURL(req, sp)
	if err != nil {
		return nil, err
	}

	return &AuthnRequestInfo{
		ID:     req.ID,
		Issuer: req.Issuer,
		ACSURL: acsURL,
		SP:     sp,
	}, nil
}

// verifyPOSTSignature verifies the enveloped XML signature on a POST-binding
// message from sp. It returns the element reconstructed from the bytes that
// were actually signed, or nil when the message is legitimately unsigned
// (the SP does not require signed requests and carries no signature).
//
// The HTTP-POST binding carries an enveloped XML-DSig signature rather than
// the HTTP-Redirect binding's signed query string, so it needs its own
// verification path; without one, RequireSignedAuthnRequests was enforced on
// the Redirect binding only and a peer could strip the signature simply by
// switching bindings.
func (idp *IdentityProvider) verifyPOSTSignature(sp *SPConfig, el *xmltree.Element, required bool) (*xmltree.Element, error) {
	if len(sp.SigningCertificates) == 0 {
		if required {
			return nil, &saml2.ValidationError{
				Reason: saml2.ErrBadSignature,
				Detail: "SP is required to sign requests but has no signing certificates configured",
			}
		}
		// Nothing to verify against, and nothing required.
		return nil, nil
	}

	verifier := &dsig.Verifier{
		TrustedCerts: sp.SigningCertificates,
		AllowSHA1:    idp.AllowSHA1,
		Clock:        idp.now,
	}

	result, err := verifier.Verify(el)
	if missing, err := saml2.IsSignatureMissing(err); missing {
		if required {
			return nil, &saml2.ValidationError{
				Reason: saml2.ErrMissingSignature,
				Detail: "SP is required to sign requests but no signature was provided",
			}
		}
		return nil, nil
	} else if err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrBadSignature,
			Detail: err.Error(),
		}
	}

	return result.Element, nil
}

// ValidateEncodedAuthnRequestRedirect decodes and validates an AuthnRequest
// received via the HTTP-Redirect binding. The samlRequest, relayState, sigAlg,
// and signature parameters come from the query string. It verifies the redirect
// signature if the SP requires signed requests or a signature is present.
func (idp *IdentityProvider) ValidateEncodedAuthnRequestRedirect(_ context.Context, samlRequest, relayState, sigAlg, signature string) (*AuthnRequestInfo, error) {
	raw, err := idp.decodeRedirectRequest(samlRequest)
	if err != nil {
		return nil, err
	}

	_, req, err := idp.decodeAuthnRequest(raw)
	if err != nil {
		return nil, err
	}

	sp, err := idp.lookupSP(req.Issuer)
	if err != nil {
		return nil, err
	}

	if sp.RequireSignedAuthnRequests || signature != "" {
		if signature == "" {
			return nil, &saml2.ValidationError{
				Reason: saml2.ErrMissingSignature,
				Detail: "SP is required to sign AuthnRequests but no signature was provided",
			}
		}

		if err := idp.verifyRedirectSignature(sp, samlRequest, relayState, sigAlg, signature); err != nil {
			return nil, err
		}
	}

	if err := idp.validateAuthnRequestAttributes(req); err != nil {
		return nil, err
	}

	acsURL, err := idp.resolveACSURL(req, sp)
	if err != nil {
		return nil, err
	}

	return &AuthnRequestInfo{
		ID:         req.ID,
		Issuer:     req.Issuer,
		ACSURL:     acsURL,
		SP:         sp,
		RelayState: relayState,
	}, nil
}

func (idp *IdentityProvider) decodeRedirectRequest(samlRequest string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("base64 decode error: %v", err),
		}
	}

	maxSize := idp.MaximumDecompressedBodySize
	if maxSize == 0 {
		maxSize = 5 * 1024 * 1024
	}

	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	raw, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("deflate error: %v", err),
		}
	}

	if int64(len(raw)) > maxSize {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: "decompressed request exceeds maximum size",
		}
	}

	return raw, nil
}

func (idp *IdentityProvider) decodeAuthnRequest(raw []byte) (*xmltree.Element, *ReceivedAuthnRequest, error) {
	doc, err := xmltree.Parse(raw)
	if err != nil {
		return nil, nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("XML validation failed: %v", err),
		}
	}

	return idp.decodeAuthnRequestElement(doc.Root())
}

// decodeAuthnRequestElement extracts a ReceivedAuthnRequest from an already
// parsed element.
func (idp *IdentityProvider) decodeAuthnRequestElement(el *xmltree.Element) (*xmltree.Element, *ReceivedAuthnRequest, error) {
	req, err := receivedAuthnRequestFromElement(el)
	if err != nil {
		return nil, nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("XML unmarshal error: %v", err),
		}
	}

	return el, req, nil
}

func (idp *IdentityProvider) validateAuthnRequestAttributes(req *ReceivedAuthnRequest) error {
	if req.ID == "" {
		return &saml2.ValidationError{
			Reason: saml2.ErrMissingElement,
			Detail: "AuthnRequest missing ID attribute",
		}
	}

	if req.Version != "2.0" {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadVersion,
			Detail: fmt.Sprintf("expected 2.0, got %s", req.Version),
		}
	}

	if req.Issuer == "" {
		return &saml2.ValidationError{
			Reason: saml2.ErrMissingElement,
			Detail: "AuthnRequest missing Issuer",
		}
	}

	if req.Destination != "" && req.Destination != idp.SSOURL {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadDestination,
			Detail: fmt.Sprintf("expected %s, got %s", idp.SSOURL, req.Destination),
		}
	}

	return nil
}

func (idp *IdentityProvider) resolveACSURL(req *ReceivedAuthnRequest, sp *SPConfig) (string, error) {
	if req.AssertionConsumerServiceURL != "" {
		for _, allowed := range sp.ACSURLs {
			if req.AssertionConsumerServiceURL == allowed {
				return req.AssertionConsumerServiceURL, nil
			}
		}
		return "", &saml2.ValidationError{
			Reason: saml2.ErrBadACSURL,
			Detail: fmt.Sprintf("requested ACS URL %s is not registered for SP %s", req.AssertionConsumerServiceURL, sp.EntityID),
		}
	}

	if len(sp.ACSURLs) > 0 {
		return sp.ACSURLs[0], nil
	}

	return "", &saml2.ValidationError{
		Reason: saml2.ErrBadACSURL,
		Detail: fmt.Sprintf("no ACS URL available for SP %s", sp.EntityID),
	}
}

func (idp *IdentityProvider) verifyRedirectSignature(sp *SPConfig, samlRequest, relayState, sigAlg, signature string) error {
	if len(sp.SigningCertificates) == 0 {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadSignature,
			Detail: "SP has no signing certificates configured",
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadSignature,
			Detail: fmt.Sprintf("error decoding signature: %v", err),
		}
	}

	hash := saml2.SignatureAlgorithmHash(sigAlg)
	if hash == 0 {
		if !idp.AllowSHA1 {
			return &saml2.ValidationError{
				Reason: saml2.ErrBadSignature,
				Detail: fmt.Sprintf("unsupported or disallowed signature algorithm: %s", sigAlg),
			}
		}
		if sigAlg == dsig.RSASHA1SignatureMethod || sigAlg == dsig.ECDSASHA1SignatureMethod {
			hash = crypto.SHA1
		} else {
			return &saml2.ValidationError{
				Reason: saml2.ErrBadSignature,
				Detail: fmt.Sprintf("unsupported signature algorithm: %s", sigAlg),
			}
		}
	}

	if hash == crypto.SHA1 && !idp.AllowSHA1 {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadSignature,
			Detail: "SHA-1 signatures are not allowed",
		}
	}

	// The SigAlg URI names both a hash and a key family. Bind to the declared
	// family so a signature is only ever checked against a certificate of the
	// matching key type, as the SP-side redirect verifier does.
	expectedKeyType := saml2.SignatureAlgorithmKeyType(sigAlg)
	if expectedKeyType == x509.UnknownPublicKeyAlgorithm {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadSignature,
			Detail: fmt.Sprintf("unsupported or unrecognized signature algorithm: %s", sigAlg),
		}
	}

	input := saml2.SignatureInputString(samlRequest, relayState, sigAlg)

	h := hash.New()
	h.Write([]byte(input))
	digest := h.Sum(nil)

	now := idp.now()

	var lastErr error
	for _, cert := range sp.SigningCertificates {
		if cert.PublicKeyAlgorithm != expectedKeyType {
			lastErr = fmt.Errorf("certificate key type %v does not match signature algorithm %s",
				cert.PublicKeyAlgorithm, sigAlg)
			continue
		}

		// Reject certificates outside their validity window. Every other
		// certificate-based verification path in the library enforces this
		// (sp.verifyRedirectSignature and dsig.Verifier), and without it a
		// retired SP signing key keeps producing acceptable requests forever,
		// so expiry stops being a way to revoke one.
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			lastErr = fmt.Errorf("SP certificate is not valid at this time (notBefore=%s, notAfter=%s)",
				cert.NotBefore, cert.NotAfter)
			continue
		}

		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(pub, hash, digest, sigBytes); err == nil {
				return nil
			}
			lastErr = fmt.Errorf("RSA signature verification failed")

		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(pub, digest, sigBytes) {
				return nil
			}
			lastErr = fmt.Errorf("ECDSA signature verification failed")

		default:
			lastErr = fmt.Errorf("unsupported public key type: %T", pub)
		}
	}

	detail := "redirect signature verification failed with all configured certificates"
	if lastErr != nil {
		detail = fmt.Sprintf("%s: %v", detail, lastErr)
	}
	return &saml2.ValidationError{
		Reason: saml2.ErrBadSignature,
		Detail: detail,
	}
}
