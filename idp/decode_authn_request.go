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
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"

	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
	saml2 "github.com/russellhaering/gosaml2/v2"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
)

func (idp *IdentityProvider) ValidateEncodedAuthnRequestPOST(_ context.Context, encodedRequest string) (*AuthnRequestInfo, error) {
	raw, err := base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("base64 decode error: %v", err),
		}
	}

	req, err := idp.decodeAuthnRequest(raw)
	if err != nil {
		return nil, err
	}

	sp, err := idp.lookupSP(req.Issuer)
	if err != nil {
		return nil, err
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

func (idp *IdentityProvider) ValidateEncodedAuthnRequestRedirect(_ context.Context, samlRequest, relayState, sigAlg, signature string) (*AuthnRequestInfo, error) {
	raw, err := idp.decodeRedirectRequest(samlRequest)
	if err != nil {
		return nil, err
	}

	req, err := idp.decodeAuthnRequest(raw)
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

func (idp *IdentityProvider) decodeAuthnRequest(raw []byte) (*ReceivedAuthnRequest, error) {
	if err := rtvalidator.Validate(bytes.NewReader(raw)); err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("XML roundtrip validation failed: %v", err),
		}
	}

	req := &ReceivedAuthnRequest{}
	if err := xml.Unmarshal(raw, req); err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrMalformed,
			Detail: fmt.Sprintf("XML unmarshal error: %v", err),
		}
	}

	return req, nil
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

	input := saml2.SignatureInputString(samlRequest, relayState, sigAlg)

	h := hash.New()
	h.Write([]byte(input))
	digest := h.Sum(nil)

	for _, cert := range sp.SigningCertificates {
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(pub, hash, digest, sigBytes); err == nil {
				return nil
			}
		}
	}

	return &saml2.ValidationError{
		Reason: saml2.ErrBadSignature,
		Detail: "redirect signature verification failed with all configured certificates",
	}
}
