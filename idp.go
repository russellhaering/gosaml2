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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/gosaml2/v2/types"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
)

// IdentityProvider represents a SAML 2.0 Identity Provider.
type IdentityProvider struct {
	// EntityID is the unique identifier for this IdP.
	EntityID string

	// SSOURL is the single sign-on endpoint URL.
	SSOURL string

	// SLOURL is the single logout endpoint URL.
	SLOURL string

	// SigningKeyStore holds the signing key and certificate.
	SigningKeyStore *KeyStore

	// SignResponses controls whether the Response element is signed.
	SignResponses bool

	// SignAssertions controls whether individual Assertion elements are signed.
	SignAssertions bool

	// SignatureAlgorithm is the XML-DSig signature method URI.
	SignatureAlgorithm string

	// SignatureCanonicalizer is an optional canonicalizer for signing.
	SignatureCanonicalizer dsig.Canonicalizer

	// ServiceProviders maps SP entity IDs to their configurations.
	ServiceProviders map[string]*SPConfig

	// ClockSkew is the maximum allowed clock difference for validation.
	ClockSkew time.Duration

	// AllowSHA1 permits SHA-1 signatures when true.
	AllowSHA1 bool

	// AssertionLifetime controls how long assertions are valid.
	AssertionLifetime time.Duration

	// SessionLifetime controls how long sessions are valid.
	SessionLifetime time.Duration

	// NameIDFormats lists the NameID formats this IdP supports.
	NameIDFormats []string

	// Clock is an optional function returning the current time.
	Clock func() time.Time

	// MetadataValidDuration controls how long generated metadata is valid.
	MetadataValidDuration time.Duration

	// MaximumDecompressedBodySize limits DEFLATE decompression (0 = default 5MB).
	MaximumDecompressedBodySize int64

	signerMu sync.RWMutex
	signer   *dsig.Signer
}

// SPConfig holds the configuration for a known Service Provider.
type SPConfig struct {
	EntityID                    string
	ACSURLs                     []string
	SLOURLs                     []string
	SigningCertificates         []*x509.Certificate
	EncryptionCertificate       *x509.Certificate
	EncryptAssertions           bool
	EncryptionAlgorithm         string
	RequireSignedAuthnRequests  bool
}

// AuthnRequestInfo contains the parsed and validated AuthnRequest data.
type AuthnRequestInfo struct {
	ID         string
	Issuer     string
	ACSURL     string
	SP         *SPConfig
	RelayState string
}

// now returns the current time.
func (idp *IdentityProvider) now() time.Time {
	if idp.Clock != nil {
		return idp.Clock()
	}
	return time.Now()
}

// clockSkew returns the configured clock skew, defaulting to 60s.
func (idp *IdentityProvider) clockSkew() time.Duration {
	if idp.ClockSkew != 0 {
		return idp.ClockSkew
	}
	return 60 * time.Second
}

// assertionLifetime returns the configured assertion lifetime, defaulting to 5 minutes.
func (idp *IdentityProvider) assertionLifetime() time.Duration {
	if idp.AssertionLifetime != 0 {
		return idp.AssertionLifetime
	}
	return 5 * time.Minute
}

// sessionLifetime returns the configured session lifetime, defaulting to 8 hours.
func (idp *IdentityProvider) sessionLifetime() time.Duration {
	if idp.SessionLifetime != 0 {
		return idp.SessionLifetime
	}
	return 8 * time.Hour
}

// Signer returns a dsig.Signer configured for this identity provider.
func (idp *IdentityProvider) Signer() (*dsig.Signer, error) {
	idp.signerMu.RLock()
	s := idp.signer
	idp.signerMu.RUnlock()

	if s != nil {
		return s, nil
	}

	idp.signerMu.Lock()
	defer idp.signerMu.Unlock()

	if idp.signer != nil {
		return idp.signer, nil
	}

	if idp.SigningKeyStore == nil {
		return nil, fmt.Errorf("no signing key store configured")
	}

	cert, err := x509.ParseCertificate(idp.SigningKeyStore.Cert)
	if err != nil {
		return nil, fmt.Errorf("error parsing signing certificate: %w", err)
	}

	idp.signer = &dsig.Signer{
		Key:   idp.SigningKeyStore.Signer,
		Certs: []*x509.Certificate{cert},
		Hash:  signatureAlgorithmHash(idp.SignatureAlgorithm),
	}
	if idp.SignatureCanonicalizer != nil {
		idp.signer.Canonicalizer = idp.SignatureCanonicalizer
	}

	return idp.signer, nil
}

// signElement signs the given element and reorders children so that
// the Signature element appears immediately after the Issuer element,
// per the SAML schema.
func (idp *IdentityProvider) signElement(el *etree.Element) (*etree.Element, error) {
	signer, err := idp.Signer()
	if err != nil {
		return nil, err
	}

	signed, err := signer.SignEnveloped(el)
	if err != nil {
		return nil, err
	}

	// SignEnveloped appends the signature as the last child token.
	// Per SAML schema, Signature must come right after Issuer.
	// We cannot use RemoveChild here because SignEnveloped adds the
	// signature via direct slice append without setting parent pointers.
	// Instead, manipulate the Child slice directly.
	n := len(signed.Child)
	if n >= 2 {
		sigToken := signed.Child[n-1]
		// Build new slice: [first child (Issuer), Signature, rest...]
		newChildren := make([]etree.Token, 0, n)
		newChildren = append(newChildren, signed.Child[0])
		newChildren = append(newChildren, sigToken)
		newChildren = append(newChildren, signed.Child[1:n-1]...)
		signed.Child = newChildren
	}

	return signed, nil
}

// lookupSP returns the SPConfig for the given entity ID.
func (idp *IdentityProvider) lookupSP(entityID string) (*SPConfig, error) {
	if idp.ServiceProviders == nil {
		return nil, &ValidationError{
			Reason: ErrUnknownSP,
			Detail: fmt.Sprintf("no service providers configured, got %s", entityID),
		}
	}
	sp, ok := idp.ServiceProviders[entityID]
	if !ok {
		return nil, &ValidationError{
			Reason: ErrUnknownSP,
			Detail: fmt.Sprintf("unknown entity ID: %s", entityID),
		}
	}
	return sp, nil
}

// ConfigureFromSPMetadata creates an SPConfig from a parsed EntityDescriptor.
func ConfigureFromSPMetadata(ed *types.EntityDescriptor) (*SPConfig, error) {
	if ed.SPSSODescriptor == nil {
		return nil, fmt.Errorf("entity descriptor has no SPSSODescriptor")
	}

	sp := &SPConfig{
		EntityID: ed.EntityID,
	}

	for _, acs := range ed.SPSSODescriptor.AssertionConsumerServices {
		sp.ACSURLs = append(sp.ACSURLs, acs.Location)
	}

	for _, slo := range ed.SPSSODescriptor.SingleLogoutServices {
		sp.SLOURLs = append(sp.SLOURLs, slo.Location)
	}

	for _, kd := range ed.SPSSODescriptor.KeyDescriptors {
		for _, x509Cert := range kd.KeyInfo.X509Data.X509Certificates {
			certBytes, err := base64.StdEncoding.DecodeString(x509Cert.Data)
			if err != nil {
				return nil, fmt.Errorf("error decoding certificate: %w", err)
			}

			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing certificate: %w", err)
			}

			switch kd.Use {
			case "signing":
				sp.SigningCertificates = append(sp.SigningCertificates, cert)
			case "encryption":
				sp.EncryptionCertificate = cert
			case "":
				// No use specified — certificate can be used for both
				sp.SigningCertificates = append(sp.SigningCertificates, cert)
				if sp.EncryptionCertificate == nil {
					sp.EncryptionCertificate = cert
				}
			}
		}
	}

	return sp, nil
}
