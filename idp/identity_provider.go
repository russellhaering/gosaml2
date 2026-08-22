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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/russellhaering/gosaml2/v2/types"
)

// IdentityProvider represents a SAML 2.0 Identity Provider.
type IdentityProvider struct {
	EntityID               string
	SSOURL                 string
	SLOURL                 string
	SigningKeyStore        *saml2.KeyStore
	SignResponses          bool
	SignAssertions         bool
	SignatureAlgorithm     string
	SignatureCanonicalizer dsig.Canonicalizer
	ServiceProviders       map[string]*SPConfig
	ClockSkew              time.Duration

	// MaxIssueInstantAge bounds how old a LogoutRequest's IssueInstant may be
	// before it is rejected, defaulting to 5 minutes.
	MaxIssueInstantAge          time.Duration
	AllowSHA1                   bool
	AssertionLifetime           time.Duration
	SessionLifetime             time.Duration
	NameIDFormats               []string
	Clock                       func() time.Time
	MetadataValidDuration       time.Duration
	MaximumDecompressedBodySize int64

	signerMu sync.RWMutex
	signer   *dsig.Signer
}

// SPConfig holds the configuration for a known Service Provider.
type SPConfig struct {
	EntityID                   string
	ACSURLs                    []string
	SLOURLs                    []string
	SigningCertificates        []*x509.Certificate
	EncryptionCertificate      *x509.Certificate
	EncryptAssertions          bool
	EncryptionAlgorithm        string
	RequireSignedAuthnRequests bool

	// AllowUnsignedLogoutRequests permits LogoutRequests from this SP to be
	// accepted without a valid signature. It defaults to false: unlike
	// AuthnRequests, which SAML does not require to be signed, LogoutRequests
	// are session-terminating messages that the SAML Single Logout profile
	// expects to be signed on front-channel bindings, so a signature is
	// required unless this is explicitly set.
	AllowUnsignedLogoutRequests bool
}

// AuthnRequestInfo contains the parsed and validated AuthnRequest data.
type AuthnRequestInfo struct {
	ID         string
	Issuer     string
	ACSURL     string
	SP         *SPConfig
	RelayState string
}

func (idp *IdentityProvider) now() time.Time {
	if idp.Clock != nil {
		return idp.Clock()
	}
	return time.Now()
}

func (idp *IdentityProvider) clockSkew() time.Duration {
	if idp.ClockSkew != 0 {
		return idp.ClockSkew
	}
	return 60 * time.Second
}

// maxIssueInstantAge returns the configured LogoutRequest lifetime, defaulting
// to 5 minutes.
func (idp *IdentityProvider) maxIssueInstantAge() time.Duration {
	if idp.MaxIssueInstantAge != 0 {
		return idp.MaxIssueInstantAge
	}
	return 5 * time.Minute
}

func (idp *IdentityProvider) assertionLifetime() time.Duration {
	if idp.AssertionLifetime != 0 {
		return idp.AssertionLifetime
	}
	return 5 * time.Minute
}

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
		Hash:  saml2.SignatureAlgorithmHash(idp.SignatureAlgorithm),
	}
	if idp.SignatureCanonicalizer != nil {
		idp.signer.Canonicalizer = idp.SignatureCanonicalizer
	}

	return idp.signer, nil
}

func (idp *IdentityProvider) signElement(el *xmltree.Element) (*xmltree.Element, error) {
	signer, err := idp.Signer()
	if err != nil {
		return nil, err
	}

	signed, err := signer.SignEnveloped(el)
	if err != nil {
		return nil, err
	}

	n := len(signed.Child)
	if n >= 2 {
		sigToken := signed.Child[n-1]
		newChildren := make([]xmltree.Token, 0, n)
		newChildren = append(newChildren, signed.Child[0])
		newChildren = append(newChildren, sigToken)
		newChildren = append(newChildren, signed.Child[1:n-1]...)
		signed.Child = newChildren
	}

	return signed, nil
}

func (idp *IdentityProvider) lookupSP(entityID string) (*SPConfig, error) {
	if idp.ServiceProviders == nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrUnknownSP,
			Detail: fmt.Sprintf("no service providers configured, got %s", entityID),
		}
	}
	sp, ok := idp.ServiceProviders[entityID]
	if !ok {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrUnknownSP,
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
				sp.SigningCertificates = append(sp.SigningCertificates, cert)
				if sp.EncryptionCertificate == nil {
					sp.EncryptionCertificate = cert
				}
			}
		}
	}

	return sp, nil
}
