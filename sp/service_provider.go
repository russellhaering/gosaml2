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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	"github.com/russellhaering/gosaml2/v2/types"
)

// ServiceProvider represents a SAML 2.0 Service Provider. Configure its
// fields and use its methods to build AuthnRequests, validate responses,
// and generate SP metadata.
type ServiceProvider struct {
	// Service Provider identity
	EntityID string
	ACSURL   string
	SLOURL   string

	// Identity Provider
	IDPEntityID   string
	IDPSSOURL     string
	IDPSSOBinding string
	IDPSLOURL     string
	IDPSLOBinding string

	// Certificates and keys
	IDPCertificates   []*x509.Certificate
	SPKeyStore        *saml2.KeyStore
	SPSigningKeyStore *saml2.KeyStore

	// Security
	InsecureSkipSignatureValidation bool

	// InsecureAllowIDPInitiatedReplay accepts IdP-initiated responses without an
	// AssertionReplayCache, and ignores saml:OneTimeUse when nothing else bounds
	// reuse. A captured unsolicited response can then be replayed for as long as
	// its assertion is valid, each replay minting a fresh session. Configure
	// AssertionReplayCache instead; this exists for deployments that knowingly
	// accept that risk.
	InsecureAllowIDPInitiatedReplay bool

	// InsecureSkipAudienceValidation accepts assertions without checking that
	// this service provider is a named audience. Audience restriction is what
	// scopes an assertion to a relying party, so skipping it means an assertion
	// the IdP issued for a different party is accepted wherever the bearer
	// confirmation's Recipient still matches -- notably a multi-tenant SP whose
	// tenants share one ACS URL. Set AudienceURIs instead; this exists for
	// deployments that knowingly rely on Recipient alone.
	InsecureSkipAudienceValidation bool
	AllowSHA1                      bool
	ValidateEncryptionCert         bool
	AllowIDPInitiated              bool

	// Signing
	SignAuthnRequests              bool
	SignAuthnRequestsAlgorithm     string
	SignAuthnRequestsCanonicalizer dsig.Canonicalizer

	// Validation
	ClockSkew time.Duration

	// MaxIssueInstantAge bounds how old a logout message's IssueInstant may be
	// before it is rejected, defaulting to 5 minutes. Logout messages are
	// short-lived by design, and the redirect binding carries the whole signed
	// message in a URL, where it persists in browser history, proxy and server
	// logs, and can leak via Referer. Without an upper bound on age such a
	// capture stays verifiable forever.
	MaxIssueInstantAge time.Duration
	AudienceURIs       []string
	RequestTracker     RequestTracker

	// AssertionReplayCache records accepted assertion IDs so a bearer assertion
	// authenticates at most once. RequestTracker only bounds solicited flows, by
	// consuming the request ID a response answers; an unsolicited
	// (IdP-initiated) response has no request ID, so replay can only be
	// prevented by remembering assertion IDs. Required when AllowIDPInitiated is
	// set, and to honour saml:OneTimeUse.
	AssertionReplayCache AssertionReplayCache

	// Request building
	RequestedAuthnContext *saml2.RequestedAuthnContext
	ForceAuthn            bool
	IsPassive             bool
	NameIDFormat          string

	// Advanced
	Clock                       func() time.Time
	MaximumDecompressedBodySize int64
	MetadataValidDuration       time.Duration

	signerMu sync.RWMutex
	signer   *dsig.Signer
}

// ProxyRestriction contains proxy restriction info from an assertion.
type ProxyRestriction struct {
	Count    int
	Audience []string
}

// AssertionInfo contains assertion data extracted from a SAML response.
type AssertionInfo struct {
	NameID                     string
	NameIDFormat               string
	Values                     Values
	SessionIndex               string
	AuthnInstant               *time.Time
	SessionNotOnOrAfter        *time.Time
	Assertions                 []types.Assertion
	ResponseSignatureValidated bool
	OneTimeUse                 bool
	ProxyRestriction           *ProxyRestriction
}

// Metadata generates an EntityDescriptor for this Service Provider, suitable
// for publishing at a metadata endpoint. It includes key descriptors for any
// configured signing and encryption keys, and SLO endpoints if SLOURL is set.
func (sp *ServiceProvider) Metadata() (*types.EntityDescriptor, error) {
	keyDescriptors := make([]types.KeyDescriptor, 0, 2)
	if sp.getSigningKeyStore() != nil {
		signingCertBytes, err := sp.GetSigningCertBytes()
		if err != nil {
			return nil, err
		}
		keyDescriptors = append(keyDescriptors, types.KeyDescriptor{
			Use: "signing",
			KeyInfo: types.KeyInfo{
				X509Data: types.X509Data{
					X509Certificates: []types.X509Certificate{{
						Data: base64.StdEncoding.EncodeToString(signingCertBytes),
					}},
				},
			},
		})
	}

	encryptionCertBytes, err := sp.GetEncryptionCertBytes()
	if err != nil {
		return nil, err
	}
	if encryptionCertBytes != nil {
		keyDescriptors = append(keyDescriptors, types.KeyDescriptor{
			Use: "encryption",
			KeyInfo: types.KeyInfo{
				X509Data: types.X509Data{
					X509Certificates: []types.X509Certificate{{
						Data: base64.StdEncoding.EncodeToString(encryptionCertBytes),
					}},
				},
			},
			EncryptionMethods: []types.EncryptionMethod{
				{Algorithm: types.MethodAES128GCM},
				{Algorithm: types.MethodAES192GCM},
				{Algorithm: types.MethodAES256GCM},
				{Algorithm: types.MethodAES128CBC},
				{Algorithm: types.MethodAES256CBC},
			},
		})
	}

	validDuration := sp.MetadataValidDuration
	if validDuration == 0 {
		validDuration = time.Hour * 24 * 7 // 7 days
	}

	desc := &types.EntityDescriptor{
		ValidUntil: sp.now().UTC().Add(validDuration),
		EntityID:   sp.EntityID,
		SPSSODescriptor: &types.SPSSODescriptor{
			AuthnRequestsSigned:        sp.SignAuthnRequests,
			WantAssertionsSigned:       !sp.InsecureSkipSignatureValidation,
			ProtocolSupportEnumeration: saml2.SAMLProtocolNamespace,
			KeyDescriptors:             keyDescriptors,
			AssertionConsumerServices: []types.IndexedEndpoint{{
				Binding:  saml2.BindingHttpPost,
				Location: sp.ACSURL,
				Index:    1,
			}},
		},
	}

	if sp.SLOURL != "" {
		desc.SPSSODescriptor.SingleLogoutServices = []types.Endpoint{{
			Binding:  saml2.BindingHttpPost,
			Location: sp.SLOURL,
		}}
	}

	return desc, nil
}

// now returns the current time using the configured clock, or time.Now.
func (sp *ServiceProvider) now() time.Time {
	if sp.Clock != nil {
		return sp.Clock()
	}
	return time.Now()
}

// maxIssueInstantAge returns the configured logout message lifetime,
// defaulting to 5 minutes.
func (sp *ServiceProvider) maxIssueInstantAge() time.Duration {
	if sp.MaxIssueInstantAge != 0 {
		return sp.MaxIssueInstantAge
	}
	return 5 * time.Minute
}

// clockSkew returns the configured clock skew, defaulting to 60s.
func (sp *ServiceProvider) clockSkew() time.Duration {
	if sp.ClockSkew != 0 {
		return sp.ClockSkew
	}
	return 60 * time.Second
}

// getSigningKeyStore returns the key store to use for signing.
func (sp *ServiceProvider) getSigningKeyStore() *saml2.KeyStore {
	if sp.SPSigningKeyStore != nil {
		return sp.SPSigningKeyStore
	}
	return sp.SPKeyStore
}

// GetEncryptionCertBytes returns the raw DER-encoded encryption certificate
// from SPKeyStore.
func (sp *ServiceProvider) GetEncryptionCertBytes() ([]byte, error) {
	if sp.SPKeyStore == nil {
		return nil, fmt.Errorf("empty SP encryption certificate")
	}
	if len(sp.SPKeyStore.Cert) < 1 {
		return nil, fmt.Errorf("empty SP encryption certificate")
	}
	return sp.SPKeyStore.Cert, nil
}

// GetSigningCertBytes returns the raw DER-encoded signing certificate. It uses
// SPSigningKeyStore if set, otherwise falls back to SPKeyStore.
func (sp *ServiceProvider) GetSigningCertBytes() ([]byte, error) {
	ks := sp.getSigningKeyStore()
	if ks == nil {
		return nil, fmt.Errorf("empty SP signing certificate")
	}
	if len(ks.Cert) < 1 {
		return nil, fmt.Errorf("empty SP signing certificate")
	}
	return ks.Cert, nil
}

// Signer returns a dsig.Signer configured for this service provider.
func (sp *ServiceProvider) Signer() (*dsig.Signer, error) {
	sp.signerMu.RLock()
	s := sp.signer
	sp.signerMu.RUnlock()

	if s != nil {
		return s, nil
	}

	sp.signerMu.Lock()
	defer sp.signerMu.Unlock()

	// Re-check after acquiring write lock.
	if sp.signer != nil {
		return sp.signer, nil
	}

	ks := sp.getSigningKeyStore()
	if ks == nil {
		return nil, fmt.Errorf("no signing key store configured")
	}

	cert, err := x509.ParseCertificate(ks.Cert)
	if err != nil {
		return nil, fmt.Errorf("error parsing signing certificate: %w", err)
	}

	sp.signer = &dsig.Signer{
		Key:   ks.Signer,
		Certs: []*x509.Certificate{cert},
		Hash:  saml2.SignatureAlgorithmHash(sp.SignAuthnRequestsAlgorithm),
	}
	if sp.SignAuthnRequestsCanonicalizer != nil {
		sp.signer.Canonicalizer = sp.SignAuthnRequestsCanonicalizer
	}

	return sp.signer, nil
}
