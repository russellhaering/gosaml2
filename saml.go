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

package saml2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/russellhaering/gosaml2/v2/types"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
)

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
	IDPCertificates []*x509.Certificate
	SPKeyStore      *KeyStore
	SPSigningKeyStore *KeyStore

	// Security
	InsecureSkipSignatureValidation bool
	AllowSHA1                       bool
	ValidateEncryptionCert          bool
	AllowIDPInitiated               bool

	// Signing
	SignAuthnRequests              bool
	SignAuthnRequestsAlgorithm     string
	SignAuthnRequestsCanonicalizer dsig.Canonicalizer

	// Validation
	ClockSkew      time.Duration
	AudienceURIs   []string
	RequestTracker RequestTracker

	// Request building
	RequestedAuthnContext *RequestedAuthnContext
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

// KeyStore holds a signing key and its associated certificate.
type KeyStore struct {
	Signer crypto.Signer
	Cert   []byte
}

// RequestedAuthnContext controls which authentication mechanisms are requested of
// the identity provider. It is generally sufficient to omit this and let the
// identity provider select an authentication mechanism.
type RequestedAuthnContext struct {
	// The RequestedAuthnContext comparison policy to use. See the section 3.3.2.2.1
	// of the SAML 2.0 specification for details. Constants named AuthnPolicyMatch*
	// contain standardized values.
	Comparison string

	// Contexts will be passed as AuthnContextClassRefs. For example, to force password
	// authentication on some identity providers, Contexts should have a value of
	// []string{AuthnContextPasswordProtectedTransport}, and Comparison should have a
	// value of AuthnPolicyMatchExact.
	Contexts []string
}

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
			ProtocolSupportEnumeration: SAMLProtocolNamespace,
			KeyDescriptors:             keyDescriptors,
			AssertionConsumerServices: []types.IndexedEndpoint{{
				Binding:  BindingHttpPost,
				Location: sp.ACSURL,
				Index:    1,
			}},
		},
	}

	if sp.SLOURL != "" {
		desc.SPSSODescriptor.SingleLogoutServices = []types.Endpoint{{
			Binding:  BindingHttpPost,
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

// clockSkew returns the configured clock skew, defaulting to 60s.
func (sp *ServiceProvider) clockSkew() time.Duration {
	if sp.ClockSkew != 0 {
		return sp.ClockSkew
	}
	return 60 * time.Second
}

// getSigningKeyStore returns the key store to use for signing.
func (sp *ServiceProvider) getSigningKeyStore() *KeyStore {
	if sp.SPSigningKeyStore != nil {
		return sp.SPSigningKeyStore
	}
	return sp.SPKeyStore
}

func (sp *ServiceProvider) GetEncryptionCertBytes() ([]byte, error) {
	if sp.SPKeyStore == nil {
		return nil, fmt.Errorf("empty SP encryption certificate")
	}
	if len(sp.SPKeyStore.Cert) < 1 {
		return nil, fmt.Errorf("empty SP encryption certificate")
	}
	return sp.SPKeyStore.Cert, nil
}

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
		Hash:  signatureAlgorithmHash(sp.SignAuthnRequestsAlgorithm),
	}
	if sp.SignAuthnRequestsCanonicalizer != nil {
		sp.signer.Canonicalizer = sp.SignAuthnRequestsCanonicalizer
	}

	return sp.signer, nil
}

// signatureAlgorithmHash returns the crypto.Hash for a given signature method URI.
// Returns 0 if unrecognized or empty; callers must treat 0 as an error.
func signatureAlgorithmHash(algorithm string) crypto.Hash {
	switch algorithm {
	case dsig.RSASHA1SignatureMethod, dsig.ECDSASHA1SignatureMethod:
		return crypto.SHA1
	case dsig.RSASHA256SignatureMethod, dsig.ECDSASHA256SignatureMethod:
		return crypto.SHA256
	case dsig.RSASHA384SignatureMethod, dsig.ECDSASHA384SignatureMethod:
		return crypto.SHA384
	case dsig.RSASHA512SignatureMethod, dsig.ECDSASHA512SignatureMethod:
		return crypto.SHA512
	default:
		return 0
	}
}

// signatureMethodIdentifier returns the XML-DSig signature method URI for the
// given key and hash algorithm. This is needed for the HTTP-Redirect binding
// where the SigAlg query parameter must be set.
func signatureMethodIdentifier(key crypto.Signer, hash crypto.Hash) string {
	if hash == 0 {
		hash = crypto.SHA256
	}
	switch key.Public().(type) {
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			return dsig.RSASHA1SignatureMethod
		case crypto.SHA256:
			return dsig.RSASHA256SignatureMethod
		case crypto.SHA384:
			return dsig.RSASHA384SignatureMethod
		case crypto.SHA512:
			return dsig.RSASHA512SignatureMethod
		}
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			return dsig.ECDSASHA1SignatureMethod
		case crypto.SHA256:
			return dsig.ECDSASHA256SignatureMethod
		case crypto.SHA384:
			return dsig.ECDSASHA384SignatureMethod
		case crypto.SHA512:
			return dsig.ECDSASHA512SignatureMethod
		}
	}
	return dsig.RSASHA256SignatureMethod
}

type ProxyRestriction struct {
	Count    int
	Audience []string
}

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
