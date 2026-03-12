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
	"sync"
	"time"

	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig/v2"
)

type ErrSaml struct {
	Message string
	System  error
}

func (serr ErrSaml) Error() string {
	if serr.Message != "" {
		return serr.Message
	}
	return "SAML error"
}

type SAMLServiceProvider struct {
	IdentityProviderSSOURL     string
	IdentityProviderSSOBinding string
	IdentityProviderSLOURL     string
	IdentityProviderSLOBinding string
	IdentityProviderIssuer     string

	AssertionConsumerServiceURL string
	ServiceProviderSLOURL       string
	ServiceProviderIssuer       string

	SignAuthnRequests              bool
	SignAuthnRequestsAlgorithm     string
	SignAuthnRequestsCanonicalizer dsig.Canonicalizer

	// ForceAuthn attribute in authentication request forces the identity provider to
	// re-authenticate the presenter directly rather than rely on a previous security context.
	// NOTE: If both ForceAuthn and IsPassive are "true", the identity provider MUST NOT freshly
	// authenticate the presenter unless the constraints of IsPassive can be met.
	ForceAuthn bool
	// IsPassive attribute in authentication request requires that the identity provider and the
	// user agent itself MUST NOT visibly take control of the user interface from the requester
	// and interact with the presenter in a noticeable fashion.
	IsPassive bool
	// RequestedAuthnContext allows service providers to require that the identity
	// provider use specific authentication mechanisms. Leaving this unset will
	// permit the identity provider to choose the auth method. To maximize compatibility
	// with identity providers it is recommended to leave this unset.
	RequestedAuthnContext *RequestedAuthnContext
	AudienceURI           string

	// IDPCertificates are the trusted certificates from the identity provider.
	IDPCertificates []*x509.Certificate

	NameIdFormat            string
	ValidateEncryptionCert  bool
	SkipSignatureValidation bool
	AllowMissingAttributes  bool

	// AllowSHA1 permits SHA-1 for signature and digest algorithms.
	// Default: false (SHA-1 is rejected).
	AllowSHA1 bool

	// Clock returns the current time. If nil, time.Now is used.
	Clock func() time.Time

	// SPKeyStore holds the SP encryption/decryption key and certificate.
	SPKeyStore *KeyStore

	// SPSigningKeyStore holds the SP signing key and certificate.
	// If nil, SPKeyStore is used for signing.
	SPSigningKeyStore *KeyStore

	// MaximumDecompressedBodySize is the maximum size to which a compressed
	// SAML document will be decompressed. If a compressed document exceeds
	// this size during decompression an error will be returned.
	MaximumDecompressedBodySize int64

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
// identity provider select an authentication mechansim.
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

func (sp *SAMLServiceProvider) Metadata() (*types.EntityDescriptor, error) {
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
	return &types.EntityDescriptor{
		ValidUntil: sp.now().UTC().Add(time.Hour * 24 * 7), // 7 days
		EntityID:   sp.ServiceProviderIssuer,
		SPSSODescriptor: &types.SPSSODescriptor{
			AuthnRequestsSigned:        sp.SignAuthnRequests,
			WantAssertionsSigned:       !sp.SkipSignatureValidation,
			ProtocolSupportEnumeration: SAMLProtocolNamespace,
			KeyDescriptors:             keyDescriptors,
			AssertionConsumerServices: []types.IndexedEndpoint{{
				Binding:  BindingHttpPost,
				Location: sp.AssertionConsumerServiceURL,
				Index:    1,
			}},
		},
	}, nil
}

func (sp *SAMLServiceProvider) MetadataWithSLO(validityHours int64) (*types.EntityDescriptor, error) {
	signingCertBytes, err := sp.GetSigningCertBytes()
	if err != nil {
		return nil, err
	}
	encryptionCertBytes, err := sp.GetEncryptionCertBytes()
	if err != nil {
		return nil, err
	}

	if validityHours <= 0 {
		// By default let's keep it to 7 days.
		validityHours = int64(time.Hour * 24 * 7)
	}

	return &types.EntityDescriptor{
		ValidUntil: sp.now().UTC().Add(time.Duration(validityHours)), // default 7 days
		EntityID:   sp.ServiceProviderIssuer,
		SPSSODescriptor: &types.SPSSODescriptor{
			AuthnRequestsSigned:        sp.SignAuthnRequests,
			WantAssertionsSigned:       !sp.SkipSignatureValidation,
			ProtocolSupportEnumeration: SAMLProtocolNamespace,
			KeyDescriptors: []types.KeyDescriptor{
				{
					Use: "signing",
					KeyInfo: types.KeyInfo{
						X509Data: types.X509Data{
							X509Certificates: []types.X509Certificate{{
								Data: base64.StdEncoding.EncodeToString(signingCertBytes),
							}},
						},
					},
				},
				{
					Use: "encryption",
					KeyInfo: types.KeyInfo{
						X509Data: types.X509Data{
							X509Certificates: []types.X509Certificate{{
								Data: base64.StdEncoding.EncodeToString(encryptionCertBytes),
							}},
						},
					},
					EncryptionMethods: []types.EncryptionMethod{
						{Algorithm: types.MethodAES128GCM, DigestMethod: nil},
						{Algorithm: types.MethodAES192GCM, DigestMethod: nil},
						{Algorithm: types.MethodAES256GCM, DigestMethod: nil},
						{Algorithm: types.MethodAES128CBC, DigestMethod: nil},
						{Algorithm: types.MethodAES256CBC, DigestMethod: nil},
					},
				},
			},
			AssertionConsumerServices: []types.IndexedEndpoint{{
				Binding:  BindingHttpPost,
				Location: sp.AssertionConsumerServiceURL,
				Index:    1,
			}},
			SingleLogoutServices: []types.Endpoint{{
				Binding:  BindingHttpPost,
				Location: sp.ServiceProviderSLOURL,
			}},
		},
	}, nil
}

// now returns the current time using the configured clock, or time.Now.
func (sp *SAMLServiceProvider) now() time.Time {
	if sp.Clock != nil {
		return sp.Clock()
	}
	return time.Now()
}

// getSigningKeyStore returns the key store to use for signing.
func (sp *SAMLServiceProvider) getSigningKeyStore() *KeyStore {
	if sp.SPSigningKeyStore != nil {
		return sp.SPSigningKeyStore
	}
	return sp.SPKeyStore
}

func (sp *SAMLServiceProvider) GetEncryptionCertBytes() ([]byte, error) {
	if sp.SPKeyStore == nil {
		return nil, ErrSaml{Message: "empty SP encryption certificate"}
	}
	if len(sp.SPKeyStore.Cert) < 1 {
		return nil, ErrSaml{Message: "empty SP encryption certificate"}
	}
	return sp.SPKeyStore.Cert, nil
}

func (sp *SAMLServiceProvider) GetSigningCertBytes() ([]byte, error) {
	ks := sp.getSigningKeyStore()
	if ks == nil {
		return nil, ErrSaml{Message: "empty SP signing certificate"}
	}
	if len(ks.Cert) < 1 {
		return nil, ErrSaml{Message: "empty SP signing certificate"}
	}
	return ks.Cert, nil
}

// Signer returns a dsig.Signer configured for this service provider.
func (sp *SAMLServiceProvider) Signer() *dsig.Signer {
	sp.signerMu.RLock()
	s := sp.signer
	sp.signerMu.RUnlock()

	if s != nil {
		return s
	}

	sp.signerMu.Lock()
	defer sp.signerMu.Unlock()

	ks := sp.getSigningKeyStore()
	if ks == nil {
		return nil
	}

	cert, err := x509.ParseCertificate(ks.Cert)
	if err != nil {
		// Ideally this function should return the error, but updating the function
		// signature would be backward incompatible. Returning nil avoids the previous
		// panic while preserving the existing API contract.
		return nil
	}

	sp.signer = &dsig.Signer{
		Key:   ks.Signer,
		Certs: []*x509.Certificate{cert},
		Hash:  signatureAlgorithmHash(sp.SignAuthnRequestsAlgorithm),
	}
	if sp.SignAuthnRequestsCanonicalizer != nil {
		sp.signer.Canonicalizer = sp.SignAuthnRequestsCanonicalizer
	}

	return sp.signer
}

// signatureAlgorithmHash returns the crypto.Hash for a given signature method URI.
// Returns 0 (which defaults to SHA256 in the Signer) if unrecognized or empty.
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

type WarningInfo struct {
	OneTimeUse       bool
	ProxyRestriction *ProxyRestriction
	NotInAudience    bool
	InvalidTime      bool
}

type AssertionInfo struct {
	NameID                     string
	Values                     Values
	WarningInfo                *WarningInfo
	SessionIndex               string
	AuthnInstant               *time.Time
	SessionNotOnOrAfter        *time.Time
	Assertions                 []types.Assertion
	ResponseSignatureValidated bool
}
