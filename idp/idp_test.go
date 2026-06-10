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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"math/big"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

var testTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

// testKeyStore generates an RSA key pair with a certificate valid at the given
// time, suitable for use with a fake clock in tests.
func testKeyStore(t *testing.T, validAt time.Time) *saml2.KeyStore {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		NotBefore:             validAt.Add(-time.Hour),
		NotAfter:              validAt.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return &saml2.KeyStore{Signer: key, Cert: certBytes}
}

func testIdPKeyStore(t *testing.T) *saml2.KeyStore {
	t.Helper()
	return testKeyStore(t, testTime)
}

func testSPKeyStore(t *testing.T) (*saml2.KeyStore, *x509.Certificate) {
	t.Helper()
	ks := testKeyStore(t, testTime)
	cert, err := x509.ParseCertificate(ks.Cert)
	require.NoError(t, err)
	return ks, cert
}

func testIdentityProvider(t *testing.T) (*IdentityProvider, *saml2.KeyStore) {
	t.Helper()
	idpKS := testIdPKeyStore(t)
	spKS, spCert := testSPKeyStore(t)

	idp := &IdentityProvider{
		EntityID:        "https://idp.test/metadata",
		SSOURL:          "https://idp.test/sso",
		SLOURL:          "https://idp.test/slo",
		SigningKeyStore: idpKS,
		SignResponses:   true,
		SignAssertions:  true,
		Clock:           func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{
			"https://sp.test/metadata": {
				EntityID:              "https://sp.test/metadata",
				ACSURLs:               []string{"https://sp.test/acs"},
				SLOURLs:               []string{"https://sp.test/slo"},
				SigningCertificates:   []*x509.Certificate{spCert},
				EncryptionCertificate: spCert,
			},
		},
	}

	_ = spKS // available if caller needs it
	return idp, idpKS
}

func TestIdentityProvider_Now(t *testing.T) {
	idp := &IdentityProvider{}
	// Without clock, should be close to time.Now()
	require.WithinDuration(t, time.Now(), idp.now(), time.Second)

	// With custom clock
	fixed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	idp.Clock = func() time.Time { return fixed }
	require.Equal(t, fixed, idp.now())
}

func TestIdentityProvider_ClockSkew(t *testing.T) {
	idp := &IdentityProvider{}
	require.Equal(t, 60*time.Second, idp.clockSkew())

	idp.ClockSkew = 30 * time.Second
	require.Equal(t, 30*time.Second, idp.clockSkew())
}

func TestIdentityProvider_AssertionLifetime(t *testing.T) {
	idp := &IdentityProvider{}
	require.Equal(t, 5*time.Minute, idp.assertionLifetime())

	idp.AssertionLifetime = 10 * time.Minute
	require.Equal(t, 10*time.Minute, idp.assertionLifetime())
}

func TestIdentityProvider_SessionLifetime(t *testing.T) {
	idp := &IdentityProvider{}
	require.Equal(t, 8*time.Hour, idp.sessionLifetime())

	idp.SessionLifetime = 4 * time.Hour
	require.Equal(t, 4*time.Hour, idp.sessionLifetime())
}

func TestIdentityProvider_LookupSP(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	spConfig, err := idp.lookupSP("https://sp.test/metadata")
	require.NoError(t, err)
	require.Equal(t, "https://sp.test/metadata", spConfig.EntityID)

	_, err = idp.lookupSP("https://unknown.test/metadata")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrUnknownSP)
}

func TestIdentityProvider_LookupSP_NoProviders(t *testing.T) {
	idp := &IdentityProvider{}
	_, err := idp.lookupSP("anything")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrUnknownSP)
}

func TestIdentityProvider_Signer(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	signer, err := idp.Signer()
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Second call should return cached signer
	signer2, err := idp.Signer()
	require.NoError(t, err)
	require.Same(t, signer, signer2)
}

func TestIdentityProvider_Signer_NoKeyStore(t *testing.T) {
	idp := &IdentityProvider{}
	_, err := idp.Signer()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no signing key store")
}

func TestConfigureFromSPMetadata(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             testTime.Add(-time.Hour),
		NotAfter:              testTime.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// Build a minimal EntityDescriptor XML and parse it
	ed := &types.EntityDescriptor{
		EntityID: "https://sp.test/metadata",
		SPSSODescriptor: &types.SPSSODescriptor{
			AssertionConsumerServices: []types.IndexedEndpoint{
				{Binding: saml2.BindingHttpPost, Location: "https://sp.test/acs", Index: 1},
			},
			SingleLogoutServices: []types.Endpoint{
				{Binding: saml2.BindingHttpPost, Location: "https://sp.test/slo"},
			},
		},
	}

	// Marshal and unmarshal to simulate real metadata parsing
	xmlBytes, err := xml.Marshal(ed)
	require.NoError(t, err)

	var parsed types.EntityDescriptor
	err = xml.Unmarshal(xmlBytes, &parsed)
	require.NoError(t, err)

	spConfig, err := ConfigureFromSPMetadata(&parsed)
	require.NoError(t, err)
	require.Equal(t, "https://sp.test/metadata", spConfig.EntityID)
	require.Equal(t, []string{"https://sp.test/acs"}, spConfig.ACSURLs)
	require.Equal(t, []string{"https://sp.test/slo"}, spConfig.SLOURLs)

	_ = certBytes
}

func TestConfigureFromSPMetadata_NoSPDescriptor(t *testing.T) {
	ed := &types.EntityDescriptor{EntityID: "test"}
	_, err := ConfigureFromSPMetadata(ed)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no SPSSODescriptor")
}

func TestIdentityProvider_Metadata(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	md, err := idp.Metadata()
	require.NoError(t, err)
	require.Equal(t, "https://idp.test/metadata", md.EntityID)
	require.NotNil(t, md.IDPSSODescriptor)
	require.Equal(t, saml2.SAMLProtocolNamespace, md.IDPSSODescriptor.ProtocolSupportEnumeration)
	require.True(t, md.IDPSSODescriptor.WantAuthnRequestsSigned)
	require.Len(t, md.IDPSSODescriptor.KeyDescriptors, 1)
	require.Equal(t, "signing", md.IDPSSODescriptor.KeyDescriptors[0].Use)
	require.Len(t, md.IDPSSODescriptor.SingleSignOnServices, 2)
	require.Len(t, md.IDPSSODescriptor.SingleLogoutServices, 2)

	// NameID formats
	require.Len(t, md.IDPSSODescriptor.NameIDFormats, 1)
	require.Equal(t, saml2.NameIdFormatTransient, md.IDPSSODescriptor.NameIDFormats[0].Value)

	// ValidUntil should be 7 days from testTime
	require.Equal(t, testTime.UTC().Add(7*24*time.Hour), md.ValidUntil)
}

func TestIdentityProvider_Metadata_CustomNameIDFormats(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	idp.NameIDFormats = []string{saml2.NameIdFormatEmailAddress, saml2.NameIdFormatPersistent}

	md, err := idp.Metadata()
	require.NoError(t, err)
	require.Len(t, md.IDPSSODescriptor.NameIDFormats, 2)
	require.Equal(t, saml2.NameIdFormatEmailAddress, md.IDPSSODescriptor.NameIDFormats[0].Value)
	require.Equal(t, saml2.NameIdFormatPersistent, md.IDPSSODescriptor.NameIDFormats[1].Value)
}

func TestIdentityProvider_Metadata_Roundtrip(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	md, err := idp.Metadata()
	require.NoError(t, err)

	// Marshal and unmarshal to verify XML roundtrip
	xmlBytes, err := xml.Marshal(md)
	require.NoError(t, err)

	var parsed types.EntityDescriptor
	err = xml.Unmarshal(xmlBytes, &parsed)
	require.NoError(t, err)

	require.Equal(t, md.EntityID, parsed.EntityID)
	require.NotNil(t, parsed.IDPSSODescriptor)
	require.Len(t, parsed.IDPSSODescriptor.SingleSignOnServices, 2)
}
