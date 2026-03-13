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
	"context"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

func TestBuildResponseDocument(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	params := &AssertionParams{
		NameID:       "user@example.com",
		NameIDFormat: NameIdFormatEmailAddress,
		AuthnContext: AuthnContextPasswordProtectedTransport,
		InResponseTo: "_req123",
		Recipient:    "https://sp.test/acs",
		Attributes: []types.Attribute{
			{
				Name: "email",
				Values: []types.AttributeValue{
					{Value: "user@example.com", Type: "xs:string"},
				},
			},
		},
	}

	doc, acsURL, err := idp.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)
	require.Equal(t, "https://sp.test/acs", acsURL)
	require.NotNil(t, doc)

	xmlStr, err := doc.WriteToString()
	require.NoError(t, err)
	require.Contains(t, xmlStr, "user@example.com")
	require.Contains(t, xmlStr, StatusCodeSuccess)
}

func TestBuildResponseDocument_DefaultACSURL(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	params := &AssertionParams{
		NameID:       "user@example.com",
		InResponseTo: "_req123",
		// No Recipient — should use SP's first ACS URL
	}

	_, acsURL, err := idp.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)
	require.Equal(t, "https://sp.test/acs", acsURL)
}

func TestBuildResponseDocument_UnknownSP(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	params := &AssertionParams{NameID: "user@example.com"}

	_, _, err := idp.BuildResponseDocument("https://unknown.test", params)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnknownSP)
}

func TestBuildResponseBodyPost(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	params := &AssertionParams{
		NameID:       "user@example.com",
		NameIDFormat: NameIdFormatEmailAddress,
		InResponseTo: "_req123",
		Recipient:    "https://sp.test/acs",
	}

	body, err := idp.BuildResponseBodyPost("https://sp.test/metadata", params, "relay123")
	require.NoError(t, err)
	require.Contains(t, string(body), "SAMLResponse")
	require.Contains(t, string(body), "relay123")
	require.Contains(t, string(body), "https://sp.test/acs")
}

func TestBuildErrorResponseDocument(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	doc, err := idp.BuildErrorResponseDocument("https://sp.test/metadata", StatusCodeRequester, "_req123", "https://sp.test/acs")
	require.NoError(t, err)
	require.NotNil(t, doc)

	xmlStr, err := doc.WriteToString()
	require.NoError(t, err)
	require.Contains(t, xmlStr, StatusCodeRequester)
	require.Contains(t, xmlStr, "_req123")
}

func TestBuildErrorResponseDocument_UnknownSP(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	_, err := idp.BuildErrorResponseDocument("https://unknown.test", StatusCodeRequester, "_req123", "https://sp.test/acs")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnknownSP)
}

// TestResponseRoundtrip builds a Response with the IdP and validates it with the SP.
func TestResponseRoundtrip(t *testing.T) {
	idpKS := testKeyStore(t, testTime)
	spKS := testKeyStore(t, testTime)

	idpCert, err := x509.ParseCertificate(idpKS.Cert)
	require.NoError(t, err)
	spCert, err := x509.ParseCertificate(spKS.Cert)
	require.NoError(t, err)

	idp := &IdentityProvider{
		EntityID:       "https://idp.test/metadata",
		SSOURL:         "https://idp.test/sso",
		SigningKeyStore: idpKS,
		SignResponses:  true,
		SignAssertions: false,
		Clock:          func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{
			"https://sp.test/metadata": {
				EntityID:              "https://sp.test/metadata",
				ACSURLs:               []string{"https://sp.test/acs"},
				SigningCertificates:   []*x509.Certificate{spCert},
				EncryptionCertificate: spCert,
			},
		},
	}

	sp := &ServiceProvider{
		EntityID:         "https://sp.test/metadata",
		ACSURL:           "https://sp.test/acs",
		IDPEntityID:      "https://idp.test/metadata",
		IDPSSOURL:        "https://idp.test/sso",
		IDPCertificates:  []*x509.Certificate{idpCert},
		SPKeyStore:       spKS,
		AudienceURIs:     []string{"https://sp.test/metadata"},
		AllowIDPInitiated: true,
		Clock:            func() time.Time { return testTime },
	}

	params := &AssertionParams{
		NameID:       "user@example.com",
		NameIDFormat: NameIdFormatEmailAddress,
		AuthnContext: AuthnContextPasswordProtectedTransport,
		Recipient:    "https://sp.test/acs",
		Attributes: []types.Attribute{
			{
				Name: "email",
				Values: []types.AttributeValue{
					{Value: "user@example.com", Type: "xs:string"},
				},
			},
			{
				Name: "name",
				Values: []types.AttributeValue{
					{Value: "Test User", Type: "xs:string"},
				},
			},
		},
	}

	doc, acsURL, err := idp.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)
	require.Equal(t, "https://sp.test/acs", acsURL)

	docBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	encodedResponse := base64.StdEncoding.EncodeToString(docBytes)

	// SP validates the response
	response, err := sp.ValidateEncodedResponse(context.Background(), encodedResponse)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.True(t, response.SignatureValidated)
	require.Equal(t, "https://idp.test/metadata", response.Issuer.Value)
	require.Len(t, response.Assertions, 1)

	assertion := response.Assertions[0]
	require.Equal(t, "user@example.com", assertion.Subject.NameID.Value)
	require.Equal(t, NameIdFormatEmailAddress, assertion.Subject.NameID.Format)

	// Check attributes
	require.Len(t, assertion.AttributeStatements, 1)
	attrs := assertion.AttributeStatements[0].Attributes
	require.Len(t, attrs, 2)
}

// TestResponseRoundtrip_SignedAssertions tests with only assertion-level signing.
func TestResponseRoundtrip_SignedAssertions(t *testing.T) {
	idpKS := testKeyStore(t, testTime)
	spKS := testKeyStore(t, testTime)

	idpCert, err := x509.ParseCertificate(idpKS.Cert)
	require.NoError(t, err)
	spCert, err := x509.ParseCertificate(spKS.Cert)
	require.NoError(t, err)

	idp := &IdentityProvider{
		EntityID:       "https://idp.test/metadata",
		SSOURL:         "https://idp.test/sso",
		SigningKeyStore: idpKS,
		SignResponses:  false,
		SignAssertions: true,
		Clock:          func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{
			"https://sp.test/metadata": {
				EntityID:            "https://sp.test/metadata",
				ACSURLs:             []string{"https://sp.test/acs"},
				SigningCertificates: []*x509.Certificate{spCert},
			},
		},
	}

	sp := &ServiceProvider{
		EntityID:         "https://sp.test/metadata",
		ACSURL:           "https://sp.test/acs",
		IDPEntityID:      "https://idp.test/metadata",
		IDPSSOURL:        "https://idp.test/sso",
		IDPCertificates:  []*x509.Certificate{idpCert},
		SPKeyStore:       spKS,
		AudienceURIs:     []string{"https://sp.test/metadata"},
		AllowIDPInitiated: true,
		Clock:            func() time.Time { return testTime },
	}

	params := &AssertionParams{
		NameID:       "user@example.com",
		NameIDFormat: NameIdFormatEmailAddress,
		Recipient:    "https://sp.test/acs",
	}

	doc, _, err := idp.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)

	docBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	encodedResponse := base64.StdEncoding.EncodeToString(docBytes)

	response, err := sp.ValidateEncodedResponse(context.Background(), encodedResponse)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Len(t, response.Assertions, 1)
	require.True(t, response.Assertions[0].SignatureValidated)
}

// TestResponseRoundtrip_BothSigned tests with both response and assertion signing.
func TestResponseRoundtrip_BothSigned(t *testing.T) {
	idpKS := testKeyStore(t, testTime)
	spKS := testKeyStore(t, testTime)

	idpCert, err := x509.ParseCertificate(idpKS.Cert)
	require.NoError(t, err)
	spCert, err := x509.ParseCertificate(spKS.Cert)
	require.NoError(t, err)

	idp := &IdentityProvider{
		EntityID:       "https://idp.test/metadata",
		SSOURL:         "https://idp.test/sso",
		SigningKeyStore: idpKS,
		SignResponses:  true,
		SignAssertions: true,
		Clock:          func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{
			"https://sp.test/metadata": {
				EntityID:            "https://sp.test/metadata",
				ACSURLs:             []string{"https://sp.test/acs"},
				SigningCertificates: []*x509.Certificate{spCert},
			},
		},
	}

	sp := &ServiceProvider{
		EntityID:         "https://sp.test/metadata",
		ACSURL:           "https://sp.test/acs",
		IDPEntityID:      "https://idp.test/metadata",
		IDPSSOURL:        "https://idp.test/sso",
		IDPCertificates:  []*x509.Certificate{idpCert},
		SPKeyStore:       spKS,
		AudienceURIs:     []string{"https://sp.test/metadata"},
		AllowIDPInitiated: true,
		Clock:            func() time.Time { return testTime },
	}

	params := &AssertionParams{
		NameID:       "user@example.com",
		NameIDFormat: NameIdFormatEmailAddress,
		Recipient:    "https://sp.test/acs",
		Attributes: []types.Attribute{
			{
				Name: "role",
				Values: []types.AttributeValue{
					{Value: "admin"},
				},
			},
		},
	}

	doc, _, err := idp.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)

	docBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	encodedResponse := base64.StdEncoding.EncodeToString(docBytes)

	response, err := sp.ValidateEncodedResponse(context.Background(), encodedResponse)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.True(t, response.SignatureValidated)
	require.Len(t, response.Assertions, 1)
}

// TestResponseRoundtrip_WithInResponseTo tests that InResponseTo is preserved.
func TestResponseRoundtrip_WithInResponseTo(t *testing.T) {
	idpKS := testKeyStore(t, testTime)
	spKS := testKeyStore(t, testTime)

	idpCert, err := x509.ParseCertificate(idpKS.Cert)
	require.NoError(t, err)
	spCert, err := x509.ParseCertificate(spKS.Cert)
	require.NoError(t, err)

	tracker := NewMemoryRequestTracker(10 * time.Minute)
	require.NoError(t, tracker.StoreRequest(context.Background(), "_req999"))

	idp := &IdentityProvider{
		EntityID:       "https://idp.test/metadata",
		SSOURL:         "https://idp.test/sso",
		SigningKeyStore: idpKS,
		SignResponses:  true,
		Clock:          func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{
			"https://sp.test/metadata": {
				EntityID:            "https://sp.test/metadata",
				ACSURLs:             []string{"https://sp.test/acs"},
				SigningCertificates: []*x509.Certificate{spCert},
			},
		},
	}

	sp := &ServiceProvider{
		EntityID:         "https://sp.test/metadata",
		ACSURL:           "https://sp.test/acs",
		IDPEntityID:      "https://idp.test/metadata",
		IDPSSOURL:        "https://idp.test/sso",
		IDPCertificates:  []*x509.Certificate{idpCert},
		SPKeyStore:       spKS,
		AudienceURIs:     []string{"https://sp.test/metadata"},
		RequestTracker:   tracker,
		Clock:            func() time.Time { return testTime },
	}

	params := &AssertionParams{
		NameID:       "user@example.com",
		InResponseTo: "_req999",
		Recipient:    "https://sp.test/acs",
	}

	doc, _, err := idp.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)

	docBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	encodedResponse := base64.StdEncoding.EncodeToString(docBytes)

	response, err := sp.ValidateEncodedResponse(context.Background(), encodedResponse)
	require.NoError(t, err)
	require.Equal(t, "_req999", response.InResponseTo)
}
