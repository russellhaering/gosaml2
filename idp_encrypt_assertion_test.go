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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

// TestEncryptionRoundtrip_GCM tests that an assertion encrypted with AES-256-GCM
// can be decrypted by the SP's DecryptBytes method.
func TestEncryptionRoundtrip_GCM(t *testing.T) {
	testEncryptionRoundtrip(t, types.MethodAES256GCM)
}

func TestEncryptionRoundtrip_AES128GCM(t *testing.T) {
	testEncryptionRoundtrip(t, types.MethodAES128GCM)
}

func TestEncryptionRoundtrip_AES128CBC(t *testing.T) {
	testEncryptionRoundtrip(t, types.MethodAES128CBC)
}

func TestEncryptionRoundtrip_AES256CBC(t *testing.T) {
	testEncryptionRoundtrip(t, types.MethodAES256CBC)
}

func TestEncryptionRoundtrip_DefaultAlgorithm(t *testing.T) {
	// Empty algorithm should default to AES-256-GCM
	testEncryptionRoundtrip(t, "")
}

func testEncryptionRoundtrip(t *testing.T, algorithm string) {
	t.Helper()

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
				EncryptAssertions:     true,
				EncryptionAlgorithm:   algorithm,
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
		NameID:       "encrypted-user@example.com",
		NameIDFormat: NameIdFormatEmailAddress,
		Recipient:    "https://sp.test/acs",
		Attributes: []types.Attribute{
			{
				Name: "role",
				Values: []types.AttributeValue{
					{Value: "admin", Type: "xs:string"},
				},
			},
		},
	}

	doc, _, err := idp.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)

	docBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	encodedResponse := base64.StdEncoding.EncodeToString(docBytes)

	// SP validates and decrypts
	response, err := sp.ValidateEncodedResponse(context.Background(), encodedResponse)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.True(t, response.SignatureValidated)

	// The decrypted assertion should be present
	require.Len(t, response.Assertions, 1)
	assertion := response.Assertions[0]
	require.Equal(t, "encrypted-user@example.com", assertion.Subject.NameID.Value)
	require.Len(t, assertion.AttributeStatements, 1)
	require.Len(t, assertion.AttributeStatements[0].Attributes, 1)
	require.Equal(t, "role", assertion.AttributeStatements[0].Attributes[0].Name)
}

// TestEncryptionRoundtrip_DirectDecryptBytes tests that the EncryptedAssertion
// can be decrypted using DecryptBytes directly, independent of SP validation.
func TestEncryptionRoundtrip_DirectDecryptBytes(t *testing.T) {
	idpKS := testKeyStore(t, testTime)
	spKS := testKeyStore(t, testTime)

	spCert, err := x509.ParseCertificate(spKS.Cert)
	require.NoError(t, err)

	idp := &IdentityProvider{
		EntityID:       "https://idp.test/metadata",
		SSOURL:         "https://idp.test/sso",
		SigningKeyStore: idpKS,
		SignResponses:  false,
		SignAssertions: false,
		Clock:          func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{
			"https://sp.test/metadata": {
				EntityID:              "https://sp.test/metadata",
				ACSURLs:               []string{"https://sp.test/acs"},
				EncryptionCertificate: spCert,
				EncryptAssertions:     true,
			},
		},
	}

	params := &AssertionParams{
		NameID:       "direct-decrypt@example.com",
		NameIDFormat: NameIdFormatEmailAddress,
		Recipient:    "https://sp.test/acs",
	}

	doc, _, err := idp.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)

	docBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	// Parse the response XML manually
	var response types.Response
	err = xml.Unmarshal(docBytes, &response)
	require.NoError(t, err)
	require.Len(t, response.EncryptedAssertions, 1)

	// Decrypt using the SP's certificate
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{spKS.Cert},
		PrivateKey:  spKS.Signer,
	}

	plaintext, err := response.EncryptedAssertions[0].DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Contains(t, string(plaintext), "direct-decrypt@example.com")

	// Also test Decrypt() which unmarshals
	assertion, err := response.EncryptedAssertions[0].Decrypt(tlsCert)
	require.NoError(t, err)
	require.Equal(t, "direct-decrypt@example.com", assertion.Subject.NameID.Value)
}

func TestEncryptAssertion_NoCert(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	spConfig := &SPConfig{
		EntityID:          "https://sp.test/metadata",
		EncryptAssertions: true,
		// No EncryptionCertificate
	}

	// Build a minimal assertion element
	params := &AssertionParams{
		NameID:    "test",
		Recipient: "https://sp.test/acs",
	}
	assertionEl := idp.buildAssertion(spConfig, params, "https://sp.test/acs")

	_, err := idp.encryptAssertion(assertionEl, spConfig)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEncryptionFailed)
}

func TestEncryptionKeySize(t *testing.T) {
	require.Equal(t, 16, encryptionKeySize(types.MethodAES128GCM))
	require.Equal(t, 16, encryptionKeySize(types.MethodAES128CBC))
	require.Equal(t, 24, encryptionKeySize(types.MethodAES192GCM))
	require.Equal(t, 32, encryptionKeySize(types.MethodAES256GCM))
	require.Equal(t, 32, encryptionKeySize(types.MethodAES256CBC))
	require.Equal(t, 0, encryptionKeySize("unknown"))
}
