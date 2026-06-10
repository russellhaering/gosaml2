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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/sp"
	"github.com/stretchr/testify/require"
)

func buildTestAuthnRequestXML(id, issuer, destination, acsURL string) string {
	return fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/></samlp:AuthnRequest>`,
		id, destination, acsURL, issuer)
}

func encodeAuthnRequestPOST(xmlStr string) string {
	return base64.StdEncoding.EncodeToString([]byte(xmlStr))
}

func encodeAuthnRequestRedirect(xmlStr string) string {
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	fw.Write([]byte(xmlStr))
	fw.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestValidateEncodedAuthnRequestPOST(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestAuthnRequestXML("_req123", "https://sp.test/metadata", "https://idp.test/sso", "https://sp.test/acs")
	encoded := encodeAuthnRequestPOST(xmlStr)

	info, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.NoError(t, err)
	require.Equal(t, "_req123", info.ID)
	require.Equal(t, "https://sp.test/metadata", info.Issuer)
	require.Equal(t, "https://sp.test/acs", info.ACSURL)
	require.NotNil(t, info.SP)
}

func TestValidateEncodedAuthnRequestPOST_UnknownSP(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestAuthnRequestXML("_req123", "https://unknown.test/metadata", "https://idp.test/sso", "https://sp.test/acs")
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrUnknownSP)
}

func TestValidateEncodedAuthnRequestPOST_BadACSURL(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestAuthnRequestXML("_req123", "https://sp.test/metadata", "https://idp.test/sso", "https://evil.test/acs")
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadACSURL)
}

func TestValidateEncodedAuthnRequestPOST_BadDestination(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestAuthnRequestXML("_req123", "https://sp.test/metadata", "https://evil.test/sso", "https://sp.test/acs")
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

func TestValidateEncodedAuthnRequestPOST_MissingID(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="https://idp.test/sso" AssertionConsumerServiceURL="https://sp.test/acs"><saml:Issuer>https://sp.test/metadata</saml:Issuer></samlp:AuthnRequest>`)
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

func TestValidateEncodedAuthnRequestPOST_BadVersion(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req123" Version="1.1" IssueInstant="2025-06-01T12:00:00Z" Destination="https://idp.test/sso" AssertionConsumerServiceURL="https://sp.test/acs"><saml:Issuer>https://sp.test/metadata</saml:Issuer></samlp:AuthnRequest>`)
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadVersion)
}

func TestValidateEncodedAuthnRequestPOST_DefaultACSURL(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	// No AssertionConsumerServiceURL in request -- should default to first registered ACS URL
	xmlStr := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req123" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="https://idp.test/sso"><saml:Issuer>https://sp.test/metadata</saml:Issuer></samlp:AuthnRequest>`)
	encoded := encodeAuthnRequestPOST(xmlStr)

	info, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.NoError(t, err)
	require.Equal(t, "https://sp.test/acs", info.ACSURL)
}

func TestValidateEncodedAuthnRequestPOST_InvalidBase64(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), "not-base64!!!")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMalformed)
}

func TestValidateEncodedAuthnRequestRedirect(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestAuthnRequestXML("_req456", "https://sp.test/metadata", "https://idp.test/sso", "https://sp.test/acs")
	encoded := encodeAuthnRequestRedirect(xmlStr)

	info, err := idp.ValidateEncodedAuthnRequestRedirect(context.Background(), encoded, "relay123", "", "")
	require.NoError(t, err)
	require.Equal(t, "_req456", info.ID)
	require.Equal(t, "https://sp.test/metadata", info.Issuer)
	require.Equal(t, "https://sp.test/acs", info.ACSURL)
	require.Equal(t, "relay123", info.RelayState)
}

func TestValidateEncodedAuthnRequestRedirect_RequireSignature(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	idp.ServiceProviders["https://sp.test/metadata"].RequireSignedAuthnRequests = true

	xmlStr := buildTestAuthnRequestXML("_req456", "https://sp.test/metadata", "https://idp.test/sso", "https://sp.test/acs")
	encoded := encodeAuthnRequestRedirect(xmlStr)

	// No signature provided -- should fail
	_, err := idp.ValidateEncodedAuthnRequestRedirect(context.Background(), encoded, "", "", "")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingSignature)
}

// TestValidateEncodedAuthnRequestRedirect_SPBuildsAndIdPParses tests that an SP-built
// AuthnRequest can be parsed by the IdP (not a full roundtrip since redirect signing
// verification requires more setup, but validates encoding/decoding).
func TestValidateEncodedAuthnRequestRedirect_SPBuildsAndIdPParses(t *testing.T) {
	idpKS := testIdPKeyStore(t)
	spKS := testKeyStore(t, testTime)
	spCert, err := x509.ParseCertificate(spKS.Cert)
	require.NoError(t, err)
	idpCert, err := x509.ParseCertificate(idpKS.Cert)
	require.NoError(t, err)

	spInst := &sp.ServiceProvider{
		EntityID:          "https://sp.test/metadata",
		ACSURL:            "https://sp.test/acs",
		IDPSSOURL:         "https://idp.test/sso",
		IDPEntityID:       "https://idp.test/metadata",
		SignAuthnRequests: false,
		IDPCertificates:   []*x509.Certificate{idpCert},
		Clock:             func() time.Time { return testTime },
	}

	idpInst := &IdentityProvider{
		EntityID:        "https://idp.test/metadata",
		SSOURL:          "https://idp.test/sso",
		SigningKeyStore: idpKS,
		SignResponses:   true,
		SignAssertions:  true,
		Clock:           func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{
			"https://sp.test/metadata": {
				EntityID:            "https://sp.test/metadata",
				ACSURLs:             []string{"https://sp.test/acs"},
				SigningCertificates: []*x509.Certificate{spCert},
			},
		},
	}

	// SP builds an AuthnRequest
	doc, err := spInst.BuildAuthRequestDocumentNoSig()
	require.NoError(t, err)

	xmlStr, err := doc.WriteToString()
	require.NoError(t, err)

	// Encode as redirect (DEFLATE + base64)
	encoded := encodeAuthnRequestRedirect(xmlStr)

	// IdP parses it
	info, err := idpInst.ValidateEncodedAuthnRequestRedirect(context.Background(), encoded, "", "", "")
	require.NoError(t, err)
	require.Equal(t, "https://sp.test/metadata", info.Issuer)
	require.Equal(t, "https://sp.test/acs", info.ACSURL)
}
