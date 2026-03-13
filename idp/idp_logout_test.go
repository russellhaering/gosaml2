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
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/stretchr/testify/require"
)

func buildTestLogoutRequestXML(id, issuer, destination, nameID, sessionIndex string) string {
	return fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID><samlp:SessionIndex>%s</samlp:SessionIndex></samlp:LogoutRequest>`,
		id, destination, issuer, nameID, sessionIndex)
}

func TestValidateEncodedLogoutRequestPOST(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestLogoutRequestXML("_logout123", "https://sp.test/metadata", "https://idp.test/slo", "user@example.com", "_session456")
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))

	req, spConfig, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.NoError(t, err)
	require.Equal(t, "_logout123", req.ID)
	require.Equal(t, "https://sp.test/metadata", req.Issuer)
	require.Equal(t, "user@example.com", req.NameID.Value)
	require.Equal(t, "_session456", req.SessionIndex)
	require.Equal(t, "https://sp.test/metadata", spConfig.EntityID)
}

func TestValidateEncodedLogoutRequestPOST_UnknownSP(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestLogoutRequestXML("_logout123", "https://unknown.test/metadata", "https://idp.test/slo", "user@example.com", "_session456")
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))

	_, _, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrUnknownSP)
}

func TestValidateEncodedLogoutRequestPOST_BadDestination(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestLogoutRequestXML("_logout123", "https://sp.test/metadata", "https://evil.test/slo", "user@example.com", "_session456")
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))

	_, _, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

func TestValidateEncodedLogoutRequestPOST_InvalidBase64(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	_, _, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), "not-base64!!!")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMalformed)
}

func TestValidateEncodedLogoutRequestRedirect(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestLogoutRequestXML("_logout789", "https://sp.test/metadata", "https://idp.test/slo", "user@example.com", "_session456")
	encoded := encodeAuthnRequestRedirect(xmlStr) // reuse DEFLATE+base64 encoding

	req, spConfig, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), encoded, "relay123", "", "")
	require.NoError(t, err)
	require.Equal(t, "_logout789", req.ID)
	require.Equal(t, "https://sp.test/metadata", spConfig.EntityID)
}

func TestBuildLogoutResponseDocument(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	doc, err := idp.BuildLogoutResponseDocument("https://sp.test/metadata", saml2.StatusCodeSuccess, "_logout123", "https://sp.test/slo")
	require.NoError(t, err)
	require.NotNil(t, doc)

	xmlStr, err := doc.WriteToString()
	require.NoError(t, err)
	require.Contains(t, xmlStr, saml2.StatusCodeSuccess)
	require.Contains(t, xmlStr, "_logout123")
	require.Contains(t, xmlStr, "https://sp.test/slo")
}

func TestBuildLogoutResponseDocument_UnknownSP(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	_, err := idp.BuildLogoutResponseDocument("https://unknown.test", saml2.StatusCodeSuccess, "_logout123", "https://sp.test/slo")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrUnknownSP)
}

func TestBuildLogoutResponseBodyPost(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	body, err := idp.BuildLogoutResponseBodyPost("https://sp.test/metadata", saml2.StatusCodeSuccess, "_logout123", "https://sp.test/slo", "relay456")
	require.NoError(t, err)
	require.Contains(t, string(body), "SAMLResponse")
	require.Contains(t, string(body), "relay456")
	require.Contains(t, string(body), "https://sp.test/slo")
}

func TestBuildLogoutRequestDocument(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	doc, err := idp.BuildLogoutRequestDocument("https://sp.test/metadata", "user@example.com", saml2.NameIdFormatEmailAddress, "_session123")
	require.NoError(t, err)
	require.NotNil(t, doc)

	xmlStr, err := doc.WriteToString()
	require.NoError(t, err)
	require.Contains(t, xmlStr, "user@example.com")
	require.Contains(t, xmlStr, saml2.NameIdFormatEmailAddress)
	require.Contains(t, xmlStr, "_session123")
	require.Contains(t, xmlStr, "https://sp.test/slo")
}

func TestBuildLogoutRequestDocument_UnknownSP(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	_, err := idp.BuildLogoutRequestDocument("https://unknown.test", "user@example.com", saml2.NameIdFormatEmailAddress, "_session123")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrUnknownSP)
}

func TestBuildLogoutRequestDocument_NoSLOURL(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	// Remove SLO URLs from SP config
	idp.ServiceProviders["https://sp.test/metadata"].SLOURLs = nil

	doc, err := idp.BuildLogoutRequestDocument("https://sp.test/metadata", "user@example.com", saml2.NameIdFormatEmailAddress, "")
	require.NoError(t, err)
	require.NotNil(t, doc)

	// Should still build, just without Destination attribute
	xmlStr, err := doc.WriteToString()
	require.NoError(t, err)
	require.Contains(t, xmlStr, "user@example.com")
}
