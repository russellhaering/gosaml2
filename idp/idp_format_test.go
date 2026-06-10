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

package idp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"os"
	"testing"
	"time"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/russellhaering/gosaml2/v2/sp"
	"github.com/stretchr/testify/require"
)

// idpFormatTestCase defines a test case exercising SAML response parsing for
// responses formatted in the style of a specific Identity Provider.
type idpFormatTestCase struct {
	name        string
	xmlFile     string
	idpEntityID string
	checkResult func(t *testing.T, info *sp.AssertionInfo)
}

// signResponse reads an XML response, strips existing signatures, signs with
// the SP's key, and returns the signed XML string.
func signResponse(t *testing.T, resp string, spInst *sp.ServiceProvider) string {
	t.Helper()
	doc := xmltree.NewDocument()
	err := doc.ReadFromBytes([]byte(resp))
	require.NoError(t, err)

	el := doc.Root()

	// Strip existing signatures
	signatures := el.FindElements("//Signature")
	for _, sig := range signatures {
		parent := sig.Parent()
		parent.RemoveChild(sig)
	}

	signer, err := spInst.Signer()
	require.NoError(t, err)
	el, err = signer.SignEnveloped(el)
	require.NoError(t, err)

	var buf bytes.Buffer
	el.WriteCanonicalTo(&buf)
	return buf.String()
}

// loadAndSign reads an XML response fixture, signs it with the SP's key, and
// returns the base64-encoded result ready for ValidateEncodedResponse.
func loadAndSign(t *testing.T, path string, spInst *sp.ServiceProvider) string {
	t.Helper()
	xmlBytes, err := os.ReadFile(path)
	require.NoError(t, err)
	signed := signResponse(t, string(xmlBytes), spInst)
	return base64.StdEncoding.EncodeToString([]byte(signed))
}

// TestIdPResponseFormats validates that the library correctly parses SAML
// responses formatted in the style of popular Identity Providers. Each
// response exercises different XML namespace conventions, attribute formats,
// NameID formats, and other IdP-specific characteristics.
func TestIdPResponseFormats(t *testing.T) {
	fakeTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ks := testKeyStore(t, fakeTime)

	idpCert, err := x509.ParseCertificate(ks.Cert)
	require.NoError(t, err)

	tests := []idpFormatTestCase{
		{
			// Azure AD / Microsoft Entra ID:
			// - Uses default namespace (no prefix) for assertion elements
			// - Microsoft-specific claim URIs (schemas.xmlsoap.org, schemas.microsoft.com)
			// - Multi-value attribute (authnmethodsreferences)
			// - Opaque pairwise NameID (no Format attribute)
			// - AuthnContextClassRef: Password (not PasswordProtectedTransport)
			name:        "AzureAD",
			xmlFile:     "../testdata/azure_ad_response.xml",
			idpEntityID: "https://sts.windows.net/aaaabbbb-0000-cccc-1111-dddd2222eeee/",
			checkResult: func(t *testing.T, info *sp.AssertionInfo) {
				require.Equal(t, "Uz2Pqz1X7pxe4XLWxV9KJQ+n59d573SepSAkuYKSde8=", info.NameID)
				require.Empty(t, info.NameIDFormat, "Azure AD opaque NameID has no Format")

				require.Equal(t, "testuser@contoso.com",
					info.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"))
				require.Equal(t, "Test",
					info.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"))
				require.Equal(t, "User",
					info.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"))
				require.Equal(t, "testuser@contoso.com",
					info.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"))
				require.Equal(t, "3F2504E0-4F89-11D3-9A0C-0305E82C3301",
					info.Values.Get("http://schemas.microsoft.com/identity/claims/objectidentifier"))
				require.Equal(t, "aaaabbbb-0000-cccc-1111-dddd2222eeee",
					info.Values.Get("http://schemas.microsoft.com/identity/claims/tenantid"))

				// Multi-value attribute
				authnMethods := info.Values["http://schemas.microsoft.com/claims/authnmethodsreferences"]
				require.Equal(t, 2, len(authnMethods.Values), "authnmethodsreferences should have 2 values")
				require.Equal(t, "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
					authnMethods.Values[0].Value)
				require.Equal(t, "http://schemas.microsoft.com/claims/multipleauthn",
					authnMethods.Values[1].Value)
			},
		},
		{
			// Keycloak:
			// - Uses saml:/samlp: namespace prefixes
			// - FriendlyName attribute on each Attribute element
			// - OID-based attribute names with uri NameFormat
			// - Mixed NameFormats (uri for LDAP attrs, basic for roles)
			// - Multi-value Role attribute
			// - SessionNotOnOrAfter on AuthnStatement
			name:        "Keycloak",
			xmlFile:     "../testdata/keycloak_response.xml",
			idpEntityID: "https://keycloak.example.com/realms/test",
			checkResult: func(t *testing.T, info *sp.AssertionInfo) {
				require.Equal(t, "testuser", info.NameID)
				require.Equal(t, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", info.NameIDFormat)

				// OID-based attributes
				require.Equal(t, "testuser@example.com",
					info.Values.Get("urn:oid:0.9.2342.19200300.100.1.3"))
				require.Equal(t, "Test",
					info.Values.Get("urn:oid:2.5.4.42"))
				require.Equal(t, "User",
					info.Values.Get("urn:oid:2.5.4.4"))

				// FriendlyName preserved
				mailAttr := info.Values["urn:oid:0.9.2342.19200300.100.1.3"]
				require.Equal(t, "mail", mailAttr.FriendlyName)
				givenNameAttr := info.Values["urn:oid:2.5.4.42"]
				require.Equal(t, "givenName", givenNameAttr.FriendlyName)

				// NameFormat preserved
				require.Equal(t, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", mailAttr.NameFormat)

				// Multi-value Role attribute
				roleAttr := info.Values["Role"]
				require.Equal(t, 2, len(roleAttr.Values))
				require.Equal(t, "admin", roleAttr.Values[0].Value)
				require.Equal(t, "user", roleAttr.Values[1].Value)
				require.Equal(t, "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", roleAttr.NameFormat)

				// SessionNotOnOrAfter
				require.NotNil(t, info.SessionNotOnOrAfter)

				// SessionIndex
				require.Equal(t, "_keycloak-session-001", info.SessionIndex)
			},
		},
		{
			// Shibboleth / eduPerson:
			// - Uses saml2:/saml2p: namespace prefixes (Java convention)
			// - OID-based attribute names (urn:oid:...)
			// - uri NameFormat on all attributes
			// - Transient NameID format with SPNameQualifier
			// - eduPerson attributes (eduPersonPrincipalName, eduPersonEntitlement, etc.)
			// - Multiple multi-value attributes
			name:        "Shibboleth",
			xmlFile:     "../testdata/shibboleth_response.xml",
			idpEntityID: "https://idp.example.edu/idp/shibboleth",
			checkResult: func(t *testing.T, info *sp.AssertionInfo) {
				require.Equal(t, "_transient-nameid-001", info.NameID)
				require.Equal(t, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", info.NameIDFormat)

				// eduPerson attributes via OIDs
				require.Equal(t, "student@example.edu",
					info.Values.Get("urn:oid:1.3.6.1.4.1.5923.1.1.1.6")) // eduPersonPrincipalName
				require.Equal(t, "student001",
					info.Values.Get("urn:oid:0.9.2342.19200300.100.1.1")) // uid
				require.Equal(t, "student@example.edu",
					info.Values.Get("urn:oid:0.9.2342.19200300.100.1.3")) // mail
				require.Equal(t, "Alice",
					info.Values.Get("urn:oid:2.5.4.42")) // givenName
				require.Equal(t, "Scholar",
					info.Values.Get("urn:oid:2.5.4.4")) // sn

				// Multi-value eduPersonEntitlement
				entitlements := info.Values["urn:oid:1.3.6.1.4.1.5923.1.1.1.7"]
				require.Equal(t, "eduPersonEntitlement", entitlements.FriendlyName)
				require.Equal(t, 2, len(entitlements.Values))
				require.Equal(t, "urn:mace:example.edu:entitlement:library", entitlements.Values[0].Value)
				require.Equal(t, "urn:mace:example.edu:entitlement:vpn", entitlements.Values[1].Value)

				// Multi-value eduPersonScopedAffiliation
				affiliations := info.Values["urn:oid:1.3.6.1.4.1.5923.1.1.1.9"]
				require.Equal(t, 2, len(affiliations.Values))
				require.Equal(t, "student@example.edu", affiliations.Values[0].Value)
				require.Equal(t, "member@example.edu", affiliations.Values[1].Value)
			},
		},
		{
			// Google Workspace:
			// - Uses saml:/samlp: namespace prefixes
			// - Simple attribute names (email, firstName, lastName) without URI/OID
			// - xs:anyType attribute value type
			// - emailAddress NameID format
			// - AuthnContextClassRef: unspecified
			name:        "GoogleWorkspace",
			xmlFile:     "../testdata/google_response.xml",
			idpEntityID: "https://accounts.google.com/o/saml2?idpid=C01abc123",
			checkResult: func(t *testing.T, info *sp.AssertionInfo) {
				require.Equal(t, "user@example.com", info.NameID)
				require.Equal(t, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", info.NameIDFormat)

				require.Equal(t, "user@example.com", info.Values.Get("email"))
				require.Equal(t, "Jane", info.Values.Get("firstName"))
				require.Equal(t, "Doe", info.Values.Get("lastName"))
			},
		},
		{
			// ADFS (Active Directory Federation Services):
			// - Uses default namespace (no prefix) for assertion elements
			// - Consent attribute on Response
			// - WindowsDomainQualifiedName NameID format (DOMAIN\user)
			// - Microsoft claim URIs (schemas.xmlsoap.org and schemas.microsoft.com)
			// - Multi-value role attribute
			// - SessionNotOnOrAfter on AuthnStatement
			name:        "ADFSFormat",
			xmlFile:     "../testdata/adfs_format_response.xml",
			idpEntityID: "http://adfs.example.com/adfs/services/trust",
			checkResult: func(t *testing.T, info *sp.AssertionInfo) {
				require.Equal(t, `EXAMPLE\jsmith`, info.NameID)
				require.Equal(t, "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName", info.NameIDFormat)

				require.Equal(t, "jsmith@example.com",
					info.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"))
				require.Equal(t, "John",
					info.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"))
				require.Equal(t, "Smith",
					info.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"))
				require.Equal(t, "jsmith@example.com",
					info.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"))

				// Multi-value role attribute
				roles := info.Values["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"]
				require.Equal(t, 3, len(roles.Values))
				require.Equal(t, "Domain Users", roles.Values[0].Value)
				require.Equal(t, "IT Admins", roles.Values[1].Value)
				require.Equal(t, "VPN Users", roles.Values[2].Value)

				// SessionNotOnOrAfter
				require.NotNil(t, info.SessionNotOnOrAfter)
			},
		},
		{
			// OneLogin format:
			// - Uses saml:/samlp: namespace prefixes
			// - Dot-separated attribute names (User.email, User.FirstName)
			// - basic NameFormat
			// - emailAddress NameID format
			// - Multi-value group membership (memberOf)
			// - SessionNotOnOrAfter on AuthnStatement
			name:        "OneLoginFormat",
			xmlFile:     "../testdata/onelogin_format_response.xml",
			idpEntityID: "https://app.onelogin.com/saml/metadata/123456",
			checkResult: func(t *testing.T, info *sp.AssertionInfo) {
				require.Equal(t, "alice@example.com", info.NameID)
				require.Equal(t, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", info.NameIDFormat)

				require.Equal(t, "alice@example.com", info.Values.Get("User.email"))
				require.Equal(t, "Alice", info.Values.Get("User.FirstName"))
				require.Equal(t, "Wonderland", info.Values.Get("User.LastName"))

				// Multi-value group membership
				groups := info.Values["memberOf"]
				require.Equal(t, 3, len(groups.Values))
				require.Equal(t, "Engineering", groups.Values[0].Value)
				require.Equal(t, "DevOps", groups.Values[1].Value)
				require.Equal(t, "Security", groups.Values[2].Value)

				// SessionNotOnOrAfter
				require.NotNil(t, info.SessionNotOnOrAfter)

				// SessionIndex
				require.Equal(t, "_onelogin-session-001", info.SessionIndex)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			spInst := &sp.ServiceProvider{
				ACSURL:          "http://localhost:8080/v1/_saml_callback",
				AudienceURIs:    []string{"https://sp.example.com"},
				IDPEntityID:     tc.idpEntityID,
				IDPCertificates: []*x509.Certificate{idpCert},
				SPKeyStore:      ks,
				Clock:           func() time.Time { return fakeTime },
			}
			encoded := loadAndSign(t, tc.xmlFile, spInst)

			ctx := context.Background()

			// Validate the response can be parsed
			resp, err := spInst.ValidateEncodedResponse(ctx, encoded)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.True(t, resp.SignatureValidated)

			// Extract assertion info and run checks
			info, err := spInst.RetrieveAssertionInfo(ctx, encoded)
			require.NoError(t, err)
			require.NotNil(t, info)

			tc.checkResult(t, info)
		})
	}
}

// TestDecodeUnverifiedBaseResponse_IdPFormats verifies that
// DecodeUnverifiedBaseResponse can parse responses from various IdP formats
// without requiring signature validation. This exercises the lighter-weight
// parsing path used for IdP discovery / routing.
func TestDecodeUnverifiedBaseResponse_IdPFormats(t *testing.T) {
	tests := []struct {
		name         string
		xmlFile      string
		wantIssuer   string
		wantDest     string
		wantAudience string
	}{
		{
			name:         "AzureAD",
			xmlFile:      "../testdata/azure_ad_response.xml",
			wantIssuer:   "https://sts.windows.net/aaaabbbb-0000-cccc-1111-dddd2222eeee/",
			wantDest:     "http://localhost:8080/v1/_saml_callback",
			wantAudience: "https://sp.example.com",
		},
		{
			name:         "Keycloak",
			xmlFile:      "../testdata/keycloak_response.xml",
			wantIssuer:   "https://keycloak.example.com/realms/test",
			wantDest:     "http://localhost:8080/v1/_saml_callback",
			wantAudience: "https://sp.example.com",
		},
		{
			name:         "Shibboleth",
			xmlFile:      "../testdata/shibboleth_response.xml",
			wantIssuer:   "https://idp.example.edu/idp/shibboleth",
			wantDest:     "http://localhost:8080/v1/_saml_callback",
			wantAudience: "https://sp.example.com",
		},
		{
			name:         "GoogleWorkspace",
			xmlFile:      "../testdata/google_response.xml",
			wantIssuer:   "https://accounts.google.com/o/saml2?idpid=C01abc123",
			wantDest:     "http://localhost:8080/v1/_saml_callback",
			wantAudience: "https://sp.example.com",
		},
		{
			name:         "ADFSFormat",
			xmlFile:      "../testdata/adfs_format_response.xml",
			wantIssuer:   "http://adfs.example.com/adfs/services/trust",
			wantDest:     "http://localhost:8080/v1/_saml_callback",
			wantAudience: "https://sp.example.com",
		},
		{
			name:         "OneLoginFormat",
			xmlFile:      "../testdata/onelogin_format_response.xml",
			wantIssuer:   "https://app.onelogin.com/saml/metadata/123456",
			wantDest:     "http://localhost:8080/v1/_saml_callback",
			wantAudience: "https://sp.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			xmlBytes, err := os.ReadFile(tc.xmlFile)
			require.NoError(t, err)

			encoded := base64.StdEncoding.EncodeToString(xmlBytes)
			resp, err := sp.DecodeUnverifiedBaseResponse(encoded)
			require.NoError(t, err)
			require.NotNil(t, resp)

			require.Equal(t, tc.wantIssuer, resp.Issuer.Value)
			require.Equal(t, tc.wantDest, resp.Destination)
			require.Equal(t, "2.0", resp.Version)
			require.Contains(t, resp.Audiences, tc.wantAudience)
		})
	}
}
