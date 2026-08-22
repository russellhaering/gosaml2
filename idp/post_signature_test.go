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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

const postTestSPEntityID = "https://sp.test/metadata"

// signingTestIdP returns an IdP whose registered SP's signing certificate
// matches the returned signer, so POST-binding signatures can be produced.
func signingTestIdP(t *testing.T) (*IdentityProvider, *dsig.Signer) {
	t.Helper()
	idp, _ := testIdentityProvider(t)

	spKS, spCert := testSPKeyStore(t)
	idp.ServiceProviders[postTestSPEntityID].SigningCertificates = []*x509.Certificate{spCert}

	return idp, &dsig.Signer{
		Key:   spKS.Signer,
		Certs: []*x509.Certificate{spCert},
	}
}

// signPOSTMessage signs an XML message with an enveloped signature and
// base64-encodes it for the HTTP-POST binding.
func signPOSTMessage(t *testing.T, signer *dsig.Signer, xmlStr string) string {
	t.Helper()
	doc, err := xmltree.Parse([]byte(xmlStr))
	require.NoError(t, err)

	signed, err := signer.SignEnveloped(doc.Root())
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(signed.WriteToBytes())
}

func postTestLogoutRequestXML(idp *IdentityProvider, nameID string) string {
	return fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout1" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID>%s</saml:NameID></samlp:LogoutRequest>`,
		idp.SLOURL, postTestSPEntityID, nameID)
}

// TestAuthnRequestPOSTRequiresSignature is the regression test for the binding
// downgrade: RequireSignedAuthnRequests was enforced only on the HTTP-Redirect
// binding, so a peer could strip the signature by switching to HTTP-POST.
func TestAuthnRequestPOSTRequiresSignature(t *testing.T) {
	idp, _ := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encodeAuthnRequestPOST(xmlStr))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingSignature)
}

// TestAuthnRequestPOSTAcceptsValidSignature confirms the new verification path
// accepts a properly signed request and reports the signed values.
func TestAuthnRequestPOSTAcceptsValidSignature(t *testing.T) {
	idp, signer := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")

	info, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), signPOSTMessage(t, signer, xmlStr))
	require.NoError(t, err)
	require.Equal(t, "_req123", info.ID)
	require.Equal(t, postTestSPEntityID, info.Issuer)
	require.Equal(t, "https://sp.test/acs", info.ACSURL)
}

// TestAuthnRequestPOSTRejectsTamperedSignature confirms the digest still binds
// the message content after signing.
func TestAuthnRequestPOSTRejectsTamperedSignature(t *testing.T) {
	idp, signer := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")
	encoded := signPOSTMessage(t, signer, xmlStr)

	rawSigned, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)

	// Swap the ACS URL for another registered one after signing.
	idp.ServiceProviders[postTestSPEntityID].ACSURLs = append(
		idp.ServiceProviders[postTestSPEntityID].ACSURLs, "https://sp.test/acs2")
	tampered := strings.Replace(string(rawSigned), "https://sp.test/acs", "https://sp.test/acs2", 1)
	require.NotEqual(t, string(rawSigned), tampered)

	_, err = idp.ValidateEncodedAuthnRequestPOST(context.Background(),
		base64.StdEncoding.EncodeToString([]byte(tampered)))
	require.Error(t, err)
}

// TestAuthnRequestPOSTUnsignedAllowedWhenNotRequired keeps the permissive
// default: an SP that does not require signed requests may still send them
// unsigned, since SAML does not mandate AuthnRequest signing.
func TestAuthnRequestPOSTUnsignedAllowedWhenNotRequired(t *testing.T) {
	idp, _ := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = false

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")

	info, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encodeAuthnRequestPOST(xmlStr))
	require.NoError(t, err)
	require.Equal(t, "_req123", info.ID)
}

// TestAuthnRequestPOSTRejectsBadSignatureEvenWhenNotRequired confirms that a
// signature which is present but invalid is rejected rather than ignored,
// matching the Redirect binding's "verify whenever a signature is offered".
func TestAuthnRequestPOSTRejectsBadSignatureEvenWhenNotRequired(t *testing.T) {
	idp, _ := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = false

	// Sign with a different key than the one registered for the SP.
	otherKS, otherCert := testSPKeyStore(t)
	rogue := &dsig.Signer{Key: otherKS.Signer, Certs: []*x509.Certificate{otherCert}}

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), signPOSTMessage(t, rogue, xmlStr))
	require.Error(t, err)
}

// TestLogoutRequestPOSTRequiresSignature is the regression test for a forged,
// unsigned LogoutRequest terminating an arbitrary user's session.
func TestLogoutRequestPOSTRequiresSignature(t *testing.T) {
	idp, _ := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	encoded := base64.StdEncoding.EncodeToString([]byte(postTestLogoutRequestXML(idp, "victim@example.com")))

	_, _, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingSignature)
}

// TestLogoutRequestPOSTAcceptsValidSignature confirms the signed path still works.
func TestLogoutRequestPOSTAcceptsValidSignature(t *testing.T) {
	idp, signer := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	encoded := signPOSTMessage(t, signer, postTestLogoutRequestXML(idp, "victim@example.com"))

	req, spc, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.NoError(t, err)
	require.Equal(t, "_logout1", req.ID)
	require.Equal(t, "victim@example.com", req.NameID.Value)
	require.Equal(t, postTestSPEntityID, spc.EntityID)
}
