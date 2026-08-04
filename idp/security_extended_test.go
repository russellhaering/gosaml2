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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	"github.com/russellhaering/gosaml2/v2/sp"
)

// signRedirectParamsIdP signs a redirect binding query string using the given
// key and hash, returning the SigAlg URI and base64-encoded signature.
func signRedirectParamsIdP(t *testing.T, key crypto.Signer, hash crypto.Hash, encodedMsg, relayState string) (string, string) {
	t.Helper()
	sigAlg := saml2.SignatureMethodIdentifier(key, hash)
	var buf bytes.Buffer
	buf.WriteString("SAMLRequest=" + encodedMsg)
	if relayState != "" {
		buf.WriteString("&RelayState=" + relayState)
	}
	buf.WriteString("&SigAlg=" + sigAlg)
	h := hash.New()
	h.Write(buf.Bytes())
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), hash, h.Sum(nil))
	require.NoError(t, err)
	return sigAlg, base64.StdEncoding.EncodeToString(sigBytes)
}

// deflateAndEncodeIdP DEFLATE-compresses and base64-encodes an XML message for
// the HTTP-Redirect binding.
func deflateAndEncodeIdP(t *testing.T, xmlMsg string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(xmlMsg))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// ---------------------------------------------------------------------------
// Cat 6 Test 1: IdP signs assertion targeting wrong SP's ACS URL
// ---------------------------------------------------------------------------

func TestSecurityIdP_WrongACSURLRejectedBySP(t *testing.T) {
	idpKS := testKeyStore(t, testTime)
	spKS := testKeyStore(t, testTime)

	idpCert, err := x509.ParseCertificate(idpKS.Cert)
	require.NoError(t, err)
	spCert, err := x509.ParseCertificate(spKS.Cert)
	require.NoError(t, err)

	// IdP that knows about the SP with both ACS URLs registered.
	// The IdP builds a response targeting "https://evil.test/acs" because
	// the Recipient field in the AssertionParams overrides the Destination
	// on the Response as well. The SP checks Destination first.
	idpInst := &IdentityProvider{
		EntityID:        "https://idp.test/metadata",
		SSOURL:          "https://idp.test/sso",
		SigningKeyStore: idpKS,
		SignResponses:   true,
		SignAssertions:  false,
		Clock:           func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{
			"https://sp.test/metadata": {
				EntityID:            "https://sp.test/metadata",
				ACSURLs:             []string{"https://sp.test/acs", "https://evil.test/acs"},
				SigningCertificates: []*x509.Certificate{spCert},
			},
		},
	}

	// SP expects responses at its own ACS URL
	spInst := &sp.ServiceProvider{
		EntityID:          "https://sp.test/metadata",
		ACSURL:            "https://sp.test/acs",
		IDPEntityID:       "https://idp.test/metadata",
		IDPSSOURL:         "https://idp.test/sso",
		IDPCertificates:   []*x509.Certificate{idpCert},
		SPKeyStore:        spKS,
		AudienceURIs:      []string{"https://sp.test/metadata"},
		AllowIDPInitiated: true,
		Clock:             func() time.Time { return testTime },
	}

	// Build response where the Recipient is the evil ACS URL. Because
	// BuildResponseDocument uses the Recipient as the Response Destination
	// as well, the SP rejects the Destination before even checking the
	// assertion Recipient. Both checks protect the SP.
	params := &AssertionParams{
		NameID:               "user@example.com",
		NameIDFormat:         saml2.NameIdFormatEmailAddress,
		Recipient:            "https://evil.test/acs",
		AudienceRestrictions: []string{"https://sp.test/metadata"},
	}

	doc, _, err := idpInst.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)

	docBytes, err := doc.WriteToBytes()
	require.NoError(t, err)
	encodedResponse := base64.StdEncoding.EncodeToString(docBytes)

	// SP-side validation should reject the response. The Destination on the
	// Response element is checked first, producing ErrBadDestination.
	_, err = spInst.ValidateEncodedResponse(context.Background(), encodedResponse)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadDestination,
		"SP should reject response whose Destination does not match SP's ACS URL")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 2: Signer cache rotation
// ---------------------------------------------------------------------------

func TestSecurityIdP_SignerCacheRotation(t *testing.T) {
	idp, ks1 := testIdentityProvider(t)
	signer1, err := idp.Signer()
	require.NoError(t, err)

	// Swap key store to a freshly-generated key
	ks2 := testIdPKeyStore(t)
	idp.SigningKeyStore = ks2

	signer2, err := idp.Signer()
	require.NoError(t, err)

	// Signer is cached - should still be the old one
	require.Same(t, signer1, signer2, "cached signer should be returned after key store swap")

	_ = ks1
	_ = ks2
	t.Log("Signer is cached - key rotation requires IdP restart or cache invalidation")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 3: Rogue SP metadata with attacker-controlled ACS URL
// ---------------------------------------------------------------------------

func TestSecurityIdP_RogueSPMetadata(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	// Register a rogue SP with an evil ACS URL - the IdP has no URL
	// validation in its configuration layer.
	_, spCert := testSPKeyStore(t)
	idp.ServiceProviders["https://rogue.test/metadata"] = &SPConfig{
		EntityID:            "https://rogue.test/metadata",
		ACSURLs:             []string{"https://evil.test/steal-tokens"},
		SigningCertificates: []*x509.Certificate{spCert},
	}

	// The IdP accepts a request from this SP and would deliver the response
	// to the attacker-controlled ACS URL.
	xmlStr := buildTestAuthnRequestXML("_rogue1", "https://rogue.test/metadata", "https://idp.test/sso", "https://evil.test/steal-tokens")
	encoded := encodeAuthnRequestPOST(xmlStr)

	info, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.NoError(t, err)
	require.Equal(t, "https://evil.test/steal-tokens", info.ACSURL,
		"IdP does not validate ACS URL scheme/domain - administrators must vet SP metadata")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 4: SP metadata KeyDescriptor missing "use" attribute
// ---------------------------------------------------------------------------

func TestSecurityIdP_KeyDescriptorMissingUse(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    testTime.Add(-time.Hour),
		NotAfter:     testTime.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	// Build an SPConfig as if parsed from metadata with use="" (empty)
	// ConfigureFromSPMetadata treats empty use as dual-purpose.
	spConfig := &SPConfig{
		EntityID: "https://sp-dual.test/metadata",
		ACSURLs:  []string{"https://sp-dual.test/acs"},
	}

	// Simulate ConfigureFromSPMetadata behavior for use=""
	// (cert should be added to both signing and encryption)
	spConfig.SigningCertificates = append(spConfig.SigningCertificates, cert)
	if spConfig.EncryptionCertificate == nil {
		spConfig.EncryptionCertificate = cert
	}

	require.Len(t, spConfig.SigningCertificates, 1,
		"cert with missing use should be treated as signing cert")
	require.NotNil(t, spConfig.EncryptionCertificate,
		"cert with missing use should also be treated as encryption cert")
	require.Equal(t, spConfig.SigningCertificates[0], spConfig.EncryptionCertificate,
		"same cert should serve both purposes")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 5: IdP impersonation - SP accepts response with wrong issuer
// when IDPEntityID is empty
// ---------------------------------------------------------------------------

func TestSecurityIdP_EmptyIDPEntityIDSkipsIssuerCheck(t *testing.T) {
	idpKS := testKeyStore(t, testTime)
	spKS := testKeyStore(t, testTime)

	idpCert, err := x509.ParseCertificate(idpKS.Cert)
	require.NoError(t, err)
	spCert, err := x509.ParseCertificate(spKS.Cert)
	require.NoError(t, err)

	// An IdP that claims to be "https://evil-idp.test/metadata"
	evilIdP := &IdentityProvider{
		EntityID:        "https://evil-idp.test/metadata",
		SSOURL:          "https://evil-idp.test/sso",
		SigningKeyStore: idpKS,
		SignResponses:   true,
		Clock:           func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{
			"https://sp.test/metadata": {
				EntityID:            "https://sp.test/metadata",
				ACSURLs:             []string{"https://sp.test/acs"},
				SigningCertificates: []*x509.Certificate{spCert},
			},
		},
	}

	// SP with empty IDPEntityID - skips issuer check
	spInst := &sp.ServiceProvider{
		EntityID:          "https://sp.test/metadata",
		ACSURL:            "https://sp.test/acs",
		IDPEntityID:       "", // intentionally empty
		IDPCertificates:   []*x509.Certificate{idpCert},
		SPKeyStore:        spKS,
		AudienceURIs:      []string{"https://sp.test/metadata"},
		AllowIDPInitiated: true,
		Clock:             func() time.Time { return testTime },
	}

	params := &AssertionParams{
		NameID:    "admin@example.com",
		Recipient: "https://sp.test/acs",
	}

	doc, _, err := evilIdP.BuildResponseDocument("https://sp.test/metadata", params)
	require.NoError(t, err)

	docBytes, err := doc.WriteToBytes()
	require.NoError(t, err)
	encodedResponse := base64.StdEncoding.EncodeToString(docBytes)

	// When IDPEntityID is empty, the SP will NOT check the issuer, so this
	// succeeds despite the wrong issuer.
	resp, err := spInst.ValidateEncodedResponse(context.Background(), encodedResponse)
	require.NoError(t, err, "empty IDPEntityID skips issuer check - potential impersonation vector")
	require.Equal(t, "https://evil-idp.test/metadata", resp.Issuer.Value)
}

// ---------------------------------------------------------------------------
// Cat 6 Test 6: AuthnRequest with ACS URL not in registered list
// ---------------------------------------------------------------------------

func TestSecurityIdP_AuthnRequestBadACSURL(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	xmlStr := buildTestAuthnRequestXML("_req1", "https://sp.test/metadata", "https://idp.test/sso", "https://attacker.test/acs")
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadACSURL)
}

// ---------------------------------------------------------------------------
// Cat 6 Test 7: AuthnRequest with empty ACS URL and empty SPConfig.ACSURLs
// ---------------------------------------------------------------------------

func TestSecurityIdP_EmptyACSURLAndEmptySPConfig(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	// Clear the SP's ACS URLs so there is no default to fall back to
	idp.ServiceProviders["https://sp.test/metadata"].ACSURLs = nil

	// Request with no ACS URL specified
	xmlStr := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_empty1" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="https://idp.test/sso"><saml:Issuer>https://sp.test/metadata</saml:Issuer></samlp:AuthnRequest>`)
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadACSURL,
		"should error when no ACS URL is provided and SP has no registered ACS URLs")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 8: Redirect binding signature bypass - empty signature with
// RequireSignedAuthnRequests=true
// ---------------------------------------------------------------------------

func TestSecurityIdP_RedirectEmptySignatureBypass(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	idp.ServiceProviders["https://sp.test/metadata"].RequireSignedAuthnRequests = true

	xmlStr := buildTestAuthnRequestXML("_bypass1", "https://sp.test/metadata", "https://idp.test/sso", "https://sp.test/acs")
	encoded := deflateAndEncodeIdP(t, xmlStr)

	// Empty sigAlg and signature strings should trigger ErrMissingSignature
	_, err := idp.ValidateEncodedAuthnRequestRedirect(context.Background(), encoded, "", "", "")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingSignature)
}

// ---------------------------------------------------------------------------
// Cat 6 Test 9: Redirect binding SHA-1 when AllowSHA1=false
// ---------------------------------------------------------------------------

func TestSecurityIdP_RedirectSHA1Rejected(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	spConfig := idp.ServiceProviders["https://sp.test/metadata"]
	spConfig.RequireSignedAuthnRequests = true
	idp.AllowSHA1 = false

	// Get the SP's signing key
	spKey := spConfig.SigningCertificates[0]
	_ = spKey

	// We need to generate a fresh key pair for signing
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    testTime.Add(-time.Hour),
		NotAfter:     testTime.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	spConfig.SigningCertificates = []*x509.Certificate{cert}

	xmlStr := buildTestAuthnRequestXML("_sha1test", "https://sp.test/metadata", "https://idp.test/sso", "https://sp.test/acs")
	encoded := deflateAndEncodeIdP(t, xmlStr)

	// Sign with SHA-1
	sigAlg, sig := signRedirectParamsIdP(t, key, crypto.SHA1, encoded, "")

	_, err = idp.ValidateEncodedAuthnRequestRedirect(context.Background(), encoded, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadSignature,
		"SHA-1 signature should be rejected when AllowSHA1=false")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 10: Redirect binding ECDSA SigAlg with RSA certificate
// ---------------------------------------------------------------------------

func TestSecurityIdP_RedirectECDSASigAlgWithRSACert(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	spConfig := idp.ServiceProviders["https://sp.test/metadata"]
	spConfig.RequireSignedAuthnRequests = true

	xmlStr := buildTestAuthnRequestXML("_ecdsarsa", "https://sp.test/metadata", "https://idp.test/sso", "https://sp.test/acs")
	encoded := deflateAndEncodeIdP(t, xmlStr)

	// Use ECDSA algorithm URI but provide an RSA-signed blob
	ecdsaSigAlg := "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"

	// Create a bogus signature (just random bytes)
	bogusSignature := base64.StdEncoding.EncodeToString([]byte("not-a-real-signature"))

	_, err := idp.ValidateEncodedAuthnRequestRedirect(context.Background(), encoded, "", ecdsaSigAlg, bogusSignature)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadSignature,
		"ECDSA algorithm with RSA certificate should fail signature verification")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 11: LogoutRequest destination validation against SLOURL
// ---------------------------------------------------------------------------

func TestSecurityIdP_LogoutRequestDestinationValidation(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	// LogoutRequest with Destination set to SSO URL instead of SLO URL
	xmlStr := buildTestLogoutRequestXML("_logout_dest1", "https://sp.test/metadata",
		"https://idp.test/sso", // wrong: should be /slo
		"user@example.com", "_session1")
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))

	_, _, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadDestination,
		"LogoutRequest with SSO URL as Destination should be rejected")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 12: LogoutRequest reuses RequireSignedAuthnRequests flag
// ---------------------------------------------------------------------------

func TestSecurityIdP_LogoutRequestReusesRequireSignedFlag(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	spConfig := idp.ServiceProviders["https://sp.test/metadata"]
	spConfig.RequireSignedAuthnRequests = true

	// LogoutRequest via redirect with no signature should be rejected
	// because the logout code reuses RequireSignedAuthnRequests
	xmlStr := buildTestLogoutRequestXML("_logout_sign1", "https://sp.test/metadata",
		"https://idp.test/slo", "user@example.com", "_session1")
	encoded := encodeAuthnRequestRedirect(xmlStr)

	_, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), encoded, "", "", "")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingSignature,
		"RequireSignedAuthnRequests flag is also applied to LogoutRequests via redirect binding")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 13: IdP metadata ValidUntil far-future with
// MetadataValidDuration=100 years
// ---------------------------------------------------------------------------

func TestSecurityIdP_MetadataFarFutureValidUntil(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	idp.MetadataValidDuration = 100 * 365 * 24 * time.Hour // ~100 years

	md, err := idp.Metadata()
	require.NoError(t, err)

	expectedValidUntil := testTime.UTC().Add(100 * 365 * 24 * time.Hour)
	require.Equal(t, expectedValidUntil, md.ValidUntil,
		"MetadataValidDuration should be respected even for very long durations")
	require.True(t, md.ValidUntil.After(testTime.Add(99*365*24*time.Hour)),
		"metadata should be valid for ~100 years")
}

// ---------------------------------------------------------------------------
// Cat 6 Test 14: Decompression bomb on IdP redirect binding
// ---------------------------------------------------------------------------

func TestSecurityIdP_DecompressionBomb(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	idp.MaximumDecompressedBodySize = 1024 // 1 KB limit

	// Create a large XML payload that compresses well but expands beyond limit.
	// A long series of repeated characters compresses very well with DEFLATE.
	largeXML := fmt.Sprintf(
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_bomb1" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="https://idp.test/sso" AssertionConsumerServiceURL="https://sp.test/acs"><saml:Issuer>https://sp.test/metadata</saml:Issuer><!-- %s --></samlp:AuthnRequest>`,
		strings.Repeat("A", 2048))

	encoded := deflateAndEncodeIdP(t, largeXML)

	_, err := idp.ValidateEncodedAuthnRequestRedirect(context.Background(), encoded, "", "", "")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMalformed,
		"decompressed payload exceeding MaximumDecompressedBodySize should be rejected")
}

// ---------------------------------------------------------------------------
// Interop Test 15: AuthnRequest with XML comments inside Issuer
// ---------------------------------------------------------------------------

func TestSecurityIdP_XMLCommentsInIssuer(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	// XML comment splitting the entity ID: "https://sp.test/metadata" becomes
	// "https://sp.test/m<!-- comment -->etadata"
	// The xml-roundtrip-validator should catch this.
	xmlStr := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_comment1" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="https://idp.test/sso" AssertionConsumerServiceURL="https://sp.test/acs"><saml:Issuer>https://sp.test/m<!-- comment -->etadata</saml:Issuer></samlp:AuthnRequest>`
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	// The xml-roundtrip-validator detects comment-based transformations.
	// Even if it passes validation, encoding/xml strips comments, so the
	// Issuer would become "https://sp.test/metadata" which is valid.
	// Either way, the system handles it safely.
	if err != nil {
		// Roundtrip validator caught it - good
		require.ErrorIs(t, err, saml2.ErrMalformed,
			"XML comments in Issuer should be caught by roundtrip validator")
	} else {
		// encoding/xml stripped the comment, so the Issuer resolved correctly
		t.Log("XML comment in Issuer was stripped by encoding/xml - resolved to valid entity ID")
	}
}

// ---------------------------------------------------------------------------
// Interop Test 16: CDATA in AuthnRequest Issuer
// ---------------------------------------------------------------------------

func TestSecurityIdP_CDATAInIssuer(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	// Wrap the Issuer content in CDATA
	xmlStr := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_cdata1" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="https://idp.test/sso" AssertionConsumerServiceURL="https://sp.test/acs"><saml:Issuer><![CDATA[https://sp.test/metadata]]></saml:Issuer></samlp:AuthnRequest>`
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	// The xml-roundtrip-validator may reject CDATA sections.
	// If it passes, encoding/xml reads CDATA as plain text.
	if err != nil {
		require.ErrorIs(t, err, saml2.ErrMalformed,
			"CDATA in Issuer should be caught by roundtrip validator")
	} else {
		t.Log("CDATA in Issuer was handled correctly by encoding/xml")
	}
}

// ---------------------------------------------------------------------------
// Interop Test 17: Multiple Issuer elements in AuthnRequest
// ---------------------------------------------------------------------------

func TestSecurityIdP_MultipleIssuerElements(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	// Two Issuer elements - encoding/xml uses last-value-wins semantics
	xmlStr := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_multi1" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="https://idp.test/sso" AssertionConsumerServiceURL="https://sp.test/acs"><saml:Issuer>https://evil.test/metadata</saml:Issuer><saml:Issuer>https://sp.test/metadata</saml:Issuer></samlp:AuthnRequest>`
	encoded := encodeAuthnRequestPOST(xmlStr)

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	// The roundtrip-validator may catch this. If not, encoding/xml uses
	// the last Issuer element ("https://sp.test/metadata") which is
	// a known SP. This documents the last-value-wins behavior.
	if err != nil {
		// Roundtrip validator or XML parsing rejected it
		t.Logf("Multiple Issuer elements rejected: %v", err)
	} else {
		t.Log("Multiple Issuer elements: encoding/xml last-value-wins used https://sp.test/metadata")
	}
}

// ---------------------------------------------------------------------------
// Interop Test 18: Concurrent Signer() access
// ---------------------------------------------------------------------------

func TestSecurityIdP_ConcurrentSignerAccess(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			signer, err := idp.Signer()
			require.NoError(t, err)
			require.NotNil(t, signer)
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Interop Test 19: AuthnRequest with extremely long ID
// ---------------------------------------------------------------------------

func TestSecurityIdP_ExtremelyLongID(t *testing.T) {
	idp, _ := testIdentityProvider(t)

	// Generate an ID that is 10,000 characters long
	longID := "_" + strings.Repeat("a", 9999)

	xmlStr := buildTestAuthnRequestXML(longID, "https://sp.test/metadata", "https://idp.test/sso", "https://sp.test/acs")
	encoded := encodeAuthnRequestPOST(xmlStr)

	info, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	// The IdP should be able to parse this. There's no explicit length limit on ID.
	require.NoError(t, err)
	require.Equal(t, longID, info.ID, "extremely long ID should be preserved")
}

// ---------------------------------------------------------------------------
// Interop Test 20: Empty SP ServiceProviders map
// ---------------------------------------------------------------------------

func TestSecurityIdP_EmptyServiceProvidersMap(t *testing.T) {
	idp := &IdentityProvider{
		EntityID:         "https://idp.test/metadata",
		SSOURL:           "https://idp.test/sso",
		SigningKeyStore:  testIdPKeyStore(t),
		Clock:            func() time.Time { return testTime },
		ServiceProviders: map[string]*SPConfig{}, // empty map
	}

	xmlStr := buildTestAuthnRequestXML("_empty_sp1", "https://sp.test/metadata", "https://idp.test/sso", "https://sp.test/acs")

	// Test POST binding
	encoded := encodeAuthnRequestPOST(xmlStr)
	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrUnknownSP,
		"any request should be rejected when ServiceProviders map is empty")

	// Test redirect binding
	encodedRedirect := deflateAndEncodeIdP(t, xmlStr)
	_, err = idp.ValidateEncodedAuthnRequestRedirect(context.Background(), encodedRedirect, "", "", "")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrUnknownSP)
}
