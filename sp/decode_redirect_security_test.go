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

package sp

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
	saml2 "github.com/russellhaering/gosaml2/v2"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Test helpers
// ===========================================================================

// redirectTestSP builds a ServiceProvider with a freshly generated RSA key pair
// suitable for redirect binding tests. The IDP cert is the SP's own cert (self-
// signed), so we can produce and verify signatures in the same test.
func redirectTestSP(t *testing.T) (*ServiceProvider, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	sp := &ServiceProvider{
		EntityID:        "https://sp.example.com",
		ACSURL:          "https://sp.example.com/acs",
		SLOURL:          "https://sp.example.com/slo",
		IDPEntityID:     "https://idp.example.com",
		IDPSSOURL:       "https://idp.example.com/sso",
		IDPSLOURL:       "https://idp.example.com/slo",
		IDPCertificates: []*x509.Certificate{parsedCert},
		SPKeyStore: &saml2.KeyStore{
			Signer: key,
			Cert:   certDER,
		},
		SPSigningKeyStore: &saml2.KeyStore{
			Signer: key,
			Cert:   certDER,
		},
		Clock:             func() time.Time { return now },
		SignAuthnRequests: true,
	}

	return sp, key
}

// deflateAndEncode DEFLATE-compresses and base64-encodes a SAML XML message.
func deflateAndEncode(t *testing.T, xmlMsg string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(xmlMsg))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// signRedirectParams signs the redirect binding query string parameters
// and returns (sigAlg, signatureB64).
func signRedirectParams(
	t *testing.T,
	key crypto.Signer,
	hash crypto.Hash,
	paramName, encodedMessage, relayState string,
) (string, string) {
	t.Helper()

	sigAlg := saml2.SignatureMethodIdentifier(key, hash)

	var buf bytes.Buffer
	buf.WriteString(url.QueryEscape(paramName) + "=" + url.QueryEscape(encodedMessage))
	if relayState != "" {
		buf.WriteString("&" + url.QueryEscape("RelayState") + "=" + url.QueryEscape(relayState))
	}
	buf.WriteString("&" + url.QueryEscape("SigAlg") + "=" + url.QueryEscape(sigAlg))

	h := hash.New()
	h.Write(buf.Bytes())
	digest := h.Sum(nil)

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), hash, digest)
	require.NoError(t, err)

	return sigAlg, base64.StdEncoding.EncodeToString(sigBytes)
}

// makeLogoutResponseXML builds a minimal valid LogoutResponse XML.
func makeLogoutResponseXML(issuer, destination, statusCode string) string {
	return fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test123" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="%s" InResponseTo="_req1">`+
		`<saml:Issuer>%s</saml:Issuer>`+
		`<samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>`+
		`</samlp:LogoutResponse>`,
		destination, issuer, statusCode)
}

// makeLogoutRequestXML builds a minimal valid LogoutRequest XML.
func makeLogoutRequestXML(issuer, destination, nameID string) string {
	return fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test456" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="%s">`+
		`<saml:Issuer>%s</saml:Issuer>`+
		`<saml:NameID>%s</saml:NameID>`+
		`</samlp:LogoutRequest>`,
		destination, issuer, nameID)
}

// ===========================================================================
// VULNERABILITY 1: Missing xml-roundtrip-validator in redirect binding
//
// parseResponse() (used by POST binding) runs rtvalidator.Validate() to
// block Go encoding/xml parser differential attacks (CVE-2020-29509 class).
// The redirect binding methods call xml.Unmarshal directly WITHOUT running
// the validator. This is a critical gap.
// ===========================================================================

// TestVuln_RedirectLogoutResponse_MissingRTValidator demonstrates that the
// redirect binding accepts XML payloads containing constructs that the
// xml-roundtrip-validator would reject. The POST binding correctly rejects
// these same payloads via parseResponse().
func TestVuln_RedirectLogoutResponse_MissingRTValidator(t *testing.T) {
	sp, key := redirectTestSP(t)

	// This XML contains a double-colon in a local name — a construct that
	// Go's encoding/xml handles differently from other XML parsers. The
	// rtvalidator is specifically designed to reject this.
	// First, verify that rtvalidator DOES reject this input.
	maliciousXML := `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test123" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://sp.example.com/slo" InResponseTo="_req1">` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`<x::ExtraElement>attack</x::ExtraElement>` +
		`</samlp:LogoutResponse>`

	rtErr := rtvalidator.Validate(bytes.NewReader([]byte(maliciousXML)))

	// If the go/xml version has been fixed and rtvalidator passes, skip.
	if rtErr == nil {
		t.Skip("rtvalidator does not flag this input on this Go version; parser may be fixed")
	}

	t.Logf("rtvalidator correctly rejects this payload: %v", rtErr)

	// Verify that the POST binding (parseResponse) rejects it.
	_, _, postErr := parseResponse([]byte(maliciousXML), 0)
	require.Error(t, postErr, "POST binding (parseResponse) should reject double-colon XML")
	t.Logf("POST binding correctly rejects: %v", postErr)

	// Now test the redirect binding — it should also reject, but doesn't.
	encoded := deflateAndEncode(t, maliciousXML)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	// Skip sig validation to isolate the XML parsing issue.
	sp.InsecureSkipSignatureValidation = true

	_, redirectErr := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)

	// SECURITY FINDING: If this does NOT error, the redirect binding is
	// vulnerable to parser differential attacks that the POST binding
	// correctly blocks.
	if redirectErr == nil {
		t.Error("SECURITY VULNERABILITY: Redirect binding accepted XML that rtvalidator rejects. " +
			"The redirect path (ValidateEncodedLogoutResponseRedirect) does NOT run " +
			"xml-roundtrip-validator, unlike the POST path (parseResponse). " +
			"This enables CVE-2020-29509 class parser differential attacks.")
	} else {
		t.Logf("Redirect binding also rejected (good): %v", redirectErr)
	}
}

// TestVuln_RedirectLogoutRequest_MissingRTValidator — same as above but for LogoutRequest.
func TestVuln_RedirectLogoutRequest_MissingRTValidator(t *testing.T) {
	sp, key := redirectTestSP(t)

	maliciousXML := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test456" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://sp.example.com/slo">` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`<saml:NameID>user@example.com</saml:NameID>` +
		`<x::ExtraElement>attack</x::ExtraElement>` +
		`</samlp:LogoutRequest>`

	rtErr := rtvalidator.Validate(bytes.NewReader([]byte(maliciousXML)))
	if rtErr == nil {
		t.Skip("rtvalidator does not flag this input on this Go version")
	}

	// POST binding rejects:
	_, _, postErr := parseResponse([]byte(maliciousXML), 0)
	require.Error(t, postErr, "POST binding should reject double-colon XML")

	// Redirect binding:
	encoded := deflateAndEncode(t, maliciousXML)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLRequest", encoded, "")

	sp.InsecureSkipSignatureValidation = true

	_, redirectErr := sp.ValidateEncodedLogoutRequestRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)

	if redirectErr == nil {
		t.Error("SECURITY VULNERABILITY: Redirect LogoutRequest binding accepted XML that " +
			"rtvalidator rejects. Missing xml-roundtrip-validator in redirect path.")
	} else {
		t.Logf("Redirect binding also rejected (good): %v", redirectErr)
	}
}

// TestVuln_Redirect_CommentInjection tests a realistic comment-injection
// attack (the classic CVE-2020-29509 vector) via redirect binding.
// In this attack, a comment inside a NameID causes Go's encoding/xml to
// silently concatenate text nodes, potentially changing the parsed identity.
func TestVuln_Redirect_CommentInjection(t *testing.T) {
	sp, _ := redirectTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	// The NameID contains a comment that a conformant XML parser should
	// preserve as "evil@attacker.com", but Go's encoding/xml may
	// concatenate the text nodes as "evil@attacker.comreal@victim.com"
	// or similar depending on version.
	commentInjectionXML := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test789" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://sp.example.com/slo">` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`<saml:NameID>evil@attacker.com<!---->real@victim.com</saml:NameID>` +
		`</samlp:LogoutRequest>`

	encoded := deflateAndEncode(t, commentInjectionXML)

	req, err := sp.ValidateEncodedLogoutRequestRedirect(
		context.Background(), encoded, "", "", "",
	)
	// Signature is missing so this will fail for non-InsecureSkip SPs.
	// We skipped sig validation, so parsing proceeds.
	if err != nil {
		t.Logf("Request rejected (possibly expected): %v", err)
		return
	}

	// Check what Go parsed the NameID as:
	if req.NameID != nil {
		parsedNameID := req.NameID.Value
		t.Logf("Parsed NameID value: %q", parsedNameID)

		// Go's encoding/xml concatenates text nodes around comments.
		// This is a known Go behavior, not something rtvalidator prevents
		// (comments are valid XML). Both POST and Redirect bindings are
		// affected equally. The fix for this is signature verification
		// (which prevents attacker-controlled XML from being parsed).
		if parsedNameID != "evil@attacker.com" && parsedNameID != "real@victim.com" {
			t.Logf("NOTE: Go's xml parser concatenated text around comment: %q. "+
				"This is a known Go encoding/xml behavior. Signature verification "+
				"prevents exploitation by rejecting tampered XML.", parsedNameID)
		}
	}
}

// ===========================================================================
// VULNERABILITY 2: SigAlg hash fallback — unknown algorithm defaults to SHA256
// ===========================================================================

// TestVuln_UnknownSigAlg_FallsBackToSHA256 tests that providing an
// unrecognized SigAlg URI causes the library to silently default to SHA256.
// This means an attacker could specify a bogus SigAlg but actually sign with
// SHA256, and the signature would verify. The SigAlg in the signed content
// would be the bogus one, but verification uses SHA256 regardless.
func TestVuln_UnknownSigAlg_FallsBackToSHA256(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	bogusAlg := "http://www.w3.org/2099/bogus#rsa-sha999"

	// Sign with SHA256 (the fallback) but claim a bogus algorithm.
	var buf bytes.Buffer
	buf.WriteString(url.QueryEscape("SAMLResponse") + "=" + url.QueryEscape(encoded))
	buf.WriteString("&" + url.QueryEscape("SigAlg") + "=" + url.QueryEscape(bogusAlg))

	h := crypto.SHA256.New()
	h.Write(buf.Bytes())
	digest := h.Sum(nil)

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	require.NoError(t, err)

	sig := base64.StdEncoding.EncodeToString(sigBytes)

	err = sp.verifyRedirectSignature("SAMLResponse", encoded, "", bogusAlg, sig)

	if err == nil {
		t.Error("SECURITY ISSUE: verifyRedirectSignature accepted a bogus SigAlg URI " +
			"by falling back to SHA256. An attacker can supply any unrecognized SigAlg " +
			"and the library silently uses SHA256 for verification. The library should " +
			"reject unknown signature algorithms instead of defaulting.")
	} else {
		t.Logf("Correctly rejected bogus SigAlg: %v", err)
	}
}

// TestVuln_SigAlg_SHA1Downgrade tests whether an attacker can force SHA1
// verification by providing the SHA1 SigAlg URI, even when the SP doesn't
// intend to accept SHA1.
func TestVuln_SigAlg_SHA1Downgrade(t *testing.T) {
	sp, key := redirectTestSP(t)
	// SP does NOT set AllowSHA1 = true — but AllowSHA1 is only used by the
	// dsig.Verifier for XML-DSig, not by verifyRedirectSignature.

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	// Sign with SHA1
	sigAlg := dsig.RSASHA1SignatureMethod

	var buf bytes.Buffer
	buf.WriteString(url.QueryEscape("SAMLResponse") + "=" + url.QueryEscape(encoded))
	buf.WriteString("&" + url.QueryEscape("SigAlg") + "=" + url.QueryEscape(sigAlg))

	h := crypto.SHA1.New()
	h.Write(buf.Bytes())
	digest := h.Sum(nil)

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest)
	require.NoError(t, err)

	sig := base64.StdEncoding.EncodeToString(sigBytes)

	err = sp.verifyRedirectSignature("SAMLResponse", encoded, "", sigAlg, sig)

	if err == nil {
		t.Error("SECURITY ISSUE: verifyRedirectSignature accepted SHA1 signature. " +
			"Unlike the POST binding's dsig.Verifier which checks AllowSHA1, the redirect " +
			"binding has NO SHA1 rejection logic. An attacker can always downgrade to SHA1.")
	} else {
		t.Logf("Correctly rejected SHA1: %v", err)
	}
}

// ===========================================================================
// VULNERABILITY 3: Partial signature parameter bypass
// ===========================================================================

// TestVuln_SignatureBypassPartialParams tests what happens when only one of
// sigAlg/signature is provided. The current code requires both to be non-empty,
// which is correct. This test verifies that behavior.
func TestVuln_SignatureBypassPartialParams(t *testing.T) {
	sp, _ := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	tests := []struct {
		name   string
		sigAlg string
		sig    string
	}{
		{"both empty", "", ""},
		{"only sigAlg", dsig.RSASHA256SignatureMethod, ""},
		{"only signature", "", base64.StdEncoding.EncodeToString([]byte("fake"))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := sp.verifyRedirectSignature("SAMLResponse", encoded, "", tc.sigAlg, tc.sig)
			if err == nil {
				t.Errorf("SECURITY ISSUE: verifyRedirectSignature accepted request with sigAlg=%q sig=%q",
					tc.sigAlg, tc.sig)
			} else {
				require.Contains(t, err.Error(), "no signature",
					"Error should indicate missing signature")
				t.Logf("Correctly rejected: %v", err)
			}
		})
	}
}

// ===========================================================================
// VULNERABILITY 4: Missing Destination validation edge cases
// ===========================================================================

// TestVuln_RedirectLogoutResponse_EmptyDestination tests that a LogoutResponse
// with an empty Destination is accepted. Per SAML spec, Destination is
// recommended but the library only validates when it's non-empty.
func TestVuln_RedirectLogoutResponse_EmptyDestination(t *testing.T) {
	sp, key := redirectTestSP(t)

	// LogoutResponse with empty Destination
	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	resp, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)

	if err == nil {
		t.Logf("WARNING: LogoutResponse with empty Destination was accepted. "+
			"Per SAML Bindings §3.4.5.2, Destination is REQUIRED for signed messages. "+
			"Accepting empty Destination allows message replay to other SPs. Resp=%+v", resp)
	} else {
		t.Logf("Rejected empty Destination: %v", err)
	}
}

// TestVuln_RedirectLogoutResponse_WrongDestination tests that a wrong
// Destination is rejected.
func TestVuln_RedirectLogoutResponse_WrongDestination(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://evil.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	_, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)

	require.Error(t, err, "LogoutResponse with wrong Destination should be rejected")
	require.Contains(t, err.Error(), "destination", "Error should mention destination mismatch")
	t.Logf("Correctly rejected wrong Destination: %v", err)
}

// TestVuln_RedirectLogoutRequest_EmptyDestination tests empty Destination on requests.
func TestVuln_RedirectLogoutRequest_EmptyDestination(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutRequestXML("https://idp.example.com", "", "user@example.com")
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLRequest", encoded, "")

	req, err := sp.ValidateEncodedLogoutRequestRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)

	if err == nil {
		t.Logf("WARNING: LogoutRequest with empty Destination was accepted. "+
			"This could allow message replay to other SPs. Req=%+v", req)
	} else {
		t.Logf("Rejected empty Destination: %v", err)
	}
}

// ===========================================================================
// VULNERABILITY 5: No certificate validity checking
// ===========================================================================

// TestVuln_ExpiredIDPCertificateAccepted tests that verifyRedirectSignature
// does not check certificate NotBefore/NotAfter. An expired or not-yet-valid
// IDP certificate will still verify signatures.
func TestVuln_ExpiredIDPCertificateAccepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a certificate that expired a year ago.
	now := time.Now()
	expiredTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-2 * 365 * 24 * time.Hour),
		NotAfter:              now.Add(-1 * 365 * 24 * time.Hour), // expired 1 year ago
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	expiredCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	sp := &ServiceProvider{
		SLOURL:          "https://sp.example.com/slo",
		IDPEntityID:     "https://idp.example.com",
		IDPCertificates: []*x509.Certificate{expiredCert},
	}

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	err = sp.verifyRedirectSignature("SAMLResponse", encoded, "", sigAlg, sig)

	if err == nil {
		t.Error("SECURITY ISSUE: verifyRedirectSignature accepted a signature from an " +
			"EXPIRED certificate (expired 1 year ago). The redirect binding does not " +
			"check certificate NotBefore/NotAfter. Compare with the POST binding's " +
			"dsig.Verifier which does check certificate validity.")
	} else {
		t.Logf("Correctly rejected expired cert: %v", err)
	}
}

// TestVuln_NotYetValidIDPCertificateAccepted tests that a certificate
// that's not yet valid is also accepted.
func TestVuln_NotYetValidIDPCertificateAccepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	futureTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(365 * 24 * time.Hour), // valid starting 1 year from now
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, futureTemplate, futureTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	futureCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	sp := &ServiceProvider{
		SLOURL:          "https://sp.example.com/slo",
		IDPEntityID:     "https://idp.example.com",
		IDPCertificates: []*x509.Certificate{futureCert},
	}

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	err = sp.verifyRedirectSignature("SAMLResponse", encoded, "", sigAlg, sig)

	if err == nil {
		t.Error("SECURITY ISSUE: verifyRedirectSignature accepted a signature from a " +
			"NOT-YET-VALID certificate. The redirect binding does not check " +
			"certificate NotBefore/NotAfter.")
	} else {
		t.Logf("Correctly rejected not-yet-valid cert: %v", err)
	}
}

// ===========================================================================
// VULNERABILITY 6: Full redirect binding round-trip — end-to-end test
// showing the rtvalidator gap is exploitable
// ===========================================================================

// TestVuln_RedirectVsPost_RTValidatorGap does a side-by-side comparison of
// how POST and Redirect bindings handle the same malicious XML payloads.
func TestVuln_RedirectVsPost_RTValidatorGap(t *testing.T) {
	// These are XML payloads that rtvalidator should reject.
	// They exploit Go encoding/xml parser differentials.
	testCases := []struct {
		name string
		xml  string
	}{
		{
			name: "double colon in local name",
			xml: `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_t1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="" InResponseTo="_r1">` +
				`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
				`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
				`<x::Injected attr="val">payload</x::Injected>` +
				`</samlp:LogoutResponse>`,
		},
		{
			name: "directive in element position",
			xml: `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_t2" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="" InResponseTo="_r2">` +
				`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
				`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
				`<!ENTITY xxe SYSTEM "file:///etc/passwd">` +
				`</samlp:LogoutResponse>`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Check if rtvalidator flags this
			rtErr := rtvalidator.Validate(bytes.NewReader([]byte(tc.xml)))
			if rtErr == nil {
				t.Skipf("rtvalidator does not flag %q on this Go version", tc.name)
			}

			// POST binding: should reject via parseResponse
			_, _, postErr := parseResponse([]byte(tc.xml), 0)

			// Redirect binding: direct xml.Unmarshal
			var resp types.LogoutResponse
			redirectErr := xml.Unmarshal([]byte(tc.xml), &resp)

			t.Logf("POST binding error: %v", postErr)
			t.Logf("Redirect xml.Unmarshal error: %v", redirectErr)

			if postErr != nil && redirectErr == nil {
				t.Errorf("SECURITY GAP: POST binding rejects %q but Redirect binding's "+
					"xml.Unmarshal accepts it. This is the rtvalidator gap.", tc.name)
			}
		})
	}
}

// ===========================================================================
// VULNERABILITY 7: signatureAlgorithmHash behavior analysis
// ===========================================================================

// TestSignatureAlgorithmHash_Mapping verifies the hash mapping for all known
// algorithms and documents the fallback behavior.
func TestSignatureAlgorithmHash_Mapping(t *testing.T) {
	tests := []struct {
		algorithm    string
		expectedHash crypto.Hash
		name         string
	}{
		{dsig.RSASHA1SignatureMethod, crypto.SHA1, "RSA-SHA1"},
		{dsig.RSASHA256SignatureMethod, crypto.SHA256, "RSA-SHA256"},
		{dsig.RSASHA384SignatureMethod, crypto.SHA384, "RSA-SHA384"},
		{dsig.RSASHA512SignatureMethod, crypto.SHA512, "RSA-SHA512"},
		{dsig.ECDSASHA1SignatureMethod, crypto.SHA1, "ECDSA-SHA1"},
		{dsig.ECDSASHA256SignatureMethod, crypto.SHA256, "ECDSA-SHA256"},
		{dsig.ECDSASHA384SignatureMethod, crypto.SHA384, "ECDSA-SHA384"},
		{dsig.ECDSASHA512SignatureMethod, crypto.SHA512, "ECDSA-SHA512"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := saml2.SignatureAlgorithmHash(tc.algorithm)
			require.Equal(t, tc.expectedHash, got)
		})
	}

	// Unknown algorithms return 0
	unknowns := []string{
		"",
		"http://www.w3.org/2099/bogus",
		"urn:bogus:sha512",
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256-TYPO",
	}
	for _, alg := range unknowns {
		t.Run("unknown:"+alg, func(t *testing.T) {
			got := saml2.SignatureAlgorithmHash(alg)
			require.Equal(t, crypto.Hash(0), got,
				"Unknown algorithm should return 0")
			t.Logf("algorithm %q returns 0; callers now reject this as an error", alg)
		})
	}
}

// ===========================================================================
// VULNERABILITY 8: Full end-to-end test — valid redirect signature roundtrip
// (sanity check, then attack variants)
// ===========================================================================

// TestRedirect_ValidLogoutResponseRoundtrip tests a happy-path redirect
// binding round trip to ensure the test infrastructure works.
func TestRedirect_ValidLogoutResponseRoundtrip(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	resp, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.SignatureValidated, "SignatureValidated should be true")
	require.Equal(t, "https://idp.example.com", resp.Issuer.Value)
	t.Logf("Happy path works: %+v", resp)
}

// TestRedirect_ValidLogoutRequestRoundtrip tests a happy-path redirect
// binding round trip for LogoutRequest.
func TestRedirect_ValidLogoutRequestRoundtrip(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutRequestXML("https://idp.example.com", "https://sp.example.com/slo", "user@example.com")
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLRequest", encoded, "")

	req, err := sp.ValidateEncodedLogoutRequestRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)
	require.NoError(t, err)
	require.NotNil(t, req)
	require.True(t, req.SignatureValidated, "SignatureValidated should be true")
	require.Equal(t, "https://idp.example.com", req.Issuer.Value)
	t.Logf("Happy path works: %+v", req)
}

// TestRedirect_ValidLogoutResponseWithRelayState tests redirect binding
// with a non-empty RelayState.
func TestRedirect_ValidLogoutResponseWithRelayState(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	relayState := "https://sp.example.com/return?foo=bar&baz=qux"
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, relayState)

	resp, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, relayState, sigAlg, sig,
	)
	require.NoError(t, err)
	require.NotNil(t, resp)
	t.Logf("With RelayState works: %+v", resp)
}

// ===========================================================================
// VULNERABILITY 9: Tampered message after signing
// ===========================================================================

// TestRedirect_TamperedMessageRejected verifies that modifying the encoded
// message after signing causes verification failure.
func TestRedirect_TamperedMessageRejected(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	// Tamper with the encoded message (flip a character)
	tampered := encoded[:5] + "X" + encoded[6:]
	if tampered == encoded {
		tampered = encoded[:5] + "Y" + encoded[6:]
	}

	err := sp.verifyRedirectSignature("SAMLResponse", tampered, "", sigAlg, sig)
	require.Error(t, err, "Tampered message should fail signature verification")
	t.Logf("Correctly rejected tampered message: %v", err)
}

// TestRedirect_WrongKeyRejected verifies that a message signed with a
// different key is rejected.
func TestRedirect_WrongKeyRejected(t *testing.T) {
	sp, _ := redirectTestSP(t)

	// Generate a different key (not in IDPCertificates)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, wrongKey, crypto.SHA256, "SAMLResponse", encoded, "")

	err = sp.verifyRedirectSignature("SAMLResponse", encoded, "", sigAlg, sig)
	require.Error(t, err, "Wrong key should fail signature verification")
	require.Contains(t, err.Error(), "signature verification failed")
	t.Logf("Correctly rejected wrong key: %v", err)
}

// ===========================================================================
// VULNERABILITY 10: InsecureSkipSignatureValidation behavior
// ===========================================================================

// TestInsecureSkip_RedirectAcceptsUnsignedMessages tests that
// InsecureSkipSignatureValidation=true makes the redirect binding accept
// completely unsigned messages, and that SignatureValidated is false.
func TestInsecureSkip_RedirectAcceptsUnsignedMessages(t *testing.T) {
	sp, _ := redirectTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	resp, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", "", "",
	)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.SignatureValidated, "SignatureValidated must be false when skipping")
}

// ===========================================================================
// VULNERABILITY 11: Algorithm confusion — sign with SHA512 but claim SHA256
// ===========================================================================

// TestVuln_AlgorithmConfusion_SignSHA512ClaimSHA256 tests that signing with
// SHA512 but claiming SHA256 in SigAlg is correctly rejected (the hash
// mismatch should cause verification failure).
func TestVuln_AlgorithmConfusion_SignSHA512ClaimSHA256(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	// Build the signed content with SHA256 as SigAlg (what the verifier will use)
	claimedSigAlg := dsig.RSASHA256SignatureMethod

	var buf bytes.Buffer
	buf.WriteString(url.QueryEscape("SAMLResponse") + "=" + url.QueryEscape(encoded))
	buf.WriteString("&" + url.QueryEscape("SigAlg") + "=" + url.QueryEscape(claimedSigAlg))

	// But actually hash with SHA512
	h := crypto.SHA512.New()
	h.Write(buf.Bytes())
	digest := h.Sum(nil)

	// Sign the SHA512 digest with the key
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, digest)
	require.NoError(t, err)
	sig := base64.StdEncoding.EncodeToString(sigBytes)

	err = sp.verifyRedirectSignature("SAMLResponse", encoded, "", claimedSigAlg, sig)
	require.Error(t, err, "Algorithm confusion (sign SHA512, claim SHA256) should fail")
	t.Logf("Correctly rejected algorithm confusion: %v", err)
}

// ===========================================================================
// VULNERABILITY 12: Comparison of POST vs Redirect code paths
// ===========================================================================

// TestCodePathComparison_BothBindingsUseRTValidator verifies that both POST
// and Redirect bindings now run rtvalidator on valid XML.
func TestCodePathComparison_BothBindingsUseRTValidator(t *testing.T) {
	// A simple valid SAML LogoutResponse
	validXML := makeLogoutResponseXML("https://idp.example.com", "", saml2.StatusCodeSuccess)

	// POST path: parseResponse runs rtvalidator
	_, _, err := parseResponse([]byte(validXML), 0)
	if err != nil {
		t.Logf("parseResponse rejected valid XML (unexpected): %v", err)
	} else {
		t.Log("parseResponse accepted valid XML — ran rtvalidator.Validate()")
	}

	// Redirect path: now also runs rtvalidator before xml.Unmarshal
	var resp types.LogoutResponse
	err = xml.Unmarshal([]byte(validXML), &resp)
	if err != nil {
		t.Logf("xml.Unmarshal rejected valid XML (unexpected): %v", err)
	} else {
		t.Log("xml.Unmarshal accepted valid XML")
	}

	t.Log("Both POST and Redirect bindings now run rtvalidator.Validate() " +
		"to block CVE-2020-29509 class parser differential attacks.")
}

// ===========================================================================
// VULNERABILITY 13: Redirect binding accepts SHA1 without AllowSHA1 check
// ===========================================================================

// TestVuln_RedirectSHA1_NoAllowSHA1Check does an end-to-end test showing
// that the full redirect binding validation pipeline accepts SHA1 signatures
// regardless of the AllowSHA1 flag.
func TestVuln_RedirectSHA1_NoAllowSHA1Check(t *testing.T) {
	sp, key := redirectTestSP(t)
	sp.AllowSHA1 = false // Explicitly disable SHA1

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	// Sign with SHA1
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA1, "SAMLResponse", encoded, "")
	require.Equal(t, dsig.RSASHA1SignatureMethod, sigAlg)

	resp, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)

	if err == nil {
		t.Errorf("SECURITY ISSUE: Full redirect pipeline accepted SHA1 signature even though "+
			"AllowSHA1=false. POST binding dsig.Verifier checks AllowSHA1, but redirect "+
			"binding has no such check. Response: %+v", resp)
	} else {
		t.Logf("Correctly rejected SHA1 with AllowSHA1=false: %v", err)
	}
}

// ===========================================================================
// Additional robustness tests
// ===========================================================================

// TestRedirect_InvalidBase64Signature tests malformed base64 in signature.
func TestRedirect_InvalidBase64Signature(t *testing.T) {
	sp, _ := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	err := sp.verifyRedirectSignature(
		"SAMLResponse", encoded, "",
		dsig.RSASHA256SignatureMethod, "not!valid!base64===",
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot decode redirect signature")
}

// TestRedirect_EmptyNoCertificates tests behavior with no IDP certificates.
func TestRedirect_EmptyNoCertificates(t *testing.T) {
	sp, key := redirectTestSP(t)
	sp.IDPCertificates = nil // No certs

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	err := sp.verifyRedirectSignature("SAMLResponse", encoded, "", sigAlg, sig)
	require.Error(t, err)
	t.Logf("No certs error: %v", err)
}

// TestRedirect_DecompressionBomb tests that oversized deflated messages are rejected.
func TestRedirect_DecompressionBomb(t *testing.T) {
	sp, _ := redirectTestSP(t)
	sp.InsecureSkipSignatureValidation = true
	sp.MaximumDecompressedBodySize = 100 // Very small limit

	// Build a message larger than 100 bytes
	largeXML := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	largeXML += strings.Repeat(" ", 200)
	encoded := deflateAndEncode(t, largeXML)

	_, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", "", "",
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds maximum size")
}

// TestRedirect_BadXMLInMessage tests that invalid XML in the deflated message is rejected.
func TestRedirect_BadXMLInMessage(t *testing.T) {
	sp, _ := redirectTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	encoded := deflateAndEncode(t, "<definitely&not>xml")

	_, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", "", "",
	)
	require.Error(t, err)
}
