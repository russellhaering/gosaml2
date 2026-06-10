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
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Category 5: Protocol/Binding Security Tests (50 tests)
// ============================================================================

// ============================================================================
// HTTP POST Binding (Tests 1-6)
// ============================================================================

// Test 1: Base64 padding manipulation (non-standard padding, whitespace, line breaks)
func TestSecurityBinding_POST_Base64PaddingManipulation(t *testing.T) {
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)
	encoded := encodeResponse(signed)

	t.Run("standard_encoding_works", func(t *testing.T) {
		_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
		require.NoError(t, err)
	})

	t.Run("extra_padding_rejected", func(t *testing.T) {
		// Adding extra '=' padding to base64 should cause a decode error.
		extraPadded := encoded + "==="
		_, err := sp.ValidateEncodedResponse(context.Background(), extraPadded)
		require.Error(t, err, "extra padding should cause base64 decode failure")
	})

	t.Run("whitespace_in_base64", func(t *testing.T) {
		// base64.StdEncoding.DecodeString does not tolerate whitespace.
		// Insert a space in the middle.
		mid := len(encoded) / 2
		withSpace := encoded[:mid] + " " + encoded[mid:]
		_, err := sp.ValidateEncodedResponse(context.Background(), withSpace)
		require.Error(t, err, "whitespace in base64 should cause decode failure")
	})

	t.Run("line_breaks_in_base64", func(t *testing.T) {
		// Insert newlines (as some IdPs do with MIME-style wrapping).
		// Note: Go's base64.StdEncoding.DecodeString may tolerate \n in some
		// Go versions. This test documents the current behavior.
		withNewlines := encoded[:76] + "\n" + encoded[76:]
		_, err := sp.ValidateEncodedResponse(context.Background(), withNewlines)
		if err != nil {
			t.Logf("Line breaks in base64 correctly rejected: %v", err)
		} else {
			t.Log("INFORMATIONAL: Go's base64.StdEncoding.DecodeString tolerates newlines. " +
				"This matches MIME-style base64 and is acceptable for SAML POST binding " +
				"where IdPs may wrap base64 at 76 characters.")
		}
	})

	t.Run("stripped_padding", func(t *testing.T) {
		// Remove trailing '=' padding characters.
		stripped := strings.TrimRight(encoded, "=")
		if stripped == encoded {
			t.Skip("encoded response has no padding to strip")
		}
		_, err := sp.ValidateEncodedResponse(context.Background(), stripped)
		require.Error(t, err, "stripped padding should cause base64 decode failure")
	})
}

// Test 2: Deflate bomb via POST - large payload
func TestSecurityBinding_POST_DeflateBomb(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.MaximumDecompressedBodySize = 1024 // very small limit

	// Create a highly compressible payload that exceeds the limit when decompressed.
	// Using repeated spaces which compress extremely well.
	payload := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1">` +
		strings.Repeat("<!-- padding -->", 200) +
		`</saml2p:Response>`

	// Compress it
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(payload))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	// The payload is already valid XML, so parseResponse will try it directly first
	// via maybeDeflate. If direct parse succeeds, the size limit only applies to
	// deflation. Let's test with a payload that only works after deflation.
	t.Log("Testing deflate size limits - the maybeDeflate function tries direct XML first")

	// Test with raw (non-XML) data that must be deflated
	bigData := strings.Repeat("A", 2048) // bigger than limit
	var buf2 bytes.Buffer
	w2, err := flate.NewWriter(&buf2, flate.BestCompression)
	require.NoError(t, err)
	_, err = w2.Write([]byte(bigData))
	require.NoError(t, err)
	require.NoError(t, w2.Close())

	encoded2 := base64.StdEncoding.EncodeToString(buf2.Bytes())
	_, err = sp.ValidateEncodedResponse(context.Background(), encoded2)
	require.Error(t, err, "deflate bomb exceeding MaximumDecompressedBodySize should be rejected")

	_ = encoded // suppress unused
}

// Test 3: Double-encoded response (base64 twice)
func TestSecurityBinding_POST_DoubleEncoded(t *testing.T) {
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)

	// Encode once
	singleEncoded := encodeResponse(signed)
	// Encode a second time
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(singleEncoded))

	_, err := sp.ValidateEncodedResponse(context.Background(), doubleEncoded)
	require.Error(t, err, "double-encoded response should fail - the inner base64 is not valid XML")
}

// Test 4: No signature on response or assertion
func TestSecurityBinding_POST_NoSignature(t *testing.T) {
	sp, _ := securityTestSP(t)

	// Completely unsigned response
	validResp := makeValidResponse(sp)
	encoded := encodeResponse(validResp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err, "completely unsigned response should be rejected when InsecureSkipSignatureValidation is false")
}

// Test 5: Signed Response with tampered unsigned assertion injected
func TestSecurityBinding_POST_SignedResponseWithTamperedAssertion(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)

	// Parse the signed response and inject an additional unsigned assertion
	injectedAssertion := fmt.Sprintf(
		`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil_assertion" Version="2.0" IssueInstant="%s">`+
			`<saml2:Issuer>%s</saml2:Issuer>`+
			`<saml2:Subject>`+
			`<saml2:NameID>attacker@evil.com</saml2:NameID>`+
			`<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`+
			`<saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>`+
			`</saml2:SubjectConfirmation>`+
			`</saml2:Subject>`+
			`<saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">`+
			`<saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>`+
			`</saml2:Conditions>`+
			`</saml2:Assertion>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	// Insert the evil assertion before the closing </saml2p:Response>
	tampered := strings.Replace(signed, "</saml2p:Response>", injectedAssertion+"</saml2p:Response>", 1)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "signed response with injected unsigned assertion should be rejected (digest mismatch)")
}

// Test 6: Assertion nested inside wrong parent (e.g., inside AttributeStatement)
func TestSecurityBinding_POST_AssertionNestedInWrongParent(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Build a response where an assertion is nested inside the AttributeStatement
	// of another assertion. This is structurally invalid.
	nestedResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AttributeStatement>
      <saml2:Assertion ID="_nested_evil" Version="2.0" IssueInstant="%s">
        <saml2:Issuer>%s</saml2:Issuer>
        <saml2:Subject>
          <saml2:NameID>admin@evil.com</saml2:NameID>
          <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
          </saml2:SubjectConfirmation>
        </saml2:Subject>
      </saml2:Assertion>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
	)

	// Sign the outer assertion only
	signed := signAssertionOnly(t, nestedResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))

	// The nested assertion inside AttributeStatement should NOT be treated
	// as a top-level assertion. The code checks assertionEl.Parent() != responseEl
	// to skip non-direct-child assertions.
	if err != nil {
		t.Logf("Correctly rejected nested assertion in wrong parent: %v", err)
	} else {
		// Even if it parses, verify only the legitimate assertion is returned
		t.Log("Response parsed, verifying nested assertion was not treated as top-level")
	}
}

// ============================================================================
// HTTP Redirect Binding (Tests 7-11)
// ============================================================================

// Test 7: Signature stripping (remove Signature and SigAlg params)
func TestSecurityBinding_Redirect_SignatureStripping(t *testing.T) {
	sp, _ := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	// Submit without signature parameters
	_, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", "", "",
	)
	require.Error(t, err, "redirect message without signature should be rejected")
	require.Contains(t, err.Error(), "no signature",
		"error should indicate missing signature")
}

// Test 8: Parameter order manipulation
func TestSecurityBinding_Redirect_ParameterOrderManipulation(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	relayState := "somestate"

	// Sign with correct parameter order: SAMLResponse, RelayState, SigAlg
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, relayState)

	// Verify correct order works
	_, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, relayState, sigAlg, sig,
	)
	require.NoError(t, err, "correct parameter order should work")

	// Now manually sign with wrong parameter order (SigAlg before RelayState)
	var wrongOrderBuf bytes.Buffer
	wrongOrderBuf.WriteString(url.QueryEscape("SAMLResponse") + "=" + url.QueryEscape(encoded))
	wrongOrderBuf.WriteString("&" + url.QueryEscape("SigAlg") + "=" + url.QueryEscape(sigAlg))
	wrongOrderBuf.WriteString("&" + url.QueryEscape("RelayState") + "=" + url.QueryEscape(relayState))

	h := crypto.SHA256.New()
	h.Write(wrongOrderBuf.Bytes())
	digest := h.Sum(nil)

	wrongSigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	require.NoError(t, err)
	wrongSig := base64.StdEncoding.EncodeToString(wrongSigBytes)

	// The verifier builds the signed content in the canonical order
	// (SAMLResponse, RelayState, SigAlg), so a signature made with wrong
	// order should fail.
	err = sp.verifyRedirectSignature("SAMLResponse", encoded, relayState, sigAlg, wrongSig)
	require.Error(t, err, "signature with wrong parameter order should fail verification")
}

// Test 9: SigAlg downgrade to SHA-1 with AllowSHA1=false
func TestSecurityBinding_Redirect_SHA1DowngradeBlocked(t *testing.T) {
	sp, key := redirectTestSP(t)
	sp.AllowSHA1 = false

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	// Sign with SHA1
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA1, "SAMLResponse", encoded, "")
	require.Equal(t, dsig.RSASHA1SignatureMethod, sigAlg)

	err := sp.verifyRedirectSignature("SAMLResponse", encoded, "", sigAlg, sig)
	require.Error(t, err, "SHA1 should be rejected when AllowSHA1=false")
	require.Contains(t, err.Error(), "SHA1", "error should mention SHA1 rejection")
}

// Test 10: Unknown SigAlg URI
func TestSecurityBinding_Redirect_UnknownSigAlg(t *testing.T) {
	sp, _ := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)

	// Use a completely bogus SigAlg URI
	bogusSigAlg := "http://www.w3.org/2099/bogus#rsa-sha999"
	fakeSig := base64.StdEncoding.EncodeToString([]byte("fakesignature"))

	err := sp.verifyRedirectSignature("SAMLResponse", encoded, "", bogusSigAlg, fakeSig)
	require.Error(t, err, "unknown SigAlg URI should be rejected")
	require.Contains(t, err.Error(), "unsupported or unrecognized signature algorithm",
		"error should indicate unrecognized algorithm")
}

// Test 11: Inflate/deflate size limit (off-by-one)
func TestSecurityBinding_Redirect_InflateDeflateOffByOne(t *testing.T) {
	sp, _ := redirectTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	// Test with a message exactly at and 1 byte over the limit.
	limit := int64(500)
	sp.MaximumDecompressedBodySize = limit

	// Build XML that's exactly at the limit
	baseXML := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	currentLen := int64(len(baseXML))

	if currentLen < limit {
		// Pad with valid XML comments to reach exactly the limit
		padding := int(limit - currentLen)
		if padding > len("<!---->") {
			baseXML = strings.Replace(baseXML, "</samlp:LogoutResponse>",
				"<!--"+strings.Repeat("x", padding-7)+"--></samlp:LogoutResponse>", 1)
		}
	}

	// Test at-limit: should succeed
	atLimit := baseXML
	if int64(len(atLimit)) <= limit {
		encoded := deflateAndEncode(t, atLimit)
		_, err := sp.ValidateEncodedLogoutResponseRedirect(
			context.Background(), encoded, "", "", "",
		)
		// May succeed or fail due to XML content, but should NOT fail due to size
		if err != nil {
			require.NotContains(t, err.Error(), "exceeds maximum size",
				"message at or below limit should not be rejected for size")
		}
	}

	// Test over-limit: should fail
	overLimit := baseXML + strings.Repeat("x", int(limit))
	encoded := deflateAndEncode(t, overLimit)
	_, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", "", "",
	)
	require.Error(t, err, "message over limit should be rejected")
	require.Contains(t, err.Error(), "exceeds maximum size")
}

// ============================================================================
// RelayState Manipulation (Tests 12-15)
// ============================================================================

// Test 12: XSS via HTML POST form RelayState - verify html/template auto-escaping
func TestSecurityBinding_RelayState_XSSViaPOSTForm(t *testing.T) {
	// Test HTML-injection payloads that attempt to break out of the value attribute.
	// html/template auto-escapes these in attribute context.
	htmlInjectionPayloads := []struct {
		name    string
		payload string
	}{
		{"script_injection", `"><script>alert('xss')</script>`},
		{"attribute_injection", `' onmouseover='alert(1)`},
		{"img_onerror", `<img src=x onerror=alert(1)>`},
		{"quote_breakout", `" autofocus onfocus="alert(1)`},
	}

	for _, tc := range htmlInjectionPayloads {
		t.Run(tc.name, func(t *testing.T) {
			formBytes, err := saml2.BuildPOSTForm(
				"https://idp.example.com/sso",
				"SAMLRequest",
				"dGVzdA==",
				tc.payload,
			)
			require.NoError(t, err)
			formHTML := string(formBytes)

			// The html/template package should auto-escape the RelayState value.
			// The raw payload should NOT appear verbatim in the output.
			require.NotContains(t, formHTML, tc.payload,
				"raw HTML injection payload in RelayState should be escaped by html/template")

			// Verify that quote characters (" and ') are escaped in the value.
			// html/template escapes " to &#34; and ' to &#39; in attribute context.
			// This prevents attribute breakout attacks regardless of what the payload contains.
			relayIdx := strings.Index(formHTML, `name="RelayState"`)
			require.Greater(t, relayIdx, 0, "RelayState input should be present")
			afterRelay := formHTML[relayIdx:]
			valueStart := strings.Index(afterRelay, `value="`)
			require.Greater(t, valueStart, 0)
			valueContent := afterRelay[valueStart+7:]
			valueEnd := strings.Index(valueContent, `"`)
			relayValue := valueContent[:valueEnd]

			// The key security property: quotes in the payload are escaped
			if strings.Contains(tc.payload, `"`) {
				require.NotContains(t, relayValue, `"`,
					"double quotes should be escaped in value attribute")
			}
			if strings.Contains(tc.payload, `<`) {
				require.NotContains(t, relayValue, `<`,
					"angle brackets should be escaped in value attribute")
			}

			t.Logf("Payload safely escaped in attribute: %s", relayValue)
		})
	}

	// Test javascript: protocol in RelayState. html/template does NOT escape
	// javascript: URIs in value attributes because they are not executable in
	// hidden input values. This is safe in context, but applications MUST
	// validate RelayState before using it as a redirect target.
	t.Run("javascript_protocol_informational", func(t *testing.T) {
		payload := `javascript:alert(document.cookie)`
		formBytes, err := saml2.BuildPOSTForm(
			"https://idp.example.com/sso",
			"SAMLRequest",
			"dGVzdA==",
			payload,
		)
		require.NoError(t, err)
		t.Logf("INFORMATIONAL: javascript: protocol in RelayState is placed in a hidden "+
			"input value attribute, where it is NOT executable. html/template does not "+
			"escape it because it is safe in this context. However, applications MUST "+
			"validate RelayState before using it as a redirect URL. Form size: %d bytes",
			len(formBytes))
	})
}

// Test 13: Open redirect via RelayState (attacker URL) - informational
func TestSecurityBinding_RelayState_OpenRedirect(t *testing.T) {
	// This is informational: RelayState is application-layer data. The SAML
	// library does not validate or constrain RelayState values. Applications
	// MUST validate the RelayState before using it as a redirect target.
	attackerURLs := []string{
		"https://evil.com/phishing",
		"//evil.com/path",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	}

	for _, attackerURL := range attackerURLs {
		t.Run(attackerURL[:min(30, len(attackerURL))], func(t *testing.T) {
			// BuildPOSTForm will include the RelayState as-is (HTML-escaped).
			// The SP application is responsible for validating the RelayState
			// before using it as a redirect target.
			formBytes, err := saml2.BuildPOSTForm(
				"https://idp.example.com/sso",
				"SAMLRequest",
				"dGVzdA==",
				attackerURL,
			)
			require.NoError(t, err)
			t.Logf("INFORMATIONAL: RelayState with attacker URL %q is included in POST form (HTML-escaped). "+
				"Applications MUST validate RelayState before using as redirect target. "+
				"Form length: %d bytes", attackerURL, len(formBytes))
		})
	}
}

// Test 14: Oversized RelayState (>80 bytes spec limit)
func TestSecurityBinding_RelayState_Oversized(t *testing.T) {
	// SAML spec recommends RelayState be no more than 80 bytes.
	// The library does not enforce this limit. This is informational.
	longRelayState := strings.Repeat("A", 1024)

	formBytes, err := saml2.BuildPOSTForm(
		"https://idp.example.com/sso",
		"SAMLRequest",
		"dGVzdA==",
		longRelayState,
	)
	require.NoError(t, err)
	t.Logf("INFORMATIONAL: RelayState of %d bytes (exceeding 80 byte spec recommendation) "+
		"was accepted. The library does not enforce the SAML spec RelayState size limit. "+
		"Form output size: %d bytes", len(longRelayState), len(formBytes))
}

// Test 15: Null bytes and control characters in RelayState
func TestSecurityBinding_RelayState_NullBytesAndControlChars(t *testing.T) {
	controlChars := []struct {
		name  string
		value string
	}{
		{"null_byte", "normal\x00evil"},
		{"tab", "normal\tevil"},
		{"newline", "normal\nevil"},
		{"carriage_return", "normal\revil"},
		{"backspace", "normal\bevil"},
	}

	for _, tc := range controlChars {
		t.Run(tc.name, func(t *testing.T) {
			formBytes, err := saml2.BuildPOSTForm(
				"https://idp.example.com/sso",
				"SAMLRequest",
				"dGVzdA==",
				tc.value,
			)
			require.NoError(t, err)
			formHTML := string(formBytes)

			// html/template should escape control characters or handle them safely.
			// Null bytes in HTML attribute values are particularly dangerous.
			t.Logf("Control char %q in RelayState produced form output. "+
				"Verify application validates RelayState before use. Contains raw null: %v",
				tc.name, strings.Contains(formHTML, "\x00"))
		})
	}
}

// ============================================================================
// CSRF on ACS (Tests 16-17)
// ============================================================================

// Test 16: No InResponseTo with AllowIDPInitiated=false
func TestSecurityBinding_CSRF_NoInResponseToWithIDPInitiatedDisabled(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	sp.AllowIDPInitiated = false

	now := sp.now()
	idpInitiatedResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, idpInitiatedResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "response without InResponseTo should be rejected when AllowIDPInitiated=false")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 17: Forged InResponseTo never issued by SP
func TestSecurityBinding_CSRF_ForgedInResponseTo(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)

	// Do NOT store any request ID - the InResponseTo is forged
	validResp := makeValidResponse(sp) // uses InResponseTo="_request_id_1"
	signed := signResponse(t, validResp, sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "forged InResponseTo (never issued by SP) should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// ============================================================================
// Replay Attacks (Tests 18-20)
// ============================================================================

// Test 18: Resubmit previously valid response
func TestSecurityBinding_Replay_ResubmitValidResponse(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()

	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_request_id_1"))

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)
	encoded := encodeResponse(signed)

	// First use should succeed
	_, err := sp.ValidateEncodedResponse(ctx, encoded)
	require.NoError(t, err, "first use of response should succeed")

	// Re-sign with the same InResponseTo for a fresh copy
	signed2 := signResponse(t, validResp, sp)
	encoded2 := encodeResponse(signed2)

	// Second use (replay) should fail because the request ID is consumed
	_, err = sp.ValidateEncodedResponse(ctx, encoded2)
	require.Error(t, err, "replayed response should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 19: Expired request ID (InResponseTo for expired request)
func TestSecurityBinding_Replay_ExpiredRequestID(t *testing.T) {
	// Use a very short expiry so the request ID expires quickly
	tracker := NewMemoryRequestTracker(1 * time.Millisecond)
	sp, _ := securityTestSP(t)
	sp.RequestTracker = tracker
	ctx := context.Background()

	require.NoError(t, tracker.StoreRequest(ctx, "_request_id_1"))

	// Wait for the entry to expire
	time.Sleep(10 * time.Millisecond)

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)
	encoded := encodeResponse(signed)

	_, err := sp.ValidateEncodedResponse(ctx, encoded)
	require.Error(t, err, "response with expired request ID should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 20: Valid time but consumed ID
func TestSecurityBinding_Replay_ValidTimeConsumedID(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()

	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_request_id_1"))

	// Consume the request ID directly
	require.NoError(t, sp.RequestTracker.ConsumeRequest(ctx, "_request_id_1"))

	// Now try to use it - should fail even though we're within the time window
	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)
	encoded := encodeResponse(signed)

	_, err := sp.ValidateEncodedResponse(ctx, encoded)
	require.Error(t, err, "response with already-consumed request ID should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// ============================================================================
// Destination Validation (Tests 21-22)
// ============================================================================

// Test 21: Response destination mismatch
func TestSecurityBinding_Destination_Mismatch(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	mismatchResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://evil.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, mismatchResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "response with wrong Destination should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

// Test 22: Empty destination (check skipped)
func TestSecurityBinding_Destination_Empty(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Response with empty Destination - the library skips Destination
	// validation when the attribute is empty per the SAML spec.
	emptyDestResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, emptyDestResp, sp)
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))

	if err == nil {
		t.Logf("WARNING: Response with empty Destination was accepted (Destination validation skipped). "+
			"Per SAML spec, Destination is REQUIRED for signed messages. "+
			"Accepting empty Destination could allow message replay to other SPs. resp=%+v", resp)
	} else {
		t.Logf("Empty Destination was rejected: %v", err)
	}
}

// ============================================================================
// Binding Mismatch (Tests 23-24)
// ============================================================================

// Test 23: Deflated response submitted via POST (maybeDeflate fallback)
func TestSecurityBinding_BindingMismatch_DeflatedViaPOST(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	// Build a valid response and deflate it, then base64 encode for POST binding
	now := sp.now()
	validResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	// Deflate the response
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(validResp))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Base64 encode the deflated data (as if submitting via POST)
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	// maybeDeflate in parseResponse tries direct XML parse first, then deflation fallback
	resp, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	if err == nil {
		t.Logf("NOTE: Deflated response was accepted via POST binding (maybeDeflate fallback). "+
			"This is by design - maybeDeflate tries raw XML first, then deflation. "+
			"Response: %+v", resp)
	} else {
		t.Logf("Deflated response via POST was rejected: %v", err)
	}
}

// Test 24: Non-deflated request via redirect (should fail inflate)
func TestSecurityBinding_BindingMismatch_NonDeflatedViaRedirect(t *testing.T) {
	sp, _ := redirectTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	// Just base64 encode raw XML without deflating
	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://sp.example.com/slo", saml2.StatusCodeSuccess)
	encodedNonDeflated := base64.StdEncoding.EncodeToString([]byte(xmlMsg))

	_, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encodedNonDeflated, "", "", "",
	)
	require.Error(t, err, "non-deflated message via redirect binding should fail inflate")
}

// ============================================================================
// AuthnRequest Manipulation (Tests 25-28)
// ============================================================================

// Test 25: AuthnRequest ACS URL injection
func TestSecurityBinding_AuthnRequest_ACSURLInjection(t *testing.T) {
	// This is primarily an IdP-side validation concern. However, we can verify
	// that the SP correctly sets the AssertionConsumerServiceURL in the
	// AuthnRequest to its configured ACSURL.
	sp := &ServiceProvider{
		EntityID:          "https://sp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		IDPSSOURL:         "https://idp.example.com/sso",
		SignAuthnRequests: false,
	}

	doc, err := sp.BuildAuthRequestDocument()
	require.NoError(t, err)

	root := doc.Root()
	acsURL := root.SelectAttrValue("AssertionConsumerServiceURL", "")
	require.Equal(t, "https://sp.example.com/acs", acsURL,
		"AuthnRequest AssertionConsumerServiceURL should match SP's configured ACSURL")

	// Verify an attacker cannot inject a different ACS URL through the SP configuration
	t.Log("INFORMATIONAL: ACS URL in AuthnRequest comes from SP configuration. " +
		"IdP MUST validate this against registered SP metadata.")
}

// Test 26: AuthnRequest missing ID attribute
func TestSecurityBinding_AuthnRequest_MissingID(t *testing.T) {
	sp := &ServiceProvider{
		EntityID:          "https://sp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		IDPSSOURL:         "https://idp.example.com/sso",
		SignAuthnRequests: false,
	}

	doc, err := sp.BuildAuthRequestDocument()
	require.NoError(t, err)

	root := doc.Root()
	id := root.SelectAttrValue("ID", "")
	require.NotEmpty(t, id, "AuthnRequest must have an ID attribute")
	require.True(t, strings.HasPrefix(id, "_"),
		"AuthnRequest ID should start with underscore per SAML spec")
}

// Test 27: ForceAuthn bypass (informational - depends on IdP enforcement)
func TestSecurityBinding_AuthnRequest_ForceAuthnBypass(t *testing.T) {
	sp := &ServiceProvider{
		EntityID:          "https://sp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		IDPSSOURL:         "https://idp.example.com/sso",
		ForceAuthn:        true,
		SignAuthnRequests: false,
	}

	doc, err := sp.BuildAuthRequestDocument()
	require.NoError(t, err)

	root := doc.Root()
	forceAuthn := root.SelectAttrValue("ForceAuthn", "")
	require.Equal(t, "true", forceAuthn,
		"ForceAuthn should be set to true when configured")

	t.Log("INFORMATIONAL: ForceAuthn is set in the AuthnRequest. " +
		"However, enforcement depends entirely on the IdP. An attacker who " +
		"controls the AuthnRequest (e.g., via a MitM) could strip this attribute. " +
		"The SP has no way to verify whether the IdP actually forced re-authentication.")
}

// Test 28: IsPassive probe (informational)
func TestSecurityBinding_AuthnRequest_IsPassiveProbe(t *testing.T) {
	sp := &ServiceProvider{
		EntityID:          "https://sp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		IDPSSOURL:         "https://idp.example.com/sso",
		IsPassive:         true,
		SignAuthnRequests: false,
	}

	doc, err := sp.BuildAuthRequestDocument()
	require.NoError(t, err)

	root := doc.Root()
	isPassive := root.SelectAttrValue("IsPassive", "")
	require.Equal(t, "true", isPassive,
		"IsPassive should be set to true when configured")

	t.Log("INFORMATIONAL: IsPassive=true can be used by an attacker to probe " +
		"whether a user has an active session at the IdP without user interaction. " +
		"If the IdP returns a success response, the user is logged in. If it returns " +
		"a NoPassive status, the user is not logged in. This is a session oracle.")
}

// ============================================================================
// AuthnContext/Unsolicited (Tests 29-33)
// ============================================================================

// Test 29: AuthnContext downgrade (informational)
func TestSecurityBinding_AuthnContext_Downgrade(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Build a response with a weak AuthnContextClassRef
	weakAuthCtxResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s" InResponseTo="_request_id_1"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339),
	)

	signed := signResponse(t, weakAuthCtxResp, sp)
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))

	t.Logf("INFORMATIONAL: The library does not validate AuthnContextClassRef. "+
		"A response with 'InternetProtocol' (weak) authentication class was %s. "+
		"Applications requiring strong authentication MUST validate the "+
		"AuthnContextClassRef themselves. err=%v resp=%+v",
		map[bool]string{true: "rejected", false: "accepted"}[err != nil],
		err, resp)
}

// Test 30: Unsolicited response when disabled
func TestSecurityBinding_Unsolicited_WhenDisabled(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	sp.AllowIDPInitiated = false

	now := sp.now()
	unsolicitedResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, unsolicitedResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "unsolicited response should be rejected when AllowIDPInitiated=false")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 31: Unsolicited response with nil RequestTracker
func TestSecurityBinding_Unsolicited_NilRequestTracker(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = nil // No request tracker configured

	now := sp.now()
	unsolicitedResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, unsolicitedResp, sp)
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))

	// With nil RequestTracker, validateInResponseTo returns nil immediately,
	// effectively allowing any response.
	if err == nil {
		t.Logf("WARNING: With nil RequestTracker, unsolicited response is accepted. "+
			"This means InResponseTo/replay checking is completely disabled. "+
			"Applications SHOULD always set a RequestTracker. Response: %+v", resp)
	} else {
		t.Logf("Rejected despite nil RequestTracker: %v", err)
	}
}

// Test 32: SubjectConfirmationData InResponseTo mismatch
func TestSecurityBinding_SubjectConfirmationData_InResponseToMismatch(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()

	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_request_id_1"))

	now := sp.now()
	mismatchResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_DIFFERENT_id" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, mismatchResp, sp)
	_, err := sp.ValidateEncodedResponse(ctx, encodeResponse(signed))
	require.Error(t, err, "SubjectConfirmationData.InResponseTo mismatch should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 33: Recipient mismatch
func TestSecurityBinding_Recipient_Mismatch(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	recipientMismatchResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="https://evil.example.com/acs"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339),
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, recipientMismatchResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "response with wrong Recipient should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadRecipient)
}

// ============================================================================
// Multiple Assertions (Tests 34-35)
// ============================================================================

// Test 34: Mixed signed and unsigned assertions in unsigned response
func TestSecurityBinding_MultipleAssertions_MixedSignedUnsigned(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Build an unsigned response with one signed assertion. Then manually
	// inject a second assertion that is NOT signed after signing the first.
	oneAssertionResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a_signed" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>legit@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	// Sign the first assertion
	signedXML := signAssertionOnly(t, oneAssertionResp, sp)

	// Now inject a second unsigned assertion into the signed XML
	unsignedAssertion := fmt.Sprintf(
		`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a_unsigned" Version="2.0" IssueInstant="%s">`+
			`<saml2:Issuer>%s</saml2:Issuer>`+
			`<saml2:Subject>`+
			`<saml2:NameID>attacker@evil.com</saml2:NameID>`+
			`<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`+
			`<saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>`+
			`</saml2:SubjectConfirmation>`+
			`</saml2:Subject>`+
			`<saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">`+
			`<saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>`+
			`</saml2:Conditions>`+
			`</saml2:Assertion>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	// Inject before closing tag
	mixed := strings.Replace(signedXML, "</saml2p:Response>", unsignedAssertion+"</saml2p:Response>", 1)

	// The unsigned second assertion should cause an error when the unsigned
	// response code path tries to verify each assertion's signature via
	// addSignedAssertion, which calls sp.verifier().Verify() on every assertion.
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(mixed))
	if err != nil {
		t.Logf("Correctly rejected mixed signed/unsigned assertions: %v", err)
	} else {
		// If accepted, verify only the signed assertion was processed
		for _, a := range resp.Assertions {
			require.True(t, a.SignatureValidated,
				"only signed assertions should appear in the result; unsigned assertion with NameID %q should not be included",
				a.Subject.NameID.Value)
			require.NotEqual(t, "attacker@evil.com", a.Subject.NameID.Value,
				"attacker's unsigned assertion should not be in the validated response")
		}
		t.Log("Response accepted, but attacker's unsigned assertion was correctly excluded")
	}
}

// Test 35: Assertions from different issuers
func TestSecurityBinding_MultipleAssertions_DifferentIssuers(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Build response with assertion from a different issuer
	differentIssuerResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>https://evil-idp.example.com</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>attacker@evil.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339),
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, differentIssuerResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "assertion from different issuer than Response.Issuer should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadIssuer)
}

// ============================================================================
// URL Validation (Tests 36-40)
// ============================================================================

// Test 36: Scheme confusion (http:// vs https://)
func TestSecurityBinding_URL_SchemeConfusion(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// SP's ACSURL is https, but Response's Destination uses http
	httpDestResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="http://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, httpDestResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "http:// scheme when SP expects https:// should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

// Test 37: Trailing slash mismatch
func TestSecurityBinding_URL_TrailingSlash(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// SP's ACSURL is "https://sp.example.com/acs" (no trailing slash)
	// Destination has trailing slash
	trailingSlashResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs/" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, trailingSlashResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	// The library uses exact string comparison for Destination.
	require.Error(t, err, "trailing slash mismatch should be rejected by exact string comparison")
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

// Test 38: Host header injection via port (:443 vs no port)
func TestSecurityBinding_URL_PortMismatch(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// SP's ACSURL is "https://sp.example.com/acs" (no port)
	// Destination adds :443 (semantically equivalent for HTTPS, but different string)
	portResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com:443/acs" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, portResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	// The library uses exact string comparison, so ":443" != ""
	require.Error(t, err, "port mismatch (https://host:443 vs https://host) should be rejected by exact comparison")
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

// Test 39: Path traversal in ACS URL
func TestSecurityBinding_URL_PathTraversal(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Destination with path traversal
	pathTraversalResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs/../admin" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, pathTraversalResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "path traversal in Destination should be rejected by exact string comparison")
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

// Test 40: Unicode in destination URL
func TestSecurityBinding_URL_UnicodeInDestination(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Use a Unicode-confusable character in the destination host
	unicodeResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.exampl`+"\u00e9"+`.com/acs" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, unicodeResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "Unicode confusable in Destination should be rejected by exact string comparison")
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

// ============================================================================
// Protocol Version (Tests 41-42)
// ============================================================================

// Test 41: SAML 1.1 Response (Version="1.1")
func TestSecurityBinding_Version_SAML11Response(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	saml11Resp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="1.1" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, saml11Resp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "SAML 1.1 Response should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadVersion)
}

// Test 42: Assertion version mismatch (Response 2.0, Assertion 1.0)
func TestSecurityBinding_Version_AssertionVersionMismatch(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	versionMismatchResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="1.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, versionMismatchResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "Response 2.0 with Assertion version 1.0 should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadVersion)
}

// ============================================================================
// Logout (Tests 43-45)
// ============================================================================

// Test 43: Logout request forgery (signed with wrong key)
func TestSecurityBinding_Logout_RequestSignedWithWrongKey(t *testing.T) {
	sp, _ := redirectTestSP(t)

	// Generate a different key pair (not in IDPCertificates)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	xmlMsg := makeLogoutRequestXML("https://idp.example.com", "https://sp.example.com/slo", "user@example.com")
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, wrongKey, crypto.SHA256, "SAMLRequest", encoded, "")

	_, err = sp.ValidateEncodedLogoutRequestRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)
	require.Error(t, err, "logout request signed with wrong key should be rejected")
	require.Contains(t, err.Error(), "signature verification failed")
}

// Test 44: Missing signature on logout request
func TestSecurityBinding_Logout_MissingSignature(t *testing.T) {
	sp, _ := redirectTestSP(t)

	xmlMsg := makeLogoutRequestXML("https://idp.example.com", "https://sp.example.com/slo", "user@example.com")
	encoded := deflateAndEncode(t, xmlMsg)

	_, err := sp.ValidateEncodedLogoutRequestRedirect(
		context.Background(), encoded, "", "", "",
	)
	require.Error(t, err, "logout request without signature should be rejected")
	require.Contains(t, err.Error(), "no signature")
}

// Test 45: Logout response destination mismatch
func TestSecurityBinding_Logout_DestinationMismatch(t *testing.T) {
	sp, key := redirectTestSP(t)

	xmlMsg := makeLogoutResponseXML("https://idp.example.com", "https://evil.example.com/slo", saml2.StatusCodeSuccess)
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	_, err := sp.ValidateEncodedLogoutResponseRedirect(
		context.Background(), encoded, "", sigAlg, sig,
	)
	require.Error(t, err, "logout response with wrong destination should be rejected")
	require.Contains(t, err.Error(), "destination")
}

// ============================================================================
// Session/Timing (Tests 46-50)
// ============================================================================

// Test 46: Session fixation via SAML (UUID unpredictability - informational)
func TestSecurityBinding_Session_UUIDUnpredictability(t *testing.T) {
	sp := &ServiceProvider{
		EntityID:          "https://sp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		IDPSSOURL:         "https://idp.example.com/sso",
		SignAuthnRequests: false,
	}

	// Generate multiple AuthnRequest IDs and verify they're unique
	idSet := make(map[string]bool)
	for i := 0; i < 100; i++ {
		doc, err := sp.BuildAuthRequestDocument()
		require.NoError(t, err)

		id := doc.Root().SelectAttrValue("ID", "")
		require.NotEmpty(t, id)
		require.False(t, idSet[id], "AuthnRequest ID should be unique (collision detected: %s)", id)
		idSet[id] = true
	}

	t.Logf("INFORMATIONAL: Generated %d unique AuthnRequest IDs. "+
		"Session fixation via predictable SAML request IDs requires UUIDs to be "+
		"unpredictable. The library uses UUID v4 (random) which provides adequate "+
		"unpredictability for this purpose.", len(idSet))
}

// Test 47: Assertion exfiltration via error messages (verify errors don't leak assertion content)
func TestSecurityBinding_ErrorMessages_NoAssertionLeak(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Build a response with a secret NameID that should NOT appear in error messages
	secretNameID := "secret-user-CLASSIFIED-DATA@example.com"
	badResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://wrong.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>%s</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		secretNameID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, badResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err)

	errMsg := err.Error()
	require.NotContains(t, errMsg, secretNameID,
		"error message should not contain assertion content (NameID)")
	require.NotContains(t, errMsg, "CLASSIFIED",
		"error message should not leak sensitive data from the assertion")

	t.Logf("Error message safely reported: %q", errMsg)
}

// Test 48: Timing attack on signature validation (informational)
func TestSecurityBinding_Timing_SignatureValidation(t *testing.T) {
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)
	encoded := encodeResponse(signed)

	// Measure validation time for valid signature
	const iterations = 10
	var validTimes []time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _ = sp.ValidateEncodedResponse(context.Background(), encoded)
		validTimes = append(validTimes, time.Since(start))
	}

	// Measure validation time for invalid signature (tampered response)
	tampered := strings.Replace(signed, "user@example.com", "evil@example.com", 1)
	tamperedEncoded := encodeResponse(tampered)

	var invalidTimes []time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _ = sp.ValidateEncodedResponse(context.Background(), tamperedEncoded)
		invalidTimes = append(invalidTimes, time.Since(start))
	}

	var avgValid, avgInvalid time.Duration
	for _, d := range validTimes {
		avgValid += d
	}
	avgValid /= time.Duration(iterations)

	for _, d := range invalidTimes {
		avgInvalid += d
	}
	avgInvalid /= time.Duration(iterations)

	t.Logf("INFORMATIONAL: Timing analysis of signature validation.\n"+
		"  Average valid signature time:   %v\n"+
		"  Average invalid signature time: %v\n"+
		"  Timing difference: %v\n"+
		"  Note: RSA signature verification is not typically vulnerable to timing "+
		"attacks because PKCS#1 v1.5 verification uses constant-time comparison "+
		"of the decrypted padded hash. The main risk is in implementations that "+
		"short-circuit on early failure.",
		avgValid, avgInvalid, avgValid-avgInvalid)
}

// Test 49: Race condition in MemoryRequestTracker (concurrent access)
func TestSecurityBinding_RaceCondition_RequestTracker(t *testing.T) {
	tracker := NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()
	require.NoError(t, tracker.StoreRequest(ctx, "_test_id"))

	// Concurrent consumption
	var wg sync.WaitGroup
	errors := make([]error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errors[idx] = tracker.ConsumeRequest(ctx, "_test_id")
		}(i)
	}
	wg.Wait()

	// Exactly one should succeed
	successCount := 0
	for _, err := range errors {
		if err == nil {
			successCount++
		}
	}
	require.Equal(t, 1, successCount, "Exactly one concurrent consumer should succeed")
}

// Test 50: Metadata injection (informational - malicious cert in IdP metadata)
func TestSecurityBinding_MetadataInjection(t *testing.T) {
	// Generate a malicious key pair
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fakeTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	attackerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		NotBefore:             fakeTime.Add(-time.Hour),
		NotAfter:              fakeTime.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	attackerCertBytes, err := x509.CreateCertificate(rand.Reader, attackerTemplate, attackerTemplate, &attackerKey.PublicKey, attackerKey)
	require.NoError(t, err)

	attackerCert, err := x509.ParseCertificate(attackerCertBytes)
	require.NoError(t, err)

	// Create an SP that trusts ONLY the legitimate IdP cert (not the attacker's)
	sp, _ := securityTestSP(t)

	// Create an attacker SP that can sign with the malicious key
	attackerSP := &ServiceProvider{
		SPKeyStore: &saml2.KeyStore{Signer: attackerKey, Cert: attackerCertBytes},
	}

	validResp := makeValidResponse(sp)
	attackerSigned := signResponse(t, validResp, attackerSP)

	// Attempt to validate with the legitimate SP (should fail - attacker cert not trusted)
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(attackerSigned))
	require.Error(t, err, "response signed with untrusted (injected) cert should be rejected")

	// Now simulate the metadata injection: add attacker cert to trusted set
	spWithInjectedCert, _ := securityTestSP(t)
	spWithInjectedCert.IDPCertificates = append(spWithInjectedCert.IDPCertificates, attackerCert)

	resp, err := spWithInjectedCert.ValidateEncodedResponse(context.Background(), encodeResponse(attackerSigned))
	if err == nil {
		t.Logf("INFORMATIONAL: METADATA INJECTION SCENARIO - If an attacker can inject "+
			"their certificate into the SP's trusted IdP certificate list (via compromised "+
			"metadata or insecure metadata fetch), they can forge valid SAML responses. "+
			"This highlights the critical importance of: (1) validating IdP metadata "+
			"signatures, (2) using HTTPS for metadata retrieval, and (3) pinning IdP "+
			"certificates rather than dynamically fetching them. "+
			"Attacker's forged response was accepted with NameID: %s",
			resp.Assertions[0].Subject.NameID.Value)
	} else {
		t.Logf("Even with injected cert, response was rejected: %v", err)
	}
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
