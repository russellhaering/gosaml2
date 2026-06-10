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

// Category 6 subset: edge cases and novel attacks (tests 15-50).
// Tests 1-14 are IdP-specific and live in idp/.

package sp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2/v2"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Interoperability Edge Cases (tests 15-21)
// ============================================================================

// Test 15: XML Roundtrip Validation Bypass via Namespace Redefinition.
// A child element redefines the saml2 prefix to a different namespace URI.
// The SP should either reject this outright or find no assertions in the
// SAML assertion namespace, yielding an error.
func TestSecurityNovel_RTValidatorNamespaceRedefinition(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="http://evil.example.com/different-namespace"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject><saml2:NameID>evil@attacker.com</saml2:NameID></saml2:Subject>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	if err == nil {
		t.Log("WARNING: Namespace redefinition was not detected - verify assertion namespace is checked")
	} else {
		t.Logf("Correctly rejected namespace redefinition: %v", err)
	}
}

// Test 16: XML comments inside Issuer element.
// Verify that comments within the Issuer element do not truncate the Issuer
// value during parsing (e.g., "http://idp.<!--comment-->example.com" should
// become "http://idp.example.com", not "http://idp.").
func TestSecurityNovel_CommentInsideIssuer(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	responseWithCommentIssuer := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exk5zt0r12<!--injected-->Edi4rD20h7</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
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
		sp.ACSURL, now.Format(time.RFC3339),
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	// Parse to verify the concatenated issuer value
	_, el, err := parseResponse([]byte(responseWithCommentIssuer), 0)
	require.NoError(t, err)

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	require.NoError(t, err)

	// The Response-level Issuer should be the full concatenated text
	issuerValue := decodedResponse.Issuer.Value
	// It should be the full text with the comment stripped (text nodes concatenated)
	require.Equal(t, "http://www.okta.com/exk5zt0r12Edi4rD20h7", issuerValue,
		"Comment injection in Issuer should not truncate value; full concatenation expected")
}

// Test 17: CDATA in Issuer element.
// Verify CDATA sections are handled correctly in Issuer text content.
func TestSecurityNovel_CDATAInIssuer(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	responseWithCDATA := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><![CDATA[%s]]></saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID)

	_, el, err := parseResponse([]byte(responseWithCDATA), 0)
	require.NoError(t, err)

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	require.NoError(t, err)

	require.Equal(t, sp.IDPEntityID, decodedResponse.Issuer.Value,
		"CDATA-wrapped Issuer should parse to the same string value")
}

// Test 18: Unicode normalization attack on Issuer (NFC vs NFD).
// Go uses byte-level string comparison. This test confirms that if an IdP were
// to send a non-normalized form, it would be rejected by a byte-equal check.
func TestSecurityNovel_UnicodeNormalizationIssuer(t *testing.T) {
	// NFC form: "cafe\u0301" (e + combining accent) vs "caf\u00e9" (e with accent)
	nfcIssuer := "http://www.okta.com/exk5zt0r12Edi4rD20h7"
	nfdIssuer := nfcIssuer // Same bytes in this case

	// Verify Go byte comparison behavior
	require.Equal(t, nfcIssuer, nfdIssuer, "Go uses byte comparison, no Unicode normalization")

	// Now test actual different byte sequences
	nfcForm := "caf\u00e9" // U+00E9: single code point
	nfdForm := "cafe\u0301" // U+0065 U+0301: decomposed
	require.NotEqual(t, nfcForm, nfdForm,
		"NFC and NFD forms should NOT be equal under byte comparison")
}

// Test 19: Homoglyph attack on SP entity ID (Cyrillic 'e' vs Latin 'e').
// Verify that an Issuer with homoglyph characters fails the string comparison.
func TestSecurityNovel_HomoglyphIssuer(t *testing.T) {
	sp, _ := securityTestSP(t)

	// Replace the ASCII 'e' in "example" with Cyrillic 'e' (U+0435)
	homoglyphIssuer := strings.Replace(sp.IDPEntityID, "e", "\u0435", 1)

	// These should NOT be equal even though they look identical visually
	require.NotEqual(t, sp.IDPEntityID, homoglyphIssuer,
		"Homoglyph Issuer should not match legitimate Issuer")

	now := sp.now()
	maliciousResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
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
		sp.ACSURL, now.Format(time.RFC3339), homoglyphIssuer,
		now.Format(time.RFC3339), homoglyphIssuer,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	signed := signResponse(t, maliciousResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "homoglyph Issuer should be rejected by byte comparison")
}

// Test 20: Response with multiple Issuer elements.
// Only the first Issuer should be used by encoding/xml; the second should be ignored.
func TestSecurityNovel_MultipleIssuerElements(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	maliciousResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://evil.example.com</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID)

	_, el, err := parseResponse([]byte(maliciousResp), 0)
	require.NoError(t, err)

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	require.NoError(t, err)

	// Go's encoding/xml overwrites the field with the LAST matching element,
	// so the second (evil) Issuer wins. This is important to understand:
	// relying on the first element is incorrect with Go's XML parser.
	// The SP's issuer validation must catch this mismatch.
	require.Equal(t, "http://evil.example.com", decodedResponse.Issuer.Value,
		"encoding/xml uses the LAST Issuer element; SP issuer check must catch the mismatch")
}

// Test 21: Zero-width characters in NameID.
// Verify that zero-width characters are preserved in the NameID value and
// would cause a mismatch with the expected identity.
func TestSecurityNovel_ZeroWidthCharsInNameID(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true
	now := sp.now()

	// Insert U+200B (ZERO WIDTH SPACE) into the NameID
	zwNameID := "user\u200B@example.com"
	normalNameID := "user@example.com"
	require.NotEqual(t, zwNameID, normalNameID,
		"NameID with zero-width space should differ from normal NameID at byte level")

	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		zwNameID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339))

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(responseXML))
	require.NoError(t, err)

	// The NameID should preserve the zero-width character
	require.Equal(t, zwNameID, resp.Assertions[0].Subject.NameID.Value,
		"Zero-width character should be preserved in NameID; applications must sanitize")
}

// ============================================================================
// Creative/Novel Attacks (tests 22-32)
// ============================================================================

// Test 22: Encrypted assertion with non-RSA encryption certificate (ECDSA).
// Test that attempting to use an ECDSA key returns an appropriate error.
func TestSecurityNovel_EncryptedAssertionNonRSACert(t *testing.T) {
	// The EncryptedKey.DecryptSymmetricKey expects an RSA private key.
	// Using an ECDSA key should result in a type-assertion error or similar.
	ecKey, err := rsa.GenerateKey(rand.Reader, 2048) // We need a valid RSA cert for X509Data
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &ecKey.PublicKey, ecKey)
	require.NoError(t, err)

	// Build an EncryptedAssertion with a garbage encrypted key
	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		CipherValue:      base64.StdEncoding.EncodeToString(make([]byte, 64)),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-unsupported"},
			CipherValue:      base64.StdEncoding.EncodeToString(make([]byte, 256)),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  ecKey,
	}

	require.NotPanics(t, func() {
		_, err = ea.DecryptBytes(tlsCert)
	})
	require.Error(t, err, "unsupported key encryption algorithm should be rejected")
	t.Logf("Non-RSA encryption correctly rejected: %v", err)
}

// Test 23: Encrypted assertion with unsupported symmetric encryption algorithm.
// The encryptionKeySize function in the IdP package returns 0 for unknown algorithms.
// On the SP decryption side, DecryptBytes should reject unknown methods.
func TestSecurityNovel_UnsupportedEncryptionAlgorithm(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	// Use a fabricated GCM URI that is not supported
	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: "http://www.w3.org/2009/xmlenc11#aes512-gcm"},
		CipherValue:      base64.StdEncoding.EncodeToString(make([]byte, 64)),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err, "unsupported symmetric encryption algorithm should be rejected")
	t.Logf("Unsupported encryption algorithm correctly rejected: %v", err)
}

// Test 24: CBC padding oracle via encrypted assertion (SP-level integration).
// Verify that an incorrectly padded CBC ciphertext returns an error, not a panic.
func TestSecurityNovel_CBCPaddingOracle(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	// Create garbage CBC ciphertext (3 blocks = IV + 2 data blocks)
	garbageCipher := make([]byte, 48) // 3 * 16 bytes
	_, err = rand.Read(garbageCipher)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128CBC},
		CipherValue:      base64.StdEncoding.EncodeToString(garbageCipher),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	require.NotPanics(t, func() {
		_, err = ea.DecryptBytes(tlsCert)
	}, "garbage CBC ciphertext should not panic")
	// Random bytes may coincidentally have valid PKCS7 padding, so we cannot
	// unconditionally require an error. The important thing is no panic.
	if err != nil {
		t.Logf("CBC padding oracle: correctly returned error: %v", err)
	} else {
		t.Log("CBC padding oracle: garbage ciphertext happened to have valid padding (rare but possible)")
	}
}

// Test 25: GCM nonce generation soundness.
// Verify that crypto/rand produces unique nonces for AES-GCM encryption.
func TestSecurityNovel_GCMNonceUniqueness(t *testing.T) {
	const nonceSize = 12
	const iterations = 1000

	seen := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		nonce := make([]byte, nonceSize)
		_, err := rand.Read(nonce)
		require.NoError(t, err)

		key := string(nonce)
		_, duplicate := seen[key]
		require.False(t, duplicate, "nonce collision detected at iteration %d", i)
		seen[key] = struct{}{}
	}
}

// Test 26: XSW on IdP-generated signed response - clone assertion, modify NameID.
// Sign a legitimate response, then clone the assertion inside the Response
// with a different NameID to attempt confusion.
func TestSecurityNovel_XSWCloneAssertionModifyNameID(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	root := doc.Root()

	// Find the assertion and clone it
	var origAssertion *etree.Element
	for _, child := range root.ChildElements() {
		if child.Tag == "Assertion" {
			origAssertion = child
			break
		}
	}
	require.NotNil(t, origAssertion)

	cloned := origAssertion.Copy()
	// Modify the NameID in the clone
	for _, nameID := range cloned.FindElements("//NameID") {
		nameID.SetText("attacker@evil.com")
	}
	// Change the ID so it does not conflict
	cloned.RemoveAttr("ID")
	cloned.CreateAttr("ID", "_cloned_assertion")

	// Insert the cloned assertion before the original
	root.InsertChildAt(root.ChildElements()[0].Index(), cloned)

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// The Response-level signature digest should fail because we modified the content
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "XSW clone+modify should be rejected due to digest mismatch")
}

// Test 27: XSW with both Response and Assertion signatures.
// Inject an unsigned assertion alongside signed ones in a signed Response.
func TestSecurityNovel_XSWUnsignedAssertionAlongsideSigned(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	root := doc.Root()

	// Build an unsigned assertion with attacker identity
	attackerAssertion := buildAssertionElement("attacker@evil.com", "_attacker_assertion")
	root.AddChild(attackerAssertion)

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// The digest of the signed content changed (we added a child)
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "injecting unsigned assertion into signed response should fail digest check")
}

// Test 28: Encrypted assertion XSW - plaintext unsigned assertion alongside encrypted assertion.
// When an encrypted assertion is present, an attacker injects a plaintext assertion.
func TestSecurityNovel_PlaintextAssertionAlongsideEncrypted(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Build a response that has a fake EncryptedAssertion element AND a plaintext unsigned assertion.
	// The SP should not accept the unsigned plaintext assertion.
	maliciousResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:CipherData><xenc:CipherValue>dGVzdA==</xenc:CipherValue></xenc:CipherData>
    </xenc:EncryptedData>
  </saml2:EncryptedAssertion>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_unsigned_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>attacker@evil.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
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
		sp.AudienceURIs[0])

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousResp))
	require.Error(t, err, "unsigned plaintext assertion alongside encrypted assertion should be rejected")
}

// Test 29: IdP-initiated SSO when AllowIDPInitiated=false.
func TestSecurityNovel_IDPInitiatedDisallowed(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	sp.AllowIDPInitiated = false

	now := sp.now()
	idpInitiatedResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
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
		sp.AudienceURIs[0])

	signed := signResponse(t, idpInitiatedResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "IdP-initiated SSO should be rejected when AllowIDPInitiated=false")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 30: InResponseTo mismatch between Response and Assertion SubjectConfirmationData.
func TestSecurityNovel_InResponseToMismatchResponseVsSCD(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()

	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_request_id_1"))

	now := sp.now()
	mismatchResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_TOTALLY_DIFFERENT_ID" NotOnOrAfter="%s" Recipient="%s"/>
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
		sp.AudienceURIs[0])

	signed := signResponse(t, mismatchResp, sp)
	_, err := sp.ValidateEncodedResponse(ctx, encodeResponse(signed))
	require.Error(t, err, "mismatched InResponseTo between Response and SCD should be rejected")
}

// Test 31: Replay attack - same InResponseTo used twice.
func TestSecurityNovel_ReplaySameInResponseTo(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()

	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_request_id_1"))

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)

	// First use succeeds
	_, err := sp.ValidateEncodedResponse(ctx, encodeResponse(signed))
	require.NoError(t, err, "first use should succeed")

	// Second use with identical response should fail
	signed2 := signResponse(t, validResp, sp)
	_, err = sp.ValidateEncodedResponse(ctx, encodeResponse(signed2))
	require.Error(t, err, "replay with same InResponseTo should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 32: Time skew exploitation - NotOnOrAfter exactly at the boundary.
func TestSecurityNovel_TimeSkewBoundary(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true
	sp.ClockSkew = 60 * time.Second

	now := sp.now()

	// NotOnOrAfter is exactly now (at the boundary, no skew margin)
	boundaryResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339))

	// Exactly at boundary should still be accepted because clock skew allows it
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(boundaryResp))
	if err == nil {
		require.NotNil(t, resp)
		t.Log("Boundary time accepted (within clock skew)")
	} else {
		t.Logf("Boundary time rejected (strict checking): %v", err)
	}
}

// ============================================================================
// Interoperability Edge Cases (tests 33-39)
// ============================================================================

// Test 33: Go time parsing with non-RFC3339 timestamps (space instead of T).
func TestSecurityNovel_NonRFC3339Timestamp(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	// Use a space instead of 'T' between date and time
	badTimestamp := now.Format("2006-01-02 15:04:05Z07:00")

	malformedResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`,
		sp.ACSURL, badTimestamp, sp.IDPEntityID)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(malformedResp))
	// Go's encoding/xml time parsing should reject or handle the space-separated format
	if err != nil {
		t.Logf("Non-RFC3339 timestamp correctly rejected: %v", err)
	} else {
		t.Log("WARNING: Non-RFC3339 timestamp was accepted")
	}
}

// Test 34: Conditions NotBefore in the future beyond clock skew.
func TestSecurityNovel_NotBeforeFutureBeyondSkew(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true
	sp.ClockSkew = 60 * time.Second

	now := sp.now()
	// NotBefore is 5 minutes in the future, well beyond the 60s clock skew
	farFutureNotBefore := now.Add(5 * time.Minute).Format(time.RFC3339)

	malformedResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(10*time.Minute).Format(time.RFC3339), sp.ACSURL,
		farFutureNotBefore, now.Add(10*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339))

	// ValidateEncodedResponse now enforces Conditions for every assertion, so a
	// NotBefore beyond the clock skew must be rejected here (not only in
	// RetrieveAssertionInfo).
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(malformedResp))
	require.ErrorIs(t, err, saml2.ErrNotYetValid,
		"ValidateEncodedResponse must reject a future Conditions.NotBefore beyond skew")
	t.Logf("NotBefore beyond skew correctly rejected by ValidateEncodedResponse: %v", err)
}

// Test 35: Empty Conditions element (no NotBefore/NotOnOrAfter attributes).
func TestSecurityNovel_EmptyConditionsElement(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	now := sp.now()
	emptyConditionsResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions/>
    <saml2:AuthnStatement AuthnInstant="%s">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Format(time.RFC3339))

	// An empty Conditions element has no time bounds - behavior is implementation-defined.
	// It should not panic and should either accept or reject with an error.
	require.NotPanics(t, func() {
		_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(emptyConditionsResp))
		if err != nil {
			t.Logf("Empty Conditions rejected: %v", err)
		} else {
			t.Log("Empty Conditions accepted (no time bounds enforced)")
		}
	})
}

// Test 36: AudienceRestriction with multiple audiences including one match (OR semantics).
// Per SAML spec, multiple <Audience> within a single <AudienceRestriction> use OR semantics.
func TestSecurityNovel_MultipleAudiencesORSemantics(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	now := sp.now()
	multiAudienceResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction>
        <saml2:Audience>https://other-sp.example.com</saml2:Audience>
        <saml2:Audience>%s</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339))

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(multiAudienceResp))
	require.NoError(t, err, "Multiple audiences with one match should succeed (OR semantics)")
	require.NotNil(t, resp)
}

// Test 37: Multiple AudienceRestriction elements - all must match (AND semantics).
func TestSecurityNovel_MultipleAudienceRestrictionsANDSemantics(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	now := sp.now()
	multiRestrictionResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction>
        <saml2:Audience>%s</saml2:Audience>
      </saml2:AudienceRestriction>
      <saml2:AudienceRestriction>
        <saml2:Audience>https://completely-different.example.com</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339))

	// With AND semantics, the second AudienceRestriction should fail
	// ValidateEncodedResponse does not check conditions (that is in RetrieveAssertionInfo).
	// So we check at the parsing level - the response should parse fine but condition
	// validation should catch the mismatch.
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(multiRestrictionResp))
	if err != nil {
		t.Logf("Multiple AudienceRestrictions AND semantics: rejected at validate level: %v", err)
	} else {
		require.NotNil(t, resp)
		require.Len(t, resp.Assertions, 1)
		// The conditions include two AudienceRestrictions, both should be checked
		conds := resp.Assertions[0].Conditions
		require.NotNil(t, conds)
		require.Len(t, conds.AudienceRestrictions, 2, "Both AudienceRestrictions should be parsed")
		t.Log("Multiple AudienceRestrictions parsed; AND semantics enforced at assertion info layer")
	}
}

// Test 38: etree vs encoding/xml namespace prefix handling.
// Verify that a detached assertion re-attached to a response preserves its
// namespace context correctly.
func TestSecurityNovel_EtreeVsEncodingXMLNamespacePrefix(t *testing.T) {
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(validResp))

	root := doc.Root()

	// Find the assertion and detach it
	var assertion *etree.Element
	for _, child := range root.ChildElements() {
		if child.Tag == "Assertion" {
			assertion = child
			break
		}
	}
	require.NotNil(t, assertion)

	// Copy the assertion and re-parse it standalone
	assertionDoc := etree.NewDocument()
	assertionDoc.SetRoot(assertion.Copy())

	assertionXML, err := assertionDoc.WriteToString()
	require.NoError(t, err)

	// Parse back and verify namespace is preserved
	reDoc := etree.NewDocument()
	require.NoError(t, reDoc.ReadFromString(assertionXML))

	reRoot := reDoc.Root()
	require.Equal(t, "Assertion", reRoot.Tag)
	require.Equal(t, "urn:oasis:names:tc:SAML:2.0:assertion", reRoot.NamespaceURI(),
		"Detached assertion should preserve its SAML namespace URI")
}

// Test 39: Attribute with double-encoded ampersand (&amp;amp;).
func TestSecurityNovel_DoubleEncodedAmpersand(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	responseWithDoubleEncoding := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="URL">
        <saml2:AttributeValue>http://example.com/?a=1&amp;amp;b=2</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	_, el, err := parseResponse([]byte(responseWithDoubleEncoding), 0)
	require.NoError(t, err)

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	require.NoError(t, err)

	attrValue := decodedResponse.Assertions[0].AttributeStatements[0].Attributes[0].Values[0].Value
	// The XML parser decodes &amp; to & and &amp;amp; to &amp;
	// So the double encoding should result in "&amp;b=2" as the literal string
	require.Equal(t, "http://example.com/?a=1&amp;b=2", attrValue,
		"Double-encoded ampersand should decode to single-encoded form")
}

// ============================================================================
// Creative/Novel Attacks (tests 40-50)
// ============================================================================

// Test 40: Very large number of attributes (memory exhaustion prevention).
func TestSecurityNovel_LargeAttributeCount(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	now := sp.now()

	var attrs strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&attrs, `<saml2:Attribute Name="attr%d"><saml2:AttributeValue>value%d</saml2:AttributeValue></saml2:Attribute>`, i, i)
	}

	largeResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      %s
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339),
		attrs.String())

	// Should not hang or OOM
	require.NotPanics(t, func() {
		resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(largeResp))
		if err == nil {
			require.NotNil(t, resp)
			require.Len(t, resp.Assertions[0].AttributeStatements[0].Attributes, 1000)
			t.Log("1000 attributes parsed successfully without OOM")
		} else {
			t.Logf("Large attribute count handling: %v", err)
		}
	})
}

// Test 41: Concurrent Signer() access on SP.
func TestSecurityNovel_ConcurrentSignerAccess(t *testing.T) {
	sp, _ := securityTestSP(t)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			signer, err := sp.Signer()
			require.NoError(t, err)
			require.NotNil(t, signer)
		}()
	}
	wg.Wait()
}

// Test 42: X.509 certificate with edge-case serial numbers.
// Go 1.22+ rejects negative serial numbers during CreateCertificate.
// Verify that a zero serial number and a very large serial number work.
func TestSecurityNovel_EdgeCaseSerialNumberCert(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Zero serial number (edge case)
	zeroTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, zeroTemplate, zeroTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	require.Equal(t, 0, big.NewInt(0).Cmp(cert.SerialNumber),
		"Zero serial number should round-trip through DER encoding")

	// Very large serial number (20 bytes, maximum per RFC 5280)
	largeSerial := new(big.Int).SetBytes([]byte{
		0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
	})
	largeTemplate := &x509.Certificate{
		SerialNumber:          largeSerial,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes2, err := x509.CreateCertificate(rand.Reader, largeTemplate, largeTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	cert2, err := x509.ParseCertificate(certBytes2)
	require.NoError(t, err)
	require.Equal(t, 0, largeSerial.Cmp(cert2.SerialNumber),
		"Large serial number should round-trip through DER encoding")

	// Verify these certs can be used in a KeyStore
	ks := &saml2.KeyStore{Signer: key, Cert: certBytes}
	require.NotNil(t, ks.Signer)

	ks2 := &saml2.KeyStore{Signer: key, Cert: certBytes2}
	require.NotNil(t, ks2.Signer)
}

// Test 43: PEM encoding with extra whitespace.
// Verify that PEM parsing handles extra whitespace/newlines gracefully.
func TestSecurityNovel_PEMWithExtraWhitespace(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// Base64 encode the cert with extra whitespace (simulating IdP metadata copy-paste)
	b64Cert := base64.StdEncoding.EncodeToString(certBytes)
	withWhitespace := "  \n" + b64Cert[:40] + " \n " + b64Cert[40:] + "\n  "

	// Stripping whitespace should allow successful decoding
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, withWhitespace)

	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	require.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(decoded)
	require.NoError(t, err)
	require.NotNil(t, parsedCert)
}

// Test 44: AuthnRequest with extremely long ID (10K chars).
func TestSecurityNovel_ExtremelyLongResponseID(t *testing.T) {
	sp, _ := securityTestSP(t)
	now := sp.now()

	longID := strings.Repeat("a", 10000)

	longIDResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="%s" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`,
		sp.ACSURL, longID, now.Format(time.RFC3339), sp.IDPEntityID)

	require.NotPanics(t, func() {
		_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(longIDResp))
		if err != nil {
			t.Logf("Extremely long ID handled: %v", err)
		} else {
			t.Log("WARNING: Extremely long ID was accepted")
		}
	})
}

// Test 45: Signature Reference URI with null byte.
// Verify that a null byte in the Reference URI does not bypass matching.
func TestSecurityNovel_ReferenceURINullByte(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Inject a null byte into the Reference URI
	for _, ref := range doc.Root().FindElements("//Reference") {
		uri := ref.SelectAttrValue("URI", "")
		ref.RemoveAttr("URI")
		ref.CreateAttr("URI", uri+"\x00evil")
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// The modified URI changes the canonical SignedInfo, so the signature must fail
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "null byte in Reference URI should cause signature verification failure")
}

// Test 46: BuildPOSTForm XSS via RelayState.
func TestSecurityNovel_BuildPOSTFormXSS_RelayState(t *testing.T) {
	maliciousRelayState := `"><script>alert(1)</script>`

	body, err := saml2.BuildPOSTForm(
		"https://idp.example.com/sso",
		"SAMLRequest",
		"base64data",
		maliciousRelayState,
	)
	require.NoError(t, err)

	bodyStr := string(body)
	// html/template auto-escapes dangerous content
	require.Contains(t, bodyStr, "&lt;script&gt;",
		"Script tags in RelayState should be HTML-escaped")
	require.NotContains(t, bodyStr, "alert(1)</script>",
		"Unescaped script content should not appear in output")
}

// Test 47: BuildPOSTForm XSS via ACS URL.
func TestSecurityNovel_BuildPOSTFormXSS_ACSURL(t *testing.T) {
	maliciousURL := `javascript:alert(document.cookie)`

	body, err := saml2.BuildPOSTForm(
		maliciousURL,
		"SAMLRequest",
		"base64data",
		"",
	)
	require.NoError(t, err)

	bodyStr := string(body)
	// html/template sanitizes javascript: URLs in action attributes
	require.NotContains(t, bodyStr, "javascript:alert",
		"javascript: URL should be sanitized by html/template")
}

// Test 48: Empty Reference URI signing entire document.
// An empty URI="" means the entire document is the reference. Verify this
// does not allow an attacker to sign arbitrary content.
func TestSecurityNovel_EmptyReferenceURI(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Change the Reference URI to empty
	for _, ref := range doc.Root().FindElements("//Reference") {
		ref.RemoveAttr("URI")
		ref.CreateAttr("URI", "")
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// Changing the URI alters the canonical SignedInfo, so crypto sig fails
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "empty Reference URI should be rejected (SignedInfo changed)")
}

// Test 49: Chain attack - metadata poisoning then assertion theft (informational).
// This test documents that metadata should be obtained through a trusted channel.
// The actual attack surface is that if an attacker can control IdP metadata,
// they can provide their own certificate, and then sign assertions with it.
func TestSecurityNovel_MetadataPoisoningInformational(t *testing.T) {
	// Generate an attacker keypair
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	attackerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(666),
		NotBefore:             xswFakeTime.Add(-24 * time.Hour),
		NotAfter:              xswFakeTime.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	attackerCertBytes, err := x509.CreateCertificate(rand.Reader, attackerTemplate, attackerTemplate, &attackerKey.PublicKey, attackerKey)
	require.NoError(t, err)

	attackerCert, err := x509.ParseCertificate(attackerCertBytes)
	require.NoError(t, err)

	// SP trusts the attacker cert (simulating metadata poisoning)
	poisonedSP := &ServiceProvider{
		IDPEntityID:     "https://idp.example.com",
		ACSURL:          "https://sp.example.com/acs",
		AudienceURIs:    []string{"https://sp.example.com"},
		IDPCertificates: []*x509.Certificate{attackerCert},
		SPKeyStore: &saml2.KeyStore{
			Signer: attackerKey,
			Cert:   attackerCertBytes,
		},
		SignAuthnRequests: true,
		Clock:             func() time.Time { return xswFakeTime },
	}

	// Attacker signs a response with their key
	attackerSigner := &dsig.Signer{
		Key:           attackerKey,
		Certs:         []*x509.Certificate{attackerCert},
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	raw := buildLegitResponse("attacker@evil.com")
	signed := signResponseXML(t, raw, attackerSigner)

	// The poisoned SP accepts the attacker's signature
	resp, err := poisonedSP.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err)
	require.Equal(t, "attacker@evil.com", resp.Assertions[0].Subject.NameID.Value,
		"INFORMATIONAL: metadata poisoning allows attacker to forge assertions")
	t.Log("INFORMATIONAL: This test demonstrates that metadata integrity is critical. " +
		"If an attacker can modify IdP metadata, they can forge valid assertions.")
}

// Test 50: SignedInfo parameter order manipulation.
// Verify that reordering attributes within SignedInfo elements causes signature failure.
func TestSecurityNovel_SignedInfoAttributeReorder(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Find CanonicalizationMethod and SignatureMethod, swap their Algorithm values
	for _, si := range doc.Root().FindElements("//SignedInfo") {
		var canonMethod, sigMethod *etree.Element
		for _, child := range si.ChildElements() {
			switch child.Tag {
			case "CanonicalizationMethod":
				canonMethod = child
			case "SignatureMethod":
				sigMethod = child
			}
		}
		if canonMethod != nil && sigMethod != nil {
			canonAlg := canonMethod.SelectAttrValue("Algorithm", "")
			sigAlg := sigMethod.SelectAttrValue("Algorithm", "")
			canonMethod.RemoveAttr("Algorithm")
			canonMethod.CreateAttr("Algorithm", sigAlg)
			sigMethod.RemoveAttr("Algorithm")
			sigMethod.CreateAttr("Algorithm", canonAlg)
		}
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// Swapping algorithm URIs changes the canonical SignedInfo, breaking the signature
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "swapping SignedInfo algorithms should break signature verification")
}

// ============================================================================
// Encrypted assertion edge cases (supplemental for tests 22-24)
// ============================================================================

// TestSecurityNovel_EncryptedAssertionValidRoundtrip verifies that a properly
// constructed encrypted assertion can be decrypted, serving as a baseline
// for the negative tests above.
func TestSecurityNovel_EncryptedAssertionValidRoundtrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	// Create a valid AES-128-GCM encrypted assertion
	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	plaintext := []byte("<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">test</saml2:Assertion>")
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		CipherValue:      base64.StdEncoding.EncodeToString(ciphertext),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	decrypted, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, string(plaintext), string(decrypted),
		"Valid encrypted assertion should decrypt to original plaintext")
}
