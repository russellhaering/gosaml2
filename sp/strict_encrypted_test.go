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
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

// Strict mode (PingFederate-style): an EncryptedAssertion is only ever decrypted
// from a signature-verified response. An encrypted assertion arriving in a
// response whose signature has not been verified is rejected with
// ErrUnsignedEncryptedAssertion — we never feed attacker-reachable ciphertext to
// the decrypter (CBC padding-oracle / XSW-on-decrypted-content surface).

// encryptedAssertionResponseXML embeds an EncryptedAssertion (encrypted to the
// SP's keystore certificate) into a Response envelope. The returned XML is
// unsigned; callers sign it (or not) as the scenario requires.
func encryptedAssertionResponseXML(t *testing.T, sp *ServiceProvider, innerAssertionXML, algorithm string) string {
	t.Helper()

	rsaKey, ok := sp.SPKeyStore.Signer.(*rsa.PrivateKey)
	require.True(t, ok)

	ea := encryptAssertion(t, innerAssertionXML, &rsaKey.PublicKey, sp.SPKeyStore.Cert, algorithm)

	now := sp.now()
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="%s"/>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="%s"/>
          <ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
          <xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData>
        </xenc:EncryptedKey>
      </ds:KeyInfo>
      <xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData>
    </xenc:EncryptedData>
  </saml2:EncryptedAssertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		ea.EncryptionMethod.Algorithm,
		ea.EncryptedKey.EncryptionMethod.Algorithm,
		ea.EncryptedKey.X509Data,
		ea.EncryptedKey.CipherValue,
		ea.CipherValue,
	)
}

// validInnerAssertion returns a well-formed assertion suitable for the SP's
// configuration (issuer, recipient, audience, validity window all valid).
func validInnerAssertion(sp *ServiceProvider) string {
	now := sp.now()
	return fmt.Sprintf(`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_enc_a1" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_s1">
      <saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0], now.Format(time.RFC3339))
}

// An encrypted assertion in an UNSIGNED response is rejected (both algorithms).
func TestStrict_EncryptedAssertion_UnsignedResponse_Rejected(t *testing.T) {
	for _, algo := range []string{types.MethodAES128GCM, types.MethodAES128CBC} {
		t.Run(algo, func(t *testing.T) {
			sp := setupSPWithTracker(t)
			xml := encryptedAssertionResponseXML(t, sp, validInnerAssertion(sp), algo)

			_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(xml))
			require.ErrorIs(t, err, saml2.ErrUnsignedEncryptedAssertion,
				"ValidateEncodedResponse must reject an encrypted assertion without a signed response")

			sp = setupSPWithTracker(t)
			xml = encryptedAssertionResponseXML(t, sp, validInnerAssertion(sp), algo)
			_, err = sp.RetrieveAssertionInfo(context.Background(), encodeResponse(xml))
			require.ErrorIs(t, err, saml2.ErrUnsignedEncryptedAssertion,
				"RetrieveAssertionInfo must reject an encrypted assertion without a signed response")
		})
	}
}

// Rejection happens before decryption: a garbage/undecryptable ciphertext in an
// unsigned response yields the strict error, NOT a decryption error — proving no
// ciphertext is fed to the decrypter (no padding oracle).
func TestStrict_EncryptedAssertion_UnsignedResponse_RejectedBeforeDecrypt(t *testing.T) {
	sp := setupSPWithTracker(t)
	xml := encryptedAssertionResponseXML(t, sp, validInnerAssertion(sp), types.MethodAES128CBC)
	// Corrupt the ciphertext; if decryption were attempted it would surface a
	// decrypt/padding error instead of the strict rejection.
	corrupted := replaceFirstCipherValue(xml, "QUJDREVG") // "ABCDEF"

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(corrupted))
	require.ErrorIs(t, err, saml2.ErrUnsignedEncryptedAssertion)
}

// The legitimate Okta-style profile — encrypted assertion inside a SIGNED
// response — still decrypts and validates under strict mode.
func TestStrict_EncryptedAssertion_SignedResponse_Accepted(t *testing.T) {
	for _, algo := range []string{types.MethodAES128GCM, types.MethodAES128CBC} {
		t.Run(algo, func(t *testing.T) {
			sp := setupSPWithTracker(t)
			xml := encryptedAssertionResponseXML(t, sp, validInnerAssertion(sp), algo)
			signed := signAndEncode(t, xml, sp)

			info, err := sp.RetrieveAssertionInfo(context.Background(), signed)
			require.NoError(t, err, "encrypted assertion in a signed response must decrypt and validate")
			require.Equal(t, "user@example.com", info.NameID)
			require.True(t, info.ResponseSignatureValidated)
		})
	}
}

// replaceFirstCipherValue swaps the assertion ciphertext (the final
// <xenc:CipherValue> in the template) with the supplied base64 text.
func replaceFirstCipherValue(xml, b64 string) string {
	const open = "<xenc:CipherValue>"
	last := strings.LastIndex(xml, open)
	if last < 0 {
		return xml
	}
	start := last + len(open)
	rel := strings.Index(xml[start:], "</xenc:CipherValue>")
	if rel < 0 {
		return xml
	}
	return xml[:start] + b64 + xml[start+rel:]
}
