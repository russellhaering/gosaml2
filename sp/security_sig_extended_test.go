// Copyright 2025 Russell Haering et al.
//
// Extended signature wrapping/verification security tests (Category 1, tests 9-55).
// Tests 1-8 are covered in xsw_test.go.

package sp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Signature Exclusion (tests 9-11)
// ============================================================================

// TestSignatureExclusion_StripResponseSignature strips the ds:Signature element
// entirely from a signed Response and verifies the SP rejects it.
func TestSignatureExclusion_StripResponseSignature(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Remove all Signature elements
	for _, sig := range doc.Root().FindElements("//Signature") {
		if p := sig.Parent(); p != nil {
			p.RemoveChild(sig)
		}
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// Unsigned response path requires individually signed assertions, which we also stripped
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "response with stripped signature should be rejected")
	t.Logf("StripResponseSignature correctly rejected: %v", err)
}

// TestSignatureExclusion_StripAssertionSigUnsignedResponse verifies that in the
// unsigned-Response path, an assertion without a signature is rejected.
func TestSignatureExclusion_StripAssertionSigUnsignedResponse(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)

	// Build an unsigned response with an unsigned assertion
	raw := buildLegitResponse("legit@example.com")

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(raw))
	require.Error(t, err, "unsigned assertion in unsigned response should be rejected")
	t.Logf("StripAssertionSig (unsigned response path) correctly rejected: %v", err)
}

// TestSignatureExclusion_StripAssertionSigValueInSignedResponse signs the
// response envelope while preserving the assertion's inner signature, then
// strips the SignatureValue from the assertion's signature. Because the
// response-level digest covers the assertion WITH its inner signature, removing
// the SignatureValue changes the assertion content and breaks the response digest.
func TestSignatureExclusion_StripAssertionSigValueInSignedResponse(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	// Build response and sign the assertion first
	raw := buildLegitResponse("legit@example.com")
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(raw))

	respEl := doc.Root()
	var assertionEl *xmltree.Element
	for _, child := range respEl.ChildElements() {
		if child.Tag == "Assertion" {
			assertionEl = child
			break
		}
	}
	require.NotNil(t, assertionEl)

	signedAssertion, err := signer.SignEnveloped(assertionEl)
	require.NoError(t, err)
	respEl.RemoveChild(assertionEl)
	respEl.AddChild(signedAssertion)

	// Sign the response envelope directly (preserving the assertion's inner sig).
	// We must NOT use signResponseXML since it strips all signatures first.
	signedRespEl, err := signer.SignEnveloped(respEl)
	require.NoError(t, err)

	outDoc := xmltree.NewDocument()
	outDoc.SetRoot(signedRespEl)
	signed, err := outDoc.WriteToString()
	require.NoError(t, err)

	// Verify the baseline: the doubly-signed response should validate
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err, "baseline: doubly-signed response should validate")

	// Now strip SignatureValue from the assertion's inner signature
	doc2 := xmltree.NewDocument()
	require.NoError(t, doc2.ReadFromString(signed))

	for _, a := range doc2.Root().FindElements("//Assertion") {
		for _, child := range a.ChildElements() {
			if child.Tag == "Signature" {
				for _, sigChild := range child.ChildElements() {
					if sigChild.Tag == "SignatureValue" {
						child.RemoveChild(sigChild)
					}
				}
			}
		}
	}

	tampered, err := doc2.WriteToString()
	require.NoError(t, err)

	// The response envelope digest now fails because it was computed over the
	// assertion content INCLUDING the SignatureValue, which we removed.
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "stripping assertion SignatureValue should cause digest failure")
	t.Logf("StripAssertionSigValue in signed response correctly rejected: %v", err)
}

// ============================================================================
// Malformed Signature Values (tests 12-18)
// ============================================================================

func TestMalformedSignatureValues(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	tests := []struct {
		name   string
		modify func(doc *xmltree.Document)
	}{
		{
			name: "EmptySignatureValue",
			modify: func(doc *xmltree.Document) {
				for _, sv := range doc.Root().FindElements("//SignatureValue") {
					sv.SetText("")
				}
			},
		},
		{
			name: "WhitespaceOnlySignatureValue",
			modify: func(doc *xmltree.Document) {
				for _, sv := range doc.Root().FindElements("//SignatureValue") {
					sv.SetText("   \n\t  ")
				}
			},
		},
		{
			name: "TruncatedBase64SignatureValue",
			modify: func(doc *xmltree.Document) {
				for _, sv := range doc.Root().FindElements("//SignatureValue") {
					original := sv.Text()
					if len(original) > 10 {
						sv.SetText(original[:10])
					}
				}
			},
		},
		{
			name: "InvalidBase64CharsInSignatureValue",
			modify: func(doc *xmltree.Document) {
				for _, sv := range doc.Root().FindElements("//SignatureValue") {
					sv.SetText("!!!" + sv.Text()[3:])
				}
			},
		},
		{
			name: "MissingSignedInfoElement",
			modify: func(doc *xmltree.Document) {
				for _, si := range doc.Root().FindElements("//SignedInfo") {
					if p := si.Parent(); p != nil {
						p.RemoveChild(si)
					}
				}
			},
		},
		{
			name: "DuplicateSignedInfoElements",
			modify: func(doc *xmltree.Document) {
				for _, sig := range doc.Root().FindElements("//Signature") {
					for _, si := range sig.ChildElements() {
						if si.Tag == "SignedInfo" {
							sig.AddChild(si.Copy())
							break
						}
					}
				}
			},
		},
		{
			name: "DuplicateSignatureValueElements",
			modify: func(doc *xmltree.Document) {
				for _, sig := range doc.Root().FindElements("//Signature") {
					for _, sv := range sig.ChildElements() {
						if sv.Tag == "SignatureValue" {
							sig.AddChild(sv.Copy())
							break
						}
					}
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := xmltree.NewDocument()
			require.NoError(t, doc.ReadFromString(signed))

			tc.modify(doc)

			tampered, err := doc.WriteToString()
			require.NoError(t, err)

			_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
			require.Error(t, err, "malformed signature (%s) should be rejected", tc.name)
			t.Logf("%s correctly rejected: %v", tc.name, err)
		})
	}
}

// ============================================================================
// Certificate/Key Confusion (tests 19-23)
// ============================================================================

// TestCertConfusion_EmbedAttackerCertInKeyInfo replaces the X509Certificate in
// the KeyInfo with an attacker-generated certificate. The verifier should reject
// because the attacker cert is not in the trusted set.
func TestCertConfusion_EmbedAttackerCertInKeyInfo(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	// Generate attacker key and cert
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attackerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		NotBefore:    xswFakeTime.Add(-24 * time.Hour),
		NotAfter:     xswFakeTime.Add(365 * 24 * time.Hour),
	}
	attackerCertBytes, err := x509.CreateCertificate(rand.Reader, attackerTemplate, attackerTemplate, &attackerKey.PublicKey, attackerKey)
	require.NoError(t, err)
	_ = attackerKey // suppress unused

	// Replace X509Certificate with attacker cert
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, certEl := range doc.Root().FindElements("//X509Certificate") {
		certEl.SetText(base64.StdEncoding.EncodeToString(attackerCertBytes))
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "attacker certificate in KeyInfo should be rejected")
	t.Logf("EmbedAttackerCert correctly rejected: %v", err)
}

// TestCertConfusion_OmitKeyInfoMultipleTrustedCerts verifies that when KeyInfo
// is omitted and multiple trusted certs are configured (the certificate
// rotation scenario), the verifier tries each trusted cert and accepts a
// signature made by any of them.
func TestCertConfusion_OmitKeyInfoMultipleTrustedCerts(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	// SP already has multiple trusted certs (idpCert + spCert)
	require.Greater(t, len(sp.IDPCertificates), 1, "SP should have multiple trusted certs for this test")

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	// Remove KeyInfo entirely
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, ki := range doc.Root().FindElements("//KeyInfo") {
		if p := ki.Parent(); p != nil {
			p.RemoveChild(ki)
		}
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// Without KeyInfo, each trusted cert is tried until one verifies the
	// signature. The signing cert is among the trusted set, so this succeeds.
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.NoError(t, err, "missing KeyInfo with multiple trusted certs should try each cert")
	require.Equal(t, "legit@example.com", resp.Assertions[0].Subject.NameID.Value)
}

// TestCertConfusion_CertRotationNoKeyInfo simulates IdP certificate rotation:
// the SP pins both the outgoing and incoming certs, and the IdP signs with the
// new key while omitting KeyInfo. The old cert is listed first, so acceptance
// requires trying each pinned cert rather than just the first.
func TestCertConfusion_CertRotationNoKeyInfo(t *testing.T) {
	ks := xswKeyStore(t)
	signer := xswSigner(t, ks)

	newCert, err := x509.ParseCertificate(ks.Cert)
	require.NoError(t, err)

	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	oldTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		NotBefore:    xswFakeTime.Add(-24 * time.Hour),
		NotAfter:     xswFakeTime.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	oldDER, err := x509.CreateCertificate(rand.Reader, oldTemplate, oldTemplate, &oldKey.PublicKey, oldKey)
	require.NoError(t, err)
	oldCert, err := x509.ParseCertificate(oldDER)
	require.NoError(t, err)

	sp := &ServiceProvider{
		IDPEntityID:       "https://idp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		AudienceURIs:      []string{"https://sp.example.com"},
		IDPCertificates:   []*x509.Certificate{oldCert, newCert},
		SPKeyStore:        ks,
		SignAuthnRequests: true,
		Clock:             func() time.Time { return xswFakeTime },
	}

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))
	for _, ki := range doc.Root().FindElements("//KeyInfo") {
		if p := ki.Parent(); p != nil {
			p.RemoveChild(ki)
		}
	}
	stripped, err := doc.WriteToString()
	require.NoError(t, err)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(stripped))
	require.NoError(t, err, "response signed by the second pinned cert's key should verify")
	require.Equal(t, "legit@example.com", resp.Assertions[0].Subject.NameID.Value)
}

// TestCertConfusion_OmitKeyInfoSingleTrustedCert verifies that when KeyInfo is
// omitted but only one trusted cert exists, it still works cryptographically.
func TestCertConfusion_OmitKeyInfoSingleTrustedCert(t *testing.T) {
	ks := xswKeyStore(t)
	signer := xswSigner(t, ks)

	spCert, err := x509.ParseCertificate(ks.Cert)
	require.NoError(t, err)

	// SP with only ONE trusted cert
	sp := &ServiceProvider{
		IDPEntityID:       "https://idp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		AudienceURIs:      []string{"https://sp.example.com"},
		IDPCertificates:   []*x509.Certificate{spCert},
		SPKeyStore:        ks,
		SignAuthnRequests: true,
		Clock:             func() time.Time { return xswFakeTime },
	}

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	// Remove KeyInfo entirely
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, ki := range doc.Root().FindElements("//KeyInfo") {
		if p := ki.Parent(); p != nil {
			p.RemoveChild(ki)
		}
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// With single trusted cert, the verifier should fall back to it
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	if err == nil {
		require.NotNil(t, resp)
		require.Equal(t, "legit@example.com", resp.Assertions[0].Subject.NameID.Value)
		t.Log("OmitKeyInfo (single cert): accepted correctly using fallback cert")
	} else {
		t.Logf("OmitKeyInfo (single cert): rejected (implementation choice): %v", err)
	}
}

// TestCertConfusion_ExpiredCertificateInKeyInfo embeds an expired certificate
// in KeyInfo and verifies rejection.
func TestCertConfusion_ExpiredCertificateInKeyInfo(t *testing.T) {
	// Generate a key with an expired certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	expiredTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    xswFakeTime.Add(-2 * 365 * 24 * time.Hour),
		NotAfter:     xswFakeTime.Add(-1 * 365 * 24 * time.Hour), // expired 1 year ago
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	expiredCertBytes, err := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	expiredCert, err := x509.ParseCertificate(expiredCertBytes)
	require.NoError(t, err)

	ks := &saml2.KeyStore{Signer: key, Cert: expiredCertBytes}
	signer := &dsig.Signer{
		Key:           key,
		Certs:         []*x509.Certificate{expiredCert},
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	// Trust the expired cert in the SP
	sp := &ServiceProvider{
		IDPEntityID:       "https://idp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		AudienceURIs:      []string{"https://sp.example.com"},
		IDPCertificates:   []*x509.Certificate{expiredCert},
		SPKeyStore:        ks,
		SignAuthnRequests: true,
		Clock:             func() time.Time { return xswFakeTime },
	}

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "expired certificate should be rejected")
	t.Logf("ExpiredCert correctly rejected: %v", err)
}

// TestCertConfusion_NotYetValidCertificateInKeyInfo embeds a not-yet-valid
// certificate in KeyInfo and verifies rejection.
func TestCertConfusion_NotYetValidCertificateInKeyInfo(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	futureTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		NotBefore:    xswFakeTime.Add(365 * 24 * time.Hour), // valid 1 year from now
		NotAfter:     xswFakeTime.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	futureCertBytes, err := x509.CreateCertificate(rand.Reader, futureTemplate, futureTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	futureCert, err := x509.ParseCertificate(futureCertBytes)
	require.NoError(t, err)

	ks := &saml2.KeyStore{Signer: key, Cert: futureCertBytes}
	signer := &dsig.Signer{
		Key:           key,
		Certs:         []*x509.Certificate{futureCert},
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	sp := &ServiceProvider{
		IDPEntityID:       "https://idp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		AudienceURIs:      []string{"https://sp.example.com"},
		IDPCertificates:   []*x509.Certificate{futureCert},
		SPKeyStore:        ks,
		SignAuthnRequests: true,
		Clock:             func() time.Time { return xswFakeTime },
	}

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "not-yet-valid certificate should be rejected")
	t.Logf("NotYetValidCert correctly rejected: %v", err)
}

// ============================================================================
// Digest Manipulation (tests 24-26)
// ============================================================================

// TestDigestManipulation_ReplaceDigestValueAfterSigning modifies the DigestValue
// in the signed XML. The crypto signature over SignedInfo should fail.
func TestDigestManipulation_ReplaceDigestValueAfterSigning(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, dv := range doc.Root().FindElements("//DigestValue") {
		dv.SetText(base64.StdEncoding.EncodeToString([]byte("tampered-digest-value-here")))
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "replaced DigestValue should cause signature verification failure")
	t.Logf("ReplaceDigestValue correctly rejected: %v", err)
}

// TestDigestManipulation_ModifyDigestValueLeaveSignatureIntact modifies the
// DigestValue in the XML representation but leaves the cryptographic signature
// intact. Since the verifier re-parses SignedInfo from canonical bytes AFTER
// verifying the signature, the XML-level modification cannot be used.
func TestDigestManipulation_ModifyDigestValueLeaveSignatureIntact(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Modify the DigestValue in the XML tree (but not the signature bytes)
	for _, dv := range doc.Root().FindElements("//DigestValue") {
		dv.SetText("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// The crypto sig was computed over the ORIGINAL SignedInfo. Changing DigestValue
	// in the XML changes the canonical SignedInfo, so the crypto sig verification fails.
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "modified DigestValue should cause crypto signature failure")
	t.Logf("VerifiedVsUnverifiedSignedInfo correctly rejected: %v", err)
}

// TestDigestManipulation_EmptyDigestValue sets the DigestValue to empty.
func TestDigestManipulation_EmptyDigestValue(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, dv := range doc.Root().FindElements("//DigestValue") {
		dv.SetText("")
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "empty DigestValue should be rejected")
	t.Logf("EmptyDigestValue correctly rejected: %v", err)
}

// ============================================================================
// Reference URI Manipulation (tests 27-31)
// ============================================================================

func TestReferenceURIManipulation(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	tests := []struct {
		name   string
		newURI string
	}{
		{
			name:   "EmptyURI",
			newURI: "",
		},
		{
			name:   "NonExistentID",
			newURI: "#_does_not_exist",
		},
		{
			name:   "PointToAssertionInsteadOfResponse",
			newURI: "#_assertion_1",
		},
		{
			name:   "MalformedURINoHash",
			newURI: "_response_1",
		},
		{
			name:   "XPointerExpression",
			newURI: "#xpointer(id('_response_1'))",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := xmltree.NewDocument()
			require.NoError(t, doc.ReadFromString(signed))

			// Find and modify the Reference URI
			for _, ref := range doc.Root().FindElements("//Reference") {
				ref.RemoveAttr("URI")
				ref.CreateAttr("URI", tc.newURI)
			}

			tampered, err := doc.WriteToString()
			require.NoError(t, err)

			// Modifying the Reference URI changes SignedInfo's canonical form,
			// so the crypto signature over SignedInfo should fail.
			_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
			require.Error(t, err, "manipulated Reference URI (%s) should be rejected", tc.name)
			t.Logf("%s correctly rejected: %v", tc.name, err)
		})
	}
}

// ============================================================================
// Transform Manipulation (tests 32-34)
// ============================================================================

// TestTransformManipulation_RemoveEnvelopedSignatureTransform removes the
// enveloped-signature transform after signing. This changes the canonical
// SignedInfo, causing the crypto signature to fail.
func TestTransformManipulation_RemoveEnvelopedSignatureTransform(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Remove the enveloped-signature transform
	for _, transform := range doc.Root().FindElements("//Transform") {
		algo := transform.SelectAttrValue("Algorithm", "")
		if algo == "http://www.w3.org/2000/09/xmldsig#enveloped-signature" {
			if p := transform.Parent(); p != nil {
				p.RemoveChild(transform)
			}
		}
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "removing enveloped-signature transform should be rejected")
	t.Logf("RemoveEnvelopedSigTransform correctly rejected: %v", err)
}

// TestTransformManipulation_AddExtraXSLTTransform adds an XSLT transform to the
// Transforms element after signing.
func TestTransformManipulation_AddExtraXSLTTransform(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Add an XSLT transform
	for _, transforms := range doc.Root().FindElements("//Transforms") {
		xsltTransform := xmltree.NewElement("Transform")
		xsltTransform.Space = "ds"
		xsltTransform.CreateAttr("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116")
		transforms.AddChild(xsltTransform)
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "injected XSLT transform should be rejected")
	t.Logf("AddExtraXSLTTransform correctly rejected: %v", err)
}

// TestTransformManipulation_DuplicateEnvelopedSignatureTransform duplicates the
// enveloped-signature transform in the signed XML.
func TestTransformManipulation_DuplicateEnvelopedSignatureTransform(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Duplicate the enveloped-signature transform
	for _, transforms := range doc.Root().FindElements("//Transforms") {
		for _, transform := range transforms.ChildElements() {
			algo := transform.SelectAttrValue("Algorithm", "")
			if algo == "http://www.w3.org/2000/09/xmldsig#enveloped-signature" {
				transforms.AddChild(transform.Copy())
				break
			}
		}
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "duplicated enveloped-signature transform should be rejected")
	t.Logf("DuplicateEnvelopedSigTransform correctly rejected: %v", err)
}

// ============================================================================
// C14N Algorithm (tests 35-38)
// ============================================================================

// TestC14N_UnrecognizedCanonicalizationMethod sets a bogus C14N method URI.
func TestC14N_UnrecognizedCanonicalizationMethod(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, cm := range doc.Root().FindElements("//CanonicalizationMethod") {
		cm.RemoveAttr("Algorithm")
		cm.CreateAttr("Algorithm", "http://www.w3.org/BOGUS/c14n")
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "unrecognized C14N method should be rejected")
	t.Logf("UnrecognizedC14N correctly rejected: %v", err)
}

// TestC14N_InclusiveC14N10Legacy signs with inclusive C14N 1.0 and verifies
// it is either accepted or rejected consistently.
func TestC14N_InclusiveC14N10Legacy(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)

	cert, err := x509.ParseCertificate(ks.Cert)
	require.NoError(t, err)

	// Create a signer using C14N 1.0 (inclusive, legacy)
	legacySigner := &dsig.Signer{
		Key:           ks.Signer,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: dsig.MakeC14N10RecCanonicalizer(),
	}

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, legacySigner)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	if err == nil {
		require.NotNil(t, resp)
		require.Equal(t, "legit@example.com", resp.Assertions[0].Subject.NameID.Value)
		t.Log("InclusiveC14N10Legacy: accepted (legacy algorithm is supported)")
	} else {
		t.Logf("InclusiveC14N10Legacy: rejected (implementation choice): %v", err)
	}
}

// TestC14N_WithCommentsVsWithoutComments signs with C14N with-comments and
// verifies behavior.
func TestC14N_WithCommentsVsWithoutComments(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)

	cert, err := x509.ParseCertificate(ks.Cert)
	require.NoError(t, err)

	commentsSigner := &dsig.Signer{
		Key:           ks.Signer,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(""),
	}

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, commentsSigner)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	if err == nil {
		require.NotNil(t, resp)
		require.Equal(t, "legit@example.com", resp.Assertions[0].Subject.NameID.Value)
		t.Log("C14NWithComments: accepted")
	} else {
		t.Logf("C14NWithComments: rejected: %v", err)
	}
}

// TestC14N_TransformAlgorithmManipulationAfterSigning modifies the C14N algorithm
// attribute in a Transform element within the Reference/Transforms after signing.
// Since this element is inside SignedInfo, changing it alters the canonical form,
// causing the crypto signature verification to fail.
func TestC14N_TransformAlgorithmManipulationAfterSigning(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Find Transform elements within SignedInfo and change the C14N algorithm
	modified := false
	for _, transform := range doc.Root().FindElements("//Transform") {
		algo := transform.SelectAttrValue("Algorithm", "")
		if algo == "http://www.w3.org/2001/10/xml-exc-c14n#" {
			transform.RemoveAttr("Algorithm")
			transform.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments")
			// Add an InclusiveNamespaces with a non-empty PrefixList to further
			// differentiate from the original
			incNS := transform.CreateElement("InclusiveNamespaces")
			incNS.Space = "ec"
			incNS.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
			incNS.CreateAttr("PrefixList", "xs evil")
			modified = true
		}
	}
	require.True(t, modified, "should have found at least one C14N Transform to modify")

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// Changing the Transform Algorithm alters canonical SignedInfo, so crypto sig should fail
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "modified Transform Algorithm in SignedInfo should be rejected")
	t.Logf("TransformAlgorithmManipulation correctly rejected: %v", err)
}

// ============================================================================
// Wrong Elements / Duplicate IDs (tests 39-42)
// ============================================================================

// TestWrongElement_SignAssertionClaimResponseSig signs only the assertion but
// the response has no signature. Verify the confusion is prevented: the
// unsigned-response path should verify each assertion's signature individually.
func TestWrongElement_SignAssertionClaimResponseSig(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(raw))

	// Sign the assertion only
	var assertionEl *xmltree.Element
	for _, child := range doc.Root().ChildElements() {
		if child.Tag == "Assertion" {
			assertionEl = child
			break
		}
	}
	require.NotNil(t, assertionEl)

	signedAssertion, err := signer.SignEnveloped(assertionEl)
	require.NoError(t, err)
	doc.Root().RemoveChild(assertionEl)
	doc.Root().AddChild(signedAssertion)

	assertionOnlyXML, err := doc.WriteToString()
	require.NoError(t, err)

	// The unsigned-response path should verify the assertion's individual signature
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(assertionOnlyXML))
	if err == nil {
		require.NotNil(t, resp)
		require.Equal(t, "legit@example.com", resp.Assertions[0].Subject.NameID.Value)
		t.Log("SignAssertionClaimResponseSig: assertion verified individually (correct)")
	} else {
		t.Logf("SignAssertionClaimResponseSig: rejected: %v", err)
	}
}

// TestWrongElement_SignResponseAddUnsignedAssertion signs the response, then adds
// a second unsigned assertion. The digest should fail because the signed content changed.
func TestWrongElement_SignResponseAddUnsignedAssertion(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Add a second unsigned assertion
	evilAssertion := buildAssertionElement("evil@attacker.com", "_evil_unsigned_extra")
	doc.Root().AddChild(evilAssertion)

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "adding unsigned assertion to signed response should fail digest")
	t.Logf("SignResponseAddUnsignedAssertion correctly rejected: %v", err)
}

// TestDuplicateIDs_TwoAssertionsSameID creates a signed response with two
// assertions that have the same ID, then injects a third unsigned assertion
// with the same ID into the signed document. The attack vector is: if an
// attacker can inject an unsigned assertion with the same ID as a signed one,
// the library might confuse them. The signed response path should protect
// against this because the response digest covers only the original content.
func TestDuplicateIDs_TwoAssertionsSameID(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	// Build and sign a legitimate response
	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	// Now inject a second assertion with the same ID as the original
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	evilAssertion := buildAssertionElement("evil@attacker.com", "_assertion_1")
	doc.Root().AddChild(evilAssertion)

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// Adding content to a signed response changes the digest
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	if err != nil {
		t.Logf("DuplicateIDs (injected assertion with same ID) correctly rejected: %v", err)
	} else {
		// If accepted, the library used the signed content (via verified digest),
		// so the evil assertion should not appear
		require.NotNil(t, resp)
		for _, a := range resp.Assertions {
			require.NotEqual(t, "evil@attacker.com", a.Subject.NameID.Value,
				"VULNERABILITY: injected assertion with duplicate ID was accepted")
		}
		t.Logf("DuplicateIDs: accepted safely (no evil data). Got %d assertions.", len(resp.Assertions))
	}
}

// TestDuplicateIDs_ResponseAndAssertionShareID creates a response where the
// Response ID and Assertion ID are the same value.
func TestDuplicateIDs_ResponseAndAssertionShareID(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs"
    ID="_shared_id"
    IssueInstant="2025-01-01T00:00:00Z"
    Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_shared_id" IssueInstant="2025-01-01T00:00:00Z" Version="2.0">
    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">legit@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="https://sp.example.com/acs"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>https://sp.example.com</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="2025-01-01T00:00:00Z">
      <saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`, xswNotOnOrAfter, xswNotBefore, xswNotOnOrAfter)

	signed := signResponseXML(t, responseXML, signer)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	if err == nil {
		// If accepted, the assertion content must match the signed data
		require.NotNil(t, resp)
		require.Equal(t, "legit@example.com", resp.Assertions[0].Subject.NameID.Value)
		t.Log("ResponseAndAssertionShareID: accepted (no confusion)")
	} else {
		t.Logf("ResponseAndAssertionShareID: rejected: %v", err)
	}
}

// ============================================================================
// Detached / Enveloping (tests 43-45)
// ============================================================================

// TestDetached_SignatureAsSiblingOfResponse places the Signature as a sibling
// (not child) of the Response element, wrapping both in a new root.
func TestDetached_SignatureAsSiblingOfResponse(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Extract the signature from the response
	var sigEl *xmltree.Element
	for _, child := range doc.Root().ChildElements() {
		if child.Tag == "Signature" {
			sigEl = child.Copy()
			doc.Root().RemoveChild(child)
			break
		}
	}

	if sigEl == nil {
		t.Skip("No signature found in signed response")
	}

	// Create a wrapper with signature as sibling
	wrapper := xmltree.NewDocument()
	root := xmltree.NewElement("Wrapper")
	wrapper.SetRoot(root)
	responseXML, err := doc.WriteToString()
	require.NoError(t, err)

	// Parse the sig-stripped response
	innerDoc := xmltree.NewDocument()
	require.NoError(t, innerDoc.ReadFromString(responseXML))
	root.AddChild(innerDoc.Root().Copy())
	root.AddChild(sigEl)

	tampered, err := wrapper.WriteToString()
	require.NoError(t, err)

	// The SP should either reject because the root is not a Response,
	// or fail to find the signature as a direct child
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "signature as sibling should be rejected")
	t.Logf("SignatureAsSibling correctly rejected: %v", err)
}

// TestDetached_SignatureInSeparateDocument concatenates extra XML after the
// closing Response tag.
func TestDetached_SignatureInSeparateDocument(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)

	raw := buildLegitResponse("evil@attacker.com")

	// Append garbage XML after the closing tag
	tampered := raw + `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>`

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "signature concatenated after response should be rejected")
	t.Logf("SignatureInSeparateDocument correctly rejected: %v", err)
}

// TestDetached_EnvelopingSignatureAtRoot places a Signature element at the
// document root with the Response inside a ds:Object child.
func TestDetached_EnvelopingSignatureAtRoot(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	// Build an enveloping structure: Signature at root, Response in Object
	enveloping := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>AAAA</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AAAA</ds:SignatureValue>
  <ds:Object>%s</ds:Object>
</ds:Signature>`, signed)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(enveloping))
	require.Error(t, err, "enveloping signature at root should be rejected")
	t.Logf("EnvelopingSignatureAtRoot correctly rejected: %v", err)
}

// ============================================================================
// SignedInfo / Scope (tests 46-50)
// ============================================================================

// TestSignedInfoScope_ModifyDigestMethodAfterSigning changes the DigestMethod
// Algorithm from SHA-256 to SHA-1 after signing. Since this modifies the
// canonical SignedInfo, the crypto signature should fail.
func TestSignedInfoScope_ModifyDigestMethodAfterSigning(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, dm := range doc.Root().FindElements("//DigestMethod") {
		dm.RemoveAttr("Algorithm")
		dm.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "modified DigestMethod should be rejected")
	t.Logf("ModifyDigestMethod correctly rejected: %v", err)
}

// TestSignedInfoScope_ModifySignatureMethodAfterSigning changes the
// SignatureMethod from RSA-SHA256 to RSA-SHA1 after signing.
func TestSignedInfoScope_ModifySignatureMethodAfterSigning(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, sm := range doc.Root().FindElements("//SignatureMethod") {
		sm.RemoveAttr("Algorithm")
		sm.CreateAttr("Algorithm", dsig.RSASHA1SignatureMethod)
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "modified SignatureMethod should be rejected")
	t.Logf("ModifySignatureMethod correctly rejected: %v", err)
}

// TestSignedInfoScope_ResponseSignedThenAssertionModified signs the response,
// then modifies the assertion content. The digest should detect the change.
func TestSignedInfoScope_ResponseSignedThenAssertionModified(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	// Modify the assertion after signing
	tampered := strings.Replace(signed, "legit@example.com", "evil@attacker.com", -1)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "modifying assertion after signing should fail digest")
	t.Logf("ResponseSignedThenAssertionModified correctly rejected: %v", err)
}

// TestSignedInfoScope_MissingResponseSigOnlyAssertionSigned verifies the
// unsigned-response path works with individually signed assertions.
func TestSignedInfoScope_MissingResponseSigOnlyAssertionSigned(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(raw))

	// Sign only the assertion
	var assertionEl *xmltree.Element
	for _, child := range doc.Root().ChildElements() {
		if child.Tag == "Assertion" {
			assertionEl = child
			break
		}
	}
	require.NotNil(t, assertionEl)

	signedAssertion, err := signer.SignEnveloped(assertionEl)
	require.NoError(t, err)
	doc.Root().RemoveChild(assertionEl)
	doc.Root().AddChild(signedAssertion)

	assertionOnlyXML, err := doc.WriteToString()
	require.NoError(t, err)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(assertionOnlyXML))
	require.NoError(t, err, "individually signed assertion in unsigned response should work")
	require.NotNil(t, resp)
	require.Len(t, resp.Assertions, 1)
	require.Equal(t, "legit@example.com", resp.Assertions[0].Subject.NameID.Value)
	t.Log("MissingResponseSigOnlyAssertionSigned: assertion verified individually (correct)")
}

// TestSignedInfoScope_MissingAssertionSigOnlyResponseSigned verifies that when
// only the response is signed (no assertion signature), the assertion content
// is extracted from the signed element.
func TestSignedInfoScope_MissingAssertionSigOnlyResponseSigned(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err, "response-only signature should be sufficient")
	require.NotNil(t, resp)
	require.True(t, resp.SignatureValidated)
	require.Len(t, resp.Assertions, 1)
	require.Equal(t, "legit@example.com", resp.Assertions[0].Subject.NameID.Value)
	t.Log("MissingAssertionSigOnlyResponseSigned: assertion from signed response (correct)")
}

// ============================================================================
// HMAC / Algorithm (tests 51-55)
// ============================================================================

// TestAlgorithm_HMACSHA256SignatureMethod verifies that HMAC-SHA256 as the
// SignatureMethod is rejected (symmetric signatures are not allowed).
func TestAlgorithm_HMACSHA256SignatureMethod(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Change SignatureMethod to HMAC-SHA256
	for _, sm := range doc.Root().FindElements("//SignatureMethod") {
		sm.RemoveAttr("Algorithm")
		sm.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256")
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "HMAC-SHA256 signature method should be rejected")
	t.Logf("HMACSHA256 correctly rejected: %v", err)
}

// TestAlgorithm_SHA1DigestWhenNotAllowed verifies that SHA-1 digest algorithm
// is rejected when AllowSHA1 is false.
func TestAlgorithm_SHA1DigestWhenNotAllowed(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	sp.AllowSHA1 = false
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	// Change DigestMethod to SHA-1
	for _, dm := range doc.Root().FindElements("//DigestMethod") {
		dm.RemoveAttr("Algorithm")
		dm.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	// The crypto sig over SignedInfo should fail because we changed the canonical content.
	// But even if somehow it passed, the SHA-1 digest should be rejected.
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "SHA-1 digest should be rejected when AllowSHA1 is false")
	t.Logf("SHA1DigestWhenNotAllowed correctly rejected: %v", err)
}

// TestAlgorithm_UnknownSignatureAlgorithmURI verifies that a completely unknown
// signature algorithm URI is rejected.
func TestAlgorithm_UnknownSignatureAlgorithmURI(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, sm := range doc.Root().FindElements("//SignatureMethod") {
		sm.RemoveAttr("Algorithm")
		sm.CreateAttr("Algorithm", "http://www.w3.org/UNKNOWN/signature-method")
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "unknown signature algorithm URI should be rejected")
	t.Logf("UnknownSignatureAlgorithm correctly rejected: %v", err)
}

// TestAlgorithm_NullBytesInSignatureValue injects null bytes into the
// SignatureValue.
func TestAlgorithm_NullBytesInSignatureValue(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, sv := range doc.Root().FindElements("//SignatureValue") {
		original := sv.Text()
		// Insert null bytes in the middle of the base64 value
		if len(original) > 20 {
			sv.SetText(original[:10] + "\x00\x00\x00" + original[10:])
		}
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "null bytes in SignatureValue should be rejected")
	t.Logf("NullBytesInSignatureValue correctly rejected: %v", err)
}

// TestAlgorithm_HalfLengthRSASignature truncates the RSA signature to half its
// expected length (128 bytes for a 2048-bit key instead of 256).
func TestAlgorithm_HalfLengthRSASignature(t *testing.T) {
	ks := xswKeyStore(t)
	sp := xswServiceProvider(t, ks)
	signer := xswSigner(t, ks)

	raw := buildLegitResponse("legit@example.com")
	signed := signResponseXML(t, raw, signer)

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(signed))

	for _, sv := range doc.Root().FindElements("//SignatureValue") {
		original := sv.Text()
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(original))
		if err != nil {
			continue
		}
		// Truncate to half length
		if len(decoded) > 128 {
			truncated := decoded[:128]
			sv.SetText(base64.StdEncoding.EncodeToString(truncated))
		}
	}

	tampered, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(tampered))
	require.Error(t, err, "half-length RSA signature should be rejected")
	t.Logf("HalfLengthRSASignature correctly rejected: %v", err)
}
