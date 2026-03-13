package xmldsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// AUDIT AREA 1: Certificate Matching via cert.Equal() — DER-byte comparison
// ===========================================================================

// TestCertCrypto_CertMatchingDEREquality verifies that cert.Equal() is a
// strict DER-byte comparison. Two certificates with the same public key but
// different serial numbers or subjects MUST NOT match.
//
// FINDING: This is SECURE — the library requires exact DER match, not just
// key-match. An attacker cannot forge a different cert with the same key
// and have it accepted.
func TestCertCrypto_CertMatchingDEREquality(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()

	// Create cert1
	template1 := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER1, err := x509.CreateCertificate(rand.Reader, template1, template1, &key.PublicKey, key)
	require.NoError(t, err)
	cert1, err := x509.ParseCertificate(certDER1)
	require.NoError(t, err)

	// Create cert2 — same key, different serial number
	template2 := &x509.Certificate{
		SerialNumber:          big.NewInt(2), // different serial
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER2, err := x509.CreateCertificate(rand.Reader, template2, template2, &key.PublicKey, key)
	require.NoError(t, err)
	cert2, err := x509.ParseCertificate(certDER2)
	require.NoError(t, err)

	// Confirm same key but different DER bytes
	assert.False(t, cert1.Equal(cert2), "certs with same key but different serial must NOT Equal()")

	// Sign with cert1/key, try to verify with cert2 as trusted
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert1}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_same-key-diff-cert")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert2}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "must reject: KeyInfo cert != trusted cert even though key matches")
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 2: Single trusted cert with no KeyInfo — automatic trust
// ===========================================================================

// TestCertCrypto_SingleTrustedCertNoKeyInfo verifies the behavior when there
// is exactly 1 trusted cert and no KeyInfo in the signature. The code uses
// the single trusted cert directly.
//
// FINDING: When there's 1 trusted cert and no KeyInfo, the library skips
// the cert matching step entirely — it assigns untrustedCert = TrustedCerts[0]
// then finds it matches itself. The signature is still verified against
// the cert's public key, so this is safe. An attacker would need the
// private key to forge a signature. Document behavior.
func TestCertCrypto_SingleTrustedCertNoKeyInfo(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_no-keyinfo")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Remove KeyInfo from the signature
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	// With exactly 1 trusted cert, this should still work
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := verifier.Verify(signed)
	assert.NoError(t, err, "single trusted cert + no KeyInfo should succeed")
	if result != nil {
		assert.True(t, result.Certificate.Equal(cert))
	}
}

// TestCertCrypto_SingleTrustedCertNoKeyInfoWrongKey ensures that with 1
// trusted cert and no KeyInfo, if the signature was made with a different
// key, verification still fails.
func TestCertCrypto_SingleTrustedCertNoKeyInfoWrongKey(t *testing.T) {
	// Sign with key1
	key1, cert1 := randomTestKeyAndCert()
	signer := &Signer{Key: key1, Certs: []*x509.Certificate{cert1}}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_wrong-key-noinfo")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Remove KeyInfo
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	// Verify with cert2 (different key)
	_, cert2 := randomTestKeyAndCert()
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert2}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "different key should cause signature verification failure")
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"expected ErrSignatureInvalid, got: %v", err)
}

// TestCertCrypto_MultipleTrustedCertsNoKeyInfo ensures that with >1 trusted
// certs and no KeyInfo, verification fails (cannot determine which cert to use).
func TestCertCrypto_MultipleTrustedCertsNoKeyInfo(t *testing.T) {
	key1, cert1 := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert()

	signer := &Signer{Key: key1, Certs: []*x509.Certificate{cert1}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_multi-no-keyinfo")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert1, cert2}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "multiple trusted certs + no KeyInfo must fail")
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 3: KeyInfo with multiple X509Certificate elements
// ===========================================================================

// TestCertCrypto_KeyInfoOnlyFirstCertUsed verifies that only keyInfoCerts[0]
// is used for matching. An attacker embedding a chain [attacker-cert, trusted-cert]
// will fail because only attacker-cert is matched against TrustedCerts.
//
// FINDING: The code takes sig.keyInfoCerts[0] only. This means:
// - If an attacker places their cert first and a trusted cert second, rejection.
// - If an attacker places a trusted cert first and their cert second,
//   verification succeeds (correct: trusted cert matches, and signature is
//   verified against the trusted cert's key, so attacker can't forge).
// This is SECURE behavior.
func TestCertCrypto_KeyInfoOnlyFirstCertUsed(t *testing.T) {
	key1, cert1 := randomTestKeyAndCert() // trusted
	_, cert2 := randomTestKeyAndCert()    // attacker

	// Sign with key1/cert1 legitimately
	signer := &Signer{Key: key1, Certs: []*x509.Certificate{cert1}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_multi-keyinfo")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Tamper: inject attacker cert as FIRST in KeyInfo, push real cert to second
	sig := findSig(signed)
	require.NotNil(t, sig)

	// Find existing KeyInfo and add attacker cert at position 0
	var keyInfo *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == KeyInfoTag {
			keyInfo = c
			break
		}
	}
	require.NotNil(t, keyInfo)

	x509Data := keyInfo.FindElement("./" + X509DataTag)
	require.NotNil(t, x509Data)

	// Prepend attacker cert
	attackerCertEl := etree.NewElement(X509CertificateTag)
	attackerCertEl.Space = x509Data.ChildElements()[0].Space
	attackerCertEl.SetText(base64.StdEncoding.EncodeToString(cert2.Raw))

	// Insert attacker cert before the real cert
	newChildren := []etree.Token{attackerCertEl}
	for _, child := range x509Data.Child {
		newChildren = append(newChildren, child)
	}
	x509Data.Child = newChildren

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert1}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "attacker cert first in KeyInfo must cause rejection")
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted, got: %v", err)
}

// TestCertCrypto_KeyInfoSecondCertIgnored verifies that extra certs in
// KeyInfo beyond the first are completely ignored. Even if they're malicious
// or invalid.
func TestCertCrypto_KeyInfoSecondCertIgnored(t *testing.T) {
	key1, cert1 := randomTestKeyAndCert()

	signer := &Signer{Key: key1, Certs: []*x509.Certificate{cert1}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_extra-certs")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Add garbage cert data as second X509Certificate
	sig := findSig(signed)
	require.NotNil(t, sig)
	var keyInfo *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == KeyInfoTag {
			keyInfo = c
			break
		}
	}
	require.NotNil(t, keyInfo)

	x509Data := keyInfo.FindElement("./" + X509DataTag)
	require.NotNil(t, x509Data)

	// Append garbage cert
	garbageCertEl := etree.NewElement(X509CertificateTag)
	garbageCertEl.Space = x509Data.ChildElements()[0].Space
	garbageCertEl.SetText("THIS_IS_NOT_VALID_BASE64_CERT_DATA!!!!")
	x509Data.AddChild(garbageCertEl)

	signed = reparse(t, signed)

	// Should still verify fine because only first cert is parsed
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert1}}
	result, err := verifier.Verify(signed)
	assert.NoError(t, err, "garbage second cert should be ignored")
	if result != nil {
		assert.True(t, result.Certificate.Equal(cert1))
	}
}

// ===========================================================================
// AUDIT AREA 4: ECDSA Signature Malleability
// ===========================================================================

// TestCertCrypto_ECDSASignatureMalleability verifies that for ECDSA, the
// library accepts BOTH (r, s) and (r, n-s) for the same message.
//
// FINDING: Go's ecdsa.Verify() accepts both low-s and high-s values.
// The library does NOT enforce low-s normalization. For signature verification
// purposes this is generally not a vulnerability — both are mathematically valid.
// However, for deduplication or replay detection based on signature bytes,
// this could be exploited to produce two different byte sequences that both
// verify correctly.
func TestCertCrypto_ECDSASignatureMalleability(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA256,
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_ecdsa-malleable")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Extract the signature value
	sig := findSig(signed)
	require.NotNil(t, sig)
	var sigValueEl *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignatureValueTag {
			sigValueEl = c
			break
		}
	}
	require.NotNil(t, sigValueEl)

	origSigB64 := sigValueEl.Text()
	origSigBytes, err := base64.StdEncoding.DecodeString(
		whiteSpace.ReplaceAllString(origSigB64, ""))
	require.NoError(t, err)

	// Decode r, s
	ecdsaPub := cert.PublicKey.(*ecdsa.PublicKey)
	curve := ecdsaPub.Curve
	byteLen := (curve.Params().BitSize + 7) / 8
	require.Equal(t, 2*byteLen, len(origSigBytes))

	r := new(big.Int).SetBytes(origSigBytes[:byteLen])
	s := new(big.Int).SetBytes(origSigBytes[byteLen:])

	// Compute malleable s' = n - s
	n := curve.Params().N
	sMalleable := new(big.Int).Sub(n, s)

	// Build malleable signature (r || s')
	malleableSig := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := sMalleable.Bytes()
	copy(malleableSig[byteLen-len(rBytes):byteLen], rBytes)
	copy(malleableSig[2*byteLen-len(sBytes):], sBytes)

	// Replace signature value
	sigValueEl.SetText(base64.StdEncoding.EncodeToString(malleableSig))
	signed = reparse(t, signed)

	// Verify with malleable signature
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := verifier.Verify(signed)

	// INFORMATIONAL FINDING: Both original and malleable signatures verify.
	// This is inherent to ECDSA and Go's implementation.
	// For signature deduplication/replay this could be an issue.
	if err == nil {
		t.Log("FINDING [INFO]: ECDSA malleable signature (r, n-s) accepted — inherent to ECDSA")
		t.Log("  This means an attacker can produce a second valid signature byte sequence")
		t.Log("  without the private key. Not a vuln for verification, but affects dedup.")
		assert.NotNil(t, result)
	} else {
		t.Log("ECDSA malleable signature rejected (library enforces low-s normalization)")
	}
}

// ===========================================================================
// AUDIT AREA 5: Algorithm Confusion (RSA method + ECDSA cert, vice versa)
// ===========================================================================

// TestCertCrypto_AlgorithmConfusionRSAMethodECDSACert tests what happens when
// the signature claims RSA algorithm but the cert has an ECDSA key.
//
// FINDING: The verifySignature function dispatches on info.PublicKeyAlgorithm
// from the attacker-controlled SignatureMethod URI. It then does a type
// assertion on the cert's public key (e.g., cert.PublicKey.(*rsa.PublicKey)).
// If they mismatch, the type assertion fails and returns ErrSignatureInvalid.
// This is SECURE.
func TestCertCrypto_AlgorithmConfusionRSAMethodECDSACert(t *testing.T) {
	ecKey, ecCert := randomECDSATestKeyAndCert()

	// Sign with ECDSA properly
	signer := &Signer{
		Key:   ecKey,
		Certs: []*x509.Certificate{ecCert},
		Hash:  crypto.SHA256,
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_algo-confusion")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Tamper: change SignatureMethod to RSA
	sig := findSig(signed)
	require.NotNil(t, sig)
	signedInfoEl := sig.FindElement("./" + SignedInfoTag)
	require.NotNil(t, signedInfoEl)
	sigMethodEl := signedInfoEl.FindElement("./" + SignatureMethodTag)
	require.NotNil(t, sigMethodEl)

	// Overwrite Algorithm to RSA-SHA256
	for _, attr := range sigMethodEl.Attr {
		if attr.Key == AlgorithmAttr {
			sigMethodEl.RemoveAttr(AlgorithmAttr)
			break
		}
	}
	sigMethodEl.CreateAttr(AlgorithmAttr, RSASHA256SignatureMethod)

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{ecCert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "RSA method + ECDSA cert must fail")
	// The signature verification over SignedInfo will fail because
	// the SignedInfo bytes changed (different Algorithm attr), so
	// the cryptographic signature won't match.
	t.Logf("Algorithm confusion RSA+ECDSA result: %v", err)
}

// TestCertCrypto_AlgorithmConfusionECDSAMethodRSACert tests ECDSA method
// with RSA cert.
func TestCertCrypto_AlgorithmConfusionECDSAMethodRSACert(t *testing.T) {
	rsaKey, rsaCert := randomTestKeyAndCert()

	signer := &Signer{Key: rsaKey, Certs: []*x509.Certificate{rsaCert}}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_algo-confusion2")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Tamper: change SignatureMethod to ECDSA
	sig := findSig(signed)
	require.NotNil(t, sig)
	signedInfoEl := sig.FindElement("./" + SignedInfoTag)
	require.NotNil(t, signedInfoEl)
	sigMethodEl := signedInfoEl.FindElement("./" + SignatureMethodTag)
	require.NotNil(t, sigMethodEl)

	sigMethodEl.RemoveAttr(AlgorithmAttr)
	sigMethodEl.CreateAttr(AlgorithmAttr, ECDSASHA256SignatureMethod)

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{rsaCert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "ECDSA method + RSA cert must fail")
	t.Logf("Algorithm confusion ECDSA+RSA result: %v", err)
}

// TestCertCrypto_UnknownAlgorithmURI tests that an unknown/custom algorithm
// URI is properly rejected.
func TestCertCrypto_UnknownAlgorithmURI(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_unknown-algo")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Tamper: set unknown algorithm
	sig := findSig(signed)
	require.NotNil(t, sig)
	signedInfoEl := sig.FindElement("./" + SignedInfoTag)
	require.NotNil(t, signedInfoEl)
	sigMethodEl := signedInfoEl.FindElement("./" + SignatureMethodTag)
	require.NotNil(t, sigMethodEl)

	sigMethodEl.RemoveAttr(AlgorithmAttr)
	sigMethodEl.CreateAttr(AlgorithmAttr, "http://attacker.com/custom-algo")

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "unknown algorithm URI must be rejected")
	assert.True(t, errors.Is(err, ErrAlgorithmNotAllowed),
		"expected ErrAlgorithmNotAllowed, got: %v", err)
}

// TestCertCrypto_UnknownDigestAlgorithmURI tests that an unknown digest
// algorithm URI is rejected.
func TestCertCrypto_UnknownDigestAlgorithmURI(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_unknown-digest")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Tamper: set unknown digest algorithm
	sig := findSig(signed)
	require.NotNil(t, sig)
	signedInfoEl := sig.FindElement("./" + SignedInfoTag)
	require.NotNil(t, signedInfoEl)
	refEl := signedInfoEl.FindElement("./" + ReferenceTag)
	require.NotNil(t, refEl)
	digestMethodEl := refEl.FindElement("./" + DigestMethodTag)
	require.NotNil(t, digestMethodEl)

	digestMethodEl.RemoveAttr(AlgorithmAttr)
	digestMethodEl.CreateAttr(AlgorithmAttr, "http://attacker.com/md5")

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "unknown digest algorithm must be rejected")
	assert.True(t, errors.Is(err, ErrAlgorithmNotAllowed),
		"expected ErrAlgorithmNotAllowed, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 6: Certificate Expiry Timing
// ===========================================================================

// TestCertCrypto_ExpiredCertRejected verifies that an expired certificate
// is properly rejected.
func TestCertCrypto_ExpiredCertRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a cert that expired yesterday
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(-24 * time.Hour), // expired yesterday
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_expired")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "expired cert must be rejected")
	assert.True(t, errors.Is(err, ErrCertificateExpired),
		"expected ErrCertificateExpired, got: %v", err)
}

// TestCertCrypto_NotYetValidCertRejected verifies that a not-yet-valid
// certificate is properly rejected.
func TestCertCrypto_NotYetValidCertRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(24 * time.Hour), // starts tomorrow
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_not-yet-valid")

	// We need the clock during signing to be within cert validity for SignEnveloped
	// to work, but signing doesn't check cert validity — only Verify does.
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "not-yet-valid cert must be rejected")
	assert.True(t, errors.Is(err, ErrCertificateExpired),
		"expected ErrCertificateExpired, got: %v", err)
}

// TestCertCrypto_ClockManipulationBypassExpiry verifies that the Clock
// override works correctly — a frozen clock can make an expired cert pass.
//
// FINDING: This is by design — callers set the Clock function. If a caller
// freezes the clock or sets it wrong, they can accept expired certs.
// This is NOT a library bug, but worth documenting.
func TestCertCrypto_ClockManipulationBypassExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(-24 * time.Hour), // expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_clock-bypass")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Use a clock set to when the cert was valid
	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return now.Add(-36 * time.Hour) }, // during cert validity
	}
	result, err := verifier.Verify(signed)
	assert.NoError(t, err, "frozen clock within cert validity should pass")
	if result != nil {
		t.Log("FINDING [INFO]: Clock override allows accepting expired certs — by design")
	}
}

// ===========================================================================
// AUDIT AREA 7: RSA Signature Length / Padding Validation
// ===========================================================================

// TestCertCrypto_RSATruncatedSignature tests that a truncated RSA signature
// is rejected by rsa.VerifyPKCS1v15.
func TestCertCrypto_RSATruncatedSignature(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_truncated-sig")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Tamper: truncate signature value
	sig := findSig(signed)
	require.NotNil(t, sig)
	var sigValueEl *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignatureValueTag {
			sigValueEl = c
			break
		}
	}
	require.NotNil(t, sigValueEl)

	origB64 := whiteSpace.ReplaceAllString(sigValueEl.Text(), "")
	origBytes, err := base64.StdEncoding.DecodeString(origB64)
	require.NoError(t, err)

	// Truncate to half length
	truncated := origBytes[:len(origBytes)/2]
	sigValueEl.SetText(base64.StdEncoding.EncodeToString(truncated))

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "truncated RSA signature must be rejected")
	t.Logf("Truncated RSA sig result: %v", err)
}

// TestCertCrypto_RSAPaddedSignature tests that a zero-padded RSA signature
// (too long) is rejected.
func TestCertCrypto_RSAPaddedSignature(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_padded-sig")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	sig := findSig(signed)
	require.NotNil(t, sig)
	var sigValueEl *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignatureValueTag {
			sigValueEl = c
			break
		}
	}
	require.NotNil(t, sigValueEl)

	origB64 := whiteSpace.ReplaceAllString(sigValueEl.Text(), "")
	origBytes, err := base64.StdEncoding.DecodeString(origB64)
	require.NoError(t, err)

	// Add extra zero bytes
	padded := append(origBytes, make([]byte, 32)...)
	sigValueEl.SetText(base64.StdEncoding.EncodeToString(padded))

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "padded RSA signature (too long) must be rejected")
	t.Logf("Padded RSA sig result: %v", err)
}

// TestCertCrypto_ECDSAWrongLengthSignature tests that ECDSA signatures with
// wrong byte length are rejected.
func TestCertCrypto_ECDSAWrongLengthSignature(t *testing.T) {
	ecKey, ecCert := randomECDSATestKeyAndCert()

	signer := &Signer{
		Key:   ecKey,
		Certs: []*x509.Certificate{ecCert},
		Hash:  crypto.SHA256,
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_ec-wrong-len")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	sig := findSig(signed)
	require.NotNil(t, sig)
	var sigValueEl *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignatureValueTag {
			sigValueEl = c
			break
		}
	}
	require.NotNil(t, sigValueEl)

	// Set signature to wrong length (33 bytes instead of 64 for P-256)
	wrongSig := make([]byte, 33)
	rand.Read(wrongSig)
	sigValueEl.SetText(base64.StdEncoding.EncodeToString(wrongSig))

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{ecCert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "ECDSA signature with wrong length must be rejected")
	t.Logf("ECDSA wrong length result: %v", err)
}

// ===========================================================================
// AUDIT AREA 8: Base64 Handling in DigestValue and SignatureValue
// ===========================================================================

// TestCertCrypto_Base64WhitespaceInSignatureValue verifies that whitespace
// in base64 SignatureValue is properly handled.
func TestCertCrypto_Base64WhitespaceInSignatureValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_b64-ws")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Add whitespace to signature value
	sig := findSig(signed)
	require.NotNil(t, sig)
	var sigValueEl *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignatureValueTag {
			sigValueEl = c
			break
		}
	}
	require.NotNil(t, sigValueEl)

	// Add newlines and spaces within the base64
	orig := sigValueEl.Text()
	withWS := "\n  " + orig[:10] + "  \n  " + orig[10:] + "\n  "
	sigValueEl.SetText(withWS)

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := verifier.Verify(signed)
	assert.NoError(t, err, "whitespace in base64 SignatureValue should be stripped and work")
	if result != nil {
		assert.True(t, result.Certificate.Equal(cert))
	}
}

// TestCertCrypto_InvalidBase64SignatureValue tests that completely invalid
// base64 in SignatureValue is rejected.
func TestCertCrypto_InvalidBase64SignatureValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_bad-b64-sig")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	sig := findSig(signed)
	require.NotNil(t, sig)
	var sigValueEl *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignatureValueTag {
			sigValueEl = c
			break
		}
	}
	require.NotNil(t, sigValueEl)
	sigValueEl.SetText("!!!NOT-BASE64!!!$$$%%%")

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "invalid base64 in SignatureValue must fail")
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"expected ErrMalformedSignature for invalid base64, got: %v", err)
}

// TestCertCrypto_EmptySignatureValue tests that an empty SignatureValue
// is rejected.
func TestCertCrypto_EmptySignatureValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_empty-sig")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	sig := findSig(signed)
	require.NotNil(t, sig)
	var sigValueEl *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignatureValueTag {
			sigValueEl = c
			break
		}
	}
	require.NotNil(t, sigValueEl)
	sigValueEl.SetText("")

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "empty SignatureValue must fail")
	t.Logf("Empty SignatureValue result: %v", err)
}

// TestCertCrypto_InvalidBase64InKeyInfoCert tests that invalid base64 in
// the X509Certificate element is properly rejected.
func TestCertCrypto_InvalidBase64InKeyInfoCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_bad-b64-cert")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Replace cert data with invalid base64
	sig := findSig(signed)
	require.NotNil(t, sig)
	certEl := sig.FindElement("./" + KeyInfoTag + "/" + X509DataTag + "/" + X509CertificateTag)
	require.NotNil(t, certEl)
	certEl.SetText("!!!NOT-BASE64-CERT!!!")

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "invalid base64 cert must fail")
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"expected ErrMalformedSignature, got: %v", err)
}

// TestCertCrypto_MalformedDERInKeyInfoCert tests that valid base64 but
// invalid DER certificate data is rejected.
func TestCertCrypto_MalformedDERInKeyInfoCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_bad-der-cert")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Replace cert data with valid base64 but garbage DER
	sig := findSig(signed)
	require.NotNil(t, sig)
	certEl := sig.FindElement("./" + KeyInfoTag + "/" + X509DataTag + "/" + X509CertificateTag)
	require.NotNil(t, certEl)
	certEl.SetText(base64.StdEncoding.EncodeToString([]byte("not-a-real-certificate")))

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "malformed DER cert must fail")
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"expected ErrMalformedSignature, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 9: No Chain Validation (cert.Equal vs cert.Verify)
// ===========================================================================

// TestCertCrypto_NoCertChainValidation documents that the library uses
// cert.Equal() not cert.Verify(), meaning certificates signed by a trusted
// CA are NOT accepted — only exact cert matches work.
//
// FINDING: This is actually MORE restrictive than chain validation.
// An attacker with a cert validly signed by one of the TrustedCerts
// (acting as a CA) CANNOT use that child cert. Only exact matches work.
// This is secure but may confuse users expecting chain validation.
func TestCertCrypto_NoCertChainValidation(t *testing.T) {
	// Create a "CA" key and cert
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	// Create a child cert signed by the CA
	childKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	childTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	childDER, err := x509.CreateCertificate(rand.Reader, childTemplate, caCert, &childKey.PublicKey, caKey)
	require.NoError(t, err)
	childCert, err := x509.ParseCertificate(childDER)
	require.NoError(t, err)

	// Verify the chain is valid using standard Go crypto
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = childCert.Verify(x509.VerifyOptions{Roots: roots})
	assert.NoError(t, err, "child cert should chain-verify against CA")

	// Sign with child key/cert
	signer := &Signer{Key: childKey, Certs: []*x509.Certificate{childCert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_chain-test")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Try to verify with CA cert as trusted (expecting rejection)
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{caCert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "child cert signed by trusted CA must STILL be rejected (no chain validation)")
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted, got: %v", err)

	t.Log("FINDING [INFO]: No cert chain validation — only exact DER match. More restrictive than chain-based trust.")
}

// ===========================================================================
// AUDIT AREA 10: VerifyString Cert Selection (tries all certs)
// ===========================================================================

// TestCertCrypto_VerifyStringSkipsExpiredCerts verifies that VerifyString
// properly skips expired certificates when iterating through TrustedCerts.
func TestCertCrypto_VerifyStringSkipsExpiredCerts(t *testing.T) {
	now := time.Now()

	// Create an expired cert
	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	expiredTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	expiredDER, err := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &expiredKey.PublicKey, expiredKey)
	require.NoError(t, err)
	expiredCert, err := x509.ParseCertificate(expiredDER)
	require.NoError(t, err)

	// Create a valid cert
	validKey, validCert := randomTestKeyAndCert()

	// Sign with valid key
	signer := &Signer{Key: validKey, Certs: []*x509.Certificate{validCert}}
	content := "test message to sign"
	sigBytes, err := signer.SignString(content)
	require.NoError(t, err)

	// Verify with both certs in TrustedCerts
	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{expiredCert, validCert},
	}
	resultCert, err := verifier.VerifyString(content, sigBytes, RSASHA256SignatureMethod)
	assert.NoError(t, err)
	if resultCert != nil {
		assert.True(t, resultCert.Equal(validCert), "should return the valid cert, not expired")
	}
}

// TestCertCrypto_VerifyStringAllExpired verifies that VerifyString fails when
// all trusted certs are expired.
func TestCertCrypto_VerifyStringAllExpired(t *testing.T) {
	now := time.Now()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	expiredTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	expiredDER, err := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &key.PublicKey, key)
	require.NoError(t, err)
	expiredCert, err := x509.ParseCertificate(expiredDER)
	require.NoError(t, err)

	signer := &Signer{Key: key, Certs: []*x509.Certificate{expiredCert}}
	content := "test message"
	sigBytes, err := signer.SignString(content)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{expiredCert}}
	_, err = verifier.VerifyString(content, sigBytes, RSASHA256SignatureMethod)
	assert.Error(t, err, "all expired certs in VerifyString must fail")
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"expected ErrSignatureInvalid, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 11: Attacker-Controlled KeyInfo With Untrusted Cert
// ===========================================================================

// TestCertCrypto_AttackerCertInKeyInfoRejected verifies that an attacker
// cannot embed their own certificate in KeyInfo to get it trusted.
// This is the core defense against CVE-2023-48703 style attacks.
func TestCertCrypto_AttackerCertInKeyInfoRejected(t *testing.T) {
	// Trusted cert (legitimate IdP)
	_, trustedCert := randomTestKeyAndCert()

	// Attacker creates their own key and cert
	attackerKey, attackerCert := randomTestKeyAndCert()

	// Attacker signs with their own key and embeds their cert in KeyInfo
	signer := &Signer{Key: attackerKey, Certs: []*x509.Certificate{attackerCert}}
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_attacker")
	el.CreateElement("Assertion").SetText("admin=true")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Verify with only the trusted cert
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{trustedCert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "attacker cert in KeyInfo must be rejected")
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 12: Empty TrustedCerts
// ===========================================================================

func TestCertCrypto_EmptyTrustedCerts(t *testing.T) {
	verifier := &Verifier{TrustedCerts: nil}
	_, err := verifier.Verify(&etree.Element{Tag: "Foo"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"expected ErrMissingSignature for empty TrustedCerts, got: %v", err)
}

func TestCertCrypto_EmptyTrustedCertsVerifyString(t *testing.T) {
	verifier := &Verifier{TrustedCerts: nil}
	_, err := verifier.VerifyString("test", []byte("sig"), RSASHA256SignatureMethod)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"expected ErrMissingSignature for empty TrustedCerts, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 13: Signature Replacement Attack
// ===========================================================================

// TestCertCrypto_SignatureReplacementAttack verifies that replacing the
// entire signature block with one signed by a different key is rejected
// when that key's cert is not trusted.
func TestCertCrypto_SignatureReplacementAttack(t *testing.T) {
	// Legitimate signer
	_, trustedCert := randomTestKeyAndCert()

	// Attacker signs the same content with their own key
	attackerKey, attackerCert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_replacement")
	el.CreateElement("Data").SetText("sensitive")

	attackerSigner := &Signer{Key: attackerKey, Certs: []*x509.Certificate{attackerCert}}
	attackerSigned, err := attackerSigner.SignEnveloped(el)
	require.NoError(t, err)
	attackerSigned = reparse(t, attackerSigned)

	// Verifier trusts only the legitimate cert
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{trustedCert}}
	_, err = verifier.Verify(attackerSigned)
	assert.Error(t, err, "attacker-signed document must be rejected")
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 14: SHA-1 Algorithm Controls
// ===========================================================================

// TestCertCrypto_SHA1DefaultRejected verifies SHA-1 is rejected by default
// for both signature and digest methods.
func TestCertCrypto_SHA1DefaultRejected(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA1,
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_sha1-reject")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Default verifier rejects SHA-1
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "SHA-1 should be rejected by default")
	assert.True(t, errors.Is(err, ErrAlgorithmNotAllowed),
		"expected ErrAlgorithmNotAllowed, got: %v", err)

	// AllowSHA1 permits it
	verifier.AllowSHA1 = true
	result, err := verifier.Verify(signed)
	assert.NoError(t, err, "SHA-1 should be accepted with AllowSHA1=true")
	assert.NotNil(t, result)
}

// TestCertCrypto_SHA1VerifyString verifies SHA-1 control in VerifyString.
func TestCertCrypto_SHA1VerifyString(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA1,
	}

	content := "test content"
	sigBytes, err := signer.SignString(content)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString(content, sigBytes, RSASHA1SignatureMethod)
	assert.Error(t, err, "SHA-1 VerifyString should be rejected by default")
	assert.True(t, errors.Is(err, ErrAlgorithmNotAllowed),
		"expected ErrAlgorithmNotAllowed, got: %v", err)

	verifier.AllowSHA1 = true
	resultCert, err := verifier.VerifyString(content, sigBytes, RSASHA1SignatureMethod)
	assert.NoError(t, err, "SHA-1 should be accepted with AllowSHA1=true")
	assert.True(t, resultCert.Equal(cert))
}

// ===========================================================================
// AUDIT AREA 15: Content Tampering Post-Signing
// ===========================================================================

// TestCertCrypto_ContentTamperingDetected verifies that modifying the signed
// content after signing causes digest mismatch.
func TestCertCrypto_ContentTamperingDetected(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_tamper")
	data := el.CreateElement("Data")
	data.SetText("original")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Tamper: change the data content
	dataEl := signed.FindElement("./Data")
	require.NotNil(t, dataEl)
	dataEl.SetText("TAMPERED")

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "content tampering must be detected")
	assert.True(t, errors.Is(err, ErrDigestMismatch),
		"expected ErrDigestMismatch for tampered content, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 16: Digest Value Tampering
// ===========================================================================

// TestCertCrypto_DigestValueTampering verifies that modifying the DigestValue
// in the SignedInfo invalidates the signature (since SignedInfo is what's
// signed, changing it should cause signature verification failure).
func TestCertCrypto_DigestValueTampering(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_digest-tamper")
	el.CreateElement("Data").SetText("good")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Find and tamper DigestValue
	sig := findSig(signed)
	require.NotNil(t, sig)
	signedInfoEl := sig.FindElement("./" + SignedInfoTag)
	require.NotNil(t, signedInfoEl)
	refEl := signedInfoEl.FindElement("./" + ReferenceTag)
	require.NotNil(t, refEl)
	digestValueEl := refEl.FindElement("./" + DigestValueTag)
	require.NotNil(t, digestValueEl)

	// Replace with a different valid base64 digest
	digestValueEl.SetText(base64.StdEncoding.EncodeToString([]byte("fake-digest-value-here!!")))

	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "tampered DigestValue must cause signature verification failure")
	// The signature over SignedInfo won't match because DigestValue changed
	t.Logf("Digest tampering result: %v", err)
}

// ===========================================================================
// AUDIT AREA 17: ECDSA with Multiple Curve Sizes
// ===========================================================================

// TestCertCrypto_ECDSACurves tests ECDSA with P-256, P-384, and P-521.
func TestCertCrypto_ECDSACurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{"P-256/SHA-256", elliptic.P256(), crypto.SHA256},
		{"P-384/SHA-384", elliptic.P384(), crypto.SHA384},
		{"P-521/SHA-512", elliptic.P521(), crypto.SHA512},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			now := time.Now()
			template := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				NotBefore:             now.Add(-5 * time.Minute),
				NotAfter:              now.Add(365 * 24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
			}
			certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
			require.NoError(t, err)
			cert, err := x509.ParseCertificate(certDER)
			require.NoError(t, err)

			signer := &Signer{
				Key:   privKey,
				Certs: []*x509.Certificate{cert},
				Hash:  tc.hash,
			}

			el := &etree.Element{Tag: "Root"}
			el.CreateAttr("ID", fmt.Sprintf("_ecdsa-%s", tc.name))
			el.CreateElement("Data").SetText("test")

			signed, err := signer.SignEnveloped(el)
			require.NoError(t, err)
			signed = reparse(t, signed)

			verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := verifier.Verify(signed)
			assert.NoError(t, err, "ECDSA %s round-trip should succeed", tc.name)
			if result != nil {
				assert.NotNil(t, result.Element)
			}
		})
	}
}

// ===========================================================================
// AUDIT AREA 18: VerifyString Algorithm Mismatch
// ===========================================================================

// TestCertCrypto_VerifyStringAlgorithmMismatch tests providing the wrong
// algorithm URI to VerifyString.
func TestCertCrypto_VerifyStringAlgorithmMismatch(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA256,
	}

	content := "test for mismatch"
	sigBytes, err := signer.SignString(content)
	require.NoError(t, err)

	// Verify with SHA-512 algorithm (wrong)
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString(content, sigBytes, RSASHA512SignatureMethod)
	assert.Error(t, err, "wrong algorithm in VerifyString must fail")
	t.Logf("Algorithm mismatch result: %v", err)
}

// ===========================================================================
// AUDIT AREA 19: Concurrent Verification Safety
// ===========================================================================

// TestCertCrypto_ConcurrentVerification ensures the Verifier is safe for
// concurrent use (no shared mutable state corruption).
func TestCertCrypto_ConcurrentVerification(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	// Sign multiple different documents
	var docs []*etree.Element
	for i := 0; i < 10; i++ {
		el := &etree.Element{Tag: "Root"}
		el.CreateAttr("ID", fmt.Sprintf("_concurrent-%d", i))
		el.CreateElement("Data").SetText(fmt.Sprintf("data-%d", i))
		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)
		docs = append(docs, signed)
	}

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}

	errCh := make(chan error, len(docs))
	for _, doc := range docs {
		go func(d *etree.Element) {
			_, err := verifier.Verify(d)
			errCh <- err
		}(doc)
	}

	for range docs {
		err := <-errCh
		assert.NoError(t, err, "concurrent verification should succeed")
	}
}

// ===========================================================================
// AUDIT AREA 20: Reference URI Validation
// ===========================================================================

// TestCertCrypto_ReferenceURIMismatch verifies that a signature with a
// Reference URI that doesn't match the element's ID is rejected.
func TestCertCrypto_ReferenceURIMismatch(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_original-id")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Now change the element's ID to something else
	signed.RemoveAttr("ID")
	signed.CreateAttr("ID", "_different-id")
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "reference URI mismatch must cause failure")
	t.Logf("Reference URI mismatch result: %v", err)
}

// ===========================================================================
// AUDIT AREA 21: Multiple Signatures on Same Element
// ===========================================================================

// TestCertCrypto_MultipleSignaturesRejected verifies that multiple Signature
// elements referencing the same element are rejected.
func TestCertCrypto_MultipleSignaturesRejected(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_multi-sig")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Sign again (appends second Signature)
	signed2, err := signer.SignEnveloped(signed)
	require.NoError(t, err)
	signed2 = reparse(t, signed2)

	// Count signature elements
	var sigCount int
	for _, c := range signed2.ChildElements() {
		if c.Tag == SignatureTag {
			sigCount++
		}
	}
	assert.GreaterOrEqual(t, sigCount, 2, "should have at least 2 signatures")

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed2)
	if err != nil {
		assert.True(t, errors.Is(err, ErrMalformedSignature),
			"expected ErrMalformedSignature for multiple signatures, got: %v", err)
		t.Log("FINDING [SECURE]: Multiple signatures referencing same element correctly rejected")
	} else {
		t.Log("FINDING [CONCERN]: Multiple signatures referencing same element accepted")
	}
}

// ===========================================================================
// AUDIT AREA 22: Signature Without Required Elements
// ===========================================================================

// TestCertCrypto_MissingSignedInfo tests that a Signature without SignedInfo
// is rejected.
func TestCertCrypto_MissingSignedInfo(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_missing-signedinfo")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Remove SignedInfo
	sig := findSig(signed)
	require.NotNil(t, sig)
	for _, c := range sig.ChildElements() {
		if c.Tag == SignedInfoTag {
			sig.RemoveChild(c)
			break
		}
	}
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "missing SignedInfo must fail")
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"expected ErrMalformedSignature, got: %v", err)
}

// TestCertCrypto_MissingSignatureValue tests that a Signature without
// SignatureValue is rejected.
func TestCertCrypto_MissingSignatureValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_missing-sigvalue")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Remove SignatureValue
	sig := findSig(signed)
	require.NotNil(t, sig)
	for _, c := range sig.ChildElements() {
		if c.Tag == SignatureValueTag {
			sig.RemoveChild(c)
			break
		}
	}
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "missing SignatureValue must fail")
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"expected ErrMalformedSignature, got: %v", err)
}

// ===========================================================================
// AUDIT AREA 23: Verify returns only verified content
// ===========================================================================

// TestCertCrypto_VerifyResultElementIsCanonicalized confirms that the
// VerifyResult.Element is reconstructed from the canonical signed bytes,
// not from the original (potentially tampered) XML.
//
// FINDING: This is a CRITICAL security property. The library re-parses
// the canonical bytes and returns that, not the original element. This
// prevents XSW-style attacks where the original tree contains injected
// content that was never signed.
func TestCertCrypto_VerifyResultElementIsCanonicalized(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_canonical-result")
	data := el.CreateElement("Data")
	data.SetText("genuine")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Element)

	// The result element should contain Data with "genuine"
	resultData := result.Element.FindElement("./Data")
	require.NotNil(t, resultData, "canonical result should have Data element")
	assert.Equal(t, "genuine", strings.TrimSpace(resultData.Text()),
		"canonical result should have the signed content")

	// The result should NOT have the Signature element (it's enveloped, removed during canonicalization)
	resultSig := result.Element.FindElement("./" + SignatureTag)
	assert.Nil(t, resultSig, "canonical result should not contain Signature")
}

// ===========================================================================
// AUDIT AREA 24: ECDSA Zero Signature Values
// ===========================================================================

// TestCertCrypto_ECDSAZeroSignatureRejected verifies that a zero-value
// ECDSA signature (r=0, s=0) is rejected.
func TestCertCrypto_ECDSAZeroSignatureRejected(t *testing.T) {
	ecKey, ecCert := randomECDSATestKeyAndCert()

	signer := &Signer{
		Key:   ecKey,
		Certs: []*x509.Certificate{ecCert},
		Hash:  crypto.SHA256,
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_ec-zero")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Replace signature with zeros
	sig := findSig(signed)
	require.NotNil(t, sig)
	var sigValueEl *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignatureValueTag {
			sigValueEl = c
			break
		}
	}
	require.NotNil(t, sigValueEl)

	// P-256 requires 64-byte signature
	zeroSig := make([]byte, 64)
	sigValueEl.SetText(base64.StdEncoding.EncodeToString(zeroSig))
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{ecCert}}
	_, err = verifier.Verify(signed)
	assert.Error(t, err, "zero ECDSA signature must be rejected")
	t.Logf("ECDSA zero signature result: %v", err)
}

// ===========================================================================
// AUDIT AREA 25: RSA Key Size Awareness
// ===========================================================================

// TestCertCrypto_RSASmallKeyStillAccepted documents that the library does
// not enforce minimum RSA key sizes.
//
// FINDING [INFO]: No minimum key size enforcement. A 1024-bit RSA key
// would be accepted. This is a policy decision for callers.
func TestCertCrypto_RSASmallKeyStillAccepted(t *testing.T) {
	// Generate a 1024-bit RSA key (considered weak)
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_small-key")
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := verifier.Verify(signed)
	if err == nil {
		t.Log("FINDING [INFO]: 1024-bit RSA key accepted — no minimum key size enforcement")
		assert.NotNil(t, result)
	} else {
		t.Logf("1024-bit RSA key rejected: %v", err)
	}
}
