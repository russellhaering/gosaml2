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
	"sync/atomic"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// reparse serializes el to XML and re-parses it so all etree parent pointers
// are correct. SignEnveloped appends via the Child slice directly, so a
// serialize→parse round-trip is required before calling Verify.
func reparse(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	s, err := doc.WriteToString()
	require.NoError(t, err)
	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(s))
	return doc2.Root()
}

// signAndReparse signs el enveloped, then round-trips through XML text.
func signAndReparse(t *testing.T, key crypto.Signer, cert *x509.Certificate, el *etree.Element) *etree.Element {
	t.Helper()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	return reparse(t, signed)
}

// signDoc builds <Response ID=id><Data>good</Data></Response>, signs, reparses.
func signDoc(t *testing.T, key crypto.Signer, cert *x509.Certificate, id string) *etree.Element {
	t.Helper()
	el := &etree.Element{Tag: "Response"}
	if id != "" {
		el.CreateAttr("ID", id)
	}
	el.CreateElement("Data").SetText("good")
	return signAndReparse(t, key, cert, el)
}

func newVerifier(certs ...*x509.Certificate) *Verifier {
	return &Verifier{TrustedCerts: certs}
}

func findSig(el *etree.Element) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == SignatureTag {
			return c
		}
	}
	return nil
}

func removeKeyInfoFromSig(el *etree.Element) {
	sig := findSig(el)
	if sig == nil {
		return
	}
	for _, c := range sig.ChildElements() {
		if c.Tag == KeyInfoTag {
			sig.RemoveChild(c)
			return
		}
	}
}

func customCert(key crypto.Signer, notBefore, notAfter time.Time) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

// genKeyCert creates an RSA 2048 key and self-signed cert with the given
// validity window.
func genKeyCert(t *testing.T, bits int, notBefore, notAfter time.Time) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// genECDSAKeyCert creates a P-256 ECDSA key and self-signed cert.
func genECDSAKeyCert(t *testing.T, notBefore, notAfter time.Time) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// signDocWithCerts signs a simple <Root ID=id><Data>hello</Data></Root>
// element, optionally embedding multiple certs in KeyInfo.
func signDocWithCerts(t *testing.T, key crypto.Signer, certs []*x509.Certificate, id string) *etree.Element {
	t.Helper()
	el := &etree.Element{Tag: "Root"}
	if id != "" {
		el.CreateAttr("ID", id)
	}
	el.CreateElement("Data").SetText("hello")
	signer := &Signer{Key: key, Certs: certs}
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	return reparse(t, signed)
}

// === XSW & Tampering Tests ===

func TestXSW_SignatureMovedToGrandchild(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	sig := findSig(signed)
	require.NotNil(t, sig)
	wrapper := signed.CreateElement("Wrapper")
	signed.RemoveChild(sig)
	wrapper.AddChild(sig)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrMissingSignature), "got: %v", err)
}

func TestXSW_EvilSiblingElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	evil := etree.NewElement("Evil")
	evil.SetText("bad")
	signed.InsertChildAt(0, evil)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_WrappedSignature(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	sig := findSig(signed)
	require.NotNil(t, sig)
	container := etree.NewElement("SigContainer")
	signed.RemoveChild(sig)
	container.AddChild(sig)
	signed.AddChild(container)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrMissingSignature), "got: %v", err)
}

func TestXSW_DuplicateIDDifferentContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	// Put the signed element inside an outer Envelope alongside an evil clone.
	envelope := etree.NewElement("Envelope")
	evil := etree.NewElement("Response")
	evil.CreateAttr("ID", "_r1")
	evil.CreateElement("Data").SetText("evil")
	envelope.AddChild(evil)
	envelope.AddChild(signed)

	// Verify the actual signed element; result must contain "good".
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	require.Equal(t, "good", d.Text())
}

func TestXSW_EmptyURIWithInjectedContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	// No ID → empty URI reference.
	signed := signDoc(t, key, cert, "")

	// Verify clean round-trip works.
	res, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Inject evil content.
	signed.CreateElement("Evil").SetText("bad")
	_, err = newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_ModifiedContentAfterSignature(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	signed.FindElement("//Data").SetText("tampered")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_AddedAttributeAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	signed.CreateAttr("evil", "true")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_RemovedChildAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	d := signed.FindElement("//Data")
	require.NotNil(t, d)
	signed.RemoveChild(d)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_ReorderedChildrenAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_reorder")
	el.CreateElement("First").SetText("1")
	el.CreateElement("Second").SetText("2")
	signed := signAndReparse(t, key, cert, el)

	first := signed.FindElement("//First")
	second := signed.FindElement("//Second")
	sig := findSig(signed)
	require.NotNil(t, first)
	require.NotNil(t, second)
	require.NotNil(t, sig)

	signed.Child = nil
	signed.AddChild(second)
	signed.AddChild(first)
	signed.AddChild(sig)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_ModifiedNamespaceAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response", Space: "samlp"}
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", "_ns")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	// Verify clean first.
	_, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)

	// Tamper with the namespace URI.
	for i, a := range signed.Attr {
		if a.Key == "samlp" && a.Space == "xmlns" {
			signed.Attr[i].Value = "urn:evil:ns"
			break
		}
	}

	_, err = newVerifier(cert).Verify(signed)
	require.Error(t, err)
	// May break at signature or digest level depending on c14n scope.
	require.True(t,
		errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSignatureInvalid),
		"got: %v", err)
}

func TestTamper_ModifiedTextContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	signed.FindElement("//Data").SetText("tampered")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestTamper_ModifiedAttributeValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_attr")
	el.CreateAttr("Flavor", "vanilla")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	for i, a := range signed.Attr {
		if a.Key == "Flavor" {
			signed.Attr[i].Value = "chocolate"
			break
		}
	}

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestTamper_AddedChildElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	signed.CreateElement("Injected").SetText("evil")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestTamper_RemovedChildElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	d := signed.FindElement("//Data")
	require.NotNil(t, d)
	signed.RemoveChild(d)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestTamper_AddedComment(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// --- default C14N 1.1 (strips comments) ---
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_cmt1")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	signed.InsertChildAt(0, etree.NewComment("injected"))

	res, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err, "comment should be ignored by non-comment c14n")
	require.NotNil(t, res)

	// --- WithComments canonicalizer ---
	signer2 := &Signer{
		Key: key, Certs: []*x509.Certificate{cert},
		Canonicalizer: MakeC14N11WithCommentsCanonicalizer(),
	}
	el2 := &etree.Element{Tag: "Response"}
	el2.CreateAttr("ID", "_cmt2")
	el2.CreateElement("Data").SetText("good")
	raw2, err := signer2.SignEnveloped(el2)
	require.NoError(t, err)
	signed2 := reparse(t, raw2)

	signed2.InsertChildAt(0, etree.NewComment("injected"))

	_, err = newVerifier(cert).Verify(signed2)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestAlgo_SHA1BlockedByDefault(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_sha1")
	el.CreateElement("Data").SetText("good")
	raw, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed := reparse(t, raw)

	// Default: AllowSHA1 = false.
	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = v.Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAlgorithmNotAllowed), "got: %v", err)

	// Allow SHA-1.
	v.AllowSHA1 = true
	res, err := v.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestAlgo_UnknownSignatureAlgorithm(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	sm := signed.FindElement("//" + SignatureMethodTag)
	require.NotNil(t, sm)
	for i, a := range sm.Attr {
		if a.Key == AlgorithmAttr {
			sm.Attr[i].Value = "http://example.com/bogus-sig"
			break
		}
	}

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAlgorithmNotAllowed), "got: %v", err)
}

func TestAlgo_UnknownDigestAlgorithm(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	dm := signed.FindElement("//" + DigestMethodTag)
	require.NotNil(t, dm)
	for i, a := range dm.Attr {
		if a.Key == AlgorithmAttr {
			dm.Attr[i].Value = "http://example.com/bogus-digest"
			break
		}
	}

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAlgorithmNotAllowed), "got: %v", err)
}

func TestTamper_ModifiedSignatureValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	sv := signed.FindElement("//" + SignatureValueTag)
	require.NotNil(t, sv)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sv.Text()))
	require.NoError(t, err)
	raw[0] ^= 0xff
	sv.SetText(base64.StdEncoding.EncodeToString(raw))

	_, err = newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSignatureInvalid), "got: %v", err)
}

func TestTamper_ModifiedDigestValue(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	dv := signed.FindElement("//" + DigestValueTag)
	require.NotNil(t, dv)
	dv.SetText(base64.StdEncoding.EncodeToString([]byte("fakefakefakefakefakefakefakefake")))

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	// Changing DigestValue changes SignedInfo → signature check fails first.
	require.True(t, errors.Is(err, ErrSignatureInvalid), "got: %v", err)
}

// === Certificate Trust Tests ===

func TestCert_UntrustedCertInKeyInfo(t *testing.T) {
	keyA, certA := randomTestKeyAndCert()
	_, certB := randomTestKeyAndCert()

	signed := signDoc(t, keyA, certA, "_r1")

	_, err := newVerifier(certB).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertificateNotTrusted), "got: %v", err)
}

func TestCert_SelfSignedAttackerCert(t *testing.T) {
	_, trustedCert := randomTestKeyAndCert()
	attackerKey, attackerCert := randomTestKeyAndCert()

	signed := signDoc(t, attackerKey, attackerCert, "_r1")

	_, err := newVerifier(trustedCert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertificateNotTrusted), "got: %v", err)
}

func TestCert_ExpiredCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := customCert(key,
		time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_exp")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC) },
	}
	_, verr := v.Verify(signed)
	require.Error(t, verr)
	require.True(t, errors.Is(verr, ErrCertificateExpired), "got: %v", verr)
}

func TestCert_NotYetValidCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := customCert(key,
		time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_nyv")
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) },
	}
	_, verr := v.Verify(signed)
	require.Error(t, verr)
	require.True(t, errors.Is(verr, ErrCertificateExpired), "got: %v", verr)
}

func TestCert_NoKeyInfoMultipleTrustedCerts(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert()

	signed := signDoc(t, key, cert, "_r1")
	removeKeyInfoFromSig(signed)

	_, err := newVerifier(cert, cert2).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertificateNotTrusted), "got: %v", err)
}

func TestCert_NoKeyInfoSingleTrustedCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")
	removeKeyInfoFromSig(signed)

	res, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.True(t, res.Certificate.Equal(cert))
}

func TestCert_ClockInjection(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_r1")

	var called int64
	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock: func() time.Time {
			atomic.AddInt64(&called, 1)
			return time.Now()
		},
	}
	res, err := v.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Greater(t, atomic.LoadInt64(&called), int64(0), "Clock was never called")
}

func TestCert_SwappedKeyInfoCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	_, attackerCert := randomTestKeyAndCert()

	signed := signDoc(t, key, cert, "_r1")

	certEl := signed.FindElement("//" + X509CertificateTag)
	require.NotNil(t, certEl)
	certEl.SetText(base64.StdEncoding.EncodeToString(attackerCert.Raw))

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertificateNotTrusted), "got: %v", err)
}

func TestRoundTrip_ECDSAVerifiesClean(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signed := signDoc(t, key, cert, "_ecdsa")

	res, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	require.True(t, res.Certificate.Equal(cert))
	d := res.Element.FindElement("//Data")
	require.NotNil(t, d)
	require.Equal(t, "good", d.Text())
}

// === Cross-Reference Confusion Tests ===

func TestCrossRef_DuplicateIDs_SignedElementVerifies(t *testing.T) {
	// Attack scenario: An attacker creates a document with two elements sharing
	// the same ID. The signer signs one element. If the verifier picks a different
	// element by ID, the attacker could substitute content.
	//
	// Expected behavior: When we call Verify on the actual signed element, it
	// should succeed and return the content that was actually signed ("good").
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_dup1")
	el.CreateElement("Data").SetText("good")

	signed := signAndReparse(t, key, cert, el)

	// Verify the signed element directly – must succeed.
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text())
}

func TestCrossRef_DuplicateIDs_EvilSiblingWithSameID(t *testing.T) {
	// Attack scenario: The signed element is placed alongside an evil sibling
	// that shares the same ID value. The verifier should only examine the
	// element it was asked to verify (the signed one), not resolve the ID
	// globally and potentially pick the evil sibling.
	//
	// Expected behavior: Verify on the signed element succeeds and returns
	// "good" content, not "evil".
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_dup2")

	// Create an outer envelope with an evil sibling having the same ID.
	envelope := etree.NewElement("Envelope")
	evil := etree.NewElement("Response")
	evil.CreateAttr("ID", "_dup2")
	evil.CreateElement("Data").SetText("evil")
	envelope.AddChild(evil)
	envelope.AddChild(signed)

	// Verify the actual signed element, not the envelope.
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text(), "verifier must return the actually-signed content, not evil sibling")
}

func TestCrossRef_DuplicateIDs_VerifyEvilElementFails(t *testing.T) {
	// Attack scenario: Attacker takes a legitimately signed document and tries
	// to get the verifier to accept a different element (evil) that happens to
	// share the same ID. We verify the evil element that does not contain a
	// valid signature.
	//
	// Expected behavior: Verification of the evil element fails because the
	// signature is not a direct child of it.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_dup3")

	evil := etree.NewElement("Response")
	evil.CreateAttr("ID", "_dup3")
	evil.CreateElement("Data").SetText("evil")

	envelope := etree.NewElement("Envelope")
	envelope.AddChild(evil)
	envelope.AddChild(signed)

	// Verifying the evil element should fail – it has no signature child.
	_, err := newVerifier(cert).Verify(evil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature), "got: %v", err)
}

// ---------------------------------------------------------------------------
// Test 2: URL-Encoded / Percent-Encoded URI
// ---------------------------------------------------------------------------

func TestCrossRef_PercentEncodedURI(t *testing.T) {
	// Attack scenario: The Reference URI uses percent-encoding, e.g.
	// URI="#%5Fid1" instead of URI="#_id1". If the library decodes percent-
	// encoding before matching, this could allow bypasses. XML Digital
	// Signatures should compare the URI value as-is (no percent decoding
	// for fragment identifiers in the Reference element).
	//
	// Expected behavior: A percent-encoded URI will NOT match the element's
	// ID attribute (since the library does literal string comparison), so
	// verification should fail with ErrMissingSignature.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	// Tamper: change the Reference URI to a percent-encoded equivalent.
	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)

	// Original URI is "#_id1"; replace with percent-encoded form.
	// %5F = underscore, so "#%5Fid1" is semantically "#_id1" in URL terms.
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#%5Fid1"
			break
		}
	}

	// Re-serialize to ensure consistent tree.
	reparsed := reparse(t, signed)

	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	// The literal string "%5Fid1" != "_id1", so the signature won't match.
	// It could be ErrMissingSignature (no matching ref) or ErrSignatureInvalid
	// (SignedInfo was tampered). Either way, it must not succeed.
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrDigestMismatch),
		"percent-encoded URI must not verify; got: %v", err)
}

func TestCrossRef_PercentEncodedAlpha(t *testing.T) {
	// Attack scenario: URI="#%41%42%43" which percent-decodes to "#ABC".
	// Element has ID="ABC". If the library normalizes percent-encoding,
	// it would incorrectly match.
	//
	// Expected behavior: No match, verification fails.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "ABC")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#%41%42%43"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "percent-encoded alphabetic URI must not match literal ID")
}

// ---------------------------------------------------------------------------
// Test 3: XPointer URIs
// ---------------------------------------------------------------------------

func TestCrossRef_XPointerURI(t *testing.T) {
	// Attack scenario: XPointer expressions like URI="#xpointer(/)" could
	// reference arbitrary parts of the document. The library should not
	// support XPointer and must reject (or not match) such URIs.
	//
	// Expected behavior: Verification fails – the URI doesn't match the
	// element's ID, so findSignature returns ErrMissingSignature.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_xp1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#xpointer(/)"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	// The literal "xpointer(/)" won't equal "_xp1", so no match.
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"XPointer URI must not verify; got: %v", err)
}

func TestCrossRef_XPointerID(t *testing.T) {
	// Attack scenario: URI="#xpointer(id('_xp2'))" is another XPointer form.
	// It must not be treated as a simple fragment reference.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_xp2")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#xpointer(id('_xp2'))"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "xpointer(id(...)) URI must not match")
}

// ---------------------------------------------------------------------------
// Test 4: Empty URI
// ---------------------------------------------------------------------------

func TestCrossRef_EmptyURI_ValidRoundTrip(t *testing.T) {
	// Baseline: An element with no ID attribute gets an empty URI reference.
	// A clean round-trip (sign, reparse, verify) should succeed.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	// Deliberately no ID attribute → empty URI.
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	// Confirm the Reference URI is indeed empty.
	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	assert.Equal(t, "", ref.SelectAttrValue(URIAttr, "MISSING"))

	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text())
}

func TestCrossRef_EmptyURI_InjectedContentDetected(t *testing.T) {
	// Attack scenario: With an empty URI, the signature covers the entire
	// element. An attacker injects a new child element after signing.
	// The digest must fail because the canonical form changes.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateElement("Data").SetText("good")
	signed := signAndReparse(t, key, cert, el)

	// Inject evil content outside the original scope.
	signed.CreateElement("Evil").SetText("injected")

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestCrossRef_EmptyURI_MatchesElementWithID(t *testing.T) {
	// Verify that an empty URI (meaning "whole document/element") also matches
	// an element that happens to have an ID. The library allows empty URI to
	// match any element per the spec: sig.refURI == "" is the first branch.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_hasid")
	el.CreateElement("Data").SetText("payload")

	// Sign normally (will get URI="#_hasid").
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	rawSigned, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Tamper: change Reference URI to empty.
	ref := rawSigned.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = ""
			break
		}
	}

	reparsed := reparse(t, rawSigned)

	// This should fail because we changed the URI inside SignedInfo,
	// which changes the SignedInfo canonical form, invalidating the signature.
	_, err = newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrMissingSignature),
		"changing URI after signing must invalidate signature; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test 5: External URIs
// ---------------------------------------------------------------------------

func TestCrossRef_ExternalHTTPURI(t *testing.T) {
	// Attack scenario: An attacker sets URI="http://evil.com/doc.xml" to try
	// to make the verifier fetch an external resource. The library must never
	// dereference external URIs.
	//
	// Expected behavior: The URI doesn't start with '#' and isn't empty, so
	// it won't match the element's ID → ErrMissingSignature.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_ext1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "http://evil.com/doc.xml"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	// Must not succeed. The URI doesn't start with '#' and isn't empty.
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"external HTTP URI must not verify; got: %v", err)
}

func TestCrossRef_ExternalHTTPSURI(t *testing.T) {
	// Same as above but with https.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_ext2")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "https://evil.com/doc.xml"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"external HTTPS URI must not verify; got: %v", err)
}

func TestCrossRef_FileURI(t *testing.T) {
	// Attack scenario: URI="file:///etc/passwd" – an attacker tries to make
	// the verifier read a local file.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_ext3")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "file:///etc/passwd"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "file: URI must be rejected")
}

// ---------------------------------------------------------------------------
// Test 6: URI with Query String
// ---------------------------------------------------------------------------

func TestCrossRef_URIWithQueryString(t *testing.T) {
	// Attack scenario: URI="#_id1?extra=param" – appending a query string to
	// a fragment URI. The library should not strip query parameters before
	// matching. Since it does literal string comparison after the '#',
	// "_id1?extra=param" != "_id1".
	//
	// Expected behavior: No match, verification fails.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1?extra=param"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"URI with query string must not match; got: %v", err)
}

func TestCrossRef_URIWithAnchorSuffix(t *testing.T) {
	// Attack scenario: URI="#_id1#extra" – a double-fragment.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1#extra"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "double-fragment URI must not match")
}

// ---------------------------------------------------------------------------
// Test 7: Case Sensitivity
// ---------------------------------------------------------------------------

func TestCrossRef_CaseSensitiveID(t *testing.T) {
	// Attack scenario: XML IDs are case-sensitive. An attacker changes the
	// Reference URI to a different case, hoping the verifier does a
	// case-insensitive comparison.
	//
	// Expected behavior: "_ABC" != "_abc", verification fails.
	key, cert := randomTestKeyAndCert()

	t.Run("uppercase_id_lowercase_ref", func(t *testing.T) {
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ABC")
		el.CreateElement("Data").SetText("payload")
		signed := signAndReparse(t, key, cert, el)

		ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
		require.NotNil(t, ref)
		for i, a := range ref.Attr {
			if a.Key == URIAttr {
				ref.Attr[i].Value = "#_abc"
				break
			}
		}

		reparsed := reparse(t, signed)
		_, err := newVerifier(cert).Verify(reparsed)
		require.Error(t, err)
		assert.True(t,
			errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
			"case mismatch must not match; got: %v", err)
	})

	t.Run("lowercase_id_uppercase_ref", func(t *testing.T) {
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_abc")
		el.CreateElement("Data").SetText("payload")
		signed := signAndReparse(t, key, cert, el)

		ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
		require.NotNil(t, ref)
		for i, a := range ref.Attr {
			if a.Key == URIAttr {
				ref.Attr[i].Value = "#_ABC"
				break
			}
		}

		reparsed := reparse(t, signed)
		_, err := newVerifier(cert).Verify(reparsed)
		require.Error(t, err)
		assert.True(t,
			errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
			"case mismatch must not match; got: %v", err)
	})

	t.Run("mixed_case_id_matches_exactly", func(t *testing.T) {
		// Positive test: exact case match should work.
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_AbCdEf")
		el.CreateElement("Data").SetText("payload")
		signed := signAndReparse(t, key, cert, el)

		result, err := newVerifier(cert).Verify(signed)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

// ---------------------------------------------------------------------------
// Test 8: URI with Spaces and Special Characters
// ---------------------------------------------------------------------------

func TestCrossRef_URIWithLeadingSpace(t *testing.T) {
	// Attack scenario: URI="# _id1" – a space after the '#'. The library
	// strips the '#' and compares " _id1" with "_id1", which should NOT match.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "# _id1"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with leading space after # must not match")
}

func TestCrossRef_URIWithTrailingSpace(t *testing.T) {
	// Attack scenario: URI="#_id1 " – trailing space. Should not match "_id1".
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1 "
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with trailing space must not match")
}

func TestCrossRef_URIWithTab(t *testing.T) {
	// Attack scenario: URI="#\t_id1" – tab character. Must not match.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#\t_id1"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with tab must not match")
}

func TestCrossRef_URIWithNewline(t *testing.T) {
	// Attack scenario: URI="#_id1\n" – newline in URI.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1\n"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with newline must not match")
}

// ---------------------------------------------------------------------------
// Test: Bare Hash URI
// ---------------------------------------------------------------------------

func TestCrossRef_BareHashURI(t *testing.T) {
	// Attack scenario: URI="#" – just a hash with no ID after it.
	// The code checks len(sig.refURI) > 1, so "#" (length 1) won't enter
	// the ID matching branch. It also isn't empty, so the empty-URI branch
	// doesn't apply either. This must fail.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_bare")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"bare '#' URI must not match any element; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: URI Referencing a Different Element's ID
// ---------------------------------------------------------------------------

func TestCrossRef_URIMismatch(t *testing.T) {
	// Attack scenario: The Reference URI points to a completely different ID
	// than the element being verified. The library must not match.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_real")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_completely_different"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"mismatched URI must not verify; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Non-Default ID Attribute Cross-Reference
// ---------------------------------------------------------------------------

func TestCrossRef_NonDefaultIDAttribute(t *testing.T) {
	// Verify that when a non-default ID attribute is used, the cross-reference
	// matching uses the correct attribute.
	key, cert := randomTestKeyAndCert()

	t.Run("matching_custom_id", func(t *testing.T) {
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("MyID", "_custom1")
		el.CreateElement("Data").SetText("good")

		signer := &Signer{
			Key:         key,
			Certs:       []*x509.Certificate{cert},
			IDAttribute: "MyID",
		}
		rawSigned, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed := reparse(t, rawSigned)

		v := &Verifier{
			TrustedCerts: []*x509.Certificate{cert},
			IDAttribute:  "MyID",
		}
		result, err := v.Verify(signed)
		require.NoError(t, err)
		d := result.Element.FindElement("//Data")
		require.NotNil(t, d)
		assert.Equal(t, "good", d.Text())
	})

	t.Run("wrong_id_attribute_in_verifier", func(t *testing.T) {
		// Signer uses "MyID" but verifier looks for default "ID".
		// The element has no "ID" attribute, so idAttr will be empty.
		// The Reference URI is "#_custom2" which won't match empty string.
		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("MyID", "_custom2")
		el.CreateElement("Data").SetText("good")

		signer := &Signer{
			Key:         key,
			Certs:       []*x509.Certificate{cert},
			IDAttribute: "MyID",
		}
		rawSigned, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed := reparse(t, rawSigned)

		// Verifier uses default ID attribute ("ID"), not "MyID".
		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		_, err = v.Verify(signed)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingSignature),
			"verifier with wrong ID attribute must not find signature; got: %v", err)
	})
}

// ---------------------------------------------------------------------------
// Test: URI with Only Whitespace After Hash
// ---------------------------------------------------------------------------

func TestCrossRef_URIOnlyWhitespace(t *testing.T) {
	// Attack scenario: URI="#   " – hash followed by spaces. Should not match
	// an element whose ID is empty or contains spaces.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_ws")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#   "
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with only whitespace after # must not match")
}

// ---------------------------------------------------------------------------
// Test: URI with NUL byte
// ---------------------------------------------------------------------------

func TestCrossRef_URIWithNullByte(t *testing.T) {
	// Attack scenario: URI="#_id1\x00" – null byte appended. In some
	// languages, C-string comparison would stop at the null byte and match.
	// Go strings include null bytes, so this should not match.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id1")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_id1\x00"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err, "URI with null byte must not match")
}

// ---------------------------------------------------------------------------
// Test: Positive Baseline – Verify Correct URI Works
// ---------------------------------------------------------------------------

func TestCrossRef_ValidURIRoundTrip(t *testing.T) {
	// Baseline test: a properly signed document with matching URI round-trips.
	key, cert := randomTestKeyAndCert()

	ids := []string{
		"_simple",
		"_with-dashes",
		"_with.dots",
		"_MixedCase123",
		"_a", // minimal ID
	}

	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			el := &etree.Element{Tag: "Response"}
			el.CreateAttr("ID", id)
			el.CreateElement("Data").SetText("value-" + id)
			signed := signAndReparse(t, key, cert, el)

			result, err := newVerifier(cert).Verify(signed)
			require.NoError(t, err)
			d := result.Element.FindElement("//Data")
			require.NotNil(t, d)
			assert.Equal(t, "value-"+id, d.Text())
		})
	}
}

// ---------------------------------------------------------------------------
// Test: uriRegexp is Defined but Unused – Verify Behavior
// ---------------------------------------------------------------------------

func TestCrossRef_UnusedURIRegexp(t *testing.T) {
	// The library defines uriRegexp = regexp.MustCompile("^#[a-zA-Z_][\\w.-]*$")
	// but never uses it in the verification path. This test documents that
	// URIs not matching this regex are still processed (for better or worse).
	//
	// Specifically, IDs starting with a digit (invalid per XML spec but the
	// library doesn't enforce the regex) can still be referenced.
	key, cert := randomTestKeyAndCert()

	// ID starting with a digit – invalid per XML Name rules, but the library
	// doesn't validate this.
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "123abc")
	el.CreateElement("Data").SetText("digit-id")
	signed := signAndReparse(t, key, cert, el)

	// The signer will create URI="#123abc" and signing will work.
	// The verifier does literal comparison, so it should also work.
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err, "digit-starting ID should verify (uriRegexp is unused)")
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "digit-id", d.Text())
}

// ---------------------------------------------------------------------------
// Test: Multiple Signatures Referencing Same Element
// ---------------------------------------------------------------------------

func TestCrossRef_MultipleSignaturesRejected(t *testing.T) {
	// Attack scenario: An attacker injects a second Signature element that
	// also references the same element ID. The library should reject documents
	// with multiple signatures referencing the same element.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_multi")

	// Clone the existing signature and append it as another direct child.
	sig := findSig(signed)
	require.NotNil(t, sig)
	clone := sig.Copy()
	signed.AddChild(clone)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"multiple signatures for same element should be rejected; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Signature with Reference URI Not Starting with #
// ---------------------------------------------------------------------------

func TestCrossRef_RelativeURI(t *testing.T) {
	// Attack scenario: URI="doc.xml#_id" – a relative URI with a fragment.
	// The library should not follow relative URIs.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_id")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "doc.xml#_id"
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"relative URI must not match; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: URI Tampering Changes SignedInfo Digest
// ---------------------------------------------------------------------------

func TestCrossRef_URITamperingInvalidatesSignature(t *testing.T) {
	// Security property: Any change to the Reference URI inside SignedInfo
	// must invalidate the cryptographic signature over SignedInfo, because
	// the signature covers the canonical form of SignedInfo.
	//
	// This is the fundamental protection against post-signing URI manipulation.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_orig")
	el.CreateElement("Data").SetText("payload")

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	rawSigned, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Now craft a second element with a different ID.
	el2 := &etree.Element{Tag: "Response"}
	el2.CreateAttr("ID", "_evil")
	el2.CreateElement("Data").SetText("evil-payload")

	// Take the signature from the first document and try to apply it to the
	// second element by changing the URI.
	sig := findSig(rawSigned)
	require.NotNil(t, sig)

	ref := sig.FindElement("./" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	origURI := ref.SelectAttrValue(URIAttr, "")
	assert.Equal(t, "#_orig", origURI)

	// Change URI to point to the evil element.
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_evil"
			break
		}
	}

	// Attach the tampered signature to el2.
	result := el2.Copy()
	result.AddChild(sig)
	reparsed := reparse(t, result)

	_, err = newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrDigestMismatch),
		"signature must be invalid after URI tampering; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: DigestValue Swap Attack with Different URI
// ---------------------------------------------------------------------------

func TestCrossRef_DigestSwapWithDifferentURI(t *testing.T) {
	// Attack scenario: Sign two different documents, then swap the DigestValue
	// from one into the other's SignedInfo. This changes SignedInfo, which
	// should invalidate the cryptographic signature.
	key, cert := randomTestKeyAndCert()

	// Sign document A.
	elA := &etree.Element{Tag: "Response"}
	elA.CreateAttr("ID", "_docA")
	elA.CreateElement("Data").SetText("A-content")
	signedA := signAndReparse(t, key, cert, elA)

	// Sign document B.
	elB := &etree.Element{Tag: "Response"}
	elB.CreateAttr("ID", "_docB")
	elB.CreateElement("Data").SetText("B-content")
	signedB := signAndReparse(t, key, cert, elB)

	// Extract digest from B.
	dvB := signedB.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + DigestValueTag)
	require.NotNil(t, dvB)
	digestB := dvB.Text()

	// Swap B's digest into A's SignedInfo.
	dvA := signedA.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + DigestValueTag)
	require.NotNil(t, dvA)
	dvA.SetText(digestB)

	_, err := newVerifier(cert).Verify(signedA)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"swapping DigestValue must invalidate signature; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: SignatureValue Transplant Between Documents
// ---------------------------------------------------------------------------

func TestCrossRef_SignatureTransplantBetweenDocuments(t *testing.T) {
	// Attack scenario: Take the entire Signature from a legitimately signed
	// document and transplant it to a different document with a different ID.
	// The Reference URI won't match, or the digest will differ.
	key, cert := randomTestKeyAndCert()

	// Sign legitimate document.
	elGood := &etree.Element{Tag: "Response"}
	elGood.CreateAttr("ID", "_good")
	elGood.CreateElement("Data").SetText("legitimate")
	signedGood := signAndReparse(t, key, cert, elGood)

	// Extract the signature.
	sig := findSig(signedGood)
	require.NotNil(t, sig)

	// Create evil document and attach the stolen signature.
	elEvil := &etree.Element{Tag: "Response"}
	elEvil.CreateAttr("ID", "_evil")
	elEvil.CreateElement("Data").SetText("malicious")
	elEvil.AddChild(sig.Copy())

	reparsed := reparse(t, elEvil)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	// The Reference URI is "#_good" but the element has ID="_evil" → no match.
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid),
		"transplanted signature must not verify; got: %v", err)
}

func TestCrossRef_SignatureTransplantSameID(t *testing.T) {
	// Attack scenario: Transplant signature to a different document that
	// happens to have the same ID but different content. The URI matches,
	// but the digest should not.
	key, cert := randomTestKeyAndCert()

	elGood := &etree.Element{Tag: "Response"}
	elGood.CreateAttr("ID", "_shared")
	elGood.CreateElement("Data").SetText("legitimate")
	signedGood := signAndReparse(t, key, cert, elGood)

	sig := findSig(signedGood)
	require.NotNil(t, sig)

	// Evil document with same ID but different content.
	elEvil := &etree.Element{Tag: "Response"}
	elEvil.CreateAttr("ID", "_shared")
	elEvil.CreateElement("Data").SetText("evil-content")
	elEvil.AddChild(sig.Copy())

	reparsed := reparse(t, elEvil)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDigestMismatch),
		"different content with same ID must fail digest check; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Unicode Normalization in URI
// ---------------------------------------------------------------------------

func TestCrossRef_UnicodeNormalization(t *testing.T) {
	// Attack scenario: Using different Unicode representations of the same
	// character. For example, é can be U+00E9 (precomposed) or U+0065 U+0301
	// (decomposed). If the library normalizes Unicode, these would match.
	//
	// Expected behavior: Go strings are byte sequences; no Unicode normalization
	// is performed. Different byte sequences should not match.
	key, cert := randomTestKeyAndCert()

	// Use precomposed é (U+00E9) in the ID.
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_caf\u00e9")
	el.CreateElement("Data").SetText("payload")
	signed := signAndReparse(t, key, cert, el)

	// Tamper: change Reference URI to use decomposed é (e + combining accent).
	ref := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	for i, a := range ref.Attr {
		if a.Key == URIAttr {
			ref.Attr[i].Value = "#_cafe\u0301" // decomposed form
			break
		}
	}

	reparsed := reparse(t, signed)
	_, err := newVerifier(cert).Verify(reparsed)
	require.Error(t, err,
		"different Unicode normalization forms must not match")
}

// ---------------------------------------------------------------------------
// Test: ID Attribute Value Containing '#'
// ---------------------------------------------------------------------------

func TestCrossRef_IDContainingHash(t *testing.T) {
	// Edge case: What if the ID attribute itself contains a '#' character?
	// The signer would create URI="##weird" and the verifier strips the first
	// '#' to compare "#weird" with "#weird" – this should actually work.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "#weird")
	el.CreateElement("Data").SetText("payload")

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	rawSigned, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify the Reference URI is "##weird".
	ref := rawSigned.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	assert.Equal(t, "##weird", ref.SelectAttrValue(URIAttr, ""))

	signed := reparse(t, rawSigned)
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// Test: Verifier Returns Reconstructed (Canonical) Element
// ---------------------------------------------------------------------------

func TestCrossRef_VerifyResultIsCanonicalElement(t *testing.T) {
	// Security property: The VerifyResult.Element should be reconstructed from
	// the canonical bytes that were actually digest-verified, not from the
	// original (possibly tampered) input tree.
	//
	// This ensures that consumers of VerifyResult always get the verified content.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_canon")
	el.CreateElement("Data").SetText("verified-content")
	signed := signAndReparse(t, key, cert, el)

	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)

	// The returned element should not contain the Signature (it was removed
	// by the enveloped-signature transform).
	sigInResult := result.Element.FindElement("./" + SignatureTag)
	assert.Nil(t, sigInResult, "verified element should not contain the Signature")

	// Content must match.
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "verified-content", d.Text())
}

// ---------------------------------------------------------------------------
// Test: Crafted XML with Signature Not in dsig Namespace
// ---------------------------------------------------------------------------

func TestCrossRef_FakeSignatureWrongNamespace(t *testing.T) {
	// Attack scenario: An attacker creates a <Signature> element that is NOT
	// in the XML-DSig namespace but has the same tag name. The verifier must
	// only accept Signature elements in the correct namespace.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_ns")

	// Remove the real signature.
	realSig := findSig(signed)
	require.NotNil(t, realSig)
	signed.RemoveChild(realSig)

	// Add a fake Signature in a different namespace.
	fakeSig := realSig.Copy()
	fakeSig.Space = "evil"
	fakeSig.CreateAttr("xmlns:evil", "http://evil.com/fake-dsig")
	signed.AddChild(fakeSig)

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"fake namespace Signature must not be accepted; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Empty ID Attribute
// ---------------------------------------------------------------------------

func TestCrossRef_EmptyIDAttribute(t *testing.T) {
	// Edge case: Element has ID="" (empty string). The signer will create
	// URI="" (empty). Verify that this works and is treated consistently.
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "") // Explicitly empty ID.
	el.CreateElement("Data").SetText("empty-id")

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	rawSigned, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// The Reference URI should be "" because SelectAttrValue returns "".
	ref := rawSigned.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag)
	require.NotNil(t, ref)
	assert.Equal(t, "", ref.SelectAttrValue(URIAttr, "MISSING"))

	signed := reparse(t, rawSigned)
	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "empty-id", d.Text())
}

// ---------------------------------------------------------------------------
// Test: Long URI / ID Values
// ---------------------------------------------------------------------------

func TestCrossRef_LongID(t *testing.T) {
	// Edge case: Very long ID value. Should work if the library does literal
	// string comparison without length limits.
	key, cert := randomTestKeyAndCert()

	longID := "_" + strings.Repeat("a", 10000)
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", longID)
	el.CreateElement("Data").SetText("long-id")
	signed := signAndReparse(t, key, cert, el)

	result, err := newVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "long-id", d.Text())
}

// ---------------------------------------------------------------------------
// Test: ID with Special XML Characters
// ---------------------------------------------------------------------------

func TestCrossRef_IDWithSpecialXMLChars(t *testing.T) {
	// Edge case: ID containing characters that need XML escaping in attributes.
	// The etree library handles escaping, but we verify the round-trip.
	key, cert := randomTestKeyAndCert()

	// Ampersand and angle brackets are escaped in XML attributes.
	// However, they're unusual in ID values. Let's verify the library
	// handles the escaping/unescaping consistently.
	specialIDs := []struct {
		name string
		id   string
	}{
		{"ampersand", "_id&amp"},
		{"angle_brackets", "_id<>test"},
		{"quotes", `_id"quoted"`},
	}

	for _, tc := range specialIDs {
		t.Run(tc.name, func(t *testing.T) {
			el := &etree.Element{Tag: "Response"}
			el.CreateAttr("ID", tc.id)
			el.CreateElement("Data").SetText("special")

			signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
			rawSigned, err := signer.SignEnveloped(el)
			require.NoError(t, err)

			signed := reparse(t, rawSigned)
			result, err := newVerifier(cert).Verify(signed)
			require.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: SignedInfo Integrity Protects All Reference Fields
// ---------------------------------------------------------------------------

func TestCrossRef_SignedInfoCoversDigestMethod(t *testing.T) {
	// Security property: Changing the DigestMethod inside SignedInfo
	// invalidates the signature because SignedInfo is signed.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_dm")

	dm := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + DigestMethodTag)
	require.NotNil(t, dm)

	// Change digest algorithm to SHA-384.
	for i, a := range dm.Attr {
		if a.Key == AlgorithmAttr {
			dm.Attr[i].Value = "http://www.w3.org/2001/04/xmldsig-more#sha384"
			break
		}
	}

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"changing DigestMethod must invalidate signature; got: %v", err)
}

func TestCrossRef_SignedInfoCoversTransforms(t *testing.T) {
	// Security property: Removing the enveloped-signature transform from
	// SignedInfo invalidates the signature.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_tr")

	transforms := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + TransformsTag)
	require.NotNil(t, transforms)

	// Remove the first Transform (enveloped-signature).
	children := transforms.ChildElements()
	require.GreaterOrEqual(t, len(children), 1)
	transforms.RemoveChild(children[0])

	_, err := newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"removing Transform must invalidate signature; got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Attempt to Forge Signature with Known DigestValue
// ---------------------------------------------------------------------------

func TestCrossRef_ForgedSignatureWithCorrectDigest(t *testing.T) {
	// Attack scenario: An attacker knows the correct digest for an element
	// (digests are not secret) and constructs a Signature element with the
	// correct digest but cannot produce a valid signature without the private
	// key. The cryptographic signature must fail.
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_forge")

	// Extract the correct DigestValue.
	dv := signed.FindElement("./" + SignatureTag + "/" + SignedInfoTag + "/" + ReferenceTag + "/" + DigestValueTag)
	require.NotNil(t, dv)
	correctDigest := dv.Text()
	require.NotEmpty(t, correctDigest)

	// Tamper: corrupt the SignatureValue but leave DigestValue correct.
	sv := signed.FindElement("./" + SignatureTag + "/" + SignatureValueTag)
	require.NotNil(t, sv)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sv.Text()))
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0xFF // flip last byte
	sv.SetText(base64.StdEncoding.EncodeToString(raw))

	_, err = newVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureInvalid),
		"forged SignatureValue must not verify; got: %v", err)
}

// === Namespace Confusion Tests ===

func TestNamespaceConfusion(t *testing.T) {

	// signDocWithPrefix is a helper that signs a simple document using
	// the given namespace prefix for ds: elements.
	signDocWithPrefix := func(t *testing.T, prefix string, c14n Canonicalizer) (*etree.Element, crypto.Signer, *x509.Certificate) {
		t.Helper()
		key, cert := randomTestKeyAndCert()
		signer := &Signer{
			Key:    key,
			Certs:  []*x509.Certificate{cert},
			Prefix: prefix,
		}
		if c14n != nil {
			signer.Canonicalizer = c14n
		}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_test")
		el.CreateElement("Data").SetText("payload")

		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)
		return signed, key, cert
	}

	// ----------------------------------------------------------------
	// 1. Prefix rebinding attack
	// ----------------------------------------------------------------
	t.Run("PrefixRebindingAttack", func(t *testing.T) {
		// Attack scenario: An attacker takes a validly-signed document and
		// adds a namespace declaration on an ancestor element that re-binds
		// the "ds" prefix to a different (evil) URI. If the verifier compares
		// only prefix strings ("ds" == "ds") instead of resolving to URIs,
		// it could be fooled into treating a completely different element
		// tree as a valid Signature.
		//
		// Expected: The verifier must still find the real Signature because
		// the Signature element itself carries xmlns:ds="http://www.w3.org/
		// 2000/09/xmldsig#" which shadows the evil outer declaration. If the
		// outer rebinding is placed such that it DOES shadow the Signature's
		// own declaration (not possible when the Signature carries its own),
		// the verifier must fail with ErrMissingSignature.

		signed, _, cert := signDocWithPrefix(t, "ds", nil)

		// Wrap in an outer element that rebinds "ds" to an evil URI.
		// The real Signature still carries its own xmlns:ds, so the
		// verifier should shadow correctly and still verify.
		envelope := etree.NewElement("Envelope")
		envelope.CreateAttr("xmlns:ds", "http://evil.example.com/fake-dsig")
		envelope.AddChild(signed)
		envelope = reparse(t, envelope)

		// Extract the Response child back out for verification.
		response := envelope.FindElement("//Response")
		require.NotNil(t, response)

		// Detach from envelope so it's the root for Verify.
		doc := etree.NewDocument()
		doc.SetRoot(response.Copy())
		s, err := doc.WriteToString()
		require.NoError(t, err)
		doc2 := etree.NewDocument()
		require.NoError(t, doc2.ReadFromString(s))
		responseRoot := doc2.Root()

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(responseRoot)
		// The Signature carries its own xmlns:ds declaration so it
		// should still verify successfully.
		require.NoError(t, err)
		require.NotNil(t, result)

		// Now test the case where we REMOVE the xmlns:ds from the
		// Signature element itself and rely on an ancestor that binds
		// ds to the WRONG URI. The verifier must NOT find the Signature.
		signed2, _, cert2 := signDocWithPrefix(t, "ds", nil)

		// Manually strip xmlns:ds from the Signature element.
		sig := findSig(signed2)
		require.NotNil(t, sig)
		newAttrs := make([]etree.Attr, 0, len(sig.Attr))
		for _, attr := range sig.Attr {
			if attr.Space == "xmlns" && attr.Key == "ds" {
				continue
			}
			newAttrs = append(newAttrs, attr)
		}
		sig.Attr = newAttrs

		// Add an ancestor-level xmlns:ds binding to a wrong URI.
		signed2.CreateAttr("xmlns:ds", "http://evil.example.com/not-dsig")
		signed2 = reparse(t, signed2)

		v2 := &Verifier{TrustedCerts: []*x509.Certificate{cert2}}
		_, err = v2.Verify(signed2)
		// The verifier resolves ds → http://evil.example.com/not-dsig,
		// which ≠ Namespace, so the Signature is not found.
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingSignature),
			"expected ErrMissingSignature when ds prefix is rebound to evil URI, got: %v", err)
	})

	// ----------------------------------------------------------------
	// 2. Default namespace shadowing
	// ----------------------------------------------------------------
	t.Run("DefaultNamespaceShadowing", func(t *testing.T) {
		// Attack scenario: A non-Signature element declares
		// xmlns="http://www.w3.org/2000/09/xmldsig#" (the default
		// namespace) to make its unprefixed child elements look like
		// dsig elements. The verifier must NOT confuse these with the
		// actual ds:Signature.

		key, cert := randomTestKeyAndCert()
		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_shadow")
		el.CreateElement("Data").SetText("payload")
		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)

		// Insert a decoy that uses the default namespace to masquerade.
		// <FakeContainer xmlns="http://www.w3.org/2000/09/xmldsig#">
		//   <Signature>...</Signature>
		// </FakeContainer>
		// The inner <Signature> has no prefix → Space="" → default ns
		// = dsig namespace. But it is NOT a direct child of Response,
		// so the verifier must not be confused.
		fakeContainer := signed.CreateElement("FakeContainer")
		fakeContainer.CreateAttr("xmlns", Namespace)
		fakeSig := fakeContainer.CreateElement("Signature")
		// Space is empty (default namespace).
		fakeSig.Space = ""
		fakeSig.CreateElement("FakeData").SetText("evil")

		signed = reparse(t, signed)

		// The real ds:Signature is a direct child; the decoy is nested.
		// Verify should still find the real one and succeed.
		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		_, err = v.Verify(signed)
		// The fake Signature is not structurally valid (wrong children),
		// and the real one is intact. Depending on ordering, the verifier
		// may skip the fake or may error on its structure. Either way,
		// the real data must not be corrupted.
		// Actually: the fake is a child of FakeContainer, not of Response,
		// so findSignature (which only looks at direct children) won't see it.
		// But adding FakeContainer changes the digest.
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrDigestMismatch),
			"expected ErrDigestMismatch because we added a new child, got: %v", err)
	})

	// ----------------------------------------------------------------
	// 3. Alternative prefix for Signature
	// ----------------------------------------------------------------
	t.Run("AlternativePrefixSignature", func(t *testing.T) {
		// Verify that the library correctly handles non-standard prefixes.
		// Sign with prefix "mysig" instead of "ds". The verifier must find
		// the Signature by resolving "mysig" → Namespace URI, not by
		// looking for prefix "ds".

		signed, _, cert := signDocWithPrefix(t, "mysig", nil)

		// Sanity: confirm the prefix is actually "mysig" in the output.
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		xmlStr, err := doc.WriteToString()
		require.NoError(t, err)
		assert.Contains(t, xmlStr, "mysig:Signature")
		assert.Contains(t, xmlStr, "xmlns:mysig")

		// Re-parse (WriteToString may have altered parent pointers).
		doc2 := etree.NewDocument()
		require.NoError(t, doc2.ReadFromString(xmlStr))

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(doc2.Root())
		require.NoError(t, err, "verifier should find Signature via namespace URI, not prefix name")
		require.NotNil(t, result)
		d := result.Element.FindElement("//Data")
		require.NotNil(t, d)
		assert.Equal(t, "payload", d.Text())
	})

	// ----------------------------------------------------------------
	// 4. Empty namespace undeclaration inside signed content
	// ----------------------------------------------------------------
	t.Run("EmptyNamespaceUndeclaration", func(t *testing.T) {
		// Ensure that xmlns="" on a child element within the signed
		// content is handled correctly by canonicalization.
		// We build a document with xmlns="" on a child, sign it, and
		// verify. The canonical form must be stable.

		key, cert := randomTestKeyAndCert()
		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_undecl")
		el.CreateAttr("xmlns:app", "urn:example:app")

		child := el.CreateElement("Child")
		child.Space = "app"
		child.SetText("value")

		// Undeclare default namespace on a nested element.
		nested := child.CreateElement("Nested")
		nested.CreateAttr("xmlns", "")
		nested.SetText("inner")

		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(signed)
		require.NoError(t, err, "xmlns='' undeclaration must be handled correctly by C14N")
		require.NotNil(t, result)
	})

	// ----------------------------------------------------------------
	// 5. Namespace URI in attribute values (not declarations)
	// ----------------------------------------------------------------
	t.Run("NamespaceInAttributeValues", func(t *testing.T) {
		// A namespace URI appearing in an attribute *value* (not an xmlns
		// declaration) must NOT be treated as a namespace binding. For
		// example:
		//   <Response Algorithm="http://www.w3.org/2000/09/xmldsig#">
		// This does not bind any prefix to the dsig namespace.

		key, cert := randomTestKeyAndCert()
		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_attrval")
		// Put the dsig namespace URI in a plain attribute value.
		el.CreateAttr("SchemaLocation", Namespace)
		el.CreateElement("Data").SetText("with-ns-in-attr")

		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(signed)
		require.NoError(t, err, "namespace URI in attribute value must not confuse verifier")
		require.NotNil(t, result)

		// Now tamper: add an element that uses the attribute-value URI as
		// if it were a namespace. This should break the digest.
		signed2, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed2 = reparse(t, signed2)
		signed2.CreateElement("Injected").SetText("evil")
		_, err = v.Verify(signed2)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
	})

	// ----------------------------------------------------------------
	// 6. Multiple prefixes for same namespace
	// ----------------------------------------------------------------
	t.Run("MultiplePrefixesSameNamespace", func(t *testing.T) {
		// Two different prefixes pointing to the same namespace URI.
		// Canonicalization must handle this correctly and produce a
		// stable canonical form. We build a document with both
		// xmlns:ns1 and xmlns:ns2 pointing to the same custom URI,
		// sign it, and verify.

		key, cert := randomTestKeyAndCert()
		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_multi")
		el.CreateAttr("xmlns:ns1", "urn:example:shared")
		el.CreateAttr("xmlns:ns2", "urn:example:shared")

		c1 := el.CreateElement("Child1")
		c1.Space = "ns1"
		c1.SetText("hello")

		c2 := el.CreateElement("Child2")
		c2.Space = "ns2"
		c2.SetText("world")

		signed, err := signer.SignEnveloped(el)
		require.NoError(t, err)
		signed = reparse(t, signed)

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(signed)
		require.NoError(t, err, "multiple prefixes for same NS should not break verification")
		require.NotNil(t, result)
	})

	// ----------------------------------------------------------------
	// 7. Fake Signature with wrong namespace
	// ----------------------------------------------------------------
	t.Run("FakeSignatureWrongNamespace", func(t *testing.T) {
		// Attack scenario: An attacker crafts a <fake:Signature> element
		// where "fake" maps to http://evil.com/ns instead of the real
		// dsig namespace. This must NOT be treated as a valid ds:Signature.

		key, cert := randomTestKeyAndCert()

		el := &etree.Element{Tag: "Response"}
		el.CreateAttr("ID", "_ns_fake")
		el.CreateElement("Data").SetText("payload")

		// Build a fake Signature element with a non-dsig namespace.
		fakeSig := el.CreateElement("Signature")
		fakeSig.Space = "fake"
		el.CreateAttr("xmlns:fake", "http://evil.com/ns")

		// Give it a plausible-looking structure.
		si := fakeSig.CreateElement("SignedInfo")
		si.Space = "fake"
		sv := fakeSig.CreateElement("SignatureValue")
		sv.Space = "fake"
		sv.SetText("ZmFrZQ==") // base64("fake")

		// Re-parse so namespace declarations are materialised.
		el = reparse(t, el)

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		_, err := v.Verify(el)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingSignature),
			"fake:Signature (xmlns:fake=http://evil.com/ns) must not be recognised, got: %v", err)

		// Bonus: also add a REAL signature and the fake one. The verifier
		// must use the real one, ignoring the fake.
		el2 := &etree.Element{Tag: "Response"}
		el2.CreateAttr("ID", "_ns_fake2")
		el2.CreateAttr("xmlns:fake", "http://evil.com/ns")
		el2.CreateElement("Data").SetText("payload")

		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
		signed, err := signer.SignEnveloped(el2)
		require.NoError(t, err)
		signed = reparse(t, signed)

		// Add the fake Signature as well (direct child).
		fakeSig2 := signed.CreateElement("Signature")
		fakeSig2.Space = "fake"
		fakeSignedInfo := fakeSig2.CreateElement("SignedInfo")
		fakeSignedInfo.Space = "fake"
		fakeSigVal := fakeSig2.CreateElement("SignatureValue")
		fakeSigVal.Space = "fake"
		fakeSigVal.SetText("ZmFrZQ==")

		signed = reparse(t, signed)

		// The digest will fail because we added the fake element to the tree
		// after signing, but importantly the verifier must not confuse the
		// fake Signature with the real one. The error should be digest
		// mismatch (real sig found, digest broken), NOT missing signature.
		_, err = v.Verify(signed)
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrMissingSignature),
			"verifier should find the REAL signature, not report missing; got: %v", err)
	})

	// ----------------------------------------------------------------
	// 8. Prefix reuse with different namespace on ancestor
	// ----------------------------------------------------------------
	t.Run("PrefixReuseWithDifferentNamespace", func(t *testing.T) {
		// Attack scenario: The element tree has an ancestor element
		// <ds:Foo xmlns:ds="http://other.com"> wrapping a legitimately
		// signed document. The Signature inside still declares
		// xmlns:ds="http://www.w3.org/2000/09/xmldsig#" on itself.
		// The verifier must use the NEAREST ancestor's ns declaration
		// (i.e., the one on the Signature itself), not the outer one.

		signed, _, cert := signDocWithPrefix(t, "ds", nil)

		// Serialize to XML.
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		xmlStr, err := doc.WriteToString()
		require.NoError(t, err)

		// Wrap in an outer element that reuses "ds" for a different namespace.
		wrapped := fmt.Sprintf(
			`<ds:Outer xmlns:ds="http://other.com/ns">%s</ds:Outer>`,
			xmlStr,
		)
		doc2 := etree.NewDocument()
		require.NoError(t, doc2.ReadFromString(wrapped))

		// Extract the inner Response.
		var response *etree.Element
		for _, child := range doc2.Root().ChildElements() {
			if child.Tag == "Response" {
				response = child
				break
			}
		}
		require.NotNil(t, response)

		// Re-root the response (detach from the outer element).
		doc3 := etree.NewDocument()
		doc3.SetRoot(response.Copy())
		reXML, err := doc3.WriteToString()
		require.NoError(t, err)
		doc4 := etree.NewDocument()
		require.NoError(t, doc4.ReadFromString(reXML))

		v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		result, err := v.Verify(doc4.Root())
		require.NoError(t, err, "nearest-ancestor ns declaration must win")
		require.NotNil(t, result)
	})
}

// TestNamespaceConfusion_PrefixRebindOnSignedInfoChildren tests that even
// if someone injects a namespace redeclaration on inner elements of a
// signed Signature (e.g. on SignedInfo), it either invalidates the crypto
// or is ignored.
func TestNamespaceConfusion_PrefixRebindOnSignedInfoChildren(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_rsi")

	// Attempt to add a namespace rebinding on the SignedInfo element.
	sig := findSig(signed)
	require.NotNil(t, sig)
	var signedInfo *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == SignedInfoTag {
			signedInfo = c
			break
		}
	}
	require.NotNil(t, signedInfo)

	// Rebind "ds" on SignedInfo to a different URI.
	signedInfo.CreateAttr("xmlns:ds", "http://evil.example.com/attack")
	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err := v.Verify(signed)
	// The rebinding changes the canonical form of SignedInfo, which
	// should invalidate the cryptographic signature. Alternatively,
	// findSignature may fail to find SignedInfo because it now resolves
	// to the wrong namespace.
	require.Error(t, err, "rebinding ds on SignedInfo must break verification")
	assert.True(t,
		errors.Is(err, ErrSignatureInvalid) ||
			errors.Is(err, ErrMissingSignature) ||
			errors.Is(err, ErrMalformedSignature),
		"expected crypto or structure error, got: %v", err)
}

// TestNamespaceConfusion_UnprefixedSignature tests that a Signature element
// using the default namespace (no prefix) with the correct dsig URI is
// recognised by the verifier, and that one with the wrong default namespace
// is rejected.
//
// Note: The Signer.Prefix field defaults to "ds" when empty, so we cannot
// get a truly unprefixed Signature from the Signer API alone. We test the
// verifier side using hand-crafted XML.
func TestNamespaceConfusion_UnprefixedSignature(t *testing.T) {
	_, cert := randomTestKeyAndCert()

	// Build raw XML with unprefixed Signature having the wrong namespace.
	rawXML := `<Response ID="_unpref_wrong">
  <Data>payload</Data>
  <Signature xmlns="http://evil.example.com/fake">
    <SignedInfo/>
    <SignatureValue>ZmFrZQ==</SignatureValue>
  </Signature>
</Response>`

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(rawXML))

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err := v.Verify(doc.Root())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"unprefixed Signature with wrong default namespace must be rejected, got: %v", err)

	// Now test with correct default namespace but malformed structure.
	rawXML2 := `<Response ID="_unpref_right">
  <Data>payload</Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo/>
    <SignatureValue>ZmFrZQ==</SignatureValue>
  </Signature>
</Response>`

	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(rawXML2))

	_, err = v.Verify(doc2.Root())
	require.Error(t, err)
	// The Signature IS found (correct namespace), but has invalid structure.
	assert.False(t, errors.Is(err, ErrMissingSignature),
		"unprefixed Signature with correct xmlns should be found (not missing), got: %v", err)
}

// TestNamespaceConfusion_MultipleDsigPrefixesOnSameElement tests that having
// two xmlns declarations for the dsig namespace on the same document does
// not confuse the verifier or canonicalization.
func TestNamespaceConfusion_MultipleDsigPrefixesOnSameElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_multi_dsig")
	// Declare the dsig namespace under a second prefix on the root.
	el.CreateAttr("xmlns:dsig2", Namespace)
	el.CreateElement("Data").SetText("multi-dsig")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := v.Verify(signed)
	require.NoError(t, err, "extra dsig prefix alias should not break verification")
	require.NotNil(t, result)
}

// TestNamespaceConfusion_SignatureInWrongDefaultNS ensures that an unprefixed
// <Signature> whose default namespace is NOT the dsig namespace is correctly
// ignored by the verifier.
func TestNamespaceConfusion_SignatureInWrongDefaultNS(t *testing.T) {
	_, cert := randomTestKeyAndCert()

	// Build a document from raw XML with a <Signature> element whose default
	// namespace is wrong.
	rawXML := `<Response ID="_wrong_ns">
  <Data>payload</Data>
  <Signature xmlns="http://wrong.example.com/not-dsig">
    <SignedInfo/>
    <SignatureValue>ZmFrZQ==</SignatureValue>
  </Signature>
</Response>`

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(rawXML))

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err := v.Verify(doc.Root())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"Signature in wrong default namespace must not be recognised, got: %v", err)
}

// TestNamespaceConfusion_AlternativePrefixes_ExcC14N tests that signing with
// different prefixes works correctly with exclusive C14N as well.
func TestNamespaceConfusion_AlternativePrefixes_ExcC14N(t *testing.T) {
	prefixes := []string{"ds", "dsig", "mysig", "xmldsig", ""}

	for _, prefix := range prefixes {
		name := prefix
		if name == "" {
			name = "empty"
		}
		t.Run(fmt.Sprintf("Prefix_%s", name), func(t *testing.T) {
			key, cert := randomTestKeyAndCert()
			signer := &Signer{
				Key:           key,
				Certs:         []*x509.Certificate{cert},
				Prefix:        prefix,
				Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
			}

			el := &etree.Element{Tag: "Response"}
			el.CreateAttr("ID", fmt.Sprintf("_prefix_%s", name))
			el.CreateElement("Data").SetText("test-" + name)

			signed, err := signer.SignEnveloped(el)
			require.NoError(t, err)
			signed = reparse(t, signed)

			v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := v.Verify(signed)
			require.NoError(t, err, "prefix %q with exc-c14n should verify", prefix)
			require.NotNil(t, result)

			d := result.Element.FindElement("//Data")
			require.NotNil(t, d)
			assert.Equal(t, "test-"+name, d.Text())
		})
	}
}

// TestNamespaceConfusion_XmlnsAttributeInjection tests that injecting xmlns
// attributes after signing invalidates the digest, even if the injected
// attribute doesn't change the apparent structure.
func TestNamespaceConfusion_XmlnsAttributeInjection(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_xmlns_inject")

	// Inject a new namespace declaration that wasn't there at signing time.
	signed.CreateAttr("xmlns:evil", "http://evil.example.com/ns")
	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSignatureInvalid),
		"injected xmlns attribute must invalidate signature, got: %v", err)
}

// TestNamespaceConfusion_DeeplyNestedPrefixShadowing tests that prefix
// shadowing at many levels deep is handled correctly.
func TestNamespaceConfusion_DeeplyNestedPrefixShadowing(t *testing.T) {
	// Build a document where prefix "app" is shadowed at multiple levels.
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_deep")
	el.CreateAttr("xmlns:app", "urn:level0")

	level1 := el.CreateElement("Level1")
	level1.CreateAttr("xmlns:app", "urn:level1")
	c1 := level1.CreateElement("Item")
	c1.Space = "app"
	c1.SetText("at-level-1")

	level2 := level1.CreateElement("Level2")
	level2.CreateAttr("xmlns:app", "urn:level2")
	c2 := level2.CreateElement("Item")
	c2.Space = "app"
	c2.SetText("at-level-2")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := v.Verify(signed)
	require.NoError(t, err, "deeply nested prefix shadowing should not break verification")
	require.NotNil(t, result)

	// Tamper: change one of the shadowed namespace URIs.
	signed2, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed2 = reparse(t, signed2)

	// Find Level2 and change its xmlns:app.
	doc := etree.NewDocument()
	doc.SetRoot(signed2)
	xmlStr, err := doc.WriteToString()
	require.NoError(t, err)
	// Tamper by replacing the namespace URI.
	tampered := strings.Replace(xmlStr, "urn:level2", "urn:evil2", 1)
	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(tampered))

	_, err = v.Verify(doc2.Root())
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSignatureInvalid),
		"tampering with nested namespace URI must break verification, got: %v", err)
}

// === Certificate Edge Case Tests ===

func TestCertEdge_NotBeforeInFuture(t *testing.T) {
	now := time.Now()
	// Cert valid from tomorrow to +2 days.
	notBefore := now.Add(24 * time.Hour)
	notAfter := now.Add(48 * time.Hour)
	key, cert := genKeyCert(t, 2048, notBefore, notAfter)

	// Sign within the cert's validity window so the signature is
	// cryptographically valid; the failure should come from time checking.
	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_future")

	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return now }, // now is before NotBefore
	}
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateExpired),
		"expected ErrCertificateExpired, got: %v", err)
}

// ---------------------------------------------------------------------------
// 2. NotAfter in past → ErrCertificateExpired
// ---------------------------------------------------------------------------
func TestCertEdge_NotAfterInPast(t *testing.T) {
	now := time.Now()
	// Cert was valid yesterday only.
	notBefore := now.Add(-48 * time.Hour)
	notAfter := now.Add(-24 * time.Hour)
	key, cert := genKeyCert(t, 2048, notBefore, notAfter)

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_expired")

	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return now }, // now is after NotAfter
	}
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateExpired),
		"expected ErrCertificateExpired, got: %v", err)
}

// ---------------------------------------------------------------------------
// 3. Clock manipulation: custom clock inside validity window
// ---------------------------------------------------------------------------
func TestCertEdge_ClockManipulationAccepts(t *testing.T) {
	// Cert valid in a narrow window: 2030-Jun-01 to 2030-Jun-02.
	windowStart := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := time.Date(2030, 6, 2, 0, 0, 0, 0, time.UTC)
	key, cert := genKeyCert(t, 2048, windowStart, windowEnd)

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_clock")

	// Real wall clock is outside the window. Custom Clock returns time inside.
	midWindow := windowStart.Add(12 * time.Hour)
	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return midWindow },
	}
	res, err := v.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert))
}

// ---------------------------------------------------------------------------
// 4. Same public key, different cert (DER bytes differ)
// ---------------------------------------------------------------------------
func TestCertEdge_SameKeyDifferentCert(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(1 * time.Hour)

	// Generate one RSA key.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create the "real" (trusted) cert.
	realTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	realDER, err := x509.CreateCertificate(rand.Reader, realTpl, realTpl, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	realCert, err := x509.ParseCertificate(realDER)
	require.NoError(t, err)

	// Create an "attacker" cert with the SAME public key but different serial.
	attackerTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	attackerDER, err := x509.CreateCertificate(rand.Reader, attackerTpl, attackerTpl, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	attackerCert, err := x509.ParseCertificate(attackerDER)
	require.NoError(t, err)

	// Certs share the key but are not equal (different DER).
	require.False(t, realCert.Equal(attackerCert), "certs must differ")

	// Sign with the attacker cert in KeyInfo.
	signed := signDocWithCerts(t, rsaKey, []*x509.Certificate{attackerCert}, "_samekey")

	// Trust only the real cert.
	v := &Verifier{TrustedCerts: []*x509.Certificate{realCert}}
	_, err = v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted, got: %v", err)
}

// ---------------------------------------------------------------------------
// 5. Multiple KeyInfo certs — only the first is used
// ---------------------------------------------------------------------------
func TestCertEdge_MultipleKeyInfoCerts(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	_, extraCert := randomTestKeyAndCert()

	// Sign with both certs in KeyInfo. Signer embeds all certs in order.
	signed := signDocWithCerts(t, key, []*x509.Certificate{cert, extraCert}, "_multi")

	// Verify: the library picks the first cert. Trust the signing cert → success.
	v := newVerifier(cert)
	res, err := v.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert))

	// If we trust only the second cert, it should fail because the code only
	// checks the first X509Certificate element.
	v2 := newVerifier(extraCert)
	_, err = v2.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"second cert in KeyInfo should be ignored; got: %v", err)
}

// ---------------------------------------------------------------------------
// 6. KeyInfo cert omitted: single trusted → fallback; multiple → error
// ---------------------------------------------------------------------------
func TestCertEdge_NoKeyInfo_SingleTrustedFallback(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_noki")

	// Remove KeyInfo so the verifier must fall back.
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	v := newVerifier(cert)
	res, err := v.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert))
}

func TestCertEdge_NoKeyInfo_MultipleTrustedFails(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert()

	signed := signDoc(t, key, cert, "_noki2")
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	v := newVerifier(cert, cert2)
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"expected ErrCertificateNotTrusted with multiple trusted certs and no KeyInfo, got: %v", err)
}

// ---------------------------------------------------------------------------
// 7. Small RSA key (1024 bits): library doesn't enforce minimum key sizes
// ---------------------------------------------------------------------------
func TestCertEdge_SmallRSAKey1024(t *testing.T) {
	now := time.Now()
	key, cert := genKeyCert(t, 1024, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_rsa1024")

	// NOTE: The library does NOT enforce minimum key sizes. This documents
	// current behavior. A 1024-bit RSA key is considered insecure, but the
	// library accepts it.
	v := newVerifier(cert)
	res, err := v.Verify(signed)
	require.NoError(t, err, "library currently accepts RSA-1024; if this fails, minimum key size enforcement was added")
	assert.True(t, res.Certificate.Equal(cert))
	assert.Equal(t, 1024, res.Certificate.PublicKey.(*rsa.PublicKey).N.BitLen())
}

// ---------------------------------------------------------------------------
// 8. ECDSA P-256 cert: sign and verify round-trip
// ---------------------------------------------------------------------------
func TestCertEdge_ECDSAP256(t *testing.T) {
	now := time.Now()
	key, cert := genECDSAKeyCert(t, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_ecdsa256")

	v := newVerifier(cert)
	res, err := v.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert))

	// Confirm the key is ECDSA P-256.
	ecPub, ok := res.Certificate.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "expected ECDSA public key")
	assert.Equal(t, elliptic.P256(), ecPub.Curve)
}

// ---------------------------------------------------------------------------
// 9. Cert chain (leaf + intermediate): direct equality fails against root
// ---------------------------------------------------------------------------
func TestCertEdge_CertChainNotBuilt(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(1 * time.Hour)

	// Create a "root" CA.
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	// Create a "leaf" cert signed by the root.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, rootTpl, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// Sign using the leaf key, embed leaf cert (and root) in KeyInfo.
	// The library uses only the FIRST cert from KeyInfo.
	signed := signDocWithCerts(t, leafKey, []*x509.Certificate{leafCert, rootCert}, "_chain")

	// Trust only the root. The library does direct cert.Equal comparison,
	// NOT chain building, so leaf != root → must fail.
	v := newVerifier(rootCert)
	_, err = v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateNotTrusted),
		"library uses cert equality, not chain building; got: %v", err)

	// Trust the leaf directly → should succeed.
	v2 := newVerifier(leafCert)
	res, err := v2.Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(leafCert))
}

// ---------------------------------------------------------------------------
// 10. Empty TrustedCerts → proper error
// ---------------------------------------------------------------------------
func TestCertEdge_EmptyTrustedCerts(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_empty")

	// Nil TrustedCerts
	v := &Verifier{TrustedCerts: nil}
	_, err := v.Verify(signed)
	require.Error(t, err)
	// The code wraps ErrMissingSignature for empty TrustedCerts.
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"expected error for empty TrustedCerts, got: %v", err)

	// Empty slice
	v2 := &Verifier{TrustedCerts: []*x509.Certificate{}}
	_, err = v2.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"expected error for empty TrustedCerts slice, got: %v", err)
}

// ---------------------------------------------------------------------------
// 11. KeyInfo cert matches trusted but both expired → ErrCertificateExpired
// ---------------------------------------------------------------------------
func TestCertEdge_MatchingButExpired(t *testing.T) {
	now := time.Now()
	// Cert expired 1 hour ago.
	notBefore := now.Add(-48 * time.Hour)
	notAfter := now.Add(-1 * time.Hour)
	key, cert := genKeyCert(t, 2048, notBefore, notAfter)

	signed := signDocWithCerts(t, key, []*x509.Certificate{cert}, "_matchexpired")

	// The cert in KeyInfo and the trusted cert are the same (Equal), but expired.
	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return now },
	}
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateExpired),
		"expected ErrCertificateExpired for matched-but-expired cert, got: %v", err)
}

// ---------------------------------------------------------------------------
// Additional edge case: KeyInfo contains garbage base64 cert data
// ---------------------------------------------------------------------------
func TestCertEdge_MalformedKeyInfoCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_malformed")

	// Replace the X509Certificate text with garbage.
	certEl := signed.FindElement("//" + X509CertificateTag)
	require.NotNil(t, certEl)
	certEl.SetText(base64.StdEncoding.EncodeToString([]byte("this-is-not-a-certificate")))

	v := newVerifier(cert)
	_, err := v.Verify(signed)
	require.Error(t, err)
	// Parsing garbage DER should yield a malformed signature error.
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"expected ErrMalformedSignature for garbage cert data, got: %v", err)
}

// ---------------------------------------------------------------------------
// Additional edge case: KeyInfo cert invalid base64
// ---------------------------------------------------------------------------
func TestCertEdge_InvalidBase64KeyInfoCert(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := signDoc(t, key, cert, "_badbase64")

	// Replace the X509Certificate text with invalid base64.
	certEl := signed.FindElement("//" + X509CertificateTag)
	require.NotNil(t, certEl)
	certEl.SetText("!!!not-base64!!!")

	v := newVerifier(cert)
	_, err := v.Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMalformedSignature),
		"expected ErrMalformedSignature for invalid base64 cert, got: %v", err)
}
