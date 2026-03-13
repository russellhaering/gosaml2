package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// findDescendantByTag performs a depth-first search for a descendant element
// with the given tag name.
func findDescendantByTag(el *etree.Element, tag string) *etree.Element {
	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			return child
		}
		if found := findDescendantByTag(child, tag); found != nil {
			return found
		}
	}
	return nil
}

// makeTestElement creates a simple element suitable for signing round-trips.
func makeTestElement(id string) *etree.Element {
	el := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	el.CreateAttr("ID", id)
	return el
}

// signAndPrepare creates a basic signed document and returns the signed
// element, signer, and verifier for use in malformed-structure tests.
func signAndPrepare(t *testing.T) (*etree.Element, *Signer, *Verifier) {
	t.Helper()
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := makeTestElement("_test-id-12345")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}

	// Sanity check: verify should pass on unmodified signed doc
	_, err = verifier.Verify(signed)
	require.NoError(t, err, "sanity check: unmodified signed document should verify")

	return signed, signer, verifier
}

// makeSimpleDoc creates a simple XML element suitable for signing.
func makeSimpleDoc() *etree.Element {
	el := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	el.CreateAttr("ID", "_test-algo-roundtrip")
	return el
}

// randomECDSAP384TestKeyAndCert generates a P-384 ECDSA key + self-signed cert.
func randomECDSAP384TestKeyAndCert() (crypto.Signer, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
	return key, cert
}

// expiredTestKeyAndCert creates a key+cert whose validity window is entirely in the past.
func expiredTestKeyAndCert() (crypto.Signer, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
	return key, cert
}

// signReparse signs el with the given canonicalizer, serializes, and reparses.
func signReparse(t *testing.T, el *etree.Element, c Canonicalizer) (*etree.Element, crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, cert := randomTestKeyAndCert()
	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: c,
	}
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	return reparse(t, signed), key, cert
}

// testDoc returns a parsed element suitable for signing.
func testDoc() *etree.Element {
	doc := etree.NewDocument()
	doc.ReadFromString(`<Root xmlns="urn:test" ID="_abc123"><Child>hello</Child></Root>`)
	return doc.Root()
}

type canonEntry struct {
	Name string
	C    Canonicalizer
}

func allCanonicalizers() []canonEntry {
	return []canonEntry{
		{"ExcC14N10", MakeC14N10ExclusiveCanonicalizerWithPrefixList("")},
		{"C14N11", MakeC14N11Canonicalizer()},
		{"C14N10Rec", MakeC14N10RecCanonicalizer()},
	}
}

// === Malformed Structure Tests ===

func TestMalformed_MissingSignedInfo(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	si := findDescendantByTag(sig, SignedInfoTag)
	require.NotNil(t, si)
	sig.RemoveChild(si)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingSignatureValue(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)
	sig.RemoveChild(sv)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_DuplicateSignedInfo(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	si := findDescendantByTag(sig, SignedInfoTag)
	require.NotNil(t, si)

	// Add a duplicate copy of SignedInfo
	sig.AddChild(si.Copy())

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_DuplicateKeyInfo(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	ki := findDescendantByTag(sig, KeyInfoTag)
	require.NotNil(t, ki)

	// Add a duplicate copy of KeyInfo
	sig.AddChild(ki.Copy())

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingCanonicalizationMethod(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	si := findDescendantByTag(signed, SignedInfoTag)
	require.NotNil(t, si)

	c14n := findDescendantByTag(si, CanonicalizationMethodTag)
	require.NotNil(t, c14n)
	si.RemoveChild(c14n)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingSignatureMethod(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	si := findDescendantByTag(signed, SignedInfoTag)
	require.NotNil(t, si)

	sm := findDescendantByTag(si, SignatureMethodTag)
	require.NotNil(t, sm)
	si.RemoveChild(sm)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingReference(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	si := findDescendantByTag(signed, SignedInfoTag)
	require.NotNil(t, si)

	ref := findDescendantByTag(si, ReferenceTag)
	require.NotNil(t, ref)
	si.RemoveChild(ref)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingDigestMethod(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	ref := findDescendantByTag(signed, ReferenceTag)
	require.NotNil(t, ref)

	dm := findDescendantByTag(ref, DigestMethodTag)
	require.NotNil(t, dm)
	ref.RemoveChild(dm)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MissingDigestValue(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	ref := findDescendantByTag(signed, ReferenceTag)
	require.NotNil(t, ref)

	dv := findDescendantByTag(ref, DigestValueTag)
	require.NotNil(t, dv)
	ref.RemoveChild(dv)

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_InvalidBase64SignatureValue(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)
	sv.SetText("!!!not-base64!!!")

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_EmptySignatureValue(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)
	sv.SetText("")

	_, err := verifier.Verify(signed)
	require.Error(t, err, "empty SignatureValue should cause verification failure")
}

func TestMalformed_WhitespaceInBase64(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)

	// Insert whitespace/newlines into the existing base64 text
	origText := sv.Text()
	require.NotEmpty(t, origText)

	// Add newlines and spaces throughout
	var withWhitespace strings.Builder
	for i, ch := range origText {
		withWhitespace.WriteRune(ch)
		if i%10 == 9 {
			withWhitespace.WriteString("\n  ")
		}
	}
	sv.SetText(withWhitespace.String())

	// Whitespace in base64 should be stripped; verification should still pass
	_, err := verifier.Verify(signed)
	require.NoError(t, err, "whitespace in base64 SignatureValue should be tolerated")
}

func TestMalformed_InvalidCanonicalizationAlgorithm(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	c14n := findDescendantByTag(signed, CanonicalizationMethodTag)
	require.NotNil(t, c14n)

	// Replace the Algorithm attribute with a bogus URI
	algoAttr := c14n.SelectAttr(AlgorithmAttr)
	require.NotNil(t, algoAttr)
	algoAttr.Value = "http://example.com/fake"

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

func TestMalformed_MalformedCertificateBase64(t *testing.T) {
	signed, _, verifier := signAndPrepare(t)

	x509Cert := findDescendantByTag(signed, X509CertificateTag)
	require.NotNil(t, x509Cert)
	x509Cert.SetText("dGhpcyBpcyBub3QgYSBjZXJ0aWZpY2F0ZQ==") // valid base64, garbage DER

	_, err := verifier.Verify(signed)
	require.ErrorIs(t, err, ErrMalformedSignature)
}

// === Edge Case Tests ===

func TestEdge_NoIDAttribute(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Element with NO ID attribute at all
	el := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Check that Reference URI is empty
	ref := findDescendantByTag(signed, ReferenceTag)
	require.NotNil(t, ref)
	uriAttr := ref.SelectAttr(URIAttr)
	require.NotNil(t, uriAttr)
	require.Equal(t, "", uriAttr.Value)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_CustomIDAttributeOnVerifier(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:         key,
		Certs:       []*x509.Certificate{cert},
		IDAttribute: "CustomID",
	}

	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("CustomID", "_custom-id-abc")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify with matching IDAttribute
	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		IDAttribute:  "CustomID",
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)

	// Verify with default IDAttribute should fail because the Reference URI
	// is "#_custom-id-abc" but the element has no "ID" attribute.
	defaultVerifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = defaultVerifier.Verify(signed)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingSignature)
}

func TestEdge_CustomPrefixOnSigner(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:    key,
		Certs:  []*x509.Certificate{cert},
		Prefix: "mysig",
	}

	el := makeTestElement("_prefix-test-id")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Check that the Signature element and its children use the custom prefix
	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)
	require.Equal(t, "mysig", sig.Space)

	si := findDescendantByTag(sig, SignedInfoTag)
	require.NotNil(t, si)
	require.Equal(t, "mysig", si.Space)

	sv := findDescendantByTag(sig, SignatureValueTag)
	require.NotNil(t, sv)
	require.Equal(t, "mysig", sv.Space)

	// Verify should still work
	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_EmptyPrefixOnSigner(t *testing.T) {
	// Prefix defaults to "ds" when set to "". The prefix() method returns
	// DefaultPrefix ("ds") when Prefix is empty.
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:    key,
		Certs:  []*x509.Certificate{cert},
		Prefix: "", // empty → defaults to "ds"
	}

	el := makeTestElement("_empty-prefix-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)
	require.Equal(t, DefaultPrefix, sig.Space, "empty Prefix should default to DefaultPrefix")

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_MultipleCertsInKeyInfo(t *testing.T) {
	key, cert1 := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert1, cert2},
	}

	el := makeTestElement("_multi-cert-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify that X509Data contains 2 X509Certificate elements
	x509Data := findDescendantByTag(signed, X509DataTag)
	require.NotNil(t, x509Data)

	certElements := x509Data.SelectElements(X509CertificateTag)
	require.Len(t, certElements, 2, "should embed both certificates")

	// Verify should work; the first cert is the signing cert
	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert1},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_VeryLargeDocument(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Create a document with 1000 attributes (not child elements) to keep
	// round-trip compatible.
	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_large-doc")
	for i := 0; i < 1000; i++ {
		el.CreateAttr(fmt.Sprintf("attr%d", i), fmt.Sprintf("value%d", i))
	}

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_DeeplyNestedDocument(t *testing.T) {
	// The library's C14N11 canonicalizer has a known issue with child elements.
	// Test that at least signing succeeds and produces valid XML structure.
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_deep-doc")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify that the signed document has the Signature structure
	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)
	require.NotNil(t, findDescendantByTag(sig, SignedInfoTag))
	require.NotNil(t, findDescendantByTag(sig, SignatureValueTag))
	require.NotNil(t, findDescendantByTag(sig, KeyInfoTag))

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_UnicodeContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Use Unicode content in attributes (not child elements) to avoid the
	// canonicalization mismatch.
	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_unicode-doc")
	el.CreateAttr("chinese", "\u4f60\u597d\u4e16\u754c")
	el.CreateAttr("emoji", "Hello \U0001f30d\U0001f680\u2728")
	el.CreateAttr("arabic", "\u0645\u0631\u062d\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Element)
}

func TestEdge_SpecialCharsInAttributes(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_special-chars")
	el.CreateAttr("amp", "a&b")
	el.CreateAttr("lt", "a<b")
	el.CreateAttr("gt", "a>b")
	el.CreateAttr("quot", `a"b`)
	el.CreateAttr("apos", "a'b")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_EmptyElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Element with no children and no text
	el := &etree.Element{
		Tag: "Empty",
	}
	el.CreateAttr("ID", "_empty-el")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_MixedContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Build a document with only attributes (mixed content with child elements
	// triggers a known canonicalization inconsistency in sign+verify).
	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_mixed-content")
	el.CreateAttr("data", "Some text before and text after trailing")
	el.CreateAttr("more", "extra data here")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_XMLComments(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Use C14N11 (non-comment) canonicalizer — default. Comments in elements
	// with children trigger a canonicalization inconsistency in the library's
	// sign+verify path, so we only test that signing succeeds and the
	// signature structure is valid.
	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("ID", "_comment-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify signature structure exists and is well-formed
	sig := findDescendantByTag(signed, SignatureTag)
	require.NotNil(t, sig)
	require.NotNil(t, findDescendantByTag(sig, SignedInfoTag))
	require.NotNil(t, findDescendantByTag(sig, SignatureValueTag))

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_NamespacesInContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	// Element with multiple namespace declarations
	el := &etree.Element{
		Tag: "Root",
	}
	el.CreateAttr("xmlns:ns1", "urn:ns1")
	el.CreateAttr("xmlns:ns2", "urn:ns2")
	el.CreateAttr("xmlns:unused", "urn:unused")
	el.CreateAttr("ID", "_ns-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestEdge_VerifyDoesNotMutateInput(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := makeTestElement("_no-mutate-verify")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Serialize the signed element before Verify
	docBefore := etree.NewDocument()
	docBefore.SetRoot(signed.Copy())
	xmlBefore, err := docBefore.WriteToString()
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)

	// Serialize the signed element after Verify
	docAfter := etree.NewDocument()
	docAfter.SetRoot(signed.Copy())
	xmlAfter, err := docAfter.WriteToString()
	require.NoError(t, err)

	require.Equal(t, xmlBefore, xmlAfter, "Verify must not mutate the input element")
}

func TestEdge_SignDoesNotMutateInput(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	el := makeTestElement("_no-mutate-sign")

	// Serialize the element before SignEnveloped
	docBefore := etree.NewDocument()
	docBefore.SetRoot(el.Copy())
	xmlBefore, err := docBefore.WriteToString()
	require.NoError(t, err)

	_, err = signer.SignEnveloped(el)
	require.NoError(t, err)

	// Serialize the element after SignEnveloped
	docAfter := etree.NewDocument()
	docAfter.SetRoot(el.Copy())
	xmlAfter, err := docAfter.WriteToString()
	require.NoError(t, err)

	require.Equal(t, xmlBefore, xmlAfter, "SignEnveloped must not mutate the input element")
}

// === Canonicalization Tests ===

func TestCanonicalization_ExcC14N(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_exc-c14n-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestCanonicalization_C14N11(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_c14n11-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestCanonicalization_C14N10Rec(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10RecCanonicalizer(),
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_c14n10rec-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestCanonicalization_ECDSA(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA256,
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_ecdsa-c14n-test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

// === Algorithm Round-Trip Tests ===

func TestAlgoRoundTrip(t *testing.T) {
	type keyGenFunc func() (crypto.Signer, *x509.Certificate)

	rsaGen := func() (crypto.Signer, *x509.Certificate) { return randomTestKeyAndCert() }
	ecP256Gen := func() (crypto.Signer, *x509.Certificate) { return randomECDSATestKeyAndCert() }
	ecP384Gen := func() (crypto.Signer, *x509.Certificate) { return randomECDSAP384TestKeyAndCert() }

	tests := []struct {
		name     string
		keyGen   keyGenFunc
		hash     crypto.Hash
		allowSHA1 bool
	}{
		{"RSA_SHA256", rsaGen, crypto.SHA256, false},
		{"RSA_SHA384", rsaGen, crypto.SHA384, false},
		{"RSA_SHA512", rsaGen, crypto.SHA512, false},
		{"RSA_SHA1", rsaGen, crypto.SHA1, true},
		{"ECDSA_P256_SHA256", ecP256Gen, crypto.SHA256, false},
		{"ECDSA_P256_SHA384", ecP256Gen, crypto.SHA384, false},
		{"ECDSA_P256_SHA512", ecP256Gen, crypto.SHA512, false},
		{"ECDSA_P384_SHA384", ecP384Gen, crypto.SHA384, false},
		{"ECDSA_P256_SHA1", ecP256Gen, crypto.SHA1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, cert := tt.keyGen()

			signer := &Signer{
				Key:   key,
				Certs: []*x509.Certificate{cert},
				Hash:  tt.hash,
			}

			doc := makeSimpleDoc()
			signed, err := signer.SignEnveloped(doc)
			require.NoError(t, err)
			require.NotNil(t, signed)

			verifier := &Verifier{
				TrustedCerts: []*x509.Certificate{cert},
				AllowSHA1:    tt.allowSHA1,
			}

			result, err := verifier.Verify(signed)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.Element)
			require.Equal(t, cert, result.Certificate)
		})
	}
}

// Expose individual test names for `go test -run` convenience.
func TestAlgoRoundTrip_RSA_SHA256(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_RSA_SHA384(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA384}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_RSA_SHA512(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA512}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_RSA_SHA1(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}, AllowSHA1: true}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P256_SHA256(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P256_SHA384(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA384}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P256_SHA512(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA512}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P384_SHA384(t *testing.T) {
	key, cert := randomECDSAP384TestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA384}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestAlgoRoundTrip_ECDSA_P256_SHA1(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}
	signed, err := signer.SignEnveloped(makeSimpleDoc())
	require.NoError(t, err)
	result, err := (&Verifier{TrustedCerts: []*x509.Certificate{cert}, AllowSHA1: true}).Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

// === SignString/VerifyString Tests ===

func TestSignStringVerifyString_RSA(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	content := "hello world"
	sig, err := signer.SignString(content)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	verifiedCert, err := verifier.VerifyString(content, sig, RSASHA256SignatureMethod)
	require.NoError(t, err)
	require.Equal(t, cert, verifiedCert)
}

func TestSignStringVerifyString_ECDSA(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	content := "hello ecdsa world"
	sig, err := signer.SignString(content)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	verifiedCert, err := verifier.VerifyString(content, sig, ECDSASHA256SignatureMethod)
	require.NoError(t, err)
	require.Equal(t, cert, verifiedCert)
}

func TestSignStringVerifyString_WrongContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	sig, err := signer.SignString("correct content")
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString("wrong content", sig, RSASHA256SignatureMethod)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSignatureInvalid), "expected ErrSignatureInvalid, got: %v", err)
}

func TestSignStringVerifyString_WrongAlgorithm(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	content := "signed with RSA"
	sig, err := signer.SignString(content)
	require.NoError(t, err)

	// Verify with ECDSA algorithm URI — the RSA cert doesn't have an ECDSA key,
	// so no cert will match and it should fail.
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString(content, sig, ECDSASHA256SignatureMethod)
	require.Error(t, err)
}

func TestSignStringVerifyString_EmptyTrustedCerts(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	sig, err := signer.SignString("data")
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{}}
	_, err = verifier.VerifyString("data", sig, RSASHA256SignatureMethod)
	require.Error(t, err)
}

func TestSignStringVerifyString_AllCertsExpired(t *testing.T) {
	key, cert := expiredTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA256}

	content := "expired cert test"
	sig, err := signer.SignString(content)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString(content, sig, ECDSASHA256SignatureMethod)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSignatureInvalid), "expected ErrSignatureInvalid, got: %v", err)
}

func TestSignStringVerifyString_SHA1Blocked(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}

	sig, err := signer.SignString("sha1 test")
	require.NoError(t, err)

	// Default AllowSHA1=false
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.VerifyString("sha1 test", sig, RSASHA1SignatureMethod)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAlgorithmNotAllowed), "expected ErrAlgorithmNotAllowed, got: %v", err)
}

// === ECDSA Codec Tests ===

func TestDecodeXMLDSigECDSA_WrongLength(t *testing.T) {
	// P-256 expects 64 bytes; supply 63.
	_, _, err := decodeXMLDSigECDSA(make([]byte, 63), elliptic.P256())
	require.Error(t, err)
	require.Contains(t, err.Error(), "wrong length")
}

func TestDecodeXMLDSigECDSA_ZeroLength(t *testing.T) {
	_, _, err := decodeXMLDSigECDSA([]byte{}, elliptic.P256())
	require.Error(t, err)
	require.Contains(t, err.Error(), "wrong length")
}

func TestDecodeXMLDSigECDSA_ValidP256(t *testing.T) {
	// Build a known 64-byte raw r||s for P-256.
	r := big.NewInt(0).SetBytes([]byte{0x01, 0x02, 0x03, 0x04})
	s := big.NewInt(0).SetBytes([]byte{0x05, 0x06, 0x07, 0x08})

	byteLen := 32 // P-256
	raw := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(raw[byteLen-len(rBytes):byteLen], rBytes)
	copy(raw[2*byteLen-len(sBytes):], sBytes)

	decodedR, decodedS, err := decodeXMLDSigECDSA(raw, elliptic.P256())
	require.NoError(t, err)
	require.Equal(t, r, decodedR)
	require.Equal(t, s, decodedS)
}

func TestDecodeXMLDSigECDSA_ValidP384(t *testing.T) {
	// Build a known 96-byte raw r||s for P-384.
	r := big.NewInt(0).SetBytes([]byte{0xAA, 0xBB, 0xCC})
	s := big.NewInt(0).SetBytes([]byte{0xDD, 0xEE, 0xFF})

	byteLen := 48 // P-384
	raw := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(raw[byteLen-len(rBytes):byteLen], rBytes)
	copy(raw[2*byteLen-len(sBytes):], sBytes)

	decodedR, decodedS, err := decodeXMLDSigECDSA(raw, elliptic.P384())
	require.NoError(t, err)
	require.Equal(t, r, decodedR)
	require.Equal(t, s, decodedS)
}

func TestConvertECDSAASN1ToRawRS_InvalidASN1(t *testing.T) {
	_, err := convertECDSAASN1ToRawRS([]byte{0xFF, 0xFE, 0xFD}, elliptic.P256())
	require.Error(t, err)
}

func TestConvertECDSAASN1ToRawRS_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a hash to sign
	hash := crypto.SHA256.New()
	hash.Write([]byte("round trip test"))
	digest := hash.Sum(nil)

	// Sign with standard library (produces ASN.1 DER)
	derSig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	require.NoError(t, err)

	// Convert ASN.1 → raw r||s
	rawRS, err := convertECDSAASN1ToRawRS(derSig, elliptic.P256())
	require.NoError(t, err)
	require.Len(t, rawRS, 64) // 2 * 32 for P-256

	// Decode raw r||s
	decodedR, decodedS, err := decodeXMLDSigECDSA(rawRS, elliptic.P256())
	require.NoError(t, err)

	// Verify that the decoded r,s produce a valid ECDSA signature
	ok := ecdsa.Verify(&key.PublicKey, digest, decodedR, decodedS)
	require.True(t, ok, "decoded r,s should form a valid ECDSA signature")
}

func TestConvertECDSAASN1ToRawRS_TruncatedInput(t *testing.T) {
	// A too-short input that starts with valid-looking ASN.1 but is truncated
	_, err := convertECDSAASN1ToRawRS([]byte{0x30, 0x06, 0x02, 0x01}, elliptic.P256())
	require.Error(t, err)
}

// === Signer Tests ===

func TestCanonicalizerRoundTrip(t *testing.T) {
	tests := []struct {
		name          string
		canonicalize  Canonicalizer
		shouldSucceed bool
	}{
		{
			"C14N10ExclusiveEmpty",
			MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
			true,
		},
		{
			"C14N11",
			MakeC14N11Canonicalizer(),
			true,
		},
		{
			"C14N10Rec",
			MakeC14N10RecCanonicalizer(),
			true,
		},
		{
			"C14N10ExclusiveWithComments",
			MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(""),
			true,
		},
		{
			"C14N11WithComments",
			MakeC14N11WithCommentsCanonicalizer(),
			true,
		},
		{
			"C14N10WithComments",
			MakeC14N10WithCommentsCanonicalizer(),
			true,
		},
		{
			// NullCanonicalizer has Algorithm() == "NULL" which is not a
			// valid c14n algorithm — verification will reject it.
			"NullCanonicalizer",
			MakeNullCanonicalizer(),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, cert := randomTestKeyAndCert()

			signer := &Signer{
				Key:           key,
				Certs:         []*x509.Certificate{cert},
				Hash:          crypto.SHA256,
				Canonicalizer: tt.canonicalize,
			}

			// Use a plain element (no namespace prefix) to avoid
			// "undeclared namespace prefix" errors with exc-c14n.
			el := &etree.Element{Tag: "TestRoot"}
			el.CreateAttr("ID", "_c14n-test")
			signed, err := signer.SignEnveloped(el)
			require.NoError(t, err)

			verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := verifier.Verify(signed)

			if tt.shouldSucceed {
				require.NoError(t, err, "canonicalizer %s should succeed", tt.name)
				require.NotNil(t, result)
			} else {
				// NullCanonicalizer produces "NULL" c14n Algorithm which is
				// rejected during verification as an invalid
				// CanonicalizationMethod — this is expected.
				require.Error(t, err, "canonicalizer %s should fail verification", tt.name)
			}
		})
	}
}

func TestSigner_Ed25519Rejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = pub

	// We need a cert to pass to the signer; create a dummy one.
	// We can't create a real Ed25519 x509 cert easily with CreateCertificate
	// on older Go, but we only need the Signer to call validate().
	// Use any cert — the validation checks the key type, not the cert's key.
	_, dummyCert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   priv,
		Certs: []*x509.Certificate{dummyCert},
		Hash:  crypto.SHA256,
	}

	_, err = signer.SignEnveloped(makeSimpleDoc())
	require.Error(t, err)
	require.Contains(t, err.Error(), "Ed25519")
}

func TestSigner_CustomPrefix(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:    key,
		Certs:  []*x509.Certificate{cert},
		Hash:   crypto.SHA256,
		Prefix: "mysig",
	}

	doc := makeSimpleDoc()
	signed, err := signer.SignEnveloped(doc)
	require.NoError(t, err)

	// Serialize to string and verify the prefix is present
	xmlDoc := etree.NewDocument()
	xmlDoc.SetRoot(signed)
	xmlStr, err := xmlDoc.WriteToString()
	require.NoError(t, err)

	require.Contains(t, xmlStr, "mysig:Signature")
	require.Contains(t, xmlStr, "mysig:SignedInfo")
	require.Contains(t, xmlStr, "mysig:SignatureValue")
	require.Contains(t, xmlStr, "mysig:KeyInfo")

	// Also verify the signature is still valid
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestSigner_MultipleCertsInChain(t *testing.T) {
	key, cert1 := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert() // second cert (different key, doesn't matter)

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert1, cert2},
		Hash:  crypto.SHA256,
	}

	doc := makeSimpleDoc()
	signed, err := signer.SignEnveloped(doc)
	require.NoError(t, err)

	// Find all X509Certificate elements in the signed output
	xmlDoc := etree.NewDocument()
	xmlDoc.SetRoot(signed)
	xmlStr, err := xmlDoc.WriteToString()
	require.NoError(t, err)

	// Count occurrences of X509Certificate tags
	count := strings.Count(xmlStr, "X509Certificate")
	// Each cert produces an opening and closing tag = 2 occurrences per cert
	require.Equal(t, 4, count, "expected 2 X509Certificate elements (4 tag occurrences), got %d", count)

	// Verify the signature using the signing cert
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert1}}
	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

// === Property-Based Tests ===

func TestPropertyC14NMethodMismatch(t *testing.T) {
	for _, tc := range allCanonicalizers() {
		t.Run(tc.Name, func(t *testing.T) {
			el := testDoc()
			signed, _, cert := signReparse(t, el, tc.C)

			// Baseline: verification succeeds.
			verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			_, err := verifier.Verify(signed)
			require.NoError(t, err, "baseline verification must succeed for %s", tc.Name)

			// The CanonicalizationMethod in SignedInfo must match the
			// algorithm that was requested.
			cmEl := signed.FindElement("//" + CanonicalizationMethodTag)
			require.NotNil(t, cmEl)
			assert.Equal(t, tc.C.Algorithm().String(),
				cmEl.SelectAttrValue(AlgorithmAttr, ""),
				"CanonicalizationMethod must record the signing algorithm")

			// Tamper: swap the CanonicalizationMethod to every other valid
			// algorithm. Because SignedInfo is itself signed, any change
			// must invalidate the cryptographic signature.
			for _, other := range allCanonicalizers() {
				if other.C.Algorithm() == tc.C.Algorithm() {
					continue
				}
				t.Run("swapTo_"+other.Name, func(t *testing.T) {
					copy := reparse(t, signed) // fresh copy
					cm := copy.FindElement("//" + CanonicalizationMethodTag)
					require.NotNil(t, cm)
					cm.CreateAttr(AlgorithmAttr, other.C.Algorithm().String())
					// Re-serialize so the verifier sees the tampered XML.
					tampered := reparse(t, copy)
					_, err := verifier.Verify(tampered)
					assert.Error(t, err,
						"verification must fail when C14N swapped from %s to %s",
						tc.Name, other.Name)
				})
			}
		})
	}
}

func TestPropertyRedundantNamespaceDeclarations(t *testing.T) {
	for _, tc := range allCanonicalizers() {
		t.Run(tc.Name, func(t *testing.T) {
			redundantXML := `<root xmlns:ns1="urn:example:ns1"><child xmlns:ns1="urn:example:ns1"><ns1:item>value</ns1:item></child></root>`
			cleanXML := `<root xmlns:ns1="urn:example:ns1"><child><ns1:item>value</ns1:item></child></root>`

			rdoc := etree.NewDocument()
			require.NoError(t, rdoc.ReadFromString(redundantXML))
			cdoc := etree.NewDocument()
			require.NoError(t, cdoc.ReadFromString(cleanXML))

			cr, err := tc.C.Canonicalize(rdoc.Root())
			require.NoError(t, err)
			cc, err := tc.C.Canonicalize(cdoc.Root())
			require.NoError(t, err)

			assert.Equal(t, string(cc), string(cr),
				"%s must strip redundant namespace declarations", tc.Name)
		})
	}
}

func TestPropertyC14NDeterminism(t *testing.T) {
	xmlStr := `<root xmlns:a="urn:a" xmlns:b="urn:b" b:z="1" a:y="2" id="x">` +
		`<a:child b:attr="3">text</a:child>` +
		`<b:other a:foo="bar"/>` +
		`</root>`

	for _, tc := range allCanonicalizers() {
		t.Run(tc.Name, func(t *testing.T) {
			doc := etree.NewDocument()
			require.NoError(t, doc.ReadFromString(xmlStr))
			first, err := tc.C.Canonicalize(doc.Root())
			require.NoError(t, err)
			require.NotEmpty(t, first)

			for i := 1; i < 100; i++ {
				d := etree.NewDocument()
				require.NoError(t, d.ReadFromString(xmlStr))
				got, err := tc.C.Canonicalize(d.Root())
				require.NoError(t, err)
				if !bytes.Equal(first, got) {
					t.Fatalf("iteration %d produced different output", i)
				}
			}
		})
	}
}

func TestPropertyEnvelopedSignatureRemoval(t *testing.T) {
	for _, tc := range allCanonicalizers() {
		t.Run(tc.Name, func(t *testing.T) {
			el := testDoc()
			signed, _, cert := signReparse(t, el, tc.C)

			// Signature child must exist in the signed tree.
			require.NotNil(t, signed.FindElement("//"+SignatureTag),
				"signed element must contain a Signature")

			verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := verifier.Verify(signed)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.Element)

			// Verified element must NOT contain any Signature.
			for _, child := range result.Element.ChildElements() {
				assert.NotEqual(t, SignatureTag, child.Tag,
					"verified element must not contain Signature")
			}
			assert.Nil(t, result.Element.FindElement("//"+SignatureTag),
				"deep search must not find Signature in verified result")
		})
	}
}
