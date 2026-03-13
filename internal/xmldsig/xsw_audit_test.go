package xmldsig

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// XSW Audit Test Suite
//
// These tests probe the xmldsig implementation for XML Signature Wrapping (XSW)
// vulnerabilities. Each test creates a legitimately signed document, then
// modifies it to attempt an attack, and checks whether Verify correctly
// rejects or accepts the result.
//
// References:
//   - CVE-2024-45409 (ruby-saml XSW)
//   - CVE-2020-29509 (Go encoding/xml round-trip)
//   - CVE-2022-41912 (crewjam/saml multiple assertions)
//   - CVE-2020-15216 (gosaml2/goxmldsig signature bypass)
// ============================================================================

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func xswReparse(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	s, err := doc.WriteToString()
	require.NoError(t, err)
	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(s))
	return doc2.Root()
}

func xswSignAndReparse(t *testing.T, key crypto.Signer, cert *x509.Certificate, el *etree.Element) *etree.Element {
	t.Helper()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	return xswReparse(t, signed)
}

func xswSignDoc(t *testing.T, key crypto.Signer, cert *x509.Certificate, id string) *etree.Element {
	t.Helper()
	el := &etree.Element{Tag: "Response"}
	if id != "" {
		el.CreateAttr("ID", id)
	}
	el.CreateElement("Data").SetText("good")
	return xswSignAndReparse(t, key, cert, el)
}

func xswFindSig(el *etree.Element) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == signatureTag {
			return c
		}
	}
	return nil
}

func xswVerifier(certs ...*x509.Certificate) *Verifier {
	return &Verifier{TrustedCerts: certs}
}

// buildSAMLResponse builds a minimal SAML-like Response with an Assertion.
func buildSAMLResponse(responseID, assertionID, nameID string) *etree.Element {
	resp := etree.NewElement("Response")
	resp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	resp.CreateAttr("ID", responseID)

	assertion := resp.CreateElement("Assertion")
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("ID", assertionID)

	subject := assertion.CreateElement("Subject")
	nameIDEl := subject.CreateElement("NameID")
	nameIDEl.SetText(nameID)

	conditions := assertion.CreateElement("Conditions")
	conditions.CreateAttr("NotBefore", "2020-01-01T00:00:00Z")
	conditions.CreateAttr("NotOnOrAfter", "2099-01-01T00:00:00Z")

	return resp
}

// ============================================================================
// ATTACK 1: Empty Reference URI + Element Identity Confusion
//
// When refURI=="", the spec says it references the entire document. The code
// accepts this and digests the parent element. This test checks:
// (a) That an empty-URI signature on a no-ID element verifies.
// (b) That modifying the element after signing breaks the digest.
// (c) CRITICAL: Can an attacker wrap the signed element inside a new outer
//     element, causing the SP to process the outer element while the sig
//     covers only the inner one?
// ============================================================================

func TestXSW_Audit_EmptyURI_BasicVerify(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "")

	// Should verify cleanly.
	result, err := xswVerifier(cert).Verify(signed)
	require.NoError(t, err)
	assert.NotNil(t, result.Element)

	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text())
}

func TestXSW_Audit_EmptyURI_TamperDetected(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "")

	// Tamper: modify text content.
	signed.FindElement("//Data").SetText("evil")

	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDigestMismatch), "expected digest mismatch, got: %v", err)
}

func TestXSW_Audit_EmptyURI_WrapInOuterElement(t *testing.T) {
	// Attack: Sign a <Response> with no ID (empty URI), then wrap it
	// inside a new <Envelope>. An SP that calls Verify on the outer
	// Envelope should NOT find the signature valid for the Envelope.
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "")

	envelope := etree.NewElement("Envelope")
	envelope.AddChild(signed)
	envelope = xswReparse(t, envelope)

	// The signature is on the inner Response (a grandchild of Envelope),
	// NOT a direct child of Envelope. Verify(envelope) should fail.
	_, err := xswVerifier(cert).Verify(envelope)
	require.Error(t, err, "wrapping signed element in outer envelope must not verify the envelope")
	assert.True(t, errors.Is(err, ErrMissingSignature), "got: %v", err)
}

// ============================================================================
// ATTACK 2: XSW1 — Sibling Assertion Injection
//
// Classic XSW1: The attacker adds an unsigned evil <Assertion> before the
// signed one inside a <Response>. The signature on the Response is valid
// but the SP reads the first (evil) assertion.
//
// Here, Verify is called on the signed element directly. This tests
// whether the library returns the *verified* content or the *original tree*.
// ============================================================================

func TestXSW_Audit_XSW1_EvilAssertionSibling(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Build and sign a SAML-like Response.
	resp := buildSAMLResponse("_resp1", "_assert1", "alice@good.com")
	signed := xswSignAndReparse(t, key, cert, resp)

	// Attack: inject an evil assertion as the first child.
	evilAssertion := etree.NewElement("Assertion")
	evilAssertion.CreateAttr("ID", "_evil_assert")
	evilSubject := evilAssertion.CreateElement("Subject")
	evilSubject.CreateElement("NameID").SetText("admin@evil.com")

	// Insert evil assertion at position 0 (before the real one).
	signed.InsertChildAt(0, evilAssertion)
	signed = xswReparse(t, signed)

	// Verify should fail because the document content changed.
	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err, "XSW1: injecting evil assertion sibling must be detected")
	assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

// ============================================================================
// ATTACK 3: XSW3 — Move Signed Assertion Into Extensions
//
// The attacker moves the signed assertion into an <Extensions> element and
// puts an evil assertion in the original position. The signature still
// references the original assertion by ID, but the SP reads the evil one.
//
// In this library, verification is element-centric (you pass the element to
// verify). This tests that the returned element has verified content.
// ============================================================================

func TestXSW_Audit_XSW3_MoveSignedIntoExtensions(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	resp := buildSAMLResponse("_resp3", "_assert3", "alice@good.com")
	signed := xswSignAndReparse(t, key, cert, resp)

	// The signature is an enveloped sig on Response. The digest covers
	// the Response (minus the Signature). If we move children around,
	// the digest should fail.

	// Move the real Assertion into Extensions.
	var assertion *etree.Element
	for _, c := range signed.ChildElements() {
		if c.Tag == "Assertion" {
			assertion = c
			break
		}
	}
	require.NotNil(t, assertion)

	signed.RemoveChild(assertion)
	ext := signed.CreateElement("Extensions")
	ext.AddChild(assertion)

	// Put evil assertion in original position.
	evilAssertion := etree.NewElement("Assertion")
	evilAssertion.CreateAttr("ID", "_evil_assert3")
	evilAssertion.CreateElement("Subject").CreateElement("NameID").SetText("admin@evil.com")
	signed.InsertChildAt(0, evilAssertion)

	signed = xswReparse(t, signed)

	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err, "XSW3: moving assertion into Extensions must be detected")
	assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

// ============================================================================
// ATTACK 4: Signature Position — Direct Child Requirement
//
// findSignature only searches *direct children* of the element. This tests
// that a valid signature placed deeper in the tree is not found.
// ============================================================================

func TestXSW_Audit_SignatureAsGrandchild(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "_sig_pos")

	sig := xswFindSig(signed)
	require.NotNil(t, sig)

	// Move signature into a wrapper element (making it a grandchild).
	signed.RemoveChild(sig)
	wrapper := signed.CreateElement("SignatureWrapper")
	wrapper.AddChild(sig)

	signed = xswReparse(t, signed)

	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSignature),
		"signature as grandchild must not be found; got: %v", err)
}

func TestXSW_Audit_SignatureMovedToSibling(t *testing.T) {
	// Attack: Take the signature from one element and place it as a child
	// of a sibling element. The sibling has different content.
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "_sig_sib")

	sig := xswFindSig(signed)
	require.NotNil(t, sig)

	// Create evil element with the same ID and move the sig there.
	evil := etree.NewElement("Response")
	evil.CreateAttr("ID", "_sig_sib")
	evil.CreateElement("Data").SetText("evil")
	signed.RemoveChild(sig)
	evil.AddChild(sig)

	evil = xswReparse(t, evil)

	// Verify evil element — it has the sig as child but content is different.
	_, err := xswVerifier(cert).Verify(evil)
	require.Error(t, err, "signature stolen from another element must not verify")
	// The digest was computed over the original element, so this must fail.
	assert.True(t,
		errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSignatureInvalid),
		"got: %v", err)
}

// ============================================================================
// ATTACK 5: Multiple Signatures — Same Element
//
// The code rejects multiple signatures referencing the same element.
// ============================================================================

func TestXSW_Audit_DuplicateSignatureRejected(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "_dup_sig")

	sig := xswFindSig(signed)
	require.NotNil(t, sig)

	// Duplicate the signature.
	signed.AddChild(sig.Copy())
	signed = xswReparse(t, signed)

	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err, "duplicate signatures must be rejected")
	assert.True(t, errors.Is(err, ErrMalformedSignature), "got: %v", err)
}

// ============================================================================
// ATTACK 6: Multiple Signatures — Different References
//
// What if there are two Signature elements: one referencing the element by ID,
// and one with an empty URI? The code should reject this.
// ============================================================================

func TestXSW_Audit_TwoSignaturesDifferentRefs(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Sign an element with an ID (produces URI="#_id").
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_two_ref")
	el.CreateElement("Data").SetText("good")
	signed := xswSignAndReparse(t, key, cert, el)

	// Now also sign the same element without an ID (produces URI="").
	// We'll manually construct a second signature with empty URI.
	// Clone the existing sig and tamper the Reference URI to empty.
	sig := xswFindSig(signed)
	require.NotNil(t, sig)
	sig2 := sig.Copy()

	// Change the URI in the cloned sig to empty.
	ref := sig2.FindElement(".//" + referenceTag)
	if ref != nil {
		for i, a := range ref.Attr {
			if a.Key == uriAttr {
				ref.Attr[i].Value = ""
				break
			}
		}
	}
	signed.AddChild(sig2)
	signed = xswReparse(t, signed)

	// Both signatures match: one via #_two_ref, one via empty URI.
	// The code should reject this as "multiple signatures reference the same element".
	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err, "two signatures both matching the element must be rejected")
	assert.True(t, errors.Is(err, ErrMalformedSignature), "got: %v", err)
}

// ============================================================================
// ATTACK 7: Post-Verification Element Identity
//
// After verification, verifyDigest returns doc.Root() from re-parsed canonical
// bytes. This test verifies that the returned element matches the signed
// content, NOT the (potentially tampered) input element.
// ============================================================================

func TestXSW_Audit_ReturnedElementIsCanonical(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_ret_id")
	el.CreateElement("Data").SetText("good")
	el.CreateElement("Extra").SetText("extra")
	signed := xswSignAndReparse(t, key, cert, el)

	result, err := xswVerifier(cert).Verify(signed)
	require.NoError(t, err)

	// The returned element should be the verified content.
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text())

	// The returned element should NOT have the Signature child
	// (the enveloped sig transform removes it).
	sigInResult := result.Element.FindElement(".//" + signatureTag)
	assert.Nil(t, sigInResult, "returned element should not contain the Signature")
}

// ============================================================================
// ATTACK 8: Empty URI with Non-Enveloped Sig Referencing Different Element
//
// If an element has no ID, the signer produces URI="". An attacker could try
// to place this signature as a child of a different element.
// ============================================================================

func TestXSW_Audit_EmptyURI_StolenToOtherElement(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Sign an element with no ID (empty URI).
	el := &etree.Element{Tag: "Original"}
	el.CreateElement("Data").SetText("good")
	signed := xswSignAndReparse(t, key, cert, el)

	// Extract the signature.
	sig := xswFindSig(signed)
	require.NotNil(t, sig)

	// Create a completely different element and attach the stolen sig.
	evil := etree.NewElement("EvilResponse")
	evil.CreateElement("Data").SetText("evil")
	evil.AddChild(sig.Copy())
	evil = xswReparse(t, evil)

	_, err := xswVerifier(cert).Verify(evil)
	require.Error(t, err, "stolen empty-URI signature must not verify on different element")
	assert.True(t,
		errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSignatureInvalid),
		"got: %v", err)
}

// ============================================================================
// ATTACK 9: Reference URI Mismatch (Signature references wrong ID)
//
// An attacker signs element A, then tries to get the signature to validate
// element B by changing B's ID to match.
// ============================================================================

func TestXSW_Audit_ReferenceURIMismatch(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Sign element with ID="_original".
	signed := xswSignDoc(t, key, cert, "_original")

	// The sig references URI="#_original". Change the element's ID.
	for i, a := range signed.Attr {
		if a.Key == "ID" {
			signed.Attr[i].Value = "_changed"
			break
		}
	}
	signed = xswReparse(t, signed)

	// The URI still says #_original but the element ID is now _changed.
	// findSignature should not find a matching sig.
	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err)
	// It will fail because the signature's reference URI #_original != _changed.
	assert.True(t,
		errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrDigestMismatch),
		"got: %v", err)
}

// ============================================================================
// ATTACK 10: removeElementAtPath with Multiple Signatures
//
// The enveloped signature transform uses mapPathToElement + removeElementAtPath
// to remove the *specific* Signature element. If there are multiple Signature
// elements, only the matching one should be removed. This tests that the
// path-based removal targets the correct one.
// ============================================================================

func TestXSW_Audit_RemoveElementAtPath_MultipleSignatures(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_multi_sig")
	el.CreateElement("Data").SetText("good")
	signed := xswSignAndReparse(t, key, cert, el)

	// Add a decoy Signature element (not in ds: namespace, so findSignature ignores it)
	// but it IS named "Signature" — tests that path-based removal targets the right one.
	decoy := etree.NewElement("Signature")
	decoy.CreateAttr("xmlns", "urn:fake:namespace")
	decoy.CreateElement("Fake").SetText("decoy")
	// Insert decoy BEFORE the real signature.
	signed.InsertChildAt(0, decoy)
	signed = xswReparse(t, signed)

	// Verification should still work — the decoy is in a different namespace.
	// But the digest will include the decoy element, so it should fail.
	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err, "adding a decoy Signature element changes the digest")
	assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

// ============================================================================
// ATTACK 11: Signature Wrapping via Object Element
//
// XSW variant: Move the original signed content into a <ds:Object> element
// inside the Signature, and place evil content in the parent.
// ============================================================================

func TestXSW_Audit_ContentMovedToObject(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "_obj_xsw")

	// Get the Data element.
	data := signed.FindElement("//Data")
	require.NotNil(t, data)

	// Replace data text.
	data.SetText("evil")

	// Move original data into Object inside Signature.
	sig := xswFindSig(signed)
	require.NotNil(t, sig)
	obj := sig.CreateElement("Object")
	origData := etree.NewElement("Data")
	origData.SetText("good")
	obj.AddChild(origData)

	signed = xswReparse(t, signed)

	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err, "XSW via Object element must be detected")
	// The shape validation should reject extra children, or digest should mismatch.
}

// ============================================================================
// ATTACK 12: IDAttribute Confusion
//
// The verifier uses IDAttribute (default "ID"). What if the element uses a
// different attribute (e.g., "Id" or "id") that the attacker controls?
// ============================================================================

func TestXSW_Audit_IDAttributeConfusion(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Signer uses default IDAttribute="ID".
	// Element has ID="_real" but also has id="_fake".
	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_real")
	el.CreateAttr("id", "_fake")
	el.CreateElement("Data").SetText("good")
	signed := xswSignAndReparse(t, key, cert, el)

	// Verify with default IDAttribute="ID" should work.
	result, err := xswVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text())

	// Now verify with IDAttribute="id" — the signature references #_real
	// but the verifier looks at the "id" attribute which is "_fake".
	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		IDAttribute:  "id",
	}
	_, err = v.Verify(signed)
	// The signature URI is #_real but IDAttribute="id" yields "_fake" — no match.
	require.Error(t, err, "IDAttribute mismatch should prevent verification")
	assert.True(t,
		errors.Is(err, ErrMissingSignature),
		"got: %v", err)
}

// ============================================================================
// ATTACK 13: Signature with URI Referencing Unrelated Element
//
// A Signature child of element A has Reference URI pointing to element B's ID.
// findSignature should NOT accept this because the URI doesn't match A's ID.
// ============================================================================

func TestXSW_Audit_CrossElementReference(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Sign element B.
	elB := &etree.Element{Tag: "ElementB"}
	elB.CreateAttr("ID", "_elemB")
	elB.CreateElement("Data").SetText("B-content")
	signedB := xswSignAndReparse(t, key, cert, elB)

	// Extract the signature from B.
	sigB := xswFindSig(signedB)
	require.NotNil(t, sigB)

	// Create element A with a different ID. Attach B's signature to A.
	elA := etree.NewElement("ElementA")
	elA.CreateAttr("ID", "_elemA")
	elA.CreateElement("Data").SetText("A-content")
	elA.AddChild(sigB.Copy())
	elA = xswReparse(t, elA)

	// Verify A — the signature references #_elemB, but A's ID is _elemA.
	_, err := xswVerifier(cert).Verify(elA)
	require.Error(t, err, "cross-element reference should not verify")
	assert.True(t, errors.Is(err, ErrMissingSignature), "got: %v", err)
}

// ============================================================================
// ATTACK 14: Empty URI Signature on Element WITH an ID
//
// When an element has an ID, the signer produces URI="#id". But what if an
// attacker crafts a signature with an empty URI on an element that DOES have
// an ID? The code in findSignature accepts empty URI regardless of whether
// the element has an ID.
//
// FINDING: This is a potential concern — empty URI means "whole document"
// per the spec, but the code treats it as referencing the parent element.
// An attacker who can craft a valid empty-URI signature could potentially
// have it match ANY element.
// ============================================================================

func TestXSW_Audit_EmptyURI_OnElementWithID(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Sign an element WITHOUT an ID → produces empty URI.
	el := &etree.Element{Tag: "Response"}
	el.CreateElement("Data").SetText("good")
	signed := xswSignAndReparse(t, key, cert, el)

	// Now ADD an ID to the signed element.
	signed.CreateAttr("ID", "_added_id")
	signed = xswReparse(t, signed)

	// The signature has URI="" which still matches (empty URI accepted for any element).
	// But the digest was computed over the element WITHOUT the ID attribute,
	// so adding an ID changes the canonical form → digest mismatch.
	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err, "adding an ID attribute after signing should break digest")
	assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

func TestXSW_Audit_EmptyURI_AcceptsAnyElement(t *testing.T) {
	// KEY FINDING: findSignature accepts empty URI on ANY element.
	// This means if an attacker can somehow produce a valid empty-URI
	// signature, it will match when Verify is called on ANY element.
	//
	// However, the digest still protects against content substitution
	// because it's computed over the actual element content.
	//
	// This test verifies that protection.

	key, cert := randomTestKeyAndCert()

	// Sign element with no ID.
	el := &etree.Element{Tag: "Response"}
	el.CreateElement("Data").SetText("good")
	signed := xswSignAndReparse(t, key, cert, el)

	// Verify works.
	_, err := xswVerifier(cert).Verify(signed)
	require.NoError(t, err)

	// Now create a different element and try to use this empty-URI sig.
	sig := xswFindSig(signed)
	require.NotNil(t, sig)

	evil := etree.NewElement("Response")
	evil.CreateElement("Data").SetText("evil")
	evil.AddChild(sig.Copy())
	evil = xswReparse(t, evil)

	// The empty URI matches, but digest is wrong.
	_, err = xswVerifier(cert).Verify(evil)
	require.Error(t, err, "empty-URI sig on wrong element must fail digest check")
	assert.True(t,
		errors.Is(err, ErrDigestMismatch) || errors.Is(err, ErrSignatureInvalid),
		"got: %v", err)
}

// ============================================================================
// ATTACK 15: Verify Returns Canonical Content (Critical Safety Property)
//
// The most important safety property: Verify returns a re-parsed element from
// the canonical bytes that were digest-verified. This means even if the
// original XML tree was tampered, the RETURNED element is trustworthy.
//
// This test verifies this property explicitly.
// ============================================================================

func TestXSW_Audit_VerifyReturnsVerifiedContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_verified_content")
	el.CreateElement("Data").SetText("good")
	el.CreateElement("Secret").SetText("secret-value")
	signed := xswSignAndReparse(t, key, cert, el)

	result, err := xswVerifier(cert).Verify(signed)
	require.NoError(t, err)

	// The returned element should have "good" and "secret-value".
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text())

	s := result.Element.FindElement("//Secret")
	require.NotNil(t, s)
	assert.Equal(t, "secret-value", s.Text())

	// The returned element should NOT be the same Go pointer as the input.
	// (It's reconstructed from canonical bytes.)
	assert.NotSame(t, signed, result.Element,
		"returned element must be reconstructed, not the input pointer")

	// Verify the Signature element is stripped from the result.
	assert.Nil(t, result.Element.FindElement(".//"+signatureTag),
		"Signature should be stripped from returned element")
}

// ============================================================================
// ATTACK 16: SignedInfo Tampering — Verify Uses Re-Parsed Canonical SignedInfo
//
// The code re-parses the canonical SignedInfo bytes after signature verification
// to extract digest/transform info. This prevents TOCTOU attacks where the
// attacker modifies SignedInfo fields after the cryptographic check.
// ============================================================================

func TestXSW_Audit_SignedInfoCanonicalReparsing(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "_si_reparse")

	// The code flow is:
	// 1. Parse SignedInfo from XML tree (for sig verification)
	// 2. Canonicalize SignedInfo → bytes
	// 3. Verify signature over canonical bytes
	// 4. Re-parse canonical bytes to get "verified" SignedInfo
	// 5. Use verified SignedInfo for digest checking
	//
	// This means tampering with SignedInfo in the XML tree (step 1) will be
	// caught at step 3 (signature verification fails).

	// Tamper with the DigestValue in SignedInfo.
	dv := signed.FindElement(".//" + signedInfoTag + "//" + digestValueTag)
	require.NotNil(t, dv)
	dv.SetText(base64.StdEncoding.EncodeToString([]byte("fakedigest")))
	signed = xswReparse(t, signed)

	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err, "tampering with SignedInfo must be caught by signature verification")
	// This should fail at the signature level, not the digest level.
	assert.True(t, errors.Is(err, ErrSignatureInvalid), "got: %v", err)
}

// ============================================================================
// ATTACK 17: Signature Element Shape Validation
//
// validateShape checks for exactly 1 SignedInfo, exactly 1 SignatureValue,
// and at most 1 KeyInfo. Test that malformed signatures are rejected.
// ============================================================================

func TestXSW_Audit_ShapeValidation_NoSignedInfo(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "_shape1")

	sig := xswFindSig(signed)
	require.NotNil(t, sig)

	// Remove SignedInfo.
	for _, c := range sig.ChildElements() {
		if c.Tag == signedInfoTag {
			sig.RemoveChild(c)
			break
		}
	}
	signed = xswReparse(t, signed)

	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMalformedSignature), "got: %v", err)
}

func TestXSW_Audit_ShapeValidation_DuplicateSignedInfo(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "_shape2")

	sig := xswFindSig(signed)
	require.NotNil(t, sig)

	// Find SignedInfo and duplicate it.
	var si *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == signedInfoTag {
			si = c
			break
		}
	}
	require.NotNil(t, si)
	sig.AddChild(si.Copy())
	signed = xswReparse(t, signed)

	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMalformedSignature), "got: %v", err)
}

func TestXSW_Audit_ShapeValidation_DuplicateKeyInfo(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signed := xswSignDoc(t, key, cert, "_shape3")

	sig := xswFindSig(signed)
	require.NotNil(t, sig)

	// Find KeyInfo and duplicate it.
	var ki *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == keyInfoTag {
			ki = c
			break
		}
	}
	require.NotNil(t, ki)
	sig.AddChild(ki.Copy())
	signed = xswReparse(t, signed)

	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMalformedSignature), "got: %v", err)
}

// ============================================================================
// ATTACK 18: Comment Injection in Security-Critical Fields
//
// XML comments inside text nodes can cause parser differentials.
// Canonicalization strips comments (in non-WithComments mode), but
// etree parsing may handle them differently.
// ============================================================================

func TestXSW_Audit_CommentInjectionInNameID(t *testing.T) {
	// ANALYSIS: Comment Injection + C14N Interaction
	//
	// The default C14N 1.1 (non-WithComments) strips comments before computing
	// the digest. So injecting a comment does NOT change the digest, and
	// verification succeeds.
	//
	// HOWEVER, the library reconstructs the returned element from the
	// *canonical bytes* (which don't contain the comment). So the returned
	// element is clean — no comment, no parser differential.
	//
	// This is SAFE: the SP gets a comment-free element from result.Element.
	// The attack only works if the SP ignores result.Element and re-reads
	// the original (tampered) XML tree.

	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_comment1")
	nameID := el.CreateElement("NameID")
	nameID.SetText("admin@evil.com")
	signed := xswSignAndReparse(t, key, cert, el)

	// Verify clean version works.
	result, err := xswVerifier(cert).Verify(signed)
	require.NoError(t, err)
	nid := result.Element.FindElement("//NameID")
	require.NotNil(t, nid)
	assert.Equal(t, "admin@evil.com", nid.Text())

	// Inject a comment into the NameID text.
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	xmlStr, err := doc.WriteToString()
	require.NoError(t, err)
	tampered := strings.Replace(xmlStr, "admin@evil.com", "admin<!--comment-->@evil.com", 1)
	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(tampered))

	// Verification SUCCEEDS because C14N strips comments → same digest.
	result2, err := xswVerifier(cert).Verify(doc2.Root())
	require.NoError(t, err, "comment injection is NOT detected by digest (C14N strips comments)")

	// KEY: The returned element is reconstructed from canonical bytes.
	// The canonical bytes DON'T contain the comment.
	// So the returned element is clean.
	nid2 := result2.Element.FindElement("//NameID")
	require.NotNil(t, nid2)
	assert.Equal(t, "admin@evil.com", nid2.Text(),
		"returned element should have full text (comment stripped by C14N reconstruction)")

	// Verify no comment node exists in returned element.
	for _, child := range nid2.Child {
		_, isComment := child.(*etree.Comment)
		assert.False(t, isComment, "returned element should not contain comments")
	}

	t.Log("RESULT: Comment injection bypasses digest but returned element is clean.")
	t.Log("SAFE as long as SP uses result.Element, not the original XML tree.")
}

// ============================================================================
// ATTACK 18b: Comment Injection — Exploitable Truncation Scenario
//
// Demonstrates a concrete attack: the signed document says the NameID is
// "user@legit.com" but an attacker injects a comment to make Text() return
// just "admin" — a completely different identity.
// ============================================================================

func TestXSW_Audit_CommentInjection_ReturnedElementIsClean(t *testing.T) {
	// This test demonstrates that while comment injection bypasses the digest,
	// the returned element from Verify() is reconstructed from canonical bytes
	// which DON'T contain the comment. So the SP gets a clean element.
	//
	// HOWEVER: If the SP reads from the ORIGINAL XML tree (not result.Element),
	// the comment IS present and could cause issues with naive parsers.

	key, cert := randomTestKeyAndCert()

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_comment_exploit")
	nameID := el.CreateElement("NameID")
	nameID.SetText("admin@legit-domain.com")
	signed := xswSignAndReparse(t, key, cert, el)

	// Inject comment.
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	xmlStr, _ := doc.WriteToString()
	tampered := strings.Replace(xmlStr,
		"admin@legit-domain.com",
		"admin<!--injected-->@legit-domain.com", 1)
	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(tampered))

	// The INPUT element has a comment in it.
	inputNameID := doc2.Root().FindElement("//NameID")
	require.NotNil(t, inputNameID)
	hasComment := false
	for _, child := range inputNameID.Child {
		if _, ok := child.(*etree.Comment); ok {
			hasComment = true
		}
	}
	assert.True(t, hasComment, "input element should have comment")

	// Verification succeeds (C14N strips comments → same digest).
	result, err := xswVerifier(cert).Verify(doc2.Root())
	require.NoError(t, err, "comment injection passes signature verification")

	// The RETURNED element is clean — no comment.
	nid := result.Element.FindElement("//NameID")
	require.NotNil(t, nid)
	assert.Equal(t, "admin@legit-domain.com", nid.Text(),
		"returned element has full correct text")
	assert.Equal(t, 1, len(nid.Child),
		"returned element has exactly one text child (no comment)")

	t.Log("CONFIRMED: Returned element is clean. Comment injection is safe IF SP uses result.Element.")
}

// ============================================================================
// ATTACK 19: SAML-Specific — Signed Response with Unsigned Assertion
//
// In SAML, the Response may be signed while individual Assertions are not.
// gosaml2 issue #219 reports that "Assertion signature is not verified when
// the response is signed". This library returns verified content,
// so the SP should use ONLY the returned element.
//
// This test verifies that the returned element from a signed Response contains
// the original assertion content (not injected content).
// ============================================================================

func TestXSW_Audit_SAMLSignedResponseUnsignedAssertion(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Build SAML-like Response and sign the Response (not the Assertion).
	resp := buildSAMLResponse("_saml_resp", "_saml_assert", "alice@good.com")
	signed := xswSignAndReparse(t, key, cert, resp)

	result, err := xswVerifier(cert).Verify(signed)
	require.NoError(t, err)

	// The returned element is the verified Response.
	// It should contain the assertion with alice@good.com.
	nameID := result.Element.FindElement("//NameID")
	require.NotNil(t, nameID)
	assert.Equal(t, "alice@good.com", nameID.Text())

	// Critically: if the SP uses result.Element (not the original `signed`),
	// it will always get the verified content.
}

func TestXSW_Audit_SAMLInjectedAssertionNotInVerifiedResult(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	resp := buildSAMLResponse("_saml_resp2", "_saml_assert2", "alice@good.com")
	signed := xswSignAndReparse(t, key, cert, resp)

	// Attack: inject evil assertion.
	evilAssertion := etree.NewElement("Assertion")
	evilAssertion.CreateAttr("ID", "_evil")
	evilAssertion.CreateElement("Subject").CreateElement("NameID").SetText("admin@evil.com")
	signed.InsertChildAt(0, evilAssertion)
	signed = xswReparse(t, signed)

	// Digest mismatch because the document changed.
	_, err := xswVerifier(cert).Verify(signed)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

// ============================================================================
// ATTACK 20: Empty URI with ID-bearing Element — findSignature Behavior
//
// CRITICAL ANALYSIS: In findSignature, the condition for matching is:
//
//   sig.refURI == "" || (sig.refURI starts with '#' && sig.refURI[1:] == idAttr)
//
// This means empty URI ALWAYS matches, regardless of the element's ID.
// This is by design (empty URI = "this document") but creates a concern:
// if an attacker can get a validly-signed empty-URI signature, they could
// attach it to ANY element and findSignature would accept it.
//
// HOWEVER: The digest check ensures that the content must match exactly.
// So this is safe AS LONG AS the SP uses the returned verified element.
// ============================================================================

func TestXSW_Audit_EmptyURI_MatchesElementWithAnyID(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Sign element with no ID → URI="".
	el := &etree.Element{Tag: "Response"}
	el.CreateElement("Data").SetText("good")
	signed := xswSignAndReparse(t, key, cert, el)

	// Verify works with no ID.
	result, err := xswVerifier(cert).Verify(signed)
	require.NoError(t, err)
	d := result.Element.FindElement("//Data")
	require.NotNil(t, d)
	assert.Equal(t, "good", d.Text())

	// Now: can we verify the exact same element if we add an ID?
	// Adding an attribute changes canonical form → digest mismatch.
	el2 := signed.Copy()
	el2.CreateAttr("ID", "_sneaky")
	el2 = xswReparse(t, el2)

	_, err = xswVerifier(cert).Verify(el2)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDigestMismatch), "got: %v", err)
}

// ============================================================================
// ATTACK 21: verifyDigest refURI Check Bug
//
// CRITICAL CODE REVIEW FINDING:
//
//   In verifyDigest, the refURI check has a subtle logic issue:
//
//     if verifiedSig.refURI != "" && !(len(verifiedSig.refURI) > 1 && ...) {
//         if verifiedSig.refURI != "" {
//             return nil, fmt.Errorf(...)
//         }
//     }
//
//   The outer condition is: refURI != "" AND NOT matching.
//   The inner condition is: refURI != "".
//   When the outer is true, refURI is guaranteed non-empty, so the inner
//   check is always true. This is redundant but not a vulnerability.
//
//   HOWEVER: The real question is — when refURI is empty, the check is
//   completely skipped. This means an empty URI always passes.
//   Combined with findSignature also accepting empty URIs, this means:
//   empty-URI signatures are accepted on any element, with only the
//   digest protecting against content substitution.
//
//   This is correct behavior but important for SP authors to understand.
// ============================================================================

func TestXSW_Audit_VerifyDigest_EmptyURISkipsCheck(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Sign without ID.
	el := &etree.Element{Tag: "Response"}
	el.CreateElement("Data").SetText("good")
	signed := xswSignAndReparse(t, key, cert, el)

	// Verify — empty URI, no ID check, just digest.
	result, err := xswVerifier(cert).Verify(signed)
	require.NoError(t, err)
	assert.Equal(t, "good", result.Element.FindElement("//Data").Text())
}

// ============================================================================
// ATTACK 22: Exc-C14N Canonicalizer — Prefix List Manipulation
//
// If the InclusiveNamespaces PrefixList can be manipulated to change what
// namespaces are included in canonicalization, it could affect the digest.
// ============================================================================

func TestXSW_Audit_ExcC14N_PrefixListTamper(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	el := &etree.Element{Tag: "Response"}
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("ID", "_exc_c14n")
	el.CreateElement("Data").SetText("good")

	signedEl, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed := xswReparse(t, signedEl)

	// Verify clean.
	_, err = xswVerifier(cert).Verify(signed)
	require.NoError(t, err)

	// Tamper: modify the PrefixList in the transform.
	// Find the exc-c14n Transform and add a PrefixList.
	transforms := signed.FindElements(".//" + transformTag)
	for _, tr := range transforms {
		alg := tr.SelectAttrValue(algorithmAttr, "")
		if alg == string(CanonicalXML10ExclusiveAlgorithmId) {
			incNS := tr.CreateElement(inclusiveNamespacesTag)
			incNS.CreateAttr("xmlns", "http://www.w3.org/2001/10/xml-exc-c14n#")
			incNS.CreateAttr(prefixListAttr, "saml")
			break
		}
	}
	signed = xswReparse(t, signed)

	// This should fail — modifying the transform in SignedInfo changes the
	// canonical SignedInfo, which invalidates the signature.
	_, err = xswVerifier(cert).Verify(signed)
	require.Error(t, err, "tampering with PrefixList must be caught")
	assert.True(t,
		errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrDigestMismatch),
		"got: %v", err)
}

// ============================================================================
// Summary Assessment Helper — Not a test, just documents findings.
// ============================================================================

func TestXSW_Audit_Summary(t *testing.T) {
	t.Log("=== XSW AUDIT SUMMARY ===")
	t.Log("")
	t.Log("FINDING 1 (LOW): Comment injection bypasses digest but returned element is clean.")
	t.Log("  The default C14N 1.1 canonicalizer strips comments, so injecting a comment")
	t.Log("  (e.g. 'admin<!--x-->@evil.com') does NOT change the digest.")
	t.Log("  Verification succeeds. HOWEVER, the returned element is reconstructed from")
	t.Log("  canonical bytes which DON'T contain the comment. So result.Element is clean.")
	t.Log("  SAFE as long as the SP uses result.Element (not the original XML tree).")
	t.Log("  NOTE: If an SP reads from the original tree, it WOULD see the comment.")
	t.Log("")
	t.Log("FINDING 2 (LOW): Empty Reference URI accepted on any element.")
	t.Log("  findSignature accepts URI=\"\" regardless of element ID.")
	t.Log("  verifyDigest also skips URI matching when URI is empty.")
	t.Log("  IMPACT: Low — digest still protects content integrity.")
	t.Log("  RECOMMENDATION: Consider rejecting empty URI when element has an ID.")
	t.Log("")
	t.Log("FINDING 3 (INFO): verifyDigest has redundant refURI check.")
	t.Log("  The inner 'if verifiedSig.refURI != \"\"' is always true when reached.")
	t.Log("  Not a vulnerability, but confusing code.")
	t.Log("")
	t.Log("FINDING 4 (GOOD): Verify returns reconstructed element from canonical bytes.")
	t.Log("  This is the KEY safety property that prevents most XSW variants.")
	t.Log("  Comments are stripped during C14N, so returned element is comment-free.")
	t.Log("")
	t.Log("FINDING 5 (GOOD): SignedInfo is re-parsed from canonical bytes after sig check.")
	t.Log("  This prevents TOCTOU attacks on Reference URI, DigestValue, transforms.")
	t.Log("")
	t.Log("FINDING 6 (GOOD): findSignature only searches direct children.")
	t.Log("  Signatures buried deeper in the tree are correctly rejected.")
	t.Log("")
	t.Log("FINDING 7 (GOOD): Duplicate signatures referencing same element are rejected.")
	t.Log("")
	t.Log("FINDING 8 (GOOD): Cross-element reference URIs are correctly rejected.")
	t.Log("")
	t.Log("FINDING 9 (GOOD): Shape validation catches malformed Signature elements.")
	t.Log("")
	t.Log("FINDING 10 (INFO/SP-DEPENDENT): Library correctness depends on SP behavior.")
	t.Log("  The SP MUST use result.Element from Verify, not the original XML tree.")
	t.Log("  If the SP re-parses the original XML after verification, XSW is possible.")
	t.Log("")
	t.Log("OVERALL: xmldsig has strong XSW protections. No exploitable XSW")
	t.Log("vulnerabilities found. The key safety property is that Verify() returns")
	t.Log("a reconstructed element from verified canonical bytes, preventing all")
	t.Log("classic XSW attack variants. SPs MUST use result.Element.")
}
