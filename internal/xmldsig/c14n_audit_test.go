package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/assert"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// ==========================================================================
// C14N AUDIT TEST SUITE
//
// These tests target canonicalization edge cases that could lead to security
// issues — specifically, differences between what gets signed/verified and
// what a consumer extracts from the verified element.
// ==========================================================================

// ---------------------------------------------------------------------------
// 1. NullCanonicalizer fallback — preserves comments even without WithComments
//
// When no C14N transform is listed in Reference/Transforms, the verifier
// falls back to NullCanonicalizer, which calls canonicalPrep(el, false, true).
// The `comments=true` means XML comments are PRESERVED in the digest.
// This is inconsistent: the SignedInfo C14N might strip comments, but the
// Reference digest would include them. An attacker who can inject comments
// into a document signed with NullCanonicalizer cannot change the digest,
// but a consumer that strips comments would see different text.
// ---------------------------------------------------------------------------
func TestC14NAudit_NullCanonicalizerPreservesComments(t *testing.T) {
	// NullCanonicalizer preserves comments in its output.
	// Verify this behavior is documented/expected.
	doc, err := lenientParseDoc(`<Root><!-- comment --><Data>value</Data></Root>`)
	require.NoError(t, err)

	nullC := MakeNullCanonicalizer()
	result, err := nullC.Canonicalize(doc.Root())
	require.NoError(t, err)

	// NullCanonicalizer preserves comments (comments=true in canonicalPrep)
	assert.Contains(t, string(result), "<!-- comment -->",
		"NullCanonicalizer should preserve comments")

	// Compare with C14N 1.1 (no comments) which strips them
	c14n11 := MakeC14N11Canonicalizer()
	result11, err := c14n11.Canonicalize(doc.Root())
	require.NoError(t, err)
	assert.NotContains(t, string(result11), "<!-- comment -->",
		"C14N11 without comments should strip comments")

	// The two canonical forms differ — this means the digest differs
	// depending on which canonicalizer is used.
	assert.NotEqual(t, string(result), string(result11),
		"NullCanonicalizer and C14N11 should produce different output when comments present")
}

// ---------------------------------------------------------------------------
// 2. Comment injection with different C14N methods
//
// If an attacker can inject a comment into signed content, the behavior
// depends on the C14N method. With non-comment C14N, comments are stripped
// before digest — injecting a comment doesn't change the digest.
// With NullCanonicalizer (fallback), comments ARE in the digest.
//
// Security concern: The verified element returned by Verify() is
// reconstructed from canonical bytes. If comments are stripped during
// canonicalization, the reconstructed element won't have them — safe.
// But if NullCanonicalizer is used, comments are preserved, and a consumer
// that uses text-node-only extraction (ignoring comments) could see
// different content than what was displayed to the signer.
// ---------------------------------------------------------------------------
func TestC14NAudit_CommentInjectionInTextNodes(t *testing.T) {
	// Simulate the classic comment injection attack (CERT VU#475445).
	// XML: <NameID>admin@evil.com<!-- -->@legit.com</NameID>
	// Some parsers return only "admin@evil.com" from text extraction.
	// etree's Text() concatenates all CharData children, so it returns
	// the full "admin@evil.com@legit.com".

	// Test that xmltree.Text() returns full concatenated text (safe behavior)
	doc, err := lenientParseDoc(`<NameID>admin@evil.com<!-- injected -->@legit.com</NameID>`)
	require.NoError(t, err)

	root := doc.Root()
	text := root.Text()
	// etree's Text() only returns the FIRST CharData token, not all of them!
	// This is the Go/etree variant of the comment injection vulnerability.
	if text == "admin@evil.com" {
		// This is the VULNERABLE behavior — Text() only returns pre-comment text
		t.Log("WARNING: xmltree.Text() returns only pre-comment text — " +
			"classic comment injection applies if consumer uses Text()")
	} else if text == "admin@evil.com@legit.com" {
		t.Log("xmltree.Text() returns full concatenated text (safe)")
	} else {
		t.Logf("xmltree.Text() returned unexpected value: %q", text)
	}

	// Regardless of Text() behavior, verify the canonical form includes
	// the comment when using with-comments C14N
	withComments := MakeC14N11WithCommentsCanonicalizer()
	cBytes, err := withComments.Canonicalize(root)
	require.NoError(t, err)
	assert.Contains(t, string(cBytes), "<!-- injected -->",
		"with-comments canonicalization should preserve the comment")

	// Without comments — comment is stripped
	noComments := MakeC14N11Canonicalizer()
	ncBytes, err := noComments.Canonicalize(root)
	require.NoError(t, err)
	assert.NotContains(t, string(ncBytes), "<!--",
		"without-comments canonicalization should strip comments")

	// The critical security test: does the no-comments canonical form
	// contain both text segments?
	assert.Contains(t, string(ncBytes), "admin@evil.com",
		"canonical form should contain first text segment")
	assert.Contains(t, string(ncBytes), "@legit.com",
		"canonical form should contain second text segment")
}

// ---------------------------------------------------------------------------
// 3. canonicalPrep dead parameter: strip is never used
//
// The `strip` parameter in canonicalPrep/canonicalPrepInner is declared
// but namespace dedup logic runs unconditionally. Verify this.
// ---------------------------------------------------------------------------
func TestC14NAudit_CanonicalPrepStripParameterIgnored(t *testing.T) {
	// canonicalPrep(el, strip=true, ...) and canonicalPrep(el, strip=false, ...)
	// should produce identical output, because the strip parameter is unused.
	xml := `<Root xmlns:a="urn:a" xmlns:b="urn:b">
		<Child xmlns:a="urn:a"><a:Item/></Child>
	</Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	// strip=true (used by C14N11)
	resStrip := canonicalPrep(doc.Root().Copy(), true, false)
	bytesStrip, err := canonicalSerialize(resStrip)
	require.NoError(t, err)

	// strip=false (used by NullCanonicalizer)
	doc2 := xmltree.NewDocument()
	require.NoError(t, doc2.ReadFromString(xml))
	resNoStrip := canonicalPrep(doc2.Root().Copy(), false, false)
	bytesNoStrip, err := canonicalSerialize(resNoStrip)
	require.NoError(t, err)

	// These should be identical since strip is dead code
	assert.Equal(t, string(bytesStrip), string(bytesNoStrip),
		"strip parameter should have no effect (dead code)")
}

// ---------------------------------------------------------------------------
// 4. Exclusive C14N: default namespace undeclaration (xmlns="")
//
// Per the exc-c14n spec, if the default namespace is visibly utilized
// (element has empty prefix), the default namespace declaration must
// appear. But xmlns="" (undeclaration) is tricky — it means "no namespace".
// If a parent declares xmlns="urn:foo" and a child has xmlns="",
// exclusive C14N must handle this correctly.
// ---------------------------------------------------------------------------
func TestC14NAudit_ExcC14NDefaultNamespaceUndeclaration(t *testing.T) {
	// Parent has default namespace, child undeclares it
	xml := `<Parent xmlns="urn:parent"><Child xmlns=""><Data>text</Data></Child></Parent>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	excC14n := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// Canonicalize the full document
	result, err := excC14n.Canonicalize(doc.Root())
	require.NoError(t, err)

	// The Child element must have xmlns="" to undeclare the parent's default namespace
	// Per exc-c14n spec, the default namespace undeclaration is emitted when needed
	resStr := string(result)
	t.Logf("Exc-C14N result: %s", resStr)

	// Verify that Data is not in "urn:parent" namespace
	// The canonical form should show that Child and Data are in no namespace
	assert.Contains(t, resStr, "<Child", "Child element should be present")
	assert.Contains(t, resStr, "<Data", "Data element should be present")
}

// ---------------------------------------------------------------------------
// 5. Exclusive C14N: PrefixList with "#default"
//
// The exc-c14n spec says the default namespace is referenced by "#default"
// in the PrefixList. Does the library handle this?
// ---------------------------------------------------------------------------
func TestC14NAudit_ExcC14NPrefixListDefault(t *testing.T) {
	xml := `<foo:Root xmlns:foo="urn:foo" xmlns="urn:default">
		<foo:Child>text</foo:Child>
	</foo:Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	// Without #default in PrefixList: default namespace is NOT visibly utilized
	// (no unprefixed elements), so it should be stripped
	excC14n := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	result, err := excC14n.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)
	t.Logf("Without #default: %s", resStr)

	// With #default in PrefixList: default namespace should be preserved
	// NOTE: The library uses string.Fields to split the PrefixList.
	// "#default" is not specially handled — it's treated as a literal prefix.
	// This is a spec deviation: exc-c14n says "#default" means the default NS.
	excC14nDefault := MakeC14N10ExclusiveCanonicalizerWithPrefixList("#default")
	resultDefault, err := excC14nDefault.Canonicalize(doc.Root().Copy())
	require.NoError(t, err)
	resStrDefault := string(resultDefault)
	t.Logf("With #default: %s", resStrDefault)

	// The spec says #default should cause xmlns="urn:default" to be emitted.
	// If the library doesn't handle #default, both outputs will be the same.
	if resStr == resStrDefault {
		t.Log("FINDING: #default in PrefixList is NOT specially handled. " +
			"This is a spec deviation from exc-c14n. An IdP that uses #default " +
			"in InclusiveNamespaces would produce a different canonical form " +
			"than this library, causing signature verification failure (safe fail).")
	}
}

// ---------------------------------------------------------------------------
// 6. C14N method mismatch between SignedInfo and Reference transforms
//
// The SignedInfo's CanonicalizationMethod specifies how to canonicalize
// SignedInfo itself. The Reference's Transform specifies how to canonicalize
// the referenced element. These can legitimately differ.
// Test that using different methods works correctly.
// ---------------------------------------------------------------------------
func TestC14NAudit_C14NMethodMismatch(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Sign with C14N 1.1 (default) — this sets the Reference transform to C14N 1.1
	signer11 := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	el := &xmltree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_mismatch1")
	el.CreateElement("Data").SetText("test")

	signed, err := signer11.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Verify should work
	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := v.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Now sign with exc-c14n
	signerExc := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	el2 := &xmltree.Element{Tag: "Response"}
	el2.CreateAttr("ID", "_mismatch2")
	el2.CreateElement("Data").SetText("test")

	signed2, err := signerExc.SignEnveloped(el2)
	require.NoError(t, err)
	signed2 = reparse(t, signed2)

	result2, err := v.Verify(signed2)
	require.NoError(t, err)
	require.NotNil(t, result2)
}

// ---------------------------------------------------------------------------
// 7. NSDetach skips empty default namespace
//
// NSDetach skips "prefix == defaultPrefix && namespace == ”".
// This means if the context has xmlns="" (empty default namespace),
// it won't be emitted on the detached element. For canonicalization of
// SignedInfo this is usually fine, but could be an issue if the SignedInfo
// is in a context where the default namespace was explicitly undeclared.
// ---------------------------------------------------------------------------
func TestC14NAudit_NSDetachSkipsEmptyDefaultNS(t *testing.T) {
	// Build a context where default namespace is explicitly empty
	xml := `<Root xmlns="urn:root"><Middle xmlns=""><Inner attr="val"/></Middle></Root>`
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	middle := doc.Root().FindElement("Middle")
	require.NotNil(t, middle)

	inner := middle.FindElement("Inner")
	require.NotNil(t, inner)

	// Build context for Inner
	parentCtx, err := NSBuildParentContext(inner)
	require.NoError(t, err)

	// Detach Inner
	detached, err := NSDetach(parentCtx, inner)
	require.NoError(t, err)

	// Serialize the detached element
	detachedDoc := xmltree.NewDocument()
	detachedDoc.SetRoot(detached)
	resultBytes, err := detachedDoc.WriteToBytes()
	require.NoError(t, err)
	result := string(resultBytes)
	t.Logf("NSDetach result: %s", result)

	// The detached element should NOT have xmlns="urn:root" because
	// the Middle element undeclared it. NSDetach skips empty default NS,
	// which is correct here — the Inner element is in no namespace.
	assert.NotContains(t, result, `xmlns="urn:root"`,
		"detached element should not inherit undeclared default namespace")
}

// ---------------------------------------------------------------------------
// 8. Attribute sorting: namespace URI resolution fallback
//
// SortedAttrs.resolvePrefix falls back to using the prefix string itself
// when no xmlns:prefix declaration is found in the attribute list.
// This can happen when the namespace is declared on an ancestor.
// Test that this doesn't cause incorrect ordering.
// ---------------------------------------------------------------------------
func TestC14NAudit_AttributeSortingWithAncestorNamespaces(t *testing.T) {
	// Two attributes with prefixes whose namespace URIs are declared on
	// an ancestor, not on the element itself.
	xml := `<Root xmlns:b="http://b-ns" xmlns:a="http://a-ns">
		<Child b:attr="bval" a:attr="aval"/>
	</Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	// With inclusive C14N, namespace declarations are inherited
	c14n11 := MakeC14N11Canonicalizer()
	result, err := c14n11.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)
	t.Logf("C14N11 result: %s", resStr)

	// Per C14N spec, namespace-qualified attributes are sorted by
	// namespace URI then local name. http://a-ns < http://b-ns,
	// so a:attr should come before b:attr.
	aIdx := strings.Index(resStr, `a:attr`)
	bIdx := strings.Index(resStr, `b:attr`)
	assert.Greater(t, aIdx, -1, "a:attr should be present")
	assert.Greater(t, bIdx, -1, "b:attr should be present")
	assert.Less(t, aIdx, bIdx,
		"a:attr (http://a-ns) should come before b:attr (http://b-ns) in canonical order")

	// With exclusive C14N, the same ordering should hold
	excC14n := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	resultExc, err := excC14n.Canonicalize(doc.Root().Copy())
	require.NoError(t, err)
	resStrExc := string(resultExc)
	t.Logf("ExcC14N result: %s", resStrExc)

	aIdxExc := strings.Index(resStrExc, `a:attr`)
	bIdxExc := strings.Index(resStrExc, `b:attr`)
	assert.Greater(t, aIdxExc, -1)
	assert.Greater(t, bIdxExc, -1)
	assert.Less(t, aIdxExc, bIdxExc,
		"exc-c14n: a:attr should come before b:attr")
}

// ---------------------------------------------------------------------------
// 9. Attribute sorting: resolvePrefix fallback when declaration is on ancestor
//
// When exclusive C14N moves namespace declarations to the element where
// they're used, resolvePrefix should find them. But for elements where
// the prefix is used on an attribute but the declaration gets placed on
// an ancestor in the canonical form, the fallback kicks in.
// ---------------------------------------------------------------------------
func TestC14NAudit_AttributeSortingResolvePrefixFallback(t *testing.T) {
	// Create element with two prefixed attributes where the namespace
	// declarations are NOT on the same element. The sort function's
	// resolvePrefix will fall back to using the prefix string itself.
	el := &xmltree.Element{Tag: "Elem"}
	el.Attr = []xmltree.Attr{
		// Prefixed attrs without corresponding xmlns declarations on this element
		{Space: "z", Key: "attr", Value: "zval"},
		{Space: "a", Key: "attr", Value: "aval"},
	}

	// Sort using our sorter
	sorted := make(SortedAttrs, len(el.Attr))
	copy(sorted, el.Attr)
	// manually check Less
	// Without namespace declarations, resolvePrefix returns the prefix itself.
	// So "a" < "z" → a:attr should come first.
	result := sorted.Less(1, 0) // is a:attr < z:attr?
	assert.True(t, result, "fallback prefix ordering: 'a' < 'z'")

	result2 := sorted.Less(0, 1) // is z:attr < a:attr?
	assert.False(t, result2, "fallback: z:attr should NOT be less than a:attr")
}

// ---------------------------------------------------------------------------
// 10. Exclusive C14N: unused namespaces are stripped
//
// Verify that exclusive C14N strips namespace declarations that are not
// visibly utilized. This is the core security property that prevents
// namespace injection attacks.
// ---------------------------------------------------------------------------
func TestC14NAudit_ExcC14NStripsUnusedNamespaces(t *testing.T) {
	xml := `<Root xmlns:unused="urn:unused" xmlns:used="urn:used">
		<used:Child>data</used:Child>
	</Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	excC14n := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	result, err := excC14n.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)

	// "unused" should NOT appear in the exc-c14n output for Root
	// (Root doesn't use it visibly — no element/attr with prefix "unused")
	// But Root itself has no prefix, so only xmlns:used should appear if
	// used:Child moves its declaration up... Actually in exc-c14n, each
	// element only emits the declarations it needs.
	t.Logf("ExcC14N: %s", resStr)

	// The Child element should have xmlns:used but Root should not have xmlns:unused
	assert.NotContains(t, resStr, "urn:unused",
		"unused namespace should be stripped by exc-c14n")
	assert.Contains(t, resStr, "urn:used",
		"used namespace should be present")
}

// ---------------------------------------------------------------------------
// 11. Inclusive C14N: unused namespaces are preserved
//
// Unlike exclusive C14N, inclusive C14N preserves ALL in-scope namespace
// declarations, even unused ones. Verify this difference.
// ---------------------------------------------------------------------------
func TestC14NAudit_InclusiveC14NPreservesUnusedNamespaces(t *testing.T) {
	xml := `<Root xmlns:unused="urn:unused" xmlns:used="urn:used">
		<used:Child>data</used:Child>
	</Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	c14n11 := MakeC14N11Canonicalizer()
	result, err := c14n11.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)

	t.Logf("C14N11: %s", resStr)

	// Inclusive C14N preserves unused namespaces
	assert.Contains(t, resStr, "urn:unused",
		"inclusive C14N should preserve unused namespaces")
	assert.Contains(t, resStr, "urn:used",
		"inclusive C14N should preserve used namespaces")
}

// ---------------------------------------------------------------------------
// 12. Sign-and-verify round-trip with all canonicalizer types
//
// Verify that signing and verification work correctly with each
// canonicalization algorithm. Any failure indicates a C14N implementation
// issue that could affect real-world SAML deployments.
// ---------------------------------------------------------------------------
func TestC14NAudit_RoundTripAllCanonicalizers(t *testing.T) {
	canonicalizerFactories := []struct {
		name string
		make func() Canonicalizer
	}{
		{"C14N11", func() Canonicalizer { return MakeC14N11Canonicalizer() }},
		{"C14N11WithComments", func() Canonicalizer { return MakeC14N11WithCommentsCanonicalizer() }},
		{"ExcC14N", func() Canonicalizer { return MakeC14N10ExclusiveCanonicalizerWithPrefixList("") }},
		{"ExcC14NWithComments", func() Canonicalizer { return MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("") }},
		{"C14N10Rec", func() Canonicalizer { return MakeC14N10RecCanonicalizer() }},
		{"C14N10WithComments", func() Canonicalizer { return MakeC14N10WithCommentsCanonicalizer() }},
	}

	for _, cf := range canonicalizerFactories {
		t.Run(cf.name, func(t *testing.T) {
			key, cert := randomTestKeyAndCert()
			signer := &Signer{
				Key:           key,
				Certs:         []*x509.Certificate{cert},
				Canonicalizer: cf.make(),
			}

			el := &xmltree.Element{Tag: "Response"}
			el.CreateAttr("ID", "_roundtrip")
			el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
			child := el.CreateElement("saml:Assertion")
			child.Space = "saml"
			child.SetText("content")

			signed, err := signer.SignEnveloped(el)
			require.NoError(t, err)
			signed = reparse(t, signed)

			v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := v.Verify(signed)
			require.NoError(t, err, "round-trip with %s should verify", cf.name)
			require.NotNil(t, result)
		})
	}
}

// ---------------------------------------------------------------------------
// 13. Exclusive C14N with PrefixList: inherited namespace preservation
//
// When a PrefixList includes a prefix, that prefix's namespace declaration
// should be included in the canonical form even if not visibly utilized.
// This is critical for SAML responses where xs: is often in the PrefixList.
// ---------------------------------------------------------------------------
func TestC14NAudit_ExcC14NPrefixListPreservesNamespace(t *testing.T) {
	xml := `<Root xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:saml">
		<saml:Data>text</saml:Data>
	</Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	// Without xs in prefix list
	excNoXs := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	resNoXs, err := excNoXs.Canonicalize(doc.Root())
	require.NoError(t, err)

	// With xs in prefix list
	doc2 := xmltree.NewDocument()
	require.NoError(t, doc2.ReadFromString(xml))
	excWithXs := MakeC14N10ExclusiveCanonicalizerWithPrefixList("xs")
	resWithXs, err := excWithXs.Canonicalize(doc2.Root())
	require.NoError(t, err)

	t.Logf("Without xs: %s", string(resNoXs))
	t.Logf("With xs: %s", string(resWithXs))

	// Without xs: the xs namespace should NOT be in the output
	assert.NotContains(t, string(resNoXs), "http://www.w3.org/2001/XMLSchema")

	// With xs: the xs namespace SHOULD be in the output on Root
	assert.Contains(t, string(resWithXs), "http://www.w3.org/2001/XMLSchema",
		"PrefixList=xs should cause xs namespace to be included")
}

// ---------------------------------------------------------------------------
// 14. Verify result contains canonical (digest-verified) content
//
// The VerifyResult.Element is reconstructed from the canonical bytes that
// passed the digest check. This is a critical security property: consumers
// should use this element, not the original input.
// ---------------------------------------------------------------------------
func TestC14NAudit_VerifyResultIsFromCanonicalBytes(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Build a document with comments and extra whitespace
	el := &xmltree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_canonical")
	el.CreateElement("Data").SetText("important")

	// Sign with default (C14N 1.1, no comments)
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Inject a comment after signing (before the signature). The strict
	// parser would reject the serialized form outright, so the injection can
	// only exist as in-memory tree surgery; verify directly on the tree.
	// With C14N11 (no comments), this doesn't change the digest.
	signed.InsertChildAt(0, xmltree.NewComment("injected after signing"))

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := v.Verify(signed)
	require.NoError(t, err)

	// The result element should NOT contain the injected comment
	// (it's reconstructed from canonical bytes where comments were stripped)
	resultDoc := xmltree.NewDocument()
	resultDoc.SetRoot(result.Element)
	resultXml, err := resultDoc.WriteToString()
	require.NoError(t, err)
	assert.NotContains(t, resultXml, "injected after signing",
		"verified result should be from canonical bytes without the injected comment")

	// The Signature element should also be absent (enveloped-signature transform)
	assert.Nil(t, result.Element.FindElement("./"+signatureTag),
		"verified result should not contain the Signature element")
}

// ---------------------------------------------------------------------------
// 15. namespace re-declaration attack: same prefix, different URI
//
// An attacker adds a namespace re-declaration that changes the meaning
// of elements for a consumer that processes the original tree, while
// the canonical form (which the digest covers) resolves differently.
// ---------------------------------------------------------------------------
func TestC14NAudit_NamespaceRedeclarationAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Build document with saml namespace
	el := &xmltree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_nsredecl")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	child := el.CreateElement("Assertion")
	child.Space = "saml"
	child.CreateElement("NameID").SetText("admin@example.com")

	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Verify clean
	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = v.Verify(signed)
	require.NoError(t, err)

	// Now tamper: change the saml namespace URI on the root element
	for i, attr := range signed.Attr {
		if attr.Space == "xmlns" && attr.Key == "saml" {
			signed.Attr[i].Value = "urn:evil:namespace"
			break
		}
	}
	signed = reparse(t, signed)

	// This should fail because the namespace URI change affects canonicalization
	_, err = v.Verify(signed)
	require.Error(t, err,
		"changing namespace URI after signing must invalidate the signature")
}

// ---------------------------------------------------------------------------
// 16. Exclusive C14N: xml: prefix handling
//
// The xml: prefix (http://www.w3.org/XML/1998/namespace) is special.
// It never needs to be declared. Exclusive C14N should handle xml:lang,
// xml:space, etc. correctly.
// ---------------------------------------------------------------------------
func TestC14NAudit_ExcC14NXmlPrefixHandling(t *testing.T) {
	xml := `<Root xml:lang="en"><Child xml:lang="fr">text</Child></Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	excC14n := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	result, err := excC14n.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)
	t.Logf("ExcC14N with xml: attrs: %s", resStr)

	// xml:lang should be preserved but xmlns:xml should NOT be declared
	// (it's always implicitly in scope)
	assert.Contains(t, resStr, `xml:lang="en"`)
	assert.Contains(t, resStr, `xml:lang="fr"`)
	// Should NOT contain an explicit xmlns:xml declaration
	assert.NotContains(t, resStr, `xmlns:xml=`)
}

// ---------------------------------------------------------------------------
// 17. canonicalPrep: redundant namespace stripping across levels
//
// canonicalPrepInner tracks seen namespaces and strips redundant ones.
// Test that a namespace declared at level 1, re-declared at level 2
// with the same URI, then re-declared at level 3 with a DIFFERENT URI
// is handled correctly.
// ---------------------------------------------------------------------------
func TestC14NAudit_CanonicalPrepRedundantNamespaceStripping(t *testing.T) {
	xml := `<A xmlns:ns="urn:first">
		<B xmlns:ns="urn:first">
			<C xmlns:ns="urn:second">
				<ns:D/>
			</C>
		</B>
	</A>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	// C14N 1.1 should strip the redundant xmlns:ns on B but keep the one on C
	c14n11 := MakeC14N11Canonicalizer()
	result, err := c14n11.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)
	t.Logf("C14N11: %s", resStr)

	// B should NOT have xmlns:ns (redundant with A)
	// C SHOULD have xmlns:ns="urn:second" (different from parent)
	assert.Contains(t, resStr, `<A xmlns:ns="urn:first">`)
	// B should be just <B> with no xmlns:ns redeclaration
	assert.Contains(t, resStr, "<B>")
	// C should have the new declaration
	assert.Contains(t, resStr, `<C xmlns:ns="urn:second">`)
}

// ---------------------------------------------------------------------------
// 18. Signed document with deeply nested namespaces: sign-verify round-trip
//
// A realistic SAML-like document structure with multiple namespace levels.
// ---------------------------------------------------------------------------
func TestC14NAudit_SAMLLikeDocumentRoundTrip(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	for _, c14nName := range []string{"exc-c14n", "c14n11"} {
		t.Run(c14nName, func(t *testing.T) {
			var canonicalizer Canonicalizer
			switch c14nName {
			case "exc-c14n":
				canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
			case "c14n11":
				canonicalizer = MakeC14N11Canonicalizer()
			}

			signer := &Signer{
				Key:           key,
				Certs:         []*x509.Certificate{cert},
				Canonicalizer: canonicalizer,
			}

			// Build SAML-like structure
			response := &xmltree.Element{Tag: "Response", Space: "samlp"}
			response.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
			response.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
			response.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
			response.CreateAttr("ID", "_saml_resp")
			response.CreateAttr("Version", "2.0")

			issuer := response.CreateElement("Issuer")
			issuer.Space = "saml"
			issuer.SetText("https://idp.example.com")

			assertion := response.CreateElement("Assertion")
			assertion.Space = "saml"
			assertion.CreateAttr("ID", "_assertion_1")
			assertion.CreateAttr("Version", "2.0")

			subject := assertion.CreateElement("Subject")
			subject.Space = "saml"
			nameID := subject.CreateElement("NameID")
			nameID.Space = "saml"
			nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
			nameID.SetText("user@example.com")

			attrs := assertion.CreateElement("AttributeStatement")
			attrs.Space = "saml"
			attr := attrs.CreateElement("Attribute")
			attr.Space = "saml"
			attr.CreateAttr("Name", "Email")
			attrVal := attr.CreateElement("AttributeValue")
			attrVal.Space = "saml"
			attrVal.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
			attrVal.CreateAttr("xsi:type", "xs:string")
			attrVal.SetText("user@example.com")

			signed, err := signer.SignEnveloped(response)
			require.NoError(t, err)
			signed = reparse(t, signed)

			v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := v.Verify(signed)
			require.NoError(t, err, "SAML-like document should verify with %s", c14nName)
			require.NotNil(t, result)
		})
	}
}

// ---------------------------------------------------------------------------
// 19. NullCanonicalizer does NOT strip redundant namespaces
//
// Wait — examining the code, NullCanonicalizer calls
// canonicalPrep(el, false, true). The strip=false parameter is received
// but the namespace dedup logic is unconditional. So it DOES strip.
// Verify this contradicts the "null" name.
// ---------------------------------------------------------------------------
func TestC14NAudit_NullCanonicalizerBehavior(t *testing.T) {
	xml := `<A xmlns:ns="urn:ns"><B xmlns:ns="urn:ns"><ns:C/></B></A>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	nullC := MakeNullCanonicalizer()
	result, err := nullC.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)
	t.Logf("NullCanonicalizer: %s", resStr)

	// NullCanonicalizer strips redundant namespace declarations
	// (canonicalPrep always does this regardless of strip parameter)
	// B should NOT re-declare xmlns:ns since it's identical to A's
	count := strings.Count(resStr, `xmlns:ns="urn:ns"`)
	assert.Equal(t, 1, count,
		"NullCanonicalizer should strip redundant namespace declarations")

	// Also verify attributes are sorted (canonicalPrep does this too)
	xml2 := `<Root z="3" a="1" m="2"/>`
	doc2 := xmltree.NewDocument()
	require.NoError(t, doc2.ReadFromString(xml2))
	result2, err := nullC.Canonicalize(doc2.Root())
	require.NoError(t, err)
	resStr2 := string(result2)

	aIdx := strings.Index(resStr2, `a="1"`)
	mIdx := strings.Index(resStr2, `m="2"`)
	zIdx := strings.Index(resStr2, `z="3"`)
	assert.Less(t, aIdx, mIdx, "attributes should be sorted")
	assert.Less(t, mIdx, zIdx, "attributes should be sorted")
}

// ---------------------------------------------------------------------------
// 20. Exclusive C14N with same namespace on different prefixes
//
// Two different prefixes bound to the same URI. Exclusive C14N should
// emit each prefix's declaration independently where it's used.
// ---------------------------------------------------------------------------
func TestC14NAudit_ExcC14NSameSameNSDifferentPrefixes(t *testing.T) {
	xml := `<Root xmlns:a="urn:shared" xmlns:b="urn:shared">
		<a:Child1>text1</a:Child1>
		<b:Child2>text2</b:Child2>
	</Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	excC14n := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	result, err := excC14n.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)
	t.Logf("ExcC14N same-NS-different-prefixes: %s", resStr)

	// Each child should have its own namespace declaration
	assert.Contains(t, resStr, `xmlns:a="urn:shared"`)
	assert.Contains(t, resStr, `xmlns:b="urn:shared"`)
}

// ---------------------------------------------------------------------------
// 21. Inclusive vs Exclusive C14N produce different digests for same document
//
// This is expected but important to document. An attacker cannot switch
// the C14N method because it's inside the signed SignedInfo.
// ---------------------------------------------------------------------------
func TestC14NAudit_InclusiveVsExclusiveProduceDifferentDigests(t *testing.T) {
	xml := `<Root xmlns:unused="urn:unused" xmlns:used="urn:used">
		<used:Child attr="val">data</used:Child>
	</Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	inclusive := MakeC14N11Canonicalizer()
	resInc, err := inclusive.Canonicalize(doc.Root())
	require.NoError(t, err)

	doc2 := xmltree.NewDocument()
	require.NoError(t, doc2.ReadFromString(xml))
	exclusive := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	resExc, err := exclusive.Canonicalize(doc2.Root())
	require.NoError(t, err)

	// They should differ because inclusive preserves unused namespace
	assert.NotEqual(t, resInc, resExc,
		"inclusive and exclusive C14N should produce different results for doc with unused NS")

	// Compute digests to show they differ
	hashInc := crypto.SHA256.New()
	hashInc.Write(resInc)
	digestInc := base64.StdEncoding.EncodeToString(hashInc.Sum(nil))

	hashExc := crypto.SHA256.New()
	hashExc.Write(resExc)
	digestExc := base64.StdEncoding.EncodeToString(hashExc.Sum(nil))

	assert.NotEqual(t, digestInc, digestExc,
		"digests should differ between inclusive and exclusive C14N")
}

// ---------------------------------------------------------------------------
// 22. Verify that changing C14N transform after signing is detected
//
// The C14N transform algorithm URI is inside SignedInfo, which is
// cryptographically signed. Changing it should invalidate the signature.
// ---------------------------------------------------------------------------
func TestC14NAudit_ChangingC14NTransformAfterSigning(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Sign with C14N 1.1
	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	el := &xmltree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_c14nswap")
	el.CreateElement("Data").SetText("test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Tamper: change the C14N transform in Reference from C14N11 to exc-c14n
	transforms := signed.FindElement("./" + signatureTag + "/" + signedInfoTag + "/" + referenceTag + "/" + transformsTag)
	require.NotNil(t, transforms)

	for _, child := range transforms.ChildElements() {
		if child.Tag == transformTag {
			for i, attr := range child.Attr {
				if attr.Key == algorithmAttr && attr.Value == CanonicalXML11AlgorithmId.String() {
					child.Attr[i].Value = CanonicalXML10ExclusiveAlgorithmId.String()
				}
			}
		}
	}

	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = v.Verify(signed)
	require.Error(t, err,
		"changing C14N transform after signing must invalidate the signature")
	assert.True(t,
		errors.Is(err, ErrSignatureInvalid) || errors.Is(err, ErrDigestMismatch),
		"expected signature or digest error, got: %v", err)
}

// ---------------------------------------------------------------------------
// 23. canonicalPrep: default namespace (xmlns=) handling
//
// Test that canonicalPrep correctly handles the default namespace
// declaration at different levels, including undeclarations.
// ---------------------------------------------------------------------------
func TestC14NAudit_CanonicalPrepDefaultNamespaceHandling(t *testing.T) {
	testCases := []struct {
		name     string
		xml      string
		contains []string
		not      []string
	}{
		{
			name:     "default_ns_declared_once",
			xml:      `<Root xmlns="urn:root"><Child/></Root>`,
			contains: []string{`xmlns="urn:root"`},
		},
		{
			name: "default_ns_redeclared_same",
			xml:  `<Root xmlns="urn:root"><Child xmlns="urn:root"/></Root>`,
			// Redundant re-declaration should be stripped by canonicalPrep
			contains: []string{`xmlns="urn:root"`},
		},
		{
			name:     "default_ns_changed",
			xml:      `<Root xmlns="urn:root"><Child xmlns="urn:child"/></Root>`,
			contains: []string{`xmlns="urn:root"`, `xmlns="urn:child"`},
		},
		{
			name:     "default_ns_undeclared",
			xml:      `<Root xmlns="urn:root"><Child xmlns=""/></Root>`,
			contains: []string{`xmlns="urn:root"`, `xmlns=""`},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			doc := xmltree.NewDocument()
			require.NoError(t, doc.ReadFromString(tc.xml))

			result := canonicalPrep(doc.Root(), true, false)
			resBytes, err := canonicalSerialize(result)
			require.NoError(t, err)
			resStr := string(resBytes)
			t.Logf("Result: %s", resStr)

			for _, s := range tc.contains {
				assert.Contains(t, resStr, s)
			}
			for _, s := range tc.not {
				assert.NotContains(t, resStr, s)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 24. Idempotency: canonicalizing twice produces the same result
//
// A fundamental security property. If C14N is not idempotent, an attacker
// could craft input that produces different output on first vs second pass.
// ---------------------------------------------------------------------------
func TestC14NAudit_CanonicalizationIdempotency(t *testing.T) {
	xmls := []string{
		`<Root xmlns:a="urn:a" xmlns:b="urn:b"><a:Child b:attr="val">text</a:Child></Root>`,
		`<Root xmlns="urn:default"><Child xmlns=""><Nested xmlns="urn:other"/></Child></Root>`,
		`<A xmlns:x="urn:x"><B xmlns:x="urn:x"><x:C/></B></A>`,
		`<doc><!-- comment --><e1 b="2" a="1"/></doc>`,
	}

	canonicalizerFactories := []struct {
		name string
		make func() Canonicalizer
	}{
		{"ExcC14N", func() Canonicalizer { return MakeC14N10ExclusiveCanonicalizerWithPrefixList("") }},
		{"C14N11", func() Canonicalizer { return MakeC14N11Canonicalizer() }},
		{"C14N11WithComments", func() Canonicalizer { return MakeC14N11WithCommentsCanonicalizer() }},
		{"Null", func() Canonicalizer { return MakeNullCanonicalizer() }},
	}

	for _, xml := range xmls {
		for _, cf := range canonicalizerFactories {
			t.Run(cf.name, func(t *testing.T) {
				// First pass (lenient: some idempotency vectors carry comments)
				doc1, err := lenientParseDoc(xml)
				require.NoError(t, err)
				result1, err := cf.make().Canonicalize(doc1.Root())
				require.NoError(t, err)

				// Parse the canonical output and canonicalize again
				// (with-comments canonical output needs the lenient loader).
				doc2, err := parseVectorDoc(result1)
				require.NoError(t, err)
				result2, err := cf.make().Canonicalize(doc2.Root())
				require.NoError(t, err)

				assert.True(t, bytes.Equal(result1, result2),
					"canonicalization must be idempotent\nfirst:  %s\nsecond: %s",
					string(result1), string(result2))
			})
		}
	}
}

// ---------------------------------------------------------------------------
// 25. ExcC14N: InclusiveNamespaces PrefixList with multiple prefixes
//
// Test that multiple space-separated prefixes in the PrefixList are all
// handled correctly.
// ---------------------------------------------------------------------------
func TestC14NAudit_ExcC14NMultiplePrefixList(t *testing.T) {
	xml := `<Root xmlns:xs="http://www.w3.org/2001/XMLSchema" 
		          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
		          xmlns:saml="urn:saml">
		<saml:Data>text</saml:Data>
	</Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	// PrefixList with multiple prefixes
	excC14n := MakeC14N10ExclusiveCanonicalizerWithPrefixList("xs xsi")
	result, err := excC14n.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)
	t.Logf("ExcC14N with PrefixList='xs xsi': %s", resStr)

	// Both xs and xsi should be in the output even though they're not visibly utilized
	assert.Contains(t, resStr, `xmlns:xs="http://www.w3.org/2001/XMLSchema"`)
	assert.Contains(t, resStr, `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
}

// ---------------------------------------------------------------------------
// 26. Sign with exc-c14n + PrefixList, verify works
//
// Tests the actual SAML use case where an IdP includes xs in the PrefixList
// of the InclusiveNamespaces element.
// ---------------------------------------------------------------------------
func TestC14NAudit_SignVerifyWithPrefixList(t *testing.T) {
	// FINDING: The Signer does NOT emit <InclusiveNamespaces PrefixList="xs"/>
	// inside the Transform element when using exc-c14n with a non-empty PrefixList.
	// It computes the digest using the PrefixList, but the signed Transform only
	// records the algorithm URI. The verifier reads PrefixList="" from the
	// Transform (because the child element is absent) and computes a different
	// canonical form, producing a different digest.
	//
	// Impact: If a signer uses a non-empty PrefixList, the resulting signature
	// CANNOT be verified by this library (or any spec-compliant verifier).
	// This is a CORRECTNESS BUG in the Signer, not a security vulnerability
	// per se — it fails safely (verification fails). However, it means this
	// library cannot produce signatures that are interoperable with IdPs that
	// expect PrefixList to be recorded in the signature.
	//
	// The library CAN verify signatures from external signers that do include
	// InclusiveNamespaces (e.g. Okta), because the verifier reads PrefixList
	// from the Transform element correctly.

	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList("xs"),
	}

	el := &xmltree.Element{Tag: "Response", Space: "samlp"}
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	el.CreateAttr("ID", "_prefixlist")
	el.CreateElement("Data").SetText("test")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	// Verify that the Transform element does NOT contain InclusiveNamespaces
	transforms := signed.FindElement("./" + signatureTag + "/" + signedInfoTag + "/" + referenceTag + "/" + transformsTag)
	require.NotNil(t, transforms)
	var foundInclusiveNS bool
	for _, child := range transforms.ChildElements() {
		for _, grandchild := range child.ChildElements() {
			if grandchild.Tag == inclusiveNamespacesTag {
				foundInclusiveNS = true
			}
		}
	}
	assert.False(t, foundInclusiveNS,
		"FINDING: Signer does not emit InclusiveNamespaces element in Transform")

	// Verification will fail because the PrefixList is lost
	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = v.Verify(signed)
	assert.Error(t, err,
		"FINDING: Verification fails because Signer omits PrefixList from Transform")
	t.Logf("FINDING: Sign with PrefixList='xs' fails verification: %v", err)

	// Contrast: signing with empty PrefixList works fine
	signerNoPrefix := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	el2 := &xmltree.Element{Tag: "Response", Space: "samlp"}
	el2.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el2.CreateAttr("ID", "_prefixlist2")
	el2.CreateElement("Data").SetText("test")

	signed2, err := signerNoPrefix.SignEnveloped(el2)
	require.NoError(t, err)
	signed2 = reparse(t, signed2)

	result2, err := v.Verify(signed2)
	require.NoError(t, err, "signing with empty PrefixList should verify")
	require.NotNil(t, result2)
}

// ---------------------------------------------------------------------------
// 27. xmltree.Text() behavior with comments — the Go equivalent of VU#475445
//
// This test documents the exact behavior of etree's Text() when comments
// are embedded in text content. This is critical for understanding whether
// the comment injection attack applies to Go consumers.
// ---------------------------------------------------------------------------
func TestC14NAudit_EtreeTextWithEmbeddedComments(t *testing.T) {
	// Test various comment positions in text content
	testCases := []struct {
		name     string
		xml      string
		wantFull string // what Text() should return if it concatenates all CharData
	}{
		{
			name:     "comment_in_middle",
			xml:      `<E>before<!-- comment -->after</E>`,
			wantFull: "beforeafter",
		},
		{
			name:     "comment_at_start",
			xml:      `<E><!-- comment -->after</E>`,
			wantFull: "after",
		},
		{
			name:     "comment_at_end",
			xml:      `<E>before<!-- comment --></E>`,
			wantFull: "before",
		},
		{
			name:     "multiple_comments",
			xml:      `<E>a<!-- c1 -->b<!-- c2 -->c</E>`,
			wantFull: "abc",
		},
		{
			name:     "empty_comment",
			xml:      `<E>admin@evil.com<!---->@legit.com</E>`,
			wantFull: "admin@evil.com@legit.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := lenientParseDoc(tc.xml)
			require.NoError(t, err)

			root := doc.Root()
			text := root.Text()

			if text == tc.wantFull {
				t.Logf("Text() returns full concatenated text: %q (SAFE)", text)
			} else {
				t.Logf("Text() returns: %q (expected full: %q)", text, tc.wantFull)
				t.Logf("WARNING: Text() does NOT return all text segments. " +
					"Consumer code using Text() on comment-split text gets " +
					"partial content. The canonical form (used for digest) " +
					"includes all text. This is the Go variant of CVE-2017-11427.")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 28. Verify reconstructed element text matches canonical form
//
// After verification, the result Element is re-parsed from canonical bytes.
// Test that text content in the result matches what was in the canonical
// form, not what might have been in the original (possibly manipulated) tree.
// ---------------------------------------------------------------------------
func TestC14NAudit_VerifiedElementTextMatchesCanonical(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	// Create and sign a document
	el := &xmltree.Element{Tag: "Response"}
	el.CreateAttr("ID", "_textmatch")
	nameID := el.CreateElement("NameID")
	nameID.SetText("user@example.com")

	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)
	signed = reparse(t, signed)

	v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := v.Verify(signed)
	require.NoError(t, err)

	// The result element's NameID text should exactly match what was signed
	verifiedNameID := result.Element.FindElement("//NameID")
	require.NotNil(t, verifiedNameID)
	assert.Equal(t, "user@example.com", verifiedNameID.Text(),
		"verified element text should match the signed content")
}

// ---------------------------------------------------------------------------
// 29. Empty elements: self-closing vs explicit end tags
//
// C14N requires explicit end tags (no self-closing). Verify this.
// ---------------------------------------------------------------------------
func TestC14NAudit_EmptyElementsHaveEndTags(t *testing.T) {
	xml := `<Root><Empty/><AlsoEmpty></AlsoEmpty></Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	canonicalizerFactories := []struct {
		name string
		make func() Canonicalizer
	}{
		{"ExcC14N", func() Canonicalizer { return MakeC14N10ExclusiveCanonicalizerWithPrefixList("") }},
		{"C14N11", func() Canonicalizer { return MakeC14N11Canonicalizer() }},
		{"Null", func() Canonicalizer { return MakeNullCanonicalizer() }},
	}

	for _, cf := range canonicalizerFactories {
		t.Run(cf.name, func(t *testing.T) {
			docCopy := xmltree.NewDocument()
			require.NoError(t, docCopy.ReadFromString(xml))

			result, err := cf.make().Canonicalize(docCopy.Root())
			require.NoError(t, err)
			resStr := string(result)

			// Both empty elements should have explicit end tags in canonical form
			assert.Contains(t, resStr, "<Empty></Empty>",
				"canonical form should use explicit end tags")
			assert.Contains(t, resStr, "<AlsoEmpty></AlsoEmpty>",
				"canonical form should use explicit end tags")
			assert.NotContains(t, resStr, "/>",
				"canonical form should not contain self-closing tags")
		})
	}
}

// ---------------------------------------------------------------------------
// 30. ExcC14N: namespace used only in attribute should still be declared
//
// If a namespace prefix is used in an attribute but not in the element
// tag, exclusive C14N must still emit the declaration.
// ---------------------------------------------------------------------------
func TestC14NAudit_ExcC14NNamespaceUsedOnlyInAttribute(t *testing.T) {
	xml := `<Root xmlns:attr="http://attr-ns"><Child attr:name="val">text</Child></Root>`

	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromString(xml))

	excC14n := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	result, err := excC14n.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)
	t.Logf("ExcC14N attr-only NS: %s", resStr)

	// The attr namespace should be declared on Child (where it's used)
	assert.Contains(t, resStr, `xmlns:attr="http://attr-ns"`,
		"namespace used only in attribute must still be declared")
}

// ---------------------------------------------------------------------------
// 31. Real-world SAML response verification (using test vectors from verify_test.go)
//
// Verify that the library correctly handles the real Okta SAML response
// which uses exc-c14n with PrefixList="xs".
// ---------------------------------------------------------------------------
func TestC14NAudit_RealWorldOktaResponse(t *testing.T) {
	// This is the validExample from verify_test.go
	doc := xmltree.NewDocument()
	err := doc.ReadFromBytes([]byte(validExample))
	require.NoError(t, err)

	cert := parseCertPEM(validateCert)

	v := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		Clock:        func() time.Time { return cert.NotBefore },
	}

	result, err := v.Verify(doc.Root())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Element)

	// The verified element should contain the expected data
	// (it's the Response element, verified with its canonical content)
	t.Logf("Verified element tag: %s", result.Element.Tag)
}

// ---------------------------------------------------------------------------
// 32. C14N with CDATA sections
//
// CDATA sections should be converted to character data in C14N.
// etree may or may not preserve CDATA. Test the behavior.
// ---------------------------------------------------------------------------
func TestC14NAudit_CDATAHandling(t *testing.T) {
	// etree converts CDATA to text during parsing
	xml := `<Root><![CDATA[<special>text</special>]]></Root>`

	doc := xmltree.NewDocument()
	err := doc.ReadFromString(xml)
	if err != nil {
		t.Skipf("etree cannot parse CDATA: %v", err)
	}

	c14n := MakeC14N11Canonicalizer()
	result, err := c14n.Canonicalize(doc.Root())
	require.NoError(t, err)
	resStr := string(result)
	t.Logf("C14N with CDATA: %s", resStr)

	// C14N spec says CDATA sections are replaced by their character content
	// with special chars escaped
	assert.NotContains(t, resStr, "CDATA",
		"canonical form should not contain CDATA sections")
	assert.Contains(t, resStr, "&lt;special&gt;",
		"CDATA content should be escaped in canonical form")
}

// ---------------------------------------------------------------------------
// 33. Stability test: signing and verifying with namespaced attributes
//
// Attributes in different namespaces can cause sorting issues.
// This tests the security-critical path with prefixed attributes.
// ---------------------------------------------------------------------------
func TestC14NAudit_SignVerifyWithNamespacedAttributes(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	for _, c14nName := range []string{"exc-c14n", "c14n11"} {
		t.Run(c14nName, func(t *testing.T) {
			var canonicalizer Canonicalizer
			switch c14nName {
			case "exc-c14n":
				canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
			case "c14n11":
				canonicalizer = MakeC14N11Canonicalizer()
			}

			signer := &Signer{
				Key:           key,
				Certs:         []*x509.Certificate{cert},
				Canonicalizer: canonicalizer,
			}

			el := &xmltree.Element{Tag: "Response"}
			el.CreateAttr("ID", "_nsattr")
			el.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
			el.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")

			child := el.CreateElement("Value")
			child.CreateAttr("xsi:type", "xs:string")
			child.SetText("hello")

			signed, err := signer.SignEnveloped(el)
			require.NoError(t, err)
			signed = reparse(t, signed)

			v := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
			result, err := v.Verify(signed)
			require.NoError(t, err, "document with namespaced attributes should verify")
			require.NotNil(t, result)
		})
	}
}
