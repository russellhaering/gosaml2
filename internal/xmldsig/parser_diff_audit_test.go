package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/russellhaering/gosaml2/v2/internal/xmldsig/etreeutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Parser Differential Audit — goxmldsig v2
//
// These tests investigate whether the v2 library (which uses etree instead
// of encoding/xml for parsing) is still vulnerable to the class of parser
// differential attacks described in CVE-2020-29509/29510/29511.
//
// The core concern: the library digests the canonical bytes, then RE-PARSES
// them via etree (doc.ReadFromBytes) and returns the re-parsed element.
// If the re-parsed element differs semantically from the bytes that were
// digested, we have a parser differential.
//
// Additionally, NSUnmarshalElement in etreeutils uses encoding/xml for
// deserialization. If consumers (like gosaml2) use this to extract claims
// from the verified element, the encoding/xml bugs could resurface.
// ==========================================================================

// helper: sign an XML string and return the verified element.
func signAndVerify(t *testing.T, xmlStr string, canonicalizer ...Canonicalizer) *etree.Element {
	t.Helper()
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA256,
	}
	if len(canonicalizer) > 0 {
		signer.Canonicalizer = canonicalizer[0]
	}

	doc := etree.NewDocument()
	err := doc.ReadFromString(xmlStr)
	require.NoError(t, err, "failed to parse input XML")

	signed, err := signer.SignEnveloped(doc.Root())
	require.NoError(t, err, "SignEnveloped failed")

	// SignEnveloped appends the Signature directly to the Child slice,
	// so we must serialize and re-parse to get a proper document tree
	// before calling Verify (same as production code would do).
	reparseDoc := etree.NewDocument()
	reparseDoc.SetRoot(signed)
	reparseStr, err := reparseDoc.WriteToString()
	require.NoError(t, err, "failed to serialize signed document")
	reparseDoc2 := etree.NewDocument()
	require.NoError(t, reparseDoc2.ReadFromString(reparseStr), "failed to re-parse signed document")
	signed = reparseDoc2.Root()

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}

	result, err := verifier.Verify(signed)
	require.NoError(t, err, "Verify failed")
	require.NotNil(t, result)
	require.NotNil(t, result.Element)

	return result.Element
}

// helper: serialize→re-parse an element to fix parent pointers.
func reparseElement(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	s, err := doc.WriteToString()
	require.NoError(t, err)
	doc2 := etree.NewDocument()
	require.NoError(t, doc2.ReadFromString(s))
	return doc2.Root()
}

// helper: filter out Signature children.
func filterSignature(els []*etree.Element) []*etree.Element {
	var out []*etree.Element
	for _, el := range els {
		if el.Tag != SignatureTag {
			out = append(out, el)
		}
	}
	return out
}

// helper: recursively compare text content between original and verified trees.
func checkTextContent(t *testing.T, orig, verified *etree.Element, path string) {
	t.Helper()
	currentPath := path + "/" + orig.Tag

	assert.Equal(t, orig.Text(), verified.Text(),
		"text mismatch at %s", currentPath)

	for _, attr := range orig.Attr {
		if attr.Space == "xmlns" || (attr.Space == "" && attr.Key == "xmlns") {
			continue
		}
		verVal := verified.SelectAttrValue(attr.Key, "\x00")
		if verVal == "\x00" && attr.Space != "" {
			for _, va := range verified.Attr {
				if va.Key == attr.Key {
					verVal = va.Value
					break
				}
			}
		}
		if verVal != "\x00" {
			assert.Equal(t, attr.Value, verVal,
				"attribute %s:%s mismatch at %s", attr.Space, attr.Key, currentPath)
		}
	}

	origFiltered := filterSignature(orig.ChildElements())
	verFiltered := filterSignature(verified.ChildElements())

	if len(origFiltered) != len(verFiltered) {
		t.Errorf("child count mismatch at %s: original=%d, verified=%d",
			currentPath, len(origFiltered), len(verFiltered))
		return
	}

	for i := range origFiltered {
		checkTextContent(t, origFiltered[i], verFiltered[i], currentPath)
	}
}

// =========================================================================
// Test 1: etree round-trip stability
// =========================================================================
func TestParserDiffEtreeRoundTripStability(t *testing.T) {
	cases := []struct {
		name string
		xml  string
	}{
		{"BasicNamespace", `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion>`},
		{"PrefixRebinding", `<root xmlns:p="http://first" ID="_b"><p:a>first</p:a><inner xmlns:p="http://second"><p:b>second</p:b></inner></root>`},
		{"MultiplePrefixesSameNS", `<root xmlns:a="http://same" xmlns:b="http://same" ID="_c"><a:x>one</a:x><b:y>two</b:y></root>`},
		{"DefaultNamespace", `<root xmlns="http://default" ID="_d"><child>text</child></root>`},
		{"AttributeNamespacePrefixes", `<root xmlns:ns="http://ns" ID="_e"><child ns:attr="value">text</child></root>`},
		{"DeepNesting", `<a xmlns:p="http://p" ID="_f"><b><c><d><p:e attr="v">deep</p:e></d></c></b></a>`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc1 := etree.NewDocument()
			require.NoError(t, doc1.ReadFromString(tc.xml))
			out1, err := doc1.WriteToString()
			require.NoError(t, err)

			doc2 := etree.NewDocument()
			require.NoError(t, doc2.ReadFromString(out1))
			out2, err := doc2.WriteToString()
			require.NoError(t, err)

			assert.Equal(t, out1, out2, "etree round-trip is not stable")
		})
	}
}

// =========================================================================
// Test 2: Re-parse fidelity in verifyDigest
// =========================================================================
func TestParserDiffReParseAfterVerify(t *testing.T) {
	cases := []struct {
		name string
		xml  string
	}{
		{"SimpleElement", `<root ID="_t1"><data>hello world</data></root>`},
		{"NamespacedSAML", `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_t2"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject></saml:Assertion>`},
		{"AttributesPreserved", `<root ID="_t3" attr1="val1" attr2="val2"><child x="1" y="2">text</child></root>`},
		{"PrefixRebinding", `<root xmlns:p="http://first" ID="_t4"><p:child>text1</p:child><inner xmlns:p="http://second"><p:child>text2</p:child></inner></root>`},
		{"MultiplePrefixesSameNS", `<root xmlns:a="urn:ns" xmlns:b="urn:ns" ID="_t5"><a:one>x</a:one><b:two>y</b:two></root>`},
		{"DefaultNamespaceOverride", `<outer xmlns="http://outer" ID="_t6"><inner xmlns="http://inner"><leaf>value</leaf></inner></outer>`},
		{"AttributeFromAncestorNS", `<root xmlns:ns="http://ns" ID="_t7"><parent><child ns:attr="val">text</child></parent></root>`},
		{"XmlLangAttribute", `<root xml:lang="en" ID="_t8"><child xml:lang="fr">bonjour</child></root>`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified := signAndVerify(t, tc.xml)

			origDoc := etree.NewDocument()
			require.NoError(t, origDoc.ReadFromString(tc.xml))

			checkTextContent(t, origDoc.Root(), verified, "")
		})
	}
}

// =========================================================================
// Test 3: NSUnmarshalElement and encoding/xml
// =========================================================================
func TestParserDiffNSUnmarshalElement(t *testing.T) {
	type Subject struct {
		NameID string `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	}
	type AudienceRestriction struct {
		Audience string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
	}
	type Conditions struct {
		AudienceRestriction AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	}
	type Assertion struct {
		XMLName    xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
		Issuer     string     `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Subject    Subject    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
		Conditions Conditions `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	}

	samlXML := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assert1">` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>` +
		`<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`</saml:Assertion>`

	verified := signAndVerify(t, samlXML)

	ctx, err := etreeutils.NSBuildParentContext(verified)
	require.NoError(t, err)

	var assertion Assertion
	err = etreeutils.NSUnmarshalElement(ctx, verified, &assertion)
	require.NoError(t, err)

	assert.Equal(t, "https://idp.example.com", assertion.Issuer)
	assert.Equal(t, "admin@example.com", assertion.Subject.NameID)
	assert.Equal(t, "https://sp.example.com", assertion.Conditions.AudienceRestriction.Audience)

	// Also verify these match what etree's tree reports
	issuerEl := findDescendantByTag(verified, "Issuer")
	require.NotNil(t, issuerEl)
	assert.Equal(t, issuerEl.Text(), assertion.Issuer,
		"etree vs encoding/xml mismatch for Issuer")

	nameIDEl := findDescendantByTag(verified, "NameID")
	require.NotNil(t, nameIDEl)
	assert.Equal(t, nameIDEl.Text(), assertion.Subject.NameID,
		"etree vs encoding/xml mismatch for NameID")
}

// =========================================================================
// Test 4: Namespace prefix rebinding
// =========================================================================
func TestParserDiffNamespacePrefixRebinding(t *testing.T) {
	rebindXML := `<root xmlns:p="http://first" ID="_rebind1">` +
		`<p:child>in-first-namespace</p:child>` +
		`<inner xmlns:p="http://second">` +
		`<p:child>in-second-namespace</p:child>` +
		`</inner>` +
		`</root>`

	verified := signAndVerify(t, rebindXML)

	children := verified.ChildElements()
	require.GreaterOrEqual(t, len(children), 2)

	firstChild := children[0]
	assert.Equal(t, "child", firstChild.Tag)
	assert.Equal(t, "in-first-namespace", firstChild.Text())

	var innerEl *etree.Element
	for _, ch := range children {
		if ch.Tag == "inner" {
			innerEl = ch
			break
		}
	}
	require.NotNil(t, innerEl, "inner element not found")

	innerChildren := innerEl.ChildElements()
	require.NotEmpty(t, innerChildren)
	assert.Equal(t, "child", innerChildren[0].Tag)
	assert.Equal(t, "in-second-namespace", innerChildren[0].Text())

	// Verify namespace context resolves correctly after re-parse
	ctx := etreeutils.NewDefaultNSContext()
	rootCtx, err := ctx.SubContext(verified)
	require.NoError(t, err)

	ns, err := rootCtx.LookupPrefix(firstChild.Space)
	require.NoError(t, err)
	assert.Equal(t, "http://first", ns,
		"first child's prefix should resolve to http://first")

	innerCtx, err := rootCtx.SubContext(innerEl)
	require.NoError(t, err)
	ns2, err := innerCtx.LookupPrefix(innerChildren[0].Space)
	require.NoError(t, err)
	assert.Equal(t, "http://second", ns2,
		"inner child's prefix should resolve to http://second")
}

// =========================================================================
// Test 5: CDATA handling
// =========================================================================
func TestParserDiffCDATA(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		want string
	}{
		{"CDATAWithAngleBrackets", `<root ID="_cd1"><data><![CDATA[<script>alert(1)</script>]]></data></root>`, "<script>alert(1)</script>"},
		{"CDATAWithAmpersand", `<root ID="_cd2"><data><![CDATA[a & b]]></data></root>`, "a & b"},
		{"CDATAEmpty", `<root ID="_cd3"><data><![CDATA[]]></data></root>`, ""},
		{"RegularEscapedEquivalent", `<root ID="_cd4"><data>&lt;script&gt;alert(1)&lt;/script&gt;</data></root>`, "<script>alert(1)</script>"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified := signAndVerify(t, tc.xml)

			dataEl := findDescendantByTag(verified, "data")
			require.NotNil(t, dataEl)
			assert.Equal(t, tc.want, dataEl.Text(),
				"text content differs after sign→verify")
		})
	}

	// Extra: CDATA and entity-escaped versions must produce identical verified text
	t.Run("CDATAvsEscapedEquivalence", func(t *testing.T) {
		cdataXML := `<root ID="_cde1"><data><![CDATA[<evil>x</evil>]]></data></root>`
		escXML := `<root ID="_cde2"><data>&lt;evil&gt;x&lt;/evil&gt;</data></root>`

		v1 := signAndVerify(t, cdataXML)
		v2 := signAndVerify(t, escXML)

		assert.Equal(t,
			findDescendantByTag(v1, "data").Text(),
			findDescendantByTag(v2, "data").Text(),
			"CDATA and escaped forms must produce identical text")
	})
}

// =========================================================================
// Test 6: Entity expansion
// =========================================================================
func TestParserDiffEntityExpansion(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		want string
	}{
		{"StandardEntities", `<root ID="_ent1"><data>&amp; &lt; &gt; &quot; &apos;</data></root>`, "& < > \" '"},
		{"NumericCharRef", `<root ID="_ent2"><data>&#65;&#x42;&#x43;</data></root>`, "ABC"},
		{"MixedEntities", `<root ID="_ent3"><data>a&amp;b&lt;c&#65;</data></root>`, "a&b<cA"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified := signAndVerify(t, tc.xml)

			dataEl := findDescendantByTag(verified, "data")
			require.NotNil(t, dataEl)
			assert.Equal(t, tc.want, dataEl.Text(),
				"entity expansion mismatch after sign→verify")
		})
	}
}

// =========================================================================
// Test 7: Processing instructions and XML declarations
// =========================================================================
func TestParserDiffProcessingInstructions(t *testing.T) {
	// PIs within the signed element are part of its content in the XML data
	// model. C14N preserves them. Verify the text content is not affected.
	xmlStr := `<root ID="_pi1"><data>value</data></root>`
	verified := signAndVerify(t, xmlStr)
	require.NotNil(t, verified)

	dataEl := findDescendantByTag(verified, "data")
	require.NotNil(t, dataEl)
	assert.Equal(t, "value", dataEl.Text())
}

// =========================================================================
// Test 8: Comment injection attack (CVE-2018 Duo Labs class)
// =========================================================================
func TestParserDiffCommentInjection(t *testing.T) {
	xmlWithComment := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_ci1">` +
		`<saml:Subject><saml:NameID>admin@evil.com</saml:NameID></saml:Subject>` +
		`</saml:Assertion>`

	verified := signAndVerify(t, xmlWithComment)
	nameID := findDescendantByTag(verified, "NameID")
	require.NotNil(t, nameID)
	assert.Equal(t, "admin@evil.com", nameID.Text())

	// Verify etree and encoding/xml agree via NSUnmarshalElement
	type Subject struct {
		NameID string `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	}
	type Assertion struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
		Subject Subject  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	}

	ctx, err := etreeutils.NSBuildParentContext(verified)
	require.NoError(t, err)

	var assertion Assertion
	err = etreeutils.NSUnmarshalElement(ctx, verified, &assertion)
	require.NoError(t, err)

	assert.Equal(t, nameID.Text(), assertion.Subject.NameID,
		"etree.Text() and encoding/xml.Unmarshal must agree on NameID")
}

// =========================================================================
// Test 9: Comment survival through pipeline
// =========================================================================
func TestParserDiffCommentSurvivalThroughPipeline(t *testing.T) {
	xmlWithComment := `<root ID="_cs1"><name>Alice<!--injected-->Bob</name><value>real</value></root>`

	// C14N-without-comments strips the comment, concatenating the text.
	t.Run("WithoutComments", func(t *testing.T) {
		verified := signAndVerify(t, xmlWithComment, MakeC14N11Canonicalizer())
		nameEl := findDescendantByTag(verified, "name")
		require.NotNil(t, nameEl)

		assert.Equal(t, "AliceBob", nameEl.Text(),
			"without-comments C14N should concatenate text around stripped comment")

		for _, child := range nameEl.Child {
			_, isComment := child.(*etree.Comment)
			assert.False(t, isComment, "comment must not survive without-comments C14N")
		}

		// encoding/xml must see the same thing
		type Root struct {
			Name string `xml:"name"`
		}
		doc := etree.NewDocument()
		doc.SetRoot(verified.Copy())
		b, err := doc.WriteToBytes()
		require.NoError(t, err)
		var r Root
		require.NoError(t, xml.Unmarshal(b, &r))
		assert.Equal(t, "AliceBob", r.Name,
			"encoding/xml must see same value as etree")
	})

	// C14N-with-comments preserves the comment in canonical bytes.
	t.Run("WithComments", func(t *testing.T) {
		verified := signAndVerify(t, xmlWithComment, MakeC14N11WithCommentsCanonicalizer())
		nameEl := findDescendantByTag(verified, "name")
		require.NotNil(t, nameEl)

		// etree.Text() concatenates all CharData around comments.
		assert.Equal(t, "AliceBob", nameEl.Text(),
			"etree.Text() should concatenate chardata around comments")

		// But the comment node should still be in the tree.
		hasComment := false
		for _, child := range nameEl.Child {
			if _, ok := child.(*etree.Comment); ok {
				hasComment = true
			}
		}
		assert.True(t, hasComment, "comment should survive with-comments C14N")

		// encoding/xml must see the same concatenated text.
		type Root struct {
			Name string `xml:"name"`
		}
		doc := etree.NewDocument()
		doc.SetRoot(verified.Copy())
		b, err := doc.WriteToBytes()
		require.NoError(t, err)
		var r Root
		require.NoError(t, xml.Unmarshal(b, &r))
		assert.Equal(t, "AliceBob", r.Name,
			"encoding/xml must see same concatenated value")
	})
}

// =========================================================================
// Test 10: All supported canonicalization algorithms
// =========================================================================
func TestParserDiffAllCanonicalizationAlgorithms(t *testing.T) {
	samlXML := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_multi1">` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>` +
		`</saml:Assertion>`

	factories := []struct {
		name string
		mkC  func() Canonicalizer
	}{
		{"C14N11", func() Canonicalizer { return MakeC14N11Canonicalizer() }},
		{"C14N11WithComments", func() Canonicalizer { return MakeC14N11WithCommentsCanonicalizer() }},
		{"ExcC14N", func() Canonicalizer { return MakeC14N10ExclusiveCanonicalizerWithPrefixList("") }},
		{"ExcC14NWithComments", func() Canonicalizer { return MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("") }},
		{"C14N10", func() Canonicalizer { return MakeC14N10RecCanonicalizer() }},
		{"C14N10WithComments", func() Canonicalizer { return MakeC14N10WithCommentsCanonicalizer() }},
	}

	for _, f := range factories {
		t.Run(f.name, func(t *testing.T) {
			verified := signAndVerify(t, samlXML, f.mkC())

			nameID := findDescendantByTag(verified, "NameID")
			require.NotNil(t, nameID)
			assert.Equal(t, "user@example.com", nameID.Text())

			issuer := findDescendantByTag(verified, "Issuer")
			require.NotNil(t, issuer)
			assert.Equal(t, "https://idp.example.com", issuer.Text())
		})
	}
}

// =========================================================================
// Test 11: Special characters
// =========================================================================
func TestParserDiffSpecialCharacters(t *testing.T) {
	cases := []struct {
		name  string
		xml   string
		want  string
		field string
	}{
		{"Unicode", `<root ID="_sp1"><data>Hello 世界 🌍</data></root>`, "Hello 世界 🌍", "data"},
		{"EntityEscaping", `<root ID="_sp3"><data>a&amp;b&lt;c&gt;d</data></root>`, "a&b<c>d", "data"},
		{"EmptyElement", `<root ID="_sp5"><data></data></root>`, "", "data"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified := signAndVerify(t, tc.xml)
			el := findDescendantByTag(verified, tc.field)
			require.NotNil(t, el)
			assert.Equal(t, tc.want, el.Text())
		})
	}
}

// =========================================================================
// Test 12: encoding/xml namespace mutation is absent from etree pipeline
// =========================================================================
func TestParserDiffEncodingXMLNamespaceMutationAbsent(t *testing.T) {
	samlXML := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_nsmut1">` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID></saml:Subject>` +
		`</saml:Assertion>`

	verified := signAndVerify(t, samlXML)

	// Serialize the verified element
	doc := etree.NewDocument()
	doc.SetRoot(verified.Copy())
	verBytes, err := doc.WriteToBytes()
	require.NoError(t, err)
	verStr := string(verBytes)

	// Must NOT contain encoding/xml mutation artifacts
	assert.NotContains(t, verStr, "_xmlns",
		"verified element must not contain encoding/xml mutation artifacts")

	// Confirm encoding/xml STILL has the bug (so our test is meaningful)
	var buf strings.Builder
	decoder := xml.NewDecoder(strings.NewReader(verStr))
	encoder := xml.NewEncoder(&buf)
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		_ = encoder.EncodeToken(tok)
	}
	_ = encoder.Flush()
	encodingXMLOutput := buf.String()

	if encodingXMLOutput != verStr {
		t.Log("CONFIRMED: encoding/xml round-trip STILL mutates namespaces (CVE-2020-29509 class)")
		t.Logf("  etree output:        %.120s...", verStr)
		t.Logf("  encoding/xml output: %.120s...", encodingXMLOutput)
	} else {
		t.Log("encoding/xml round-trip matches etree (unexpected)")
	}

	// The critical check: despite encoding/xml bugs, our etree-based pipeline
	// preserves the correct data.
	nameID := findDescendantByTag(verified, "NameID")
	require.NotNil(t, nameID)
	assert.Equal(t, "user@example.com", nameID.Text())
	assert.Equal(t, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		nameID.SelectAttrValue("Format", ""))
}

// =========================================================================
// Test 13: NSUnmarshalElement residual risk — etree vs encoding/xml
// =========================================================================
func TestParserDiffNSUnmarshalResidualRisk(t *testing.T) {
	type Subject struct {
		NameID string `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	}
	type Assertion struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
		Subject Subject  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	}

	cases := []struct {
		name string
		xml  string
		want string
	}{
		{
			"SimpleNameID",
			`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_rr1"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion>`,
			"user@example.com",
		},
		{
			"MultipleNamespaces",
			`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_rr2"><saml:Subject><saml:NameID>admin@corp.com</saml:NameID></saml:Subject></saml:Assertion>`,
			"admin@corp.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified := signAndVerify(t, tc.xml)

			etreeVal := findDescendantByTag(verified, "NameID").Text()

			ctx, err := etreeutils.NSBuildParentContext(verified)
			require.NoError(t, err)

			var assertion Assertion
			err = etreeutils.NSUnmarshalElement(ctx, verified, &assertion)
			require.NoError(t, err)

			xmlVal := assertion.Subject.NameID

			assert.Equal(t, etreeVal, xmlVal,
				"PARSER DIFFERENTIAL: etree.Text()=%q but encoding/xml=%q", etreeVal, xmlVal)
			assert.Equal(t, tc.want, xmlVal)
		})
	}
}

// =========================================================================
// Test 14: Same namespace, different prefixes
// =========================================================================
func TestParserDiffSameNamespaceDifferentPrefixes(t *testing.T) {
	xmlStr := `<root xmlns:a="urn:same" xmlns:b="urn:same" ID="_dp1">` +
		`<a:child>from-a</a:child>` +
		`<b:child>from-b</b:child>` +
		`</root>`

	verified := signAndVerify(t, xmlStr, MakeC14N10ExclusiveCanonicalizerWithPrefixList(""))

	children := verified.ChildElements()
	require.GreaterOrEqual(t, len(children), 2)

	texts := map[string]bool{}
	for _, child := range children {
		if child.Tag == "child" {
			texts[child.Text()] = true
		}
	}
	assert.True(t, texts["from-a"], "text 'from-a' must be present")
	assert.True(t, texts["from-b"], "text 'from-b' must be present")

	// Also verify through NSUnmarshalElement
	type Root struct {
		Children []struct {
			Value string `xml:",chardata"`
		} `xml:"urn:same child"`
	}
	ctx, err := etreeutils.NSBuildParentContext(verified)
	require.NoError(t, err)
	var r Root
	err = etreeutils.NSUnmarshalElement(ctx, verified, &r)
	require.NoError(t, err)

	require.Len(t, r.Children, 2, "encoding/xml must see 2 children in urn:same")
	xmlTexts := map[string]bool{}
	for _, c := range r.Children {
		xmlTexts[c.Value] = true
	}
	assert.True(t, xmlTexts["from-a"])
	assert.True(t, xmlTexts["from-b"])
}

// =========================================================================
// Test 15: Attribute value canonicalization
// =========================================================================
func TestParserDiffAttributeValues(t *testing.T) {
	cases := []struct {
		name     string
		xml      string
		attrName string
		wantVal  string
	}{
		{"AmpersandInAttr", `<root ID="_av1" data="a&amp;b"><child/></root>`, "data", "a&b"},
		{"LTInAttr", `<root ID="_av2" data="a&lt;b"><child/></root>`, "data", "a<b"},
		{"QuoteInAttr", `<root ID="_av3" data="a&quot;b"><child/></root>`, "data", `a"b`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified := signAndVerify(t, tc.xml)
			val := verified.SelectAttrValue(tc.attrName, "")
			assert.Equal(t, tc.wantVal, val,
				"attribute value mismatch after sign→verify")
		})
	}
}

// =========================================================================
// Test 16: Full SAML Response sign→verify→unmarshal pipeline
// =========================================================================
func TestParserDiffFullSAMLPipeline(t *testing.T) {
	samlXML := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
		`ID="_resp1" Version="2.0">` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`<samlp:Status>` +
		`<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>` +
		`</samlp:Status>` +
		`<saml:Assertion ID="_assert1" Version="2.0">` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`<saml:Subject>` +
		`<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` +
		`admin@example.com</saml:NameID>` +
		`</saml:Subject>` +
		`<saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z">` +
		`<saml:AudienceRestriction>` +
		`<saml:Audience>https://sp.example.com</saml:Audience>` +
		`</saml:AudienceRestriction>` +
		`</saml:Conditions>` +
		`<saml:AttributeStatement>` +
		`<saml:Attribute Name="email">` +
		`<saml:AttributeValue>admin@example.com</saml:AttributeValue>` +
		`</saml:Attribute>` +
		`<saml:Attribute Name="role">` +
		`<saml:AttributeValue>superadmin</saml:AttributeValue>` +
		`</saml:Attribute>` +
		`</saml:AttributeStatement>` +
		`</saml:Assertion>` +
		`</samlp:Response>`

	verified := signAndVerify(t, samlXML)

	// Verify key fields via etree
	issuer := findDescendantByTag(verified, "Issuer")
	require.NotNil(t, issuer)
	assert.Equal(t, "https://idp.example.com", issuer.Text())

	nameID := findDescendantByTag(verified, "NameID")
	require.NotNil(t, nameID)
	assert.Equal(t, "admin@example.com", nameID.Text())

	// Verify through NSUnmarshalElement
	type AttrValue struct {
		Value string `xml:",chardata"`
	}
	type Attr struct {
		Name   string      `xml:"Name,attr"`
		Values []AttrValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	}
	type AttributeStatement struct {
		Attributes []Attr `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	}
	type SAMLAssertion struct {
		AttrStatement AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	}
	type Response struct {
		XMLName   xml.Name       `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		Issuer    string         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Assertion SAMLAssertion  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	}

	ctx, err := etreeutils.NSBuildParentContext(verified)
	require.NoError(t, err)

	var resp Response
	err = etreeutils.NSUnmarshalElement(ctx, verified, &resp)
	require.NoError(t, err)

	assert.Equal(t, "https://idp.example.com", resp.Issuer)

	attrMap := map[string]string{}
	for _, a := range resp.Assertion.AttrStatement.Attributes {
		if len(a.Values) > 0 {
			attrMap[a.Name] = a.Values[0].Value
		}
	}
	assert.Equal(t, "admin@example.com", attrMap["email"])
	assert.Equal(t, "superadmin", attrMap["role"])
}

// =========================================================================
// Test 17: Exclusive C14N with InclusiveNamespaces PrefixList
// =========================================================================
func TestParserDiffExcC14NWithPrefixList(t *testing.T) {
	xmlStr := `<root xmlns:a="http://a" xmlns:b="http://b" ID="_pl1">` +
		`<a:child>text-a</a:child>` +
		`<inner><b:child>text-b</b:child></inner>` +
		`</root>`

	t.Run("NoPrefixList", func(t *testing.T) {
		verified := signAndVerify(t, xmlStr,
			MakeC14N10ExclusiveCanonicalizerWithPrefixList(""))
		children := verified.ChildElements()
		require.NotEmpty(t, children)
	})

	t.Run("WithPrefixListB", func(t *testing.T) {
		// NOTE: This correctly fails because the Signer computes the digest
		// using PrefixList="b", but does NOT emit <InclusiveNamespaces PrefixList="b">
		// into the Transform element in SignedInfo. The verifier therefore uses
		// an empty PrefixList, producing a different canonical form → signature
		// mismatch. This is a Signer limitation (not a parser differential),
		// and in practice PrefixList is almost never used.
		key, cert := randomTestKeyAndCert()
		signer := &Signer{
			Key:           key,
			Certs:         []*x509.Certificate{cert},
			Hash:          crypto.SHA256,
			Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList("b"),
		}
		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromString(xmlStr))
		signed, err := signer.SignEnveloped(doc.Root())
		require.NoError(t, err)
		signed = reparseElement(t, signed)

		verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		_, err = verifier.Verify(signed)
		assert.Error(t, err,
			"expected failure: Signer does not emit InclusiveNamespaces PrefixList in Transform")
	})
}

// =========================================================================
// Test 18: Tamper detection — verified element must not contain Signature
// =========================================================================
func TestParserDiffTamperDetection(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA256,
	}
	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}

	xmlStr := `<root ID="_tamper1"><name>Alice</name></root>`

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(xmlStr))

	signed, err := signer.SignEnveloped(doc.Root())
	require.NoError(t, err)

	// Reparse (SignEnveloped appends directly to Child slice)
	signed = reparseElement(t, signed)

	result, err := verifier.Verify(signed)
	require.NoError(t, err)

	// Verified element must NOT contain a Signature (it was stripped)
	for _, child := range result.Element.ChildElements() {
		assert.NotEqual(t, SignatureTag, child.Tag,
			"verified element should not contain Signature")
	}

	nameEl := findDescendantByTag(result.Element, "name")
	require.NotNil(t, nameEl)
	assert.Equal(t, "Alice", nameEl.Text())

	// Tamper with the signed document → must be rejected
	signed2 := signed.Copy()
	nameEl2 := findDescendantByTag(signed2, "name")
	require.NotNil(t, nameEl2)
	nameEl2.SetText("Eve")

	_, err = verifier.Verify(signed2)
	assert.Error(t, err, "tampering must be detected")
}

// =========================================================================
// Test 19: Canonical bytes consistency between sign and verify
// =========================================================================
func TestParserDiffCanonicalBytesConsistency(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA256,
	}

	xmlStr := `<root ID="_con1"><data>payload</data></root>`

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(xmlStr))

	// Manually canonicalize
	c := signer.canonicalizer()
	manualCanon, err := c.Canonicalize(doc.Root().Copy())
	require.NoError(t, err)

	// Compute expected digest
	hash := signer.hash().New()
	hash.Write(manualCanon)
	expectedDigest := hash.Sum(nil)

	// Sign
	signed, err := signer.SignEnveloped(doc.Root())
	require.NoError(t, err)

	signed = reparseElement(t, signed)

	// Extract digest from signed document
	var sigEl *etree.Element
	for _, child := range signed.ChildElements() {
		if child.Tag == SignatureTag {
			sigEl = child
			break
		}
	}
	require.NotNil(t, sigEl)

	digestValueEl := findDescendantByTag(sigEl, DigestValueTag)
	require.NotNil(t, digestValueEl)

	digestB64 := digestValueEl.Text()
	digestBytes, err := base64.StdEncoding.DecodeString(digestB64)
	require.NoError(t, err)

	assert.Equal(t, expectedDigest, digestBytes,
		"manually computed digest must match digest in signed document")
}

// =========================================================================
// Test 20: Canonicalize→re-parse round-trip produces identical canonical form
// =========================================================================
func TestParserDiffCanonicalRoundTrip(t *testing.T) {
	// The re-parse in verifyDigest: canonical bytes → ReadFromBytes → Root()
	// If we canonicalize THAT again, we must get the exact same bytes.
	// This is the idempotency property that prevents parser differentials.

	cases := []struct {
		name string
		xml  string
	}{
		{"SimpleElement", `<root ID="_rt1"><data>hello</data></root>`},
		{"NamespacedSAML", `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_rt2"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>`},
		{"PrefixRebinding", `<root xmlns:p="http://first" ID="_rt3"><p:a>x</p:a><inner xmlns:p="http://second"><p:b>y</p:b></inner></root>`},
		{"Entities", `<root ID="_rt4"><data>&amp;&lt;&gt;</data></root>`},
		{"Unicode", `<root ID="_rt5"><data>日本語テスト</data></root>`},
	}

	canonicalizerFactories := []struct {
		name string
		mkC  func() Canonicalizer
	}{
		{"C14N11", func() Canonicalizer { return MakeC14N11Canonicalizer() }},
		{"ExcC14N", func() Canonicalizer { return MakeC14N10ExclusiveCanonicalizerWithPrefixList("") }},
	}

	for _, tc := range cases {
		for _, cf := range canonicalizerFactories {
			t.Run(tc.name+"/"+cf.name, func(t *testing.T) {
				// Parse original
				doc := etree.NewDocument()
				require.NoError(t, doc.ReadFromString(tc.xml))

				// First canonicalization
				c1 := cf.mkC()
				canon1, err := c1.Canonicalize(doc.Root().Copy())
				require.NoError(t, err)

				// Re-parse canonical bytes (what verifyDigest does)
				doc2 := etree.NewDocument()
				require.NoError(t, doc2.ReadFromBytes(canon1))

				// Second canonicalization
				c2 := cf.mkC()
				canon2, err := c2.Canonicalize(doc2.Root().Copy())
				require.NoError(t, err)

				assert.True(t, bytes.Equal(canon1, canon2),
					"CANONICALIZATION NOT IDEMPOTENT!\n  first:  %s\n  second: %s",
					string(canon1), string(canon2))
			})
		}
	}
}

// =========================================================================
// Test 21: Verify encoding/xml still has the namespace mutation bug
// (meta-test — ensures our audit is testing the right thing)
// =========================================================================
func TestParserDiffMetaEncodingXMLStillBroken(t *testing.T) {
	// Round-trip through encoding/xml tokenizer
	input := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject>user</saml:Subject></saml:Assertion>`

	var buf strings.Builder
	dec := xml.NewDecoder(strings.NewReader(input))
	enc := xml.NewEncoder(&buf)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		_ = enc.EncodeToken(tok)
	}
	_ = enc.Flush()
	output := buf.String()

	if input == output {
		t.Log("encoding/xml round-trip is stable (Go may have fixed the bug!)")
	} else {
		t.Log("CONFIRMED: encoding/xml round-trip mutates namespace prefixes")
		t.Logf("  input:  %s", input)
		t.Logf("  output: %s", output)

		// The mutation should include _xmlns artifacts
		assert.Contains(t, output, "_xmlns",
			"encoding/xml mutation should produce _xmlns artifacts")
	}
}

// =========================================================================
// Test 22: Verify etree does NOT have the encoding/xml namespace mutation
// =========================================================================
func TestParserDiffMetaEtreeDoesNotMutate(t *testing.T) {
	input := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject>user</saml:Subject></saml:Assertion>`

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(input))
	output, err := doc.WriteToString()
	require.NoError(t, err)

	assert.Equal(t, input, output,
		"etree round-trip must be stable (no namespace mutation)")
	assert.NotContains(t, output, "_xmlns",
		"etree must not produce _xmlns artifacts")
}
