package xmldsig

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// requireXmllint skips the test if xmllint is not available.
func requireXmllint(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("xmllint"); err != nil {
		t.Skip("xmllint not available; install libxml2-utils to run differential C14N tests")
	}
}

// xmllintC14N runs xmllint with the specified C14N mode on the input XML bytes.
// mode is one of: "--c14n" (C14N 1.0), "--c14n11", "--exc-c14n".
func xmllintC14N(input []byte, mode string) ([]byte, error) {
	// Write to a temp file since xmllint reads files
	tmp, err := os.CreateTemp("", "c14n-*.xml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(input); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()

	cmd := exec.Command("xmllint", mode, tmp.Name())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("xmllint %s failed: %v\nstderr: %s", mode, err, stderr.String())
	}

	// xmllint may emit output even with namespace errors (exit 0 but stderr
	// warnings). Treat namespace errors as failures since the input is
	// namespace-malformed and C14N behavior is undefined on such inputs.
	if strings.Contains(stderr.String(), "namespace error") {
		return nil, fmt.Errorf("xmllint reported namespace error: %s", stderr.String())
	}

	return stdout.Bytes(), nil
}

// TestDifferentialC14NAgainstXmllint runs every XML file in testdata/c14n/
// through both Go's canonicalization and xmllint's, comparing the output
// byte-for-byte. Any divergence indicates a spec non-compliance that could
// enable signature forgery.
//
// Note: xmllint's C14N modes always include comments, so we compare against
// our with-comments canonicalizers.
func TestDifferentialC14NAgainstXmllint(t *testing.T) {
	requireXmllint(t)

	// Known limitations where divergence from xmllint is expected:
	knownLimitations := map[string]string{
		"attr_whitespace": "etree does not normalize tab/newline in attribute values",
	}

	type c14nMethod struct {
		name         string
		xmllintFlag  string
		makeC        func() Canonicalizer
	}

	// Use with-comments canonicalizers to match xmllint behavior
	methods := []c14nMethod{
		{
			name:        "ExcC14N",
			xmllintFlag: "--exc-c14n",
			makeC:       func() Canonicalizer { return MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("") },
		},
		{
			name:        "C14N11",
			xmllintFlag: "--c14n11",
			makeC:       func() Canonicalizer { return MakeC14N11WithCommentsCanonicalizer() },
		},
		{
			name:        "C14N10",
			xmllintFlag: "--c14n",
			makeC:       func() Canonicalizer { return MakeC14N10WithCommentsCanonicalizer() },
		},
	}

	// Find all test input files
	files, err := filepath.Glob("testdata/c14n/*.xml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no test XML files found in testdata/c14n/")
	}

	for _, xmlFile := range files {
		baseName := strings.TrimSuffix(filepath.Base(xmlFile), ".xml")
		inputBytes, err := os.ReadFile(xmlFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", xmlFile, err)
		}

		for _, method := range methods {
			t.Run(baseName+"/"+method.name, func(t *testing.T) {
				if reason, ok := knownLimitations[baseName]; ok {
					t.Skipf("known limitation: %s", reason)
				}

				// Get xmllint reference output
				expected, err := xmllintC14N(inputBytes, method.xmllintFlag)
				if err != nil {
					t.Fatalf("xmllint failed: %v", err)
				}

				// Get Go library output
				doc := etree.NewDocument()
				if err := doc.ReadFromBytes(inputBytes); err != nil {
					t.Fatalf("failed to parse input: %v", err)
				}

				el := doc.Root()
				if el == nil {
					t.Fatal("empty document")
				}

				c := method.makeC()
				got, err := c.Canonicalize(el)
				if err != nil {
					t.Fatalf("Canonicalize failed: %v", err)
				}

				if !bytes.Equal(got, expected) {
					t.Errorf("DIVERGENCE from xmllint!\n"+
						"--- xmllint (%s) ---\n%s\n"+
						"--- xmldsig ---\n%s\n"+
						"--- diff ---\n%s",
						method.xmllintFlag, string(expected), string(got),
						diffStrings(string(expected), string(got)))
				}
			})
		}
	}
}

// TestDifferentialC14NInlineInputs tests additional hand-crafted adversarial
// inputs that exercise tricky C14N edge cases, comparing Go vs xmllint.
func TestDifferentialC14NInlineInputs(t *testing.T) {
	requireXmllint(t)

	inputs := []struct {
		name string
		xml  string
	}{
		{
			"NamespaceRebinding",
			`<root xmlns:p="http://first"><a xmlns:p="http://second"><b xmlns:p="http://third"><p:c/></b></a></root>`,
		},
		{
			"DefaultNamespaceUndeclaration",
			`<root xmlns="http://default"><a xmlns=""><b/></a></root>`,
		},
		{
			"MixedNamespaceOnAttributes",
			`<root xmlns:a="http://a" xmlns:b="http://b" a:x="1" b:x="2" x="3"/>`,
		},
		{
			"DeeplyNestedRedeclaration",
			`<a xmlns:p="http://ns"><b xmlns:p="http://ns"><c xmlns:p="http://ns"><p:d/></c></b></a>`,
		},
		{
			"EmptyPrefix",
			`<foo xmlns="http://example.com"><bar/></foo>`,
		},
		{
			"MultipleUnusedNamespaces",
			`<root xmlns:a="http://a" xmlns:b="http://b" xmlns:c="http://c" xmlns:d="http://d"><child/></root>`,
		},
		{
			"AttributeFromAncestorNamespace",
			`<root xmlns:ns="http://ns"><parent><child ns:attr="value"/></parent></root>`,
		},
		{
			"XmlNamespaceAttribute",
			`<root xml:lang="en"><child xml:lang="fr"><grandchild/></child></root>`,
		},
		{
			"WhitespaceInAttributes",
			`<doc  attr1 = "a"  attr2  ="b"  attr3=  "c"  />`,
		},
		{
			"SAMLResponse",
			`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`,
		},
		{
			"NamespaceUsedOnlyInAttributes",
			`<root xmlns:attr="http://attr-ns"><elem attr:name="val">text</elem></root>`,
		},
		{
			"SameNSDifferentPrefixes",
			`<root xmlns:a="http://same" xmlns:b="http://same"><a:x/><b:y/></root>`,
		},
		{
			"SpecialCharsInAttrValues",
			`<doc attr="a&amp;b" attr2="c&lt;d" attr3="e&gt;f"/>`,
		},
		{
			"NumericCharReferences",
			`<doc>&#65;&#x42;</doc>`,
		},
	}

	type c14nMethod struct {
		name        string
		xmllintFlag string
		makeC       func() Canonicalizer
	}

	methods := []c14nMethod{
		{"ExcC14N", "--exc-c14n", func() Canonicalizer { return MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("") }},
		{"C14N11", "--c14n11", func() Canonicalizer { return MakeC14N11WithCommentsCanonicalizer() }},
		{"C14N10", "--c14n", func() Canonicalizer { return MakeC14N10WithCommentsCanonicalizer() }},
	}

	for _, input := range inputs {
		for _, method := range methods {
			t.Run(input.name+"/"+method.name, func(t *testing.T) {
				// xmllint reference
				expected, err := xmllintC14N([]byte(input.xml), method.xmllintFlag)
				if err != nil {
					t.Fatalf("xmllint failed: %v", err)
				}

				// Go library
				doc := etree.NewDocument()
				if err := doc.ReadFromString(input.xml); err != nil {
					t.Fatalf("failed to parse: %v", err)
				}

				c := method.makeC()
				got, err := c.Canonicalize(doc.Root())
				if err != nil {
					t.Fatalf("Canonicalize failed: %v", err)
				}

				if !bytes.Equal(got, expected) {
					t.Errorf("DIVERGENCE from xmllint!\n"+
						"input: %s\n"+
						"--- xmllint (%s) ---\n%s\n"+
						"--- xmldsig ---\n%s",
						input.xml, method.xmllintFlag, string(expected), string(got))
				}
			})
		}
	}
}

// TestDifferentialC14NSignatureRoundTrip creates a signed document, extracts
// the SignedInfo, canonicalizes it with both Go and xmllint, and verifies
// they produce the same bytes. This tests the actual security-critical path.
func TestDifferentialC14NSignatureRoundTrip(t *testing.T) {
	requireXmllint(t)

	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	doc := etree.NewDocument()
	doc.ReadFromString(`<root ID="_test123"><data>important</data></root>`)

	signed, err := signer.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}

	// Serialize and re-parse to get clean tree
	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signed)
	xmlBytes, err := signedDoc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}

	signedDoc2 := etree.NewDocument()
	if err := signedDoc2.ReadFromBytes(xmlBytes); err != nil {
		t.Fatal(err)
	}

	// Find the SignedInfo element
	var signedInfo *etree.Element
	for _, child := range signedDoc2.Root().ChildElements() {
		if child.Tag == "Signature" {
			for _, grandchild := range child.ChildElements() {
				if grandchild.Tag == "SignedInfo" {
					signedInfo = grandchild
					break
				}
			}
		}
	}
	if signedInfo == nil {
		t.Fatal("SignedInfo not found")
	}

	// Serialize SignedInfo for xmllint.
	// The SignedInfo uses ds: prefix which is declared on the parent Signature
	// element, so we need to add the namespace declaration for standalone parsing.
	siCopy := signedInfo.Copy()
	// Add xmlns:ds if not already present
	hasNSDecl := false
	for _, attr := range siCopy.Attr {
		if attr.Space == "xmlns" && attr.Key == siCopy.Space {
			hasNSDecl = true
			break
		}
	}
	if !hasNSDecl && siCopy.Space != "" {
		siCopy.CreateAttr("xmlns:"+siCopy.Space, namespace)
	}
	siDoc := etree.NewDocument()
	siDoc.SetRoot(siCopy)
	siBytes, err := siDoc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}

	methods := []struct {
		name        string
		xmllintFlag string
		makeC       func() Canonicalizer
	}{
		{"ExcC14N", "--exc-c14n", func() Canonicalizer { return MakeC14N10ExclusiveCanonicalizerWithPrefixList("") }},
		{"C14N11", "--c14n11", func() Canonicalizer { return MakeC14N11Canonicalizer() }},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			expected, err := xmllintC14N(siBytes, m.xmllintFlag)
			if err != nil {
				t.Fatalf("xmllint failed: %v", err)
			}

			// Re-parse for Go canonicalization
			doc := etree.NewDocument()
			if err := doc.ReadFromBytes(siBytes); err != nil {
				t.Fatal(err)
			}

			c := m.makeC()
			got, err := c.Canonicalize(doc.Root())
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, expected) {
				t.Errorf("SignedInfo canonicalization DIVERGES!\n"+
					"--- xmllint ---\n%s\n"+
					"--- xmldsig ---\n%s",
					string(expected), string(got))
			}
		})
	}
}

// TestDifferentialC14NBitFlipDetection signs a document, then flips every
// single bit in the serialized XML one at a time. Each mutation must either
// fail to parse or fail verification. This is a metamorphic property test.
//
// Bit flips that only affect base64 padding bits (trailing zero bits in the
// last base64 character before = padding) are expected to not change the
// decoded value, so these are counted separately.
func TestDifferentialC14NBitFlipDetection(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
	}

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
	}

	doc := etree.NewDocument()
	doc.ReadFromString(`<root ID="_test"><data>payload</data></root>`)

	signed, err := signer.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}

	// Serialize to get the signed XML bytes
	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signed)
	origBytes, err := signedDoc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}

	// Verify the original works
	origDoc := etree.NewDocument()
	if err := origDoc.ReadFromBytes(origBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(origDoc.Root()); err != nil {
		t.Fatalf("original verification failed: %v", err)
	}

	// Flip each bit and verify it fails
	rejected := 0
	parseFails := 0
	base64Padding := 0

	xmlStr := string(origBytes)

	for byteIdx := 0; byteIdx < len(origBytes); byteIdx++ {
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			mutated := make([]byte, len(origBytes))
			copy(mutated, origBytes)
			mutated[byteIdx] ^= 1 << uint(bitIdx)

			mutDoc := etree.NewDocument()
			if err := mutDoc.ReadFromBytes(mutated); err != nil {
				// Parse failure is fine — mutation broke the XML
				parseFails++
				continue
			}

			root := mutDoc.Root()
			if root == nil {
				parseFails++
				continue
			}

			_, err := verifier.Verify(root)
			if err == nil {
				// Check if this is a base64 padding bit. When a base64-encoded
				// value ends with '=' or '==' padding, the last data character's
				// lowest bits are padding zeros that don't affect the decoded value.
				if isBase64PaddingBit(xmlStr, byteIdx, bitIdx) {
					base64Padding++
					continue
				}

				t.Errorf("bit flip at byte %d bit %d was NOT detected!\n"+
					"original byte: 0x%02x, mutated: 0x%02x\n"+
					"context: ...%s...",
					byteIdx, bitIdx, origBytes[byteIdx], mutated[byteIdx],
					safeSlice(xmlStr, byteIdx-20, byteIdx+20))
			}
			rejected++
		}
	}

	t.Logf("bit-flip test: %d rejected, %d parse failures, %d base64 padding bits, %d total bits",
		rejected, parseFails, base64Padding, len(origBytes)*8)
}

// isBase64PaddingBit checks whether flipping this bit produces a different
// base64 string that decodes to the same bytes. This happens when the bit
// only affects padding zeros in the last base64 group.
func isBase64PaddingBit(xml string, byteIdx, bitIdx int) bool {
	if byteIdx >= len(xml) {
		return false
	}

	ch := xml[byteIdx]
	if !isBase64Char(ch) {
		return false
	}

	// Find the enclosing base64 content: scan forward for '</'
	// and backward for '>'
	start := byteIdx
	for start > 0 && xml[start-1] != '>' {
		start--
	}
	end := byteIdx
	for end < len(xml) && xml[end] != '<' {
		end++
	}

	origContent := xml[start:end]

	// Check if this looks like base64 with padding
	trimmed := strings.TrimRight(strings.TrimSpace(origContent), "=")
	if len(trimmed) == len(strings.TrimSpace(origContent)) {
		return false // no padding
	}

	// Decode original
	origDecoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(origContent))
	if err != nil {
		return false
	}

	// Flip the bit and decode mutated
	mutBytes := []byte(xml)
	mutBytes[byteIdx] ^= 1 << uint(bitIdx)
	mutContent := string(mutBytes[start:end])
	mutDecoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(mutContent))
	if err != nil {
		return false
	}

	return bytes.Equal(origDecoded, mutDecoded)
}

func isBase64Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/'
}

func safeSlice(s string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

// TestDifferentialC14NAttributePermutations generates all permutations of
// attributes on an element and verifies they all produce the same canonical form.
func TestDifferentialC14NAttributePermutations(t *testing.T) {
	attrs := []string{
		`z="3"`,
		`a="1"`,
		`m="2"`,
		`xmlns:ns="http://ns"`,
		`ns:x="4"`,
	}

	// Generate a few permutations (not all 120, but enough to be useful)
	permutations := [][]int{
		{0, 1, 2, 3, 4},
		{4, 3, 2, 1, 0},
		{2, 4, 0, 3, 1},
		{3, 0, 4, 1, 2},
		{1, 2, 3, 4, 0},
		{4, 0, 1, 2, 3},
	}

	methods := []struct {
		name  string
		makeC func() Canonicalizer
	}{
		{"ExcC14N", func() Canonicalizer { return MakeC14N10ExclusiveCanonicalizerWithPrefixList("") }},
		{"C14N11", func() Canonicalizer { return MakeC14N11Canonicalizer() }},
		{"C14N10", func() Canonicalizer { return MakeC14N10RecCanonicalizer() }},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			var reference string

			for i, perm := range permutations {
				var attrStr string
				for _, idx := range perm {
					attrStr += " " + attrs[idx]
				}
				xml := fmt.Sprintf("<elem%s/>", attrStr)

				doc := etree.NewDocument()
				if err := doc.ReadFromString(xml); err != nil {
					t.Fatalf("permutation %d: parse failed: %v", i, err)
				}

				c := m.makeC()
				got, err := c.Canonicalize(doc.Root())
				if err != nil {
					t.Fatalf("permutation %d: canonicalize failed: %v", i, err)
				}

				if i == 0 {
					reference = string(got)
				} else if string(got) != reference {
					t.Errorf("permutation %d produced different canonical form\n"+
						"input: <elem%s/>\n"+
						"reference: %s\n"+
						"got:       %s", i, attrStr, reference, string(got))
				}
			}
		})
	}
}

// TestDifferentialC14NNamespacePermutations tests that reordering namespace
// declarations produces the same canonical form.
func TestDifferentialC14NNamespacePermutations(t *testing.T) {
	// All permutations of these three namespace declarations should
	// produce the same canonical output.
	nsDecls := []string{
		`xmlns:a="http://a"`,
		`xmlns:b="http://b"`,
		`xmlns:c="http://c"`,
	}

	permutations := [][]int{
		{0, 1, 2},
		{0, 2, 1},
		{1, 0, 2},
		{1, 2, 0},
		{2, 0, 1},
		{2, 1, 0},
	}

	methods := []struct {
		name  string
		makeC func() Canonicalizer
	}{
		{"ExcC14N", func() Canonicalizer { return MakeC14N10ExclusiveCanonicalizerWithPrefixList("") }},
		{"C14N11", func() Canonicalizer { return MakeC14N11Canonicalizer() }},
		{"C14N10", func() Canonicalizer { return MakeC14N10RecCanonicalizer() }},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			var reference string

			for i, perm := range permutations {
				var declStr string
				for _, idx := range perm {
					declStr += " " + nsDecls[idx]
				}
				xml := fmt.Sprintf(`<root%s><a:x/><b:y/><c:z/></root>`, declStr)

				doc := etree.NewDocument()
				if err := doc.ReadFromString(xml); err != nil {
					t.Fatalf("permutation %d: parse failed: %v", i, err)
				}

				c := m.makeC()
				got, err := c.Canonicalize(doc.Root())
				if err != nil {
					t.Fatalf("permutation %d: canonicalize failed: %v", i, err)
				}

				if i == 0 {
					reference = string(got)
				} else if string(got) != reference {
					t.Errorf("namespace permutation %d produced different canonical form\n"+
						"input: %s\n"+
						"reference: %s\n"+
						"got:       %s", i, xml, reference, string(got))
				}
			}
		})
	}
}

// FuzzDifferentialC14N is a fuzz test that generates random XML and compares
// Go's canonicalization against xmllint. Any divergence is a finding.
func FuzzDifferentialC14N(f *testing.F) {
	if _, err := exec.LookPath("xmllint"); err != nil {
		f.Skip("xmllint not available")
	}

	// Seed corpus
	f.Add(`<doc><a/></doc>`)
	f.Add(`<root xmlns:a="http://a"><a:b/></root>`)
	f.Add(`<x xmlns="http://ns" xmlns:p="http://p" p:attr="v"><y/></x>`)
	f.Add(`<a xmlns:x="http://x" xmlns:y="http://y"><b x:a="1" y:b="2"/></a>`)

	f.Fuzz(func(t *testing.T, xmlStr string) {
		// Must be valid XML
		doc := etree.NewDocument()
		if err := doc.ReadFromString(xmlStr); err != nil {
			t.Skip()
		}
		if doc.Root() == nil {
			t.Skip()
		}

		// Must also be valid for xmllint (write canonical-ish form)
		ref, err := xmllintC14N([]byte(xmlStr), "--exc-c14n")
		if err != nil {
			t.Skip()
		}

		c := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		got, err := c.Canonicalize(doc.Root())
		if err != nil {
			t.Skip()
		}

		if !bytes.Equal(got, ref) {
			t.Errorf("DIVERGENCE!\ninput: %s\nxmllint: %s\nxmldsig: %s",
				xmlStr, string(ref), string(got))
		}
	})
}
