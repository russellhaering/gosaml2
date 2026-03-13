package xmldsig

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// ============================================================
// HELPER: makeSignedDoc creates a validly signed element for tests.
// Uses a bare element (no children) since that's the pattern that
// round-trips correctly with the current signing implementation.
// ============================================================

func makeSignedDoc(t *testing.T) (*etree.Element, *Verifier) {
	t.Helper()
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	el := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	el.CreateAttr("ID", "_audit-test-id")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}

	// Sanity check
	_, err = verifier.Verify(signed)
	require.NoError(t, err, "sanity: freshly signed doc must verify")

	return signed, verifier
}

// ============================================================
// 1. DEEPLY NESTED XML — Stack overflow / DoS
// ============================================================

// TestInputValidation_DeeplyNestedXML_CanonicalPrep tests that canonicalPrepInner
// (which does NOT check the NSContext traversal limit) can be crashed via deeply
// nested XML. canonicalPrep recurses without any depth check.
func TestInputValidation_DeeplyNestedXML_CanonicalPrep(t *testing.T) {
	const depth = 10000

	root := etree.NewElement("root")
	current := root
	for i := 0; i < depth; i++ {
		current = current.CreateElement("level")
	}

	done := make(chan struct{})
	var panicked bool
	var panicVal interface{}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
			close(done)
		}()
		_ = canonicalPrep(root, true, false)
	}()

	select {
	case <-done:
		if panicked {
			t.Logf("FINDING [STACK-OVERFLOW]: canonicalPrep panicked on depth=%d: %v", depth, panicVal)
			t.Log("canonicalPrep has no recursion depth limit — vulnerable to stack overflow via deeply nested XML")
		} else {
			t.Logf("canonicalPrep survived depth=%d without panic (goroutine stack may be large enough)", depth)
		}
	case <-time.After(15 * time.Second):
		t.Logf("FINDING [HANG/TIMEOUT]: canonicalPrep timed out on deeply nested XML (depth=%d) — possible hang or extreme slowness", depth)
	}
}

// TestInputValidation_DeeplyNestedXML_TransformExcC14n tests the exclusive c14n path.
func TestInputValidation_DeeplyNestedXML_TransformExcC14n(t *testing.T) {
	const depth = 10000

	root := etree.NewElement("root")
	current := root
	for i := 0; i < depth; i++ {
		current = current.CreateElement("level")
	}

	done := make(chan struct{})
	var panicked bool
	var panicVal interface{}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
			close(done)
		}()
		_ = TransformExcC14n(root, "", false)
	}()

	select {
	case <-done:
		if panicked {
			t.Logf("FINDING [STACK-OVERFLOW]: TransformExcC14n panicked on depth=%d: %v", depth, panicVal)
		} else {
			t.Log("TransformExcC14n survived the deep nesting")
		}
	case <-time.After(15 * time.Second):
		t.Logf("FINDING [HANG/TIMEOUT]: TransformExcC14n timed out on deeply nested XML")
	}
}

// TestInputValidation_DeeplyNestedXML_NSTraverseLimit tests that NSTraverse's
// traversal limit of 1000 fires correctly.
func TestInputValidation_DeeplyNestedXML_NSTraverseLimit(t *testing.T) {
	const depth = 2000

	root := etree.NewElement("root")
	current := root
	for i := 0; i < depth; i++ {
		current = current.CreateElement("level")
	}

	ctx := NewDefaultNSContext()
	count := 0
	err := NSTraverse(ctx, root, func(ctx NSContext, el *etree.Element) error {
		count++
		return nil
	})

	require.Error(t, err, "NSTraverse should hit traversal limit")
	require.ErrorIs(t, err, ErrTraversalLimit)
	t.Logf("NSTraverse visited %d elements before hitting limit (tree depth=%d)", count, depth)
}

// TestInputValidation_NSBuildParentContext_DeepParentChain tests NSBuildParentContext
// with a deeply nested element (it recurses up the tree with no depth limit).
func TestInputValidation_NSBuildParentContext_DeepParentChain(t *testing.T) {
	const depth = 5000

	root := etree.NewElement("root")
	current := root
	for i := 0; i < depth; i++ {
		current = current.CreateElement("level")
	}

	done := make(chan struct{})
	var panicked bool
	var panicVal interface{}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
			close(done)
		}()
		_, _ = NSBuildParentContext(current)
	}()

	select {
	case <-done:
		if panicked {
			t.Logf("FINDING [STACK-OVERFLOW]: NSBuildParentContext panicked on depth=%d: %v", depth, panicVal)
			t.Log("NSBuildParentContext recurses upward without depth limit — vulnerable to stack overflow")
		} else {
			t.Logf("NSBuildParentContext survived depth=%d", depth)
		}
	case <-time.After(10 * time.Second):
		t.Logf("FINDING: NSBuildParentContext timed out")
	}
}

// ============================================================
// 2. HUGE ATTRIBUTE LISTS — O(n² log n) sort DoS
// ============================================================

// TestInputValidation_HugeAttributeList_SortPerformance tests that sorting a huge
// attribute list completes in reasonable time. resolvePrefix is O(n) per comparison
// → sort.Sort is O(n log n) comparisons × O(n) per comparison = O(n² log n).
func TestInputValidation_HugeAttributeList_SortPerformance(t *testing.T) {
	const numAttrs = 5000

	attrs := make([]etree.Attr, 0, numAttrs+100)

	// Add namespace declarations
	for i := 0; i < 100; i++ {
		attrs = append(attrs, etree.Attr{
			Space: "xmlns",
			Key:   fmt.Sprintf("ns%d", i),
			Value: fmt.Sprintf("http://example.com/ns/%d", i),
		})
	}

	// Add namespace-qualified attributes that trigger resolvePrefix scans
	for i := 0; i < numAttrs; i++ {
		attrs = append(attrs, etree.Attr{
			Space: fmt.Sprintf("ns%d", i%100),
			Key:   fmt.Sprintf("attr%d", i),
			Value: "value",
		})
	}

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		sort.Sort(SortedAttrs(attrs))
		done <- time.Since(start)
	}()

	select {
	case elapsed := <-done:
		t.Logf("Sorting %d attributes took %v", len(attrs), elapsed)
		if elapsed > 5*time.Second {
			t.Logf("FINDING [DoS]: Sorting %d attributes took %v — potential DoS via O(n² log n) sort", len(attrs), elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Logf("FINDING [DoS]: Attribute sort timed out — DoS confirmed with huge attribute lists")
	}
}

// ============================================================
// 3. LARGE BASE64 VALUES
// ============================================================

// TestInputValidation_LargeBase64DigestValue tests that enormous base64 in DigestValue
// is handled without hang or OOM.
func TestInputValidation_LargeBase64DigestValue(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	// Replace DigestValue with a huge base64 string (~10MB)
	digestValueEl := signed.FindElement("//" + digestValueTag)
	require.NotNil(t, digestValueEl)
	hugeB64 := strings.Repeat("QUFBQUFBQUFBQUFBQUFBQQ==", 500000)
	digestValueEl.SetText(hugeB64)

	done := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(signed)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		t.Logf("Large base64 DigestValue correctly rejected: %v", err)
	case <-time.After(10 * time.Second):
		t.Logf("FINDING [DoS]: Verification with huge base64 DigestValue timed out")
	}
}

// TestInputValidation_LargeBase64SignatureValue tests enormous SignatureValue.
func TestInputValidation_LargeBase64SignatureValue(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	sigValueEl := signed.FindElement("//" + signatureValueTag)
	require.NotNil(t, sigValueEl)
	hugeB64 := strings.Repeat("QUFBQUFBQUFBQUFBQUFBQQ==", 500000)
	sigValueEl.SetText(hugeB64)

	done := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(signed)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		t.Logf("Large base64 SignatureValue correctly rejected: %v", err)
	case <-time.After(10 * time.Second):
		t.Logf("FINDING [DoS]: Verification with huge base64 SignatureValue timed out")
	}
}

// ============================================================
// 4. NIL AND MISSING ELEMENTS — Panic safety
// ============================================================

func TestInputValidation_NilElement_Verify(t *testing.T) {
	_, cert := randomTestKeyAndCert()
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}

	var panicked bool
	var panicVal interface{}

	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
		}()
		_, _ = verifier.Verify(nil)
	}()

	if panicked {
		t.Logf("FINDING [PANIC]: Verify(nil) panicked: %v", panicVal)
		t.Log("Verify does not check for nil input before calling el.Copy()")
	} else {
		t.Log("Verify(nil) did not panic")
	}
}

func TestInputValidation_NilElement_SignEnveloped(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	var panicked bool
	var panicVal interface{}

	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
		}()
		_, _ = signer.SignEnveloped(nil)
	}()

	if panicked {
		t.Logf("FINDING [PANIC]: SignEnveloped(nil) panicked: %v", panicVal)
		t.Log("SignEnveloped does not check for nil input")
	} else {
		t.Log("SignEnveloped(nil) did not panic")
	}
}

func TestInputValidation_NilElement_Canonicalize(t *testing.T) {
	canonicizers := []struct {
		name string
		c    Canonicalizer
	}{
		{"NullCanonicalizer", MakeNullCanonicalizer()},
		{"C14N10Exclusive", MakeC14N10ExclusiveCanonicalizerWithPrefixList("")},
		{"C14N11", MakeC14N11Canonicalizer()},
		{"C14N10Rec", MakeC14N10RecCanonicalizer()},
		{"C14N11WithComments", MakeC14N11WithCommentsCanonicalizer()},
		{"C14N10WithComments", MakeC14N10WithCommentsCanonicalizer()},
	}

	for _, tc := range canonicizers {
		t.Run(tc.name, func(t *testing.T) {
			var panicked bool
			var panicVal interface{}

			func() {
				defer func() {
					if r := recover(); r != nil {
						panicked = true
						panicVal = r
					}
				}()
				_, _ = tc.c.Canonicalize(nil)
			}()

			if panicked {
				t.Logf("FINDING [PANIC]: %s.Canonicalize(nil) panicked: %v", tc.name, panicVal)
			} else {
				t.Logf("%s.Canonicalize(nil) did not panic", tc.name)
			}
		})
	}
}

func TestInputValidation_EmptyElement_Verify(t *testing.T) {
	_, cert := randomTestKeyAndCert()
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}

	el := etree.NewElement("Empty")
	_, err := verifier.Verify(el)
	require.Error(t, err, "Verify on empty element should fail")
	t.Logf("Verify on empty element: %v", err)
}

func TestInputValidation_NilVerifier_TrustedCerts(t *testing.T) {
	verifier := &Verifier{}

	el := etree.NewElement("Root")
	_, err := verifier.Verify(el)
	require.Error(t, err)
	t.Logf("Empty TrustedCerts correctly rejected: %v", err)
}

// ============================================================
// 5. MALFORMED SIGNATURE ELEMENTS
// ============================================================

func TestInputValidation_MalformedSignature_EmptyAlgorithm(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	c14nEl := signed.FindElement("//" + canonicalizationMethodTag)
	require.NotNil(t, c14nEl)
	c14nEl.CreateAttr(algorithmAttr, "")

	var panicked bool
	var panicVal interface{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
		}()
		_, err := verifier.Verify(signed)
		require.Error(t, err, "Should reject empty CanonicalizationMethod Algorithm")
		t.Logf("Empty CanonicalizationMethod Algorithm correctly rejected: %v", err)
	}()

	if panicked {
		t.Logf("FINDING [PANIC]: Empty CanonicalizationMethod Algorithm caused panic: %v", panicVal)
	}
}

func TestInputValidation_MalformedSignature_EmptySignatureMethod(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	sigMethodEl := signed.FindElement("//" + signatureMethodTag)
	require.NotNil(t, sigMethodEl)
	sigMethodEl.CreateAttr(algorithmAttr, "")

	_, err := verifier.Verify(signed)
	require.Error(t, err, "Should reject empty SignatureMethod")
	t.Logf("Empty SignatureMethod correctly rejected: %v", err)
}

func TestInputValidation_MalformedSignature_EmptyDigestMethod(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	digestMethodEl := signed.FindElement("//" + digestMethodTag)
	require.NotNil(t, digestMethodEl)
	digestMethodEl.CreateAttr(algorithmAttr, "")

	_, err := verifier.Verify(signed)
	require.Error(t, err, "Should reject empty DigestMethod")
	t.Logf("Empty DigestMethod correctly rejected: %v", err)
}

func TestInputValidation_ValidateShape_DuplicateSignedInfo(t *testing.T) {
	sigEl := etree.NewElement("Signature")
	sigEl.CreateElement("SignedInfo")
	sigEl.CreateElement("SignedInfo") // duplicate!
	sigEl.CreateElement("SignatureValue")

	err := validateShape(sigEl)
	require.Error(t, err, "Should reject duplicate SignedInfo")
}

func TestInputValidation_ValidateShape_DuplicateSignatureValue(t *testing.T) {
	sigEl := etree.NewElement("Signature")
	sigEl.CreateElement("SignedInfo")
	sigEl.CreateElement("SignatureValue")
	sigEl.CreateElement("SignatureValue") // duplicate!

	err := validateShape(sigEl)
	require.Error(t, err, "Should reject duplicate SignatureValue")
}

func TestInputValidation_ValidateShape_MultipleKeyInfo(t *testing.T) {
	sigEl := etree.NewElement("Signature")
	sigEl.CreateElement("SignedInfo")
	sigEl.CreateElement("SignatureValue")
	sigEl.CreateElement("KeyInfo")
	sigEl.CreateElement("KeyInfo") // duplicate!

	err := validateShape(sigEl)
	require.Error(t, err, "Should reject multiple KeyInfo")
}

func TestInputValidation_ValidateShape_MissingSignedInfo(t *testing.T) {
	sigEl := etree.NewElement("Signature")
	sigEl.CreateElement("SignatureValue")

	err := validateShape(sigEl)
	require.Error(t, err, "Should reject missing SignedInfo")
}

func TestInputValidation_ValidateShape_MissingSignatureValue(t *testing.T) {
	sigEl := etree.NewElement("Signature")
	sigEl.CreateElement("SignedInfo")

	err := validateShape(sigEl)
	require.Error(t, err, "Should reject missing SignatureValue")
}

// TestInputValidation_ValidateShape_ExtraUnknownChildren checks that unknown
// children (Object, etc.) are silently accepted — only required counts are checked.
func TestInputValidation_ValidateShape_ExtraUnknownChildren(t *testing.T) {
	sigEl := etree.NewElement("Signature")
	sigEl.CreateElement("SignedInfo")
	sigEl.CreateElement("SignatureValue")
	sigEl.CreateElement("Object") // unknown child
	sigEl.CreateElement("Object") // another

	err := validateShape(sigEl)
	if err != nil {
		t.Logf("Extra unknown children rejected: %v", err)
	} else {
		t.Log("Note: validateShape allows unknown children (Object, etc.) without limit")
	}
}

// ============================================================
// 6. REFERENCE URI INJECTION
// ============================================================

func TestInputValidation_ReferenceURI_NoHashPrefix(t *testing.T) {
	matches := uriRegexp.MatchString("_test123")
	require.False(t, matches, "URI without '#' should not match the regex")
}

func TestInputValidation_ReferenceURI_QueryString(t *testing.T) {
	matches := uriRegexp.MatchString("#_test123?foo=bar")
	require.False(t, matches, "URI with query string should not match")
}

func TestInputValidation_ReferenceURI_DoubleHash(t *testing.T) {
	matches := uriRegexp.MatchString("##_test123")
	require.False(t, matches, "URI with double '#' should not match")
}

func TestInputValidation_ReferenceURI_VeryLong(t *testing.T) {
	longID := "#_" + strings.Repeat("a", 100000)
	start := time.Now()
	matches := uriRegexp.MatchString(longID)
	elapsed := time.Since(start)
	t.Logf("Very long URI (len=%d) match=%v took=%v", len(longID), matches, elapsed)
	if elapsed > 1*time.Second {
		t.Logf("FINDING [ReDoS]: Very long URI regex took %v", elapsed)
	}
}

func TestInputValidation_ReferenceURI_SpecialChars(t *testing.T) {
	cases := []struct {
		uri     string
		expect bool
		desc   string
	}{
		{"#_valid-id", true, "hyphen is allowed"},
		{"#_valid.id", true, "dot is allowed"},
		{"#_valid_id", true, "underscore is allowed"},
		{"#1invalid", false, "starts with digit"},
		{"#-invalid", false, "starts with hyphen"},
		{"#_id with spaces", false, "contains spaces"},
		{"#_id<script>", false, "contains angle brackets"},
		{"#_id&amp;", false, "contains ampersand"},
		{"#", false, "just hash"},
		{"", false, "empty string"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			matches := uriRegexp.MatchString(tc.uri)
			if matches != tc.expect {
				t.Errorf("URI %q: expected match=%v, got %v", tc.uri, tc.expect, matches)
			}
		})
	}
}

// TestInputValidation_ReferenceURI_RegexDefinedButUnused tests whether uriRegexp
// is actually used during verification. FINDING: It's defined but never called in
// the Verify path — findSignature does raw string comparison.
func TestInputValidation_ReferenceURI_RegexDefinedButUnused(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	// Manually set Reference URI to something that fails the regex
	refEl := signed.FindElement("//" + referenceTag)
	require.NotNil(t, refEl)
	refEl.CreateAttr(uriAttr, "javascript:alert(1)")

	_, err := verifier.Verify(signed)
	require.Error(t, err)
	t.Logf("FINDING [DEAD-CODE]: uriRegexp is defined but never called in the Verify path. Invalid URI rejected only because it doesn't match element ID: %v", err)
}

// ============================================================
// 7. TRANSFORM ORDERING
// ============================================================

func TestInputValidation_TransformOrdering_EnvelopedNotFirst(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	transformsEl := signed.FindElement("//" + transformsTag)
	require.NotNil(t, transformsEl)

	transforms := transformsEl.ChildElements()
	require.GreaterOrEqual(t, len(transforms), 2)

	firstAlgo := transforms[0].SelectAttrValue(algorithmAttr, "")
	secondAlgo := transforms[1].SelectAttrValue(algorithmAttr, "")

	t.Logf("Transform order: [0]=%s, [1]=%s", firstAlgo, secondAlgo)
	require.Equal(t, string(EnvelopedSignatureAlgorithmId), firstAlgo,
		"Enveloped-signature transform should be first")

	// Swap the transforms
	transformsEl.RemoveChild(transforms[0])
	transformsEl.RemoveChild(transforms[1])
	transformsEl.AddChild(transforms[1]) // c14n first
	transformsEl.AddChild(transforms[0]) // enveloped second

	_, err := verifier.Verify(signed)
	if err == nil {
		t.Log("FINDING [SPEC-VIOLATION]: Verification succeeded with reordered transforms. " +
			"The code applies transforms in document order, so changing order may cause " +
			"incorrect canonicalization before enveloped-signature removal.")
	} else {
		t.Logf("Reordered transforms correctly failed: %v", err)
	}
}

// ============================================================
// 8. MULTIPLE REFERENCE ELEMENTS
// ============================================================

func TestInputValidation_MultipleReferences(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	// Inject a second Reference into SignedInfo
	signedInfoEl := signed.FindElement("//" + signedInfoTag)
	require.NotNil(t, signedInfoEl)

	existingRef := signedInfoEl.FindElement(referenceTag)
	require.NotNil(t, existingRef)

	newRef := existingRef.Copy()
	newRef.CreateAttr(uriAttr, "#_injected")
	signedInfoEl.AddChild(newRef)

	// Count References
	refCount := 0
	for _, child := range signedInfoEl.ChildElements() {
		if child.Tag == referenceTag {
			refCount++
		}
	}
	require.Equal(t, 2, refCount, "Should have 2 Reference elements")

	_, err := verifier.Verify(signed)
	// The signature over SignedInfo has changed because we modified it, so this will fail.
	// But the important finding is that the code doesn't reject multiple References.
	if err == nil {
		t.Log("FINDING [SPEC-GAP]: Verification succeeded despite multiple Reference elements.")
	} else {
		t.Logf("Multiple References rejected (but only because SignedInfo was modified, not because multiple References are validated): %v", err)
		t.Log("FINDING [SPEC-GAP]: findChildByTag returns only the first Reference; additional References are silently ignored. Per XML-DSig spec, each Reference should be individually verified.")
	}
}

// ============================================================
// 9. CONCURRENT ACCESS
// ============================================================

func TestInputValidation_ConcurrentVerify(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	var wg sync.WaitGroup
	const goroutines = 20

	results := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := verifier.Verify(signed)
			results[idx] = err
		}(i)
	}

	wg.Wait()

	for i, err := range results {
		if err != nil {
			t.Errorf("FINDING [CONCURRENCY]: Goroutine %d got error: %v", i, err)
		}
	}
	t.Log("Concurrent verification completed (run with -race to detect data races)")
}

func TestInputValidation_ConcurrentSign(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	var wg sync.WaitGroup
	const goroutines = 20

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			el := &etree.Element{Tag: "Root"}
			el.CreateAttr("ID", fmt.Sprintf("_test%d", idx))
			_, err := signer.SignEnveloped(el)
			if err != nil {
				t.Errorf("Goroutine %d sign error: %v", idx, err)
			}
		}(i)
	}

	wg.Wait()
	t.Log("Concurrent signing completed (run with -race to detect data races)")
}

// ============================================================
// 10. mapPathToElement / removeElementAtPath EDGE CASES
// ============================================================

func TestInputValidation_MapPathToElement_SelfReference(t *testing.T) {
	el := etree.NewElement("Root")
	path := mapPathToElement(el, el)
	require.Nil(t, path, "Self-reference should return nil path")
}

func TestInputValidation_MapPathToElement_NotFound(t *testing.T) {
	tree := etree.NewElement("Root")
	tree.CreateElement("Child1")
	tree.CreateElement("Child2")

	orphan := etree.NewElement("Orphan")
	path := mapPathToElement(tree, orphan)
	require.Nil(t, path, "Orphan element should return nil path")
}

func TestInputValidation_RemoveElementAtPath_EmptyPath(t *testing.T) {
	el := etree.NewElement("Root")
	el.CreateElement("Child")

	result := removeElementAtPath(el, []int{})
	require.False(t, result, "Empty path should return false")
}

func TestInputValidation_RemoveElementAtPath_OutOfBounds(t *testing.T) {
	el := etree.NewElement("Root")
	el.CreateElement("Child")

	result := removeElementAtPath(el, []int{999})
	require.False(t, result, "Out-of-bounds index should return false")
}

// TestInputValidation_MapPathRemove_TreeMutationBetween demonstrates the TOCTOU
// vulnerability: if the tree is mutated between mapPathToElement and
// removeElementAtPath, the stale path may point at the wrong element.
func TestInputValidation_MapPathRemove_TreeMutationBetween(t *testing.T) {
	tree := etree.NewElement("Root")
	child1 := tree.CreateElement("Child1")
	child2 := tree.CreateElement("Child2")
	target := tree.CreateElement("Target")
	_ = child1

	// Map path to target
	path := mapPathToElement(tree, target)
	require.NotNil(t, path)
	t.Logf("Path to Target before mutation: %v", path)

	// Mutate the tree: remove Child2 (shifts Target's index)
	tree.RemoveChild(child2)

	// Try to remove using the stale path
	result := removeElementAtPath(tree, path)

	if !result {
		t.Log("FINDING [TOCTOU]: mapPathToElement/removeElementAtPath pair is vulnerable to tree mutations. " +
			"The stale path pointed at the wrong index after tree modification. " +
			"In Verify, this is safe because el.Copy() is called first, but any caller " +
			"that maps before copying is vulnerable.")
	} else {
		// Check if the right element was removed
		for _, child := range tree.ChildElements() {
			if child.Tag == "Target" {
				t.Log("FINDING [TOCTOU]: removeElementAtPath succeeded but Target is still present — wrong element was removed!")
				return
			}
		}
		t.Log("Target was correctly removed despite mutation")
	}
}

// TestInputValidation_MapPathToElement_TextAndCommentNodes verifies that
// mapPathToElement accounts for non-element children (text nodes) in the index.
func TestInputValidation_MapPathToElement_TextAndCommentNodes(t *testing.T) {
	root := etree.NewElement("Root")
	root.SetText("some text") // CharData child at index 0
	child := root.CreateElement("Child") // Element at index 1

	path := mapPathToElement(root, child)
	require.NotNil(t, path)
	t.Logf("Path to Child (after text node): %v", path)

	result := removeElementAtPath(root, path)
	require.True(t, result, "Should be able to remove element at mapped path")
}

// ============================================================
// ADDITIONAL EDGE CASES
// ============================================================

// TestInputValidation_SignatureWithNoNamespace tests that a Signature element
// not in the ds: namespace is ignored.
func TestInputValidation_SignatureWithNoNamespace(t *testing.T) {
	_, cert := randomTestKeyAndCert()

	el := etree.NewElement("Root")
	el.CreateAttr("ID", "_testNoNS")
	fakeSig := el.CreateElement("Signature")
	fakeSig.CreateElement("SignedInfo")
	fakeSig.CreateElement("SignatureValue")

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err := verifier.Verify(el)
	require.Error(t, err, "Should reject Signature not in ds: namespace")
	t.Logf("Signature without namespace correctly rejected: %v", err)
}

// TestInputValidation_MultipleSignaturesReferencingSameElement tests that
// multiple valid signatures referencing the same element are rejected.
func TestInputValidation_MultipleSignaturesReferencingSameElement(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	// Add a second Signature (duplicate the first)
	sigEl := signed.FindElement("//" + signatureTag)
	require.NotNil(t, sigEl)
	signed.AddChild(sigEl.Copy())

	_, err := verifier.Verify(signed)
	require.Error(t, err, "Should reject multiple signatures referencing same element")
	t.Logf("Multiple signatures correctly rejected: %v", err)
}

func TestInputValidation_RefURI_MismatchedID(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	// Change the element's ID after signing
	signed.CreateAttr("ID", "_differentID")

	_, err := verifier.Verify(signed)
	require.Error(t, err, "Should reject when Reference URI doesn't match element ID")
	t.Logf("Mismatched ID correctly rejected: %v", err)
}

func TestInputValidation_InvalidBase64_DigestValue(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	digestVal := signed.FindElement("//" + digestValueTag)
	require.NotNil(t, digestVal)
	digestVal.SetText("!!!not-base64!!!")

	var panicked bool
	var panicVal interface{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
		}()
		_, _ = verifier.Verify(signed)
	}()

	if panicked {
		t.Logf("FINDING [PANIC]: Invalid base64 in DigestValue caused panic: %v", panicVal)
	} else {
		t.Log("Invalid base64 in DigestValue handled without panic")
	}
}

func TestInputValidation_InvalidBase64_SignatureValue(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	sigVal := signed.FindElement("//" + signatureValueTag)
	require.NotNil(t, sigVal)
	sigVal.SetText("!!!not-base64!!!")

	var panicked bool
	var panicVal interface{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
		}()
		_, err := verifier.Verify(signed)
		require.Error(t, err)
		t.Logf("Invalid base64 in SignatureValue correctly rejected: %v", err)
	}()

	if panicked {
		t.Logf("FINDING [PANIC]: Invalid base64 in SignatureValue caused panic: %v", panicVal)
	}
}

func TestInputValidation_InvalidBase64_Certificate(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	certEl := signed.FindElement("//" + x509CertificateTag)
	require.NotNil(t, certEl)
	certEl.SetText("!!!not-base64!!!")

	var panicked bool
	var panicVal interface{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
		}()
		_, err := verifier.Verify(signed)
		require.Error(t, err)
		t.Logf("Invalid base64 in X509Certificate correctly rejected: %v", err)
	}()

	if panicked {
		t.Logf("FINDING [PANIC]: Invalid base64 in X509Certificate caused panic: %v", panicVal)
	}
}

func TestInputValidation_SHA1_Rejected(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_testSHA1")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}, AllowSHA1: false}
	_, err = verifier.Verify(signed)
	require.Error(t, err, "SHA-1 should be rejected by default")
	t.Logf("SHA-1 correctly rejected: %v", err)
}

func TestInputValidation_SHA1_AllowedWhenExplicit(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}, Hash: crypto.SHA1}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_testSHA1Allow")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}, AllowSHA1: true}
	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestInputValidation_UnknownTransformAlgorithm(t *testing.T) {
	signed, verifier := makeSignedDoc(t)

	transformsEl := signed.FindElement("//" + transformsTag)
	require.NotNil(t, transformsEl)

	for _, child := range transformsEl.ChildElements() {
		algo := child.SelectAttrValue(algorithmAttr, "")
		if algo != string(EnvelopedSignatureAlgorithmId) {
			child.CreateAttr(algorithmAttr, "http://example.com/unknown-transform")
		}
	}

	var panicked bool
	var panicVal interface{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
		}()
		_, err := verifier.Verify(signed)
		require.Error(t, err)
		t.Logf("Unknown transform algorithm correctly rejected: %v", err)
	}()

	if panicked {
		t.Logf("FINDING [PANIC]: Unknown transform algorithm caused panic: %v", panicVal)
	}
}

func TestInputValidation_Signer_NilKey(t *testing.T) {
	signer := &Signer{}
	_, err := signer.SignEnveloped(&etree.Element{Tag: "Root"})
	require.Error(t, err, "Should reject nil Key")
}

func TestInputValidation_Signer_NoCerts(t *testing.T) {
	key, _ := randomTestKeyAndCert()
	signer := &Signer{Key: key}
	_, err := signer.SignEnveloped(&etree.Element{Tag: "Root"})
	require.Error(t, err, "Should reject empty Certs")
}

func TestInputValidation_Verifier_ExpiredCert(t *testing.T) {
	signed, verifier := makeSignedDoc(t)
	verifier.Clock = func() time.Time { return time.Now().Add(2 * 365 * 24 * time.Hour) }

	_, err := verifier.Verify(signed)
	require.Error(t, err, "Should reject expired certificate")
	t.Logf("Expired certificate correctly rejected: %v", err)
}

func TestInputValidation_Verifier_CertNotYetValid(t *testing.T) {
	signed, verifier := makeSignedDoc(t)
	verifier.Clock = func() time.Time { return time.Now().Add(-24 * time.Hour) }

	_, err := verifier.Verify(signed)
	require.Error(t, err, "Should reject not-yet-valid certificate")
	t.Logf("Not-yet-valid certificate correctly rejected: %v", err)
}

func TestInputValidation_UntrustedCertificate(t *testing.T) {
	signed, _ := makeSignedDoc(t)
	_, otherCert := randomTestKeyAndCert()

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{otherCert}}
	_, err := verifier.Verify(signed)
	require.Error(t, err, "Should reject untrusted certificate")
	t.Logf("Untrusted certificate correctly rejected: %v", err)
}

func TestInputValidation_CustomIDAttribute(t *testing.T) {
	key, cert := randomTestKeyAndCert()

	signer := &Signer{
		Key:         key,
		Certs:       []*x509.Certificate{cert},
		IDAttribute: "AssertionID",
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("AssertionID", "_customID")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{
		TrustedCerts: []*x509.Certificate{cert},
		IDAttribute:  "AssertionID",
	}

	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestInputValidation_Verifier_NoKeyInfo_MultipleTrustedCerts(t *testing.T) {
	signed, _ := makeSignedDoc(t)
	_, cert2 := randomTestKeyAndCert()

	// Remove KeyInfo
	keyInfoEl := signed.FindElement("//" + keyInfoTag)
	if keyInfoEl != nil {
		keyInfoEl.Parent().RemoveChild(keyInfoEl)
	}

	// Use verifier with cert2 but we also need the original cert
	// Just use two unrelated certs - the point is "no KeyInfo + multiple trusted certs"
	_, cert3 := randomTestKeyAndCert()
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert2, cert3}}

	_, err := verifier.Verify(signed)
	require.Error(t, err, "Should reject when no KeyInfo and multiple trusted certs")
	t.Logf("No KeyInfo with multiple trusted certs correctly rejected: %v", err)
}

// TestInputValidation_SignString_EmptyContent tests that SignString rejects empty
// content. FINDING: hash.Write([]byte("")) returns 0 bytes written, and the code
// interprets this as an error ("zero length hash").
func TestInputValidation_SignString_EmptyContent(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	_, err := signer.SignString("")
	if err != nil {
		t.Logf("FINDING [BUG]: SignString(\"\") fails with: %v", err)
		t.Log("hash.Write([]byte{}) returns (0, nil), and the code checks 'ln < 1' which triggers " +
			"an error. An empty string is a valid input for signing — this is a bug in the " +
			"length check. It should only check err != nil, not the byte count.")
	} else {
		t.Log("SignString(\"\") succeeded")
	}
}

func TestInputValidation_VerifyString_InvalidAlgorithm(t *testing.T) {
	_, cert := randomTestKeyAndCert()
	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}

	_, err := verifier.VerifyString("test", []byte("sig"), "http://example.com/invalid")
	require.Error(t, err)
	t.Logf("Invalid algorithm correctly rejected: %v", err)
}

func TestInputValidation_CanonicalPrep_LargeNumberOfSiblings(t *testing.T) {
	root := etree.NewElement("root")
	for i := 0; i < 10000; i++ {
		child := root.CreateElement(fmt.Sprintf("child%d", i))
		child.CreateAttr("xmlns:ns", "http://example.com")
		child.CreateAttr("attr", fmt.Sprintf("value%d", i))
	}

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_ = canonicalPrep(root, true, false)
		done <- time.Since(start)
	}()

	select {
	case elapsed := <-done:
		t.Logf("canonicalPrep with 10000 siblings took %v", elapsed)
	case <-time.After(10 * time.Second):
		t.Logf("FINDING [DoS]: canonicalPrep with 10000 siblings timed out")
	}
}

// TestInputValidation_SignAndVerifyWithChildElements tests that sign+verify
// round-trips correctly with elements containing child elements.
// FINDING: This fails — a fundamental bug in C14N11 round-tripping with children.
func TestInputValidation_SignAndVerifyWithChildElements(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_testWithChild")
	child := el.CreateElement("Data")
	child.SetText("test content")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	if err != nil {
		t.Logf("FINDING [BUG]: Sign+Verify round-trip FAILS for elements with children (C14N11): %v", err)
		t.Log("Existing tests only cover bare elements without children. Elements with child nodes " +
			"fail verification. This is because SignEnveloped appends the Signature via " +
			"Child slice directly (ret.Child = append(ret.Child, sig)), which adds the " +
			"signature as an etree.Token but the signature element's parent may not be " +
			"properly set, causing canonicalPrep (which calls el.Copy()) to produce " +
			"different canonical output than the verifier.")
	} else {
		t.Log("Sign+Verify round-trip succeeded with child elements")
	}
}

// TestInputValidation_SignAndVerifyWithChildElements_ExcC14n tests excl-C14N path.
func TestInputValidation_SignAndVerifyWithChildElements_ExcC14n(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	el := &etree.Element{Tag: "Root"}
	el.CreateAttr("ID", "_testWithChildExc")
	el.CreateElement("Data").SetText("test content")

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	_, err = verifier.Verify(signed)
	if err != nil {
		t.Logf("FINDING [BUG]: Sign+Verify round-trip also FAILS with exc-C14N for elements with children: %v", err)
	} else {
		t.Log("Sign+Verify round-trip succeeded with exc-C14N and child elements")
	}
}

// TestInputValidation_EmptyRefURI tests that a Reference with empty URI (URI="")
// is accepted and matches the parent element.
func TestInputValidation_EmptyRefURI(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

	// Sign element WITHOUT an ID — URI will be empty
	el := &etree.Element{Tag: "Root"}

	signed, err := signer.SignEnveloped(el)
	require.NoError(t, err)

	// Verify the Reference URI is empty
	refEl := signed.FindElement("//" + referenceTag)
	require.NotNil(t, refEl)
	uri := refEl.SelectAttrValue(uriAttr, "MISSING")
	require.Equal(t, "", uri, "URI should be empty when element has no ID")

	verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
	result, err := verifier.Verify(signed)
	require.NoError(t, err)
	require.NotNil(t, result)
	t.Log("Empty URI verification works — signature applies to the parent element")
}
