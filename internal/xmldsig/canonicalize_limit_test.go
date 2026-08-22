package xmldsig

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// --- correctness of the shared seenSoFar map --------------------------------

// TestInclusiveC14NSiblingScopeIsolation pins the scoping rule that the shared
// namespace map depends on. canonicalPrepInner strips redundant declarations
// against what is already in scope; if a declaration introduced by one subtree
// leaked into a sibling, the sibling's own declaration would be stripped as
// "redundant" and the canonical form would silently lose it -- changing the
// bytes that get digested.
func TestInclusiveC14NSiblingScopeIsolation(t *testing.T) {
	// <a> and <b> each declare the same prefix to DIFFERENT values. Neither may
	// be dropped, and <b>'s must not be judged redundant against <a>'s.
	doc, err := xmltree.Parse([]byte(
		`<r xmlns="urn:r">` +
			`<a xmlns:p="urn:one"><x p:v="1"/></a>` +
			`<b xmlns:p="urn:two"><y p:v="2"/></b>` +
			`</r>`))
	require.NoError(t, err)

	out, err := MakeC14N11Canonicalizer().Canonicalize(doc.Root())
	require.NoError(t, err)

	got := string(out)
	require.True(t, strings.Contains(got, `xmlns:p="urn:one"`),
		"first sibling's declaration missing from %s", got)
	require.True(t, strings.Contains(got, `xmlns:p="urn:two"`),
		"second sibling's declaration missing from %s", got)
}

// TestInclusiveC14NRedundantDeclarationStillStripped is the other half: a
// declaration genuinely redundant with an ancestor must still be removed, so
// the sibling-isolation fix above did not simply disable stripping.
func TestInclusiveC14NRedundantDeclarationStillStripped(t *testing.T) {
	doc, err := xmltree.Parse([]byte(
		`<r xmlns:p="urn:same"><a xmlns:p="urn:same"><x p:v="1"/></a></r>`))
	require.NoError(t, err)

	out, err := MakeC14N11Canonicalizer().Canonicalize(doc.Root())
	require.NoError(t, err)

	got := string(out)
	require.Equal(t, 1, strings.Count(got, `xmlns:p="urn:same"`),
		"redundant redeclaration should be stripped, got %s", got)
}

// TestInclusiveC14NDeepRedeclarationUnwind exercises many levels of
// shadow-and-restore, then a trailing sibling that must see the original.
func TestInclusiveC14NDeepRedeclarationUnwind(t *testing.T) {
	const depth = 30
	var sb strings.Builder
	sb.WriteString(`<r xmlns:p="urn:0">`)
	for i := 1; i <= depth; i++ {
		fmt.Fprintf(&sb, `<n%d xmlns:p="urn:%d">`, i, i)
	}
	for i := depth; i >= 1; i-- {
		fmt.Fprintf(&sb, `</n%d>`, i)
	}
	// Redeclaring urn:0 here is redundant with the root and must be stripped;
	// that only holds if every nested declaration was properly unwound.
	sb.WriteString(`<tail xmlns:p="urn:0"/></r>`)

	doc, err := xmltree.Parse([]byte(sb.String()))
	require.NoError(t, err)

	out, err := MakeC14N11Canonicalizer().Canonicalize(doc.Root())
	require.NoError(t, err)

	got := string(out)
	require.Equal(t, 1, strings.Count(got, `xmlns:p="urn:0"`),
		"tail redeclaration should be stripped as redundant with the root, got %s", got)
	for i := 1; i <= depth; i++ {
		require.Equal(t, 1, strings.Count(got, fmt.Sprintf(`xmlns:p="urn:%d"`, i)),
			"level %d declaration should appear exactly once", i)
	}
}

// --- the element limit -----------------------------------------------------

func inclusiveC14NPayload(levels, declsPerLevel, leaves int) *xmltree.Element {
	var sb strings.Builder
	sb.WriteString(`<root>`)
	for i := 0; i < levels; i++ {
		sb.WriteString(`<n`)
		for j := 0; j < declsPerLevel; j++ {
			fmt.Fprintf(&sb, ` xmlns:z%02d%03d="u:%02d:%03d"`, i, j, i, j)
		}
		sb.WriteString(`>`)
	}
	for l := 0; l < leaves; l++ {
		sb.WriteString(`<leaf/>`)
	}
	for i := 0; i < levels; i++ {
		sb.WriteString(`</n>`)
	}
	sb.WriteString(`</root>`)
	d, err := xmltree.Parse([]byte(sb.String()))
	if err != nil {
		panic(err)
	}
	return d.Root()
}

// TestInclusiveC14NEnforcesElementLimit is the regression test for inclusive
// canonicalization having no traversal budget while exclusive canonicalization
// had one. The CanonicalizationMethod that selects between them is
// attacker-controlled and canonicalization runs before any signature check, so
// an unbounded inclusive path is the one an attacker picks.
func TestInclusiveC14NEnforcesElementLimit(t *testing.T) {
	over := inclusiveC14NPayload(1, 1, canonicalPrepElementLimit+50)
	_, err := MakeC14N11Canonicalizer().Canonicalize(over)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCanonicalizationLimit)

	// Just under the limit still succeeds, so the limit is a bound and not a
	// blanket rejection.
	under := inclusiveC14NPayload(1, 1, 100)
	_, err = MakeC14N11Canonicalizer().Canonicalize(under)
	require.NoError(t, err)
}

// TestInclusiveC14NLimitAppliesToEveryVariant covers each inclusive algorithm
// and the null canonicalizer, which share canonicalPrep.
func TestInclusiveC14NLimitAppliesToEveryVariant(t *testing.T) {
	for name, c := range map[string]Canonicalizer{
		"c14n11":             MakeC14N11Canonicalizer(),
		"c14n11WithComments": MakeC14N11WithCommentsCanonicalizer(),
		"c14n10Rec":          MakeC14N10RecCanonicalizer(),
		"c14n10WithComments": MakeC14N10WithCommentsCanonicalizer(),
		"null":               MakeNullCanonicalizer(),
	} {
		over := inclusiveC14NPayload(1, 1, canonicalPrepElementLimit+50)
		_, err := c.Canonicalize(over)
		require.ErrorIs(t, err, ErrCanonicalizationLimit, "algorithm %s must enforce the limit", name)
	}
}

// TestInclusiveC14NPerElementCostIndependentOfAncestorDeclarations is the
// regression test for copying the accumulated namespace map at every element.
// That made the per-element cost proportional to the number of in-scope
// ancestor declarations, so a deep chain of declarations followed by many cheap
// leaves cost declarations*leaves -- and the element limit bounds the element
// count, not the per-element cost.
//
// Comparing total times would mostly compare document sizes, since a document
// with more declarations is necessarily bigger. Instead this measures the
// MARGINAL cost of adding leaves, which cancels the fixed cost of the
// declaration chain, and checks that the marginal cost per leaf does not depend
// on how many declarations are in scope.
func TestInclusiveC14NPerElementCostIndependentOfAncestorDeclarations(t *testing.T) {
	const fewLeaves = 100
	const manyLeaves = canonicalPrepElementLimit - 200

	measure := func(levels, decls, leaves int) time.Duration {
		best := time.Duration(1 << 62)
		for r := 0; r < 7; r++ {
			el := inclusiveC14NPayload(levels, decls, leaves)
			start := time.Now()
			_, err := MakeC14N11Canonicalizer().Canonicalize(el)
			require.NoError(t, err)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}

	measure(2, 5, fewLeaves) // warm up

	// Marginal cost of adding leaves under ~15,000 in-scope declarations. Using
	// the difference cancels the fixed cost of the declaration chain, so this
	// measures what each additional leaf costs rather than the document size.
	// A leaf declares nothing, so with a shared namespace map its cost does not
	// depend on the declaration count at all.
	lo := measure(60, 250, fewLeaves)
	hi := measure(60, 250, manyLeaves)

	perLeafNs := float64(hi-lo) / float64(manyLeaves-fewLeaves)
	t.Logf("marginal cost per leaf with ~15000 in-scope declarations: %.0f ns (%v -> %v)",
		perLeafNs, lo, hi)

	// Copying the map per element cost ~390,000 ns per leaf here; sharing it
	// costs on the order of hundreds. An absolute bound avoids dividing by a
	// near-zero baseline, which is too noisy to compare against under load.
	const maxPerLeafNs = 20000
	if perLeafNs > maxPerLeafNs {
		t.Errorf("each added leaf cost %.0f ns with ~15000 in-scope declarations "+
			"(limit %d ns) — is the namespace map copied per element?", perLeafNs, maxPerLeafNs)
	}
}
