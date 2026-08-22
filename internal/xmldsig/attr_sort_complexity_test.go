package xmldsig

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// buildPrefixedAttrs returns n xmlns declarations followed by n attributes that
// use those prefixes, in an order that forces the sort to do real work.
func buildPrefixedAttrs(n int) []xmltree.Attr {
	attrs := make([]xmltree.Attr, 0, 2*n)
	for i := n - 1; i >= 0; i-- {
		attrs = append(attrs, xmltree.Attr{
			Space: "xmlns",
			Key:   fmt.Sprintf("p%04d", i),
			Value: fmt.Sprintf("urn:ns:%04d", n-i),
		})
	}
	for i := n - 1; i >= 0; i-- {
		attrs = append(attrs, xmltree.Attr{
			Space: fmt.Sprintf("p%04d", i),
			Key:   "attr",
			Value: "v",
		})
	}
	return attrs
}

// TestSortAttrsMatchesSortedAttrs pins SortAttrs to the ordering documented by
// SortedAttrs.Less, so the fast comparator cannot drift from the slow one.
func TestSortAttrsMatchesSortedAttrs(t *testing.T) {
	for _, n := range []int{1, 2, 5, 17, 64} {
		viaSortAttrs := buildPrefixedAttrs(n)
		viaSortedAttrs := buildPrefixedAttrs(n)

		SortAttrs(viaSortAttrs)
		sort.Stable(SortedAttrs(viaSortedAttrs))

		require.Equal(t, len(viaSortedAttrs), len(viaSortAttrs))
		for i := range viaSortedAttrs {
			require.Equal(t, viaSortedAttrs[i].FullKey(), viaSortAttrs[i].FullKey())
			require.Equal(t, viaSortedAttrs[i].Value, viaSortAttrs[i].Value)
		}
	}
}

// TestSortAttrsMatchesSortedAttrsWithAncestorPrefixes covers the fallback path
// where a prefix has no xmlns declaration in the attribute list (it is declared
// on an ancestor) and the prefix string itself is used for ordering.
func TestSortAttrsMatchesSortedAttrsWithAncestorPrefixes(t *testing.T) {
	mk := func() []xmltree.Attr {
		return []xmltree.Attr{
			{Space: "z", Key: "attr", Value: "zval"},
			{Space: "a", Key: "attr", Value: "aval"},
			{Space: "", Key: "plain", Value: "p"},
			{Space: "xmlns", Key: "m", Value: "urn:m"},
			{Space: "m", Key: "attr", Value: "mval"},
		}
	}
	fast, slow := mk(), mk()
	SortAttrs(fast)
	sort.Stable(SortedAttrs(slow))
	for i := range slow {
		require.Equal(t, slow[i].FullKey(), fast[i].FullKey())
	}
}

// TestSortAttrsIsNotQuadratic guards the pre-authentication DoS: resolving
// namespace prefixes inside the sort comparator made canonicalizing an
// attacker-supplied SignedInfo O(n^2 log n) in the attribute count. Doubling
// the attribute count must not quadruple the time.
func TestSortAttrsIsNotQuadratic(t *testing.T) {
	measure := func(n, reps int) time.Duration {
		best := time.Duration(1 << 62)
		for r := 0; r < reps; r++ {
			attrs := buildPrefixedAttrs(n)
			start := time.Now()
			SortAttrs(attrs)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}

	// Warm up so the first measurement doesn't absorb one-time costs.
	measure(128, 3)

	small := measure(256, 20)
	large := measure(2048, 20)

	// 8x the attributes. O(n log n) predicts ~9x; the quadratic comparator
	// predicts ~74x. Allow generous headroom for a noisy machine.
	ratio := float64(large) / float64(small)
	t.Logf("SortAttrs: n=256 %v, n=2048 %v (ratio %.1fx)", small, large, ratio)
	if ratio > 30 {
		t.Errorf("SortAttrs scaling looks superlinear: 8x attributes took %.1fx longer "+
			"(n=256 %v, n=2048 %v) — is the comparator rescanning the attribute list?",
			ratio, small, large)
	}
}
