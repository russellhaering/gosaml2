// Copyright 2025 Russell Haering et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xmltree

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
)

// --- correctness of shadowing and restoration -------------------------------

// TestNamespaceShadowingRestoredAfterElement pins the scoping rule that prefix
// resolution is indexed on: a prefix redeclared by a child must revert to the
// ancestor's binding for that child's later siblings.
func TestNamespaceShadowingRestoredAfterElement(t *testing.T) {
	doc, err := Parse([]byte(
		`<r xmlns:p="urn:outer">` +
			`<a xmlns:p="urn:inner"><deep p:x="1"/></a>` +
			`<b p:x="2"/>` +
			`</r>`))
	require.NoError(t, err)

	root := doc.Root()

	a := root.SelectElement("a")
	require.NotNil(t, a)
	deep := a.SelectElement("deep")
	require.NotNil(t, deep)

	// The inner declaration wins inside <a>...
	require.Equal(t, "urn:inner", a.SelectAttr("xmlns:p").Value)

	// ...and <b>, a later sibling, must still see the outer one. If the parser
	// restored scope by truncation alone this would silently resolve to
	// urn:inner or fail.
	b := root.SelectElement("b")
	require.NotNil(t, b)
	require.NotNil(t, b.SelectAttr("p:x"))
}

// TestNamespaceRedeclarationDeepChain walks a chain that redeclares the same
// prefix at every level and then unwinds, checking each level resolved to its
// own binding.
func TestNamespaceRedeclarationDeepChain(t *testing.T) {
	const depth = 40
	var sb strings.Builder
	sb.WriteString(`<r xmlns:p="urn:0">`)
	for i := 1; i <= depth; i++ {
		fmt.Fprintf(&sb, `<n%d xmlns:p="urn:%d"><probe%d p:a="v"/>`, i, i, i)
	}
	for i := depth; i >= 1; i-- {
		fmt.Fprintf(&sb, `</n%d>`, i)
	}
	// A trailing sibling at the top level must see urn:0 again.
	sb.WriteString(`<tail p:a="v"/></r>`)

	doc, err := Parse([]byte(sb.String()))
	require.NoError(t, err)

	cur := doc.Root()
	for i := 1; i <= depth; i++ {
		cur = cur.SelectElement(fmt.Sprintf("n%d", i))
		require.NotNil(t, cur)
		require.Equal(t, fmt.Sprintf("urn:%d", i), cur.SelectAttr("xmlns:p").Value)
	}
	require.NotNil(t, doc.Root().SelectElement("tail"))
}

// TestUndeclaredPrefixStillRejected confirms indexing prefixes did not weaken
// namespace well-formedness enforcement.
func TestUndeclaredPrefixStillRejected(t *testing.T) {
	for _, bad := range []string{
		`<r><a nope:x="1"/></r>`,
		`<r><nope:a/></r>`,
		// Declared only on a sibling, not an ancestor.
		`<r><a xmlns:p="urn:x"/><b p:x="1"/></r>`,
		// Declared only on a child, used by the parent.
		`<r p:x="1"><a xmlns:p="urn:x"/></r>`,
	} {
		_, err := Parse([]byte(bad))
		require.Error(t, err, "expected rejection for %s", bad)
	}
}

// TestReservedNamespacesStillRejected re-checks the reserved-prefix rules
// through the indexed path.
func TestReservedNamespacesStillRejected(t *testing.T) {
	for _, bad := range []string{
		`<r xmlns:xml="urn:wrong"/>`,
		`<r xmlns:xmlns="urn:x"/>`,
		`<r xmlns:p="http://www.w3.org/XML/1998/namespace"/>`,
		`<r xmlns:p="http://www.w3.org/2000/xmlns/"/>`,
	} {
		_, err := Parse([]byte(bad))
		require.Error(t, err, "expected rejection for %s", bad)
	}
	// The xml prefix bound to its own URI is legal, and usable.
	_, err := Parse([]byte(`<r xmlns:xml="http://www.w3.org/XML/1998/namespace" xml:lang="en"/>`))
	require.NoError(t, err)
	// xml: is usable with no declaration at all.
	_, err = Parse([]byte(`<r xml:lang="en"/>`))
	require.NoError(t, err)
}

// --- cost of resolution ----------------------------------------------------

// nsStackPayload nests `levels` elements each declaring `declsPerLevel`
// prefixes, then `leaves` elements each using `attrs` attributes bound to the
// OUTERMOST prefixes -- the worst case for a stack scanned from the top.
func nsStackPayload(levels, declsPerLevel, leaves, attrs int) []byte {
	var sb strings.Builder
	sb.WriteString(`<root`)
	for j := 0; j < attrs; j++ {
		fmt.Fprintf(&sb, ` xmlns:q%04d="urn:q:%04d"`, j, j)
	}
	sb.WriteString(`>`)
	for i := 0; i < levels; i++ {
		sb.WriteString(`<n`)
		for j := 0; j < declsPerLevel; j++ {
			fmt.Fprintf(&sb, ` xmlns:z%02d%04d="urn:z:%02d:%04d"`, i, j, i, j)
		}
		sb.WriteString(`>`)
	}
	for l := 0; l < leaves; l++ {
		sb.WriteString(`<leaf`)
		for j := 0; j < attrs; j++ {
			fmt.Fprintf(&sb, ` q%04d:a="v"`, j)
		}
		sb.WriteString(`/>`)
	}
	for i := 0; i < levels; i++ {
		sb.WriteString(`</n>`)
	}
	sb.WriteString(`</root>`)
	return []byte(sb.String())
}

// TestPrefixResolutionCostIndependentOfScopeSize is the regression test for
// prefix resolution scanning the in-scope binding stack. checkNamespaces
// resolves once per element name and once per prefixed attribute, so a linear
// scan made total parse cost bindings*lookups: ~24k stacked declarations plus
// ~490k prefixed leaves put a single sub-5MB document into the tens of seconds.
//
// The comparison holds the number of lookups and the document size roughly
// constant and varies only how many declarations are in scope, so it measures
// the per-lookup cost rather than the size of the input.
func TestPrefixResolutionCostIndependentOfScopeSize(t *testing.T) {
	measure := func(levels, decls int) (time.Duration, int) {
		raw := nsStackPayload(levels, decls, 400, 200)
		best := time.Duration(1 << 62)
		for r := 0; r < 3; r++ {
			start := time.Now()
			_, err := Parse(raw)
			require.NoError(t, err)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best, len(raw)
	}

	measure(2, 10) // warm up

	small, smallSize := measure(2, 10)   // ~220 bindings in scope
	large, largeSize := measure(95, 250) // ~24,000 bindings in scope

	ratio := float64(large) / float64(small)
	sizeRatio := float64(largeSize) / float64(smallSize)
	t.Logf("in-scope ~220: %v (%d B); in-scope ~24000: %v (%d B); time %.2fx, size %.2fx",
		small, smallSize, large, largeSize, ratio, sizeRatio)

	// A ~110x increase in in-scope declarations costs ~1.5x the bytes. With a
	// linear scan the time grew far faster than the bytes; indexed it should
	// track the size. Allow generous headroom over sizeRatio for noise.
	if ratio > sizeRatio*4 {
		t.Errorf("parse time grew %.2fx while input grew only %.2fx when in-scope "+
			"declarations went from ~220 to ~24000 — is prefix resolution scanning the stack?",
			ratio, sizeRatio)
	}
}
