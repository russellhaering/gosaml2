package xmldsig

import (
	"bytes"
	"sort"
	"testing"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

func TestSortedAttrs(t *testing.T) {
	// Adapted from https://www.w3.org/TR/2001/REC-xml-c14n-20010315#Example-SETags
	input := `<e5 a:attr="out" b:attr="sorted" attr2="all" attr="I m" xmlns:b="http://www.ietf.org" xmlns:a="http://www.w3.org" xmlns="http://example.org"></e5>`
	expected := `<e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I m" attr2="all" b:attr="sorted" a:attr="out"></e5>`

	inDoc := xmltree.NewDocument()
	require.NoError(t, inDoc.ReadFromString(input))

	outElm := inDoc.Root().Copy()
	sort.Sort(SortedAttrs(outElm.Attr))

	var buf bytes.Buffer
	outElm.WriteCanonicalTo(&buf)
	require.Equal(t, expected, buf.String())
}
