package etreeutils

import (
	"sort"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestSortedAttrs(t *testing.T) {
	// Adapted from https://www.w3.org/TR/2001/REC-xml-c14n-20010315#Example-SETags
	input := `<e5 a:attr="out" b:attr="sorted" attr2="all" attr="I m" xmlns:b="http://www.ietf.org" xmlns:a="http://www.w3.org" xmlns="http://example.org"></e5>`
	expected := `<e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I m" attr2="all" b:attr="sorted" a:attr="out"></e5>`

	inDoc := etree.NewDocument()
	inDoc.ReadFromString(input)

	outElm := inDoc.Root().Copy()
	sort.Sort(SortedAttrs(outElm.Attr))
	outDoc := etree.NewDocument()
	outDoc.SetRoot(outElm)
	outDoc.WriteSettings = etree.WriteSettings{
		CanonicalEndTags: true,
	}

	outStr, err := outDoc.WriteToString()
	require.NoError(t, err)
	require.Equal(t, expected, outStr)
}
