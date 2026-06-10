package xmldsig

import (
	"fmt"
	"testing"

	"github.com/beevik/etree"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/stretchr/testify/require"
)

// lenientParse is a TEST-ONLY loader for documents the strict parser
// rejects by design (W3C c14n vectors and attack documents containing
// comments, etc.). It parses with beevik/etree — an independent
// implementation — and converts the tree, preserving comments. Tokens the
// xmltree DOM cannot represent (processing instructions, directives) are an
// error: vectors that need them are out of the supported c14n profile.
func lenientParse(s string) (*xmltree.Element, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(s); err != nil {
		return nil, err
	}
	if doc.Root() == nil {
		return nil, fmt.Errorf("lenientParse: no root element")
	}
	return convertEtree(doc.Root())
}

func mustLenientParse(t *testing.T, s string) *xmltree.Element {
	t.Helper()
	el, err := lenientParse(s)
	require.NoError(t, err)
	return el
}

func convertEtree(el *etree.Element) (*xmltree.Element, error) {
	out := &xmltree.Element{Space: el.Space, Tag: el.Tag}
	for _, a := range el.Attr {
		out.Attr = append(out.Attr, xmltree.Attr{Space: a.Space, Key: a.Key, Value: a.Value})
	}
	for _, tok := range el.Child {
		switch c := tok.(type) {
		case *etree.Element:
			child, err := convertEtree(c)
			if err != nil {
				return nil, err
			}
			out.AddChild(child)
		case *etree.CharData:
			out.AddChild(&xmltree.CharData{Data: c.Data})
		case *etree.Comment:
			out.AddChild(xmltree.NewComment(c.Data))
		default:
			return nil, fmt.Errorf("lenientParse: unsupported token %T", tok)
		}
	}
	return out, nil
}

// lenientParseDoc wraps lenientParse in a Document, for vector-driven tests
// that operate on documents.
func lenientParseDoc(s string) (*xmltree.Document, error) {
	el, err := lenientParse(s)
	if err != nil {
		return nil, err
	}
	doc := xmltree.NewDocument()
	doc.SetRoot(el)
	return doc, nil
}

// parseVectorDoc loads a c14n test vector: strict parse where possible (it
// performs spec-correct attribute and line-ending normalization), falling
// back to the lenient loader for vectors using constructs the strict
// profile rejects (comments).
func parseVectorDoc(data []byte) (*xmltree.Document, error) {
	if doc, err := xmltree.Parse(data); err == nil {
		return doc, nil
	}
	return lenientParseDoc(string(data))
}
