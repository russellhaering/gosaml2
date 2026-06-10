package sp

import (
	"encoding/xml"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// xmlUnmarshalElement is a TEST-ONLY helper: it serializes an element and
// unmarshals the bytes via encoding/xml. Production code extracts structs
// directly from xmltree elements; tests keep this as an independent oracle
// for what a second parser sees in the same bytes.
func xmlUnmarshalElement(el *xmltree.Element, obj interface{}) error {
	doc := xmltree.NewDocument()
	doc.SetRoot(el.Copy())
	data, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(data, obj)
}
