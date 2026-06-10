package xmldsig

import (
	"encoding/xml"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// NSUnmarshalElement is a TEST-ONLY helper: it serializes an element (with
// its in-scope namespace declarations attached) and unmarshals the bytes via
// encoding/xml. Production code no longer routes anything through
// encoding/xml; the parser-differential tests keep using this as an
// independent oracle for what a second parser sees in the same bytes.
func NSUnmarshalElement(ctx NSContext, el *xmltree.Element, v interface{}) error {
	detached, err := NSDetach(ctx, el)
	if err != nil {
		return err
	}
	return xml.Unmarshal(detached.WriteToBytes(), v)
}
