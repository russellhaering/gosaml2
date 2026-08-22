package xmldsig

import (
	"bytes"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// Canonicalizer is an implementation of a canonicalization algorithm.
type Canonicalizer interface {
	Canonicalize(el *xmltree.Element) ([]byte, error)
	Algorithm() AlgorithmID
}

type NullCanonicalizer struct {
}

func MakeNullCanonicalizer() Canonicalizer {
	return &NullCanonicalizer{}
}

func (c *NullCanonicalizer) Algorithm() AlgorithmID {
	return AlgorithmID("NULL")
}

func (c *NullCanonicalizer) Canonicalize(el *xmltree.Element) ([]byte, error) {
	prepped, err := canonicalPrep(el, false, true)
	if err != nil {
		return nil, err
	}
	return canonicalSerialize(prepped)
}

type c14N10ExclusiveCanonicalizer struct {
	prefixList string
	comments   bool
}

// MakeC14N10ExclusiveCanonicalizerWithPrefixList constructs an exclusive Canonicalizer
// from a PrefixList in NMTOKENS format (a white space separated list).
func MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList string) Canonicalizer {
	return &c14N10ExclusiveCanonicalizer{
		prefixList: prefixList,
		comments:   false,
	}
}

// MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList constructs an exclusive Canonicalizer
// from a PrefixList in NMTOKENS format (a white space separated list).
func MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList string) Canonicalizer {
	return &c14N10ExclusiveCanonicalizer{
		prefixList: prefixList,
		comments:   true,
	}
}

// Canonicalize transforms the input Element into a serialized XML document in canonical form.
func (c *c14N10ExclusiveCanonicalizer) Canonicalize(el *xmltree.Element) ([]byte, error) {
	err := TransformExcC14n(el, c.prefixList, c.comments)
	if err != nil {
		return nil, err
	}

	return canonicalSerialize(el)
}

func (c *c14N10ExclusiveCanonicalizer) Algorithm() AlgorithmID {
	if c.comments {
		return CanonicalXML10ExclusiveWithCommentsAlgorithmId
	}
	return CanonicalXML10ExclusiveAlgorithmId
}

type c14N11Canonicalizer struct {
	comments bool
}

// MakeC14N11Canonicalizer constructs an inclusive canonicalizer.
func MakeC14N11Canonicalizer() Canonicalizer {
	return &c14N11Canonicalizer{
		comments: false,
	}
}

// MakeC14N11WithCommentsCanonicalizer constructs an inclusive canonicalizer.
func MakeC14N11WithCommentsCanonicalizer() Canonicalizer {
	return &c14N11Canonicalizer{
		comments: true,
	}
}

// Canonicalize transforms the input Element into a serialized XML document in canonical form.
func (c *c14N11Canonicalizer) Canonicalize(el *xmltree.Element) ([]byte, error) {
	prepped, err := canonicalPrep(el, true, c.comments)
	if err != nil {
		return nil, err
	}
	return canonicalSerialize(prepped)
}

func (c *c14N11Canonicalizer) Algorithm() AlgorithmID {
	if c.comments {
		return CanonicalXML11WithCommentsAlgorithmId
	}
	return CanonicalXML11AlgorithmId
}

type c14N10RecCanonicalizer struct {
	comments bool
}

// MakeC14N10RecCanonicalizer constructs an inclusive canonicalizer.
func MakeC14N10RecCanonicalizer() Canonicalizer {
	return &c14N10RecCanonicalizer{
		comments: false,
	}
}

// MakeC14N10WithCommentsCanonicalizer constructs an inclusive canonicalizer.
func MakeC14N10WithCommentsCanonicalizer() Canonicalizer {
	return &c14N10RecCanonicalizer{
		comments: true,
	}
}

// Canonicalize transforms the input Element into a serialized XML document in canonical form.
func (c *c14N10RecCanonicalizer) Canonicalize(inputXML *xmltree.Element) ([]byte, error) {
	parentNamespaceAttributes, parentXmlAttributes := getParentNamespaceAndXmlAttributes(inputXML)
	inputXMLCopy := inputXML.Copy()
	enhanceNamespaceAttributes(inputXMLCopy, parentNamespaceAttributes, parentXmlAttributes)
	prepped, err := canonicalPrep(inputXMLCopy, true, c.comments)
	if err != nil {
		return nil, err
	}
	return canonicalSerialize(prepped)
}

func (c *c14N10RecCanonicalizer) Algorithm() AlgorithmID {
	if c.comments {
		return CanonicalXML10WithCommentsAlgorithmId
	}
	return CanonicalXML10RecAlgorithmId

}

func composeAttr(space, key string) string {
	if space != "" {
		return space + ":" + key
	}

	return key
}

type c14nSpace struct {
	a    xmltree.Attr
	used bool
}

const nsSpace = "xmlns"

// canonicalPrep accepts an *xmltree.Element and transforms it into one which is ready
// for serialization into inclusive canonical form. Specifically this
// entails:
//
// 1. Stripping re-declarations of namespaces
// 2. Sorting attributes into canonical order
//
// Inclusive canonicalization does not strip unused namespaces.
//
// TODO(russell_h): This is very similar to excCanonicalPrep - perhaps they should
// be unified into one parameterized function?
func canonicalPrep(el *xmltree.Element, strip bool, comments bool) (*xmltree.Element, error) {
	// Create a dedicated copy of the element that canonicalPrepInner can modify.
	ne := el.Copy()
	budget := canonicalPrepElementLimit
	if err := canonicalPrepInner(ne, make(map[string]string), &budget, strip, comments); err != nil {
		return nil, err
	}
	return ne, nil
}

// canonicalPrepElementLimit bounds how many elements inclusive canonicalization
// will process. Exclusive canonicalization is bounded by NSContext.CheckLimit
// at the same count, and both run on attacker-supplied XML before any signature
// is verified -- the CanonicalizationMethod that selects between them is itself
// attacker-controlled, so an unbounded inclusive path is simply the one an
// attacker picks.
const canonicalPrepElementLimit = 1000

// canonicalPrepInner rewrites ne in place into inclusive canonical form.
//
// seenSoFar maps a namespace declaration to the value already in scope, and is
// shared across the whole traversal rather than copied per element: copying it
// at every element makes the per-element cost proportional to the number of
// ancestor declarations, so a deep chain of declarations followed by many cheap
// leaves costs declarations*leaves. Declarations this element adds are undone
// on the way back out, which keeps the shared map equivalent to a per-element
// copy without the copying.
func canonicalPrepInner(ne *xmltree.Element, seenSoFar map[string]string, budget *int, strip bool, comments bool) error {
	if *budget <= 0 {
		return ErrCanonicalizationLimit
	}
	*budget--

	SortAttrs(ne.Attr)

	// Declarations this element introduces, newest last, so they can be
	// unwound in reverse once its subtree is done.
	type shadowed struct {
		key     string
		prevURI string
		prevOK  bool
	}
	var undo []shadowed
	declare := func(key, value string) {
		prev, ok := seenSoFar[key]
		undo = append(undo, shadowed{key: key, prevURI: prev, prevOK: ok})
		seenSoFar[key] = value
	}

	n := 0
	for _, attr := range ne.Attr {
		if attr.Space != nsSpace && !(attr.Space == "" && attr.Key == nsSpace) {
			ne.Attr[n] = attr
			n++
			continue
		}

		if attr.Space == nsSpace {
			key := attr.Space + ":" + attr.Key
			if uri, seen := seenSoFar[key]; !seen || attr.Value != uri {
				ne.Attr[n] = attr
				n++
				declare(key, attr.Value)
			}
		} else {
			if uri, seen := seenSoFar[nsSpace]; (!seen && attr.Value != "") || attr.Value != uri {
				ne.Attr[n] = attr
				n++
				declare(nsSpace, attr.Value)
			}
		}
	}
	ne.Attr = ne.Attr[:n]

	if !comments {
		c := 0
		for c < len(ne.Child) {
			if _, ok := ne.Child[c].(*xmltree.Comment); ok {
				ne.RemoveChildAt(c)
			} else {
				c++
			}
		}
	}

	for _, token := range ne.Child {
		childElement, ok := token.(*xmltree.Element)
		if ok {
			if err := canonicalPrepInner(childElement, seenSoFar, budget, strip, comments); err != nil {
				return err
			}
		}
	}

	for i := len(undo) - 1; i >= 0; i-- {
		u := undo[i]
		if u.prevOK {
			seenSoFar[u.key] = u.prevURI
		} else {
			delete(seenSoFar, u.key)
		}
	}

	return nil
}

func canonicalSerialize(el *xmltree.Element) ([]byte, error) {
	var buf bytes.Buffer
	el.WriteCanonicalTo(&buf)
	return buf.Bytes(), nil
}

func getParentNamespaceAndXmlAttributes(el *xmltree.Element) (map[string]string, map[string]string) {
	namespaceMap := make(map[string]string, 23)
	xmlMap := make(map[string]string, 5)
	parents := make([]*xmltree.Element, 0, 23)
	n1 := el.Parent()
	if n1 == nil {
		return namespaceMap, xmlMap
	}
	parent := n1
	for parent != nil {
		parents = append(parents, parent)
		parent = parent.Parent()
	}
	for i := len(parents) - 1; i > -1; i-- {
		elementPos := parents[i]
		for _, attr := range elementPos.Attr {
			if attr.Space == "xmlns" && (attr.Key != "xml" || attr.Value != "http://www.w3.org/XML/1998/namespace") {
				namespaceMap[attr.Key] = attr.Value
			} else if attr.Space == "" && attr.Key == "xmlns" {
				namespaceMap[attr.Key] = attr.Value
			} else if attr.Space == "xml" {
				xmlMap[attr.Key] = attr.Value
			}
		}
	}
	return namespaceMap, xmlMap
}

func enhanceNamespaceAttributes(el *xmltree.Element, parentNamespaces map[string]string, parentXmlAttributes map[string]string) {
	for prefix, uri := range parentNamespaces {
		// Skip empty namespace URIs - they are undeclarations and should
		// not be injected onto subset root elements.
		if uri == "" {
			continue
		}
		if prefix == "xmlns" {
			el.CreateAttr("xmlns", uri)
		} else {
			el.CreateAttr("xmlns:"+prefix, uri)
		}
	}
	for attr, value := range parentXmlAttributes {
		el.CreateAttr("xml:"+attr, value)
	}
}
