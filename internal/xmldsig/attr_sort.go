package xmldsig

import (
	"sort"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// SortAttrs sorts attrs in place into the canonical C14N attribute order.
//
// This is the entry point production canonicalization uses. It resolves every
// namespace prefix once up front, so the comparator is O(1) rather than
// scanning the attribute list on each comparison. Sorting an element's
// attributes is therefore O(n log n); routing this through SortedAttrs
// instead makes it O(n² log n), which is remotely reachable during
// pre-authentication canonicalization of an attacker-supplied SignedInfo.
func SortAttrs(attrs []xmltree.Attr) {
	sort.Sort(attrSorter{attrs: attrs, uris: prefixURIs(attrs)})
}

// prefixURIs maps each namespace prefix declared in attrs to its URI. The
// parser rejects duplicate attributes, and canonicalization emits at most one
// declaration per prefix, so a prefix appears at most once.
func prefixURIs(attrs []xmltree.Attr) map[string]string {
	var uris map[string]string
	for _, attr := range attrs {
		if attr.Space == xmlnsPrefix {
			if uris == nil {
				uris = make(map[string]string, len(attrs))
			}
			if _, ok := uris[attr.Key]; !ok {
				uris[attr.Key] = attr.Value
			}
		}
	}
	return uris
}

// attrSorter sorts an attribute list using a precomputed prefix->URI map.
type attrSorter struct {
	attrs []xmltree.Attr
	uris  map[string]string
}

func (s attrSorter) Len() int      { return len(s.attrs) }
func (s attrSorter) Swap(i, j int) { s.attrs[i], s.attrs[j] = s.attrs[j], s.attrs[i] }

func (s attrSorter) Less(i, j int) bool {
	return lessAttr(s.attrs[i], s.attrs[j], s.resolvePrefix)
}

// resolvePrefix mirrors SortedAttrs.resolvePrefix, including its fallback of
// returning the prefix itself when the declaration lives on an ancestor.
func (s attrSorter) resolvePrefix(prefix string) string {
	if uri, ok := s.uris[prefix]; ok {
		return uri
	}
	return prefix
}

// SortedAttrs provides sorting capabilities, compatible with XML C14N, on top
// of an []xmltree.Attr.
//
// Deprecated for production use: its Less resolves namespace prefixes by
// rescanning the attribute list, making a sort quadratic in the number of
// attributes. Call SortAttrs instead. This type is retained because it
// documents the comparator's contract directly and is exercised as such by
// the canonicalization audit tests.
type SortedAttrs []xmltree.Attr

func (a SortedAttrs) Len() int {
	return len(a)
}

func (a SortedAttrs) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// Less implements the canonical attribute ordering from the C14N spec:
//
//  1. Default namespace declaration (xmlns="...") comes first.
//  2. namespace prefix declarations (xmlns:prefix="..."), sorted by prefix.
//  3. Unprefixed attributes, sorted by local name.
//  4. namespace-qualified attributes, sorted first by namespace URI then by
//     local name.
func (a SortedAttrs) Less(i, j int) bool {
	return lessAttr(a[i], a[j], a.resolvePrefix)
}

// lessAttr implements the canonical attribute ordering. resolve maps a
// namespace prefix to its URI; both SortedAttrs and attrSorter share this
// comparison so the two orderings cannot drift apart.
func lessAttr(x, y xmltree.Attr, resolve func(string) string) bool {
	// --- 1. Default namespace declaration (xmlns="...") ---

	// If attr y is a default namespace declaration, attr x may
	// not be strictly "less" than it.
	if y.Space == defaultPrefix && y.Key == xmlnsPrefix {
		return false
	}

	// If attr x is a default namespace declaration, it comes before everything.
	if x.Space == defaultPrefix && x.Key == xmlnsPrefix {
		return true
	}

	// --- 2. namespace prefix declarations (xmlns:prefix) sorted by prefix ---

	if x.Space == xmlnsPrefix {
		if y.Space == xmlnsPrefix {
			return x.Key < y.Key
		}
		return true
	}

	if y.Space == xmlnsPrefix {
		return false
	}

	// --- 3. Unprefixed attributes sorted by local name ---

	if x.Space == defaultPrefix {
		if y.Space == defaultPrefix {
			return x.Key < y.Key
		}
		return true
	}

	if y.Space == defaultPrefix {
		return false
	}

	// --- 4. namespace-qualified attributes, sorted by namespace URI then local name ---

	leftURI := resolve(x.Space)
	rightURI := resolve(y.Space)

	if leftURI != rightURI {
		return leftURI < rightURI
	}

	return x.Key < y.Key
}

// resolvePrefix finds the namespace URI for a prefix by scanning the attribute
// list for an xmlns:prefix declaration. If no declaration is found, the prefix
// itself is returned as a fallback (this preserves a stable sort order even
// when namespace declarations live on ancestor elements).
func (a SortedAttrs) resolvePrefix(prefix string) string {
	for _, attr := range a {
		if attr.Space == xmlnsPrefix && attr.Key == prefix {
			return attr.Value
		}
	}
	// Fallback: use prefix as-is. This happens when the namespace declaration
	// is on an ancestor element and hasn't been copied to this element's
	// attribute list. In practice, both inclusive and exclusive C14N ensure
	// that the relevant namespace declarations are present.
	return prefix
}
