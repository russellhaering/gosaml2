package etreeutils

import "github.com/beevik/etree"

// SortedAttrs provides sorting capabilities, compatible with XML C14N, on top
// of an []etree.Attr
type SortedAttrs []etree.Attr

func (a SortedAttrs) Len() int {
	return len(a)
}

func (a SortedAttrs) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// Less implements the canonical attribute ordering from the C14N spec:
//
//  1. Default namespace declaration (xmlns="...") comes first.
//  2. Namespace prefix declarations (xmlns:prefix="..."), sorted by prefix.
//  3. Unprefixed attributes, sorted by local name.
//  4. Namespace-qualified attributes, sorted first by namespace URI then by
//     local name.
//
// The namespace URI for a prefixed attribute is resolved by scanning the same
// attribute list for the corresponding xmlns:prefix declaration. This works
// because namespace declarations are already present on the element (or have
// been attached during exclusive-c14n processing) before sorting occurs.
func (a SortedAttrs) Less(i, j int) bool {
	// --- 1. Default namespace declaration (xmlns="...") ---

	// If attr j is a default namespace declaration, attr i may
	// not be strictly "less" than it.
	if a[j].Space == defaultPrefix && a[j].Key == xmlnsPrefix {
		return false
	}

	// If attr i is a default namespace declaration, it comes before everything.
	if a[i].Space == defaultPrefix && a[i].Key == xmlnsPrefix {
		return true
	}

	// --- 2. Namespace prefix declarations (xmlns:prefix) sorted by prefix ---

	if a[i].Space == xmlnsPrefix {
		if a[j].Space == xmlnsPrefix {
			return a[i].Key < a[j].Key
		}
		return true
	}

	if a[j].Space == xmlnsPrefix {
		return false
	}

	// --- 3. Unprefixed attributes sorted by local name ---

	if a[i].Space == defaultPrefix {
		if a[j].Space == defaultPrefix {
			return a[i].Key < a[j].Key
		}
		return true
	}

	if a[j].Space == defaultPrefix {
		return false
	}

	// --- 4. Namespace-qualified attributes, sorted by namespace URI then local name ---

	// Resolve namespace URIs by scanning for matching xmlns:prefix declarations.
	leftURI := a.resolvePrefix(a[i].Space)
	rightURI := a.resolvePrefix(a[j].Space)

	if leftURI != rightURI {
		return leftURI < rightURI
	}

	return a[i].Key < a[j].Key
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
