package xmldsig

import (
	"sort"
	"strings"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// TransformExcC14n transforms the passed element into xml-exc-c14n form.
func TransformExcC14n(el *xmltree.Element, inclusiveNamespacesPrefixList string, comments bool) error {
	prefixes := strings.Fields(inclusiveNamespacesPrefixList)
	prefixSet := make(map[string]struct{}, len(prefixes))

	for _, prefix := range prefixes {
		prefixSet[prefix] = struct{}{}
	}

	ctx := NewDefaultNSContext()
	err := transformExcC14n(ctx, ctx, el, prefixSet, comments)
	if err != nil {
		return err
	}

	return nil
}

func transformExcC14n(ctx, declared NSContext, el *xmltree.Element, inclusiveNamespaces map[string]struct{}, comments bool) error {
	if err := ctx.CheckLimit(); err != nil {
		return err
	}

	scope, err := ctx.SubContext(el)
	if err != nil {
		return err
	}

	visiblyUtilizedPrefixes := map[string]struct{}{
		el.Space: {},
	}

	filteredAttrs := []xmltree.Attr{}

	// Filter out all namespace declarations
	for _, attr := range el.Attr {
		switch {
		case attr.Space == xmlnsPrefix:
			if _, ok := inclusiveNamespaces[attr.Key]; ok {
				visiblyUtilizedPrefixes[attr.Key] = struct{}{}
			}

		case attr.Space == defaultPrefix && attr.Key == xmlnsPrefix:
			if _, ok := inclusiveNamespaces[defaultPrefix]; ok {
				visiblyUtilizedPrefixes[defaultPrefix] = struct{}{}
			}

		default:
			if attr.Space != defaultPrefix {
				visiblyUtilizedPrefixes[attr.Space] = struct{}{}
			}

			filteredAttrs = append(filteredAttrs, attr)
		}
	}

	el.Attr = filteredAttrs

	declared = declared.Copy()

	// Declare all visibly utilized prefixes that are in-scope but haven't
	// been declared in the canonicalized form yet. These might have been
	// declared on this element but then filtered out above, or they might
	// have been declared on an ancestor (before canonicalization) which
	// didn't visibly utilize and thus had them removed.
	for prefix := range visiblyUtilizedPrefixes {
		// Skip redundant declarations - they have to already have the same
		// value.
		if declaredNamespace, ok := declared.prefixes[prefix]; ok {
			if value, ok := scope.prefixes[prefix]; ok && declaredNamespace == value {
				continue
			}
		}

		namespace, err := scope.LookupPrefix(prefix)
		if err != nil {
			return err
		}

		el.Attr = append(el.Attr, declared.declare(prefix, namespace))
	}

	sort.Sort(SortedAttrs(el.Attr))

	if !comments {
		c := 0
		for c < len(el.Child) {
			if _, ok := el.Child[c].(*xmltree.Comment); ok {
				el.RemoveChildAt(c)
			} else {
				c++
			}
		}
	}

	// Transform child elements
	for _, child := range el.ChildElements() {
		err := transformExcC14n(scope, declared, child, inclusiveNamespaces, comments)
		if err != nil {
			return err
		}
	}

	return nil
}
