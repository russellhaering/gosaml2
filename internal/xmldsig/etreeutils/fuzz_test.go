package etreeutils

import (
	"testing"

	"github.com/beevik/etree"
)

func FuzzNSTraverse(f *testing.F) {
	f.Add([]byte(`<root xmlns:a="http://a"><a:child>text</a:child></root>`))
	f.Add([]byte(`<r xmlns="http://default" xmlns:x="http://x"><x:a><b xmlns:y="http://y"><y:c x:d="val"/></b></x:a></r>`))
	f.Add([]byte(`<a xmlns:n1="http://n1" xmlns:n2="http://n2" xmlns:n3="http://n3"><n1:b n2:attr="v"><n3:c/></n1:b></a>`))
	f.Add([]byte(`<e xml:lang="en"><e xml:space="preserve"><e/></e></e>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		ctx := NewDefaultNSContext()

		// Exercise tree traversal — looking for panics and hangs.
		NSTraverse(ctx, root, func(_ NSContext, _ *etree.Element) error {
			return nil
		})

		// Exercise find iterate with a common namespace.
		NSFindIterate(root, "http://www.w3.org/2000/09/xmldsig#", "Signature", func(_ NSContext, _ *etree.Element) error {
			return ErrTraversalHalted
		})

		// Exercise select one.
		NSSelectOne(root, "http://www.w3.org/2000/09/xmldsig#", "SignedInfo")
	})
}

func FuzzTransformExcC14n(f *testing.F) {
	f.Add([]byte(`<root xmlns:a="http://a" xmlns:b="http://b"><a:child b:attr="val">text</a:child></root>`), "")
	f.Add([]byte(`<r xmlns="http://d"><child xmlns:x="http://x" x:a="1"/></r>`), "x")
	f.Add([]byte(`<e xmlns:ns1="http://ns1"><ns1:a><!-- comment --></ns1:a></e>`), "ns1")

	f.Fuzz(func(t *testing.T, data []byte, prefixList string) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		// Test with comments=false
		el := root.Copy()
		TransformExcC14n(el, prefixList, false)

		// Test with comments=true
		el = root.Copy()
		TransformExcC14n(el, prefixList, true)
	})
}
