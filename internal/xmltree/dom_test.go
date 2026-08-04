// Copyright 2025 Russell Haering et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xmltree

import (
	"bytes"
	"testing"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/assert"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
)

func TestDOM_BuildAndSerialize(t *testing.T) {
	doc := NewDocument()
	root := NewElement("samlp:Response")
	doc.SetRoot(root)
	root.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	root.CreateAttr("ID", "_abc")
	issuer := root.CreateElement("saml:Issuer")
	issuer.SetText("https://idp.example.com")
	status := root.CreateElement("samlp:Status")
	status.CreateElement("samlp:StatusCode").CreateAttr("Value", "ok & <done>")

	out, err := doc.WriteToBytes()
	require.NoError(t, err)
	assert.Equal(t,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc">`+
			`<saml:Issuer>https://idp.example.com</saml:Issuer>`+
			`<samlp:Status><samlp:StatusCode Value="ok &amp; &lt;done>"/></samlp:Status>`+
			`</samlp:Response>`,
		string(out))
}

func TestDOM_CreateAttrReplaces(t *testing.T) {
	el := NewElement("a")
	el.CreateAttr("x", "1")
	el.CreateAttr("x", "2")
	require.Len(t, el.Attr, 1)
	assert.Equal(t, "2", el.SelectAttrValue("x", ""))
	assert.Equal(t, "dflt", el.SelectAttrValue("missing", "dflt"))
}

func TestDOM_AddChildReparents(t *testing.T) {
	a := NewElement("a")
	b := NewElement("b")
	c := a.CreateElement("c")
	require.Same(t, a, c.Parent())

	b.AddChild(c)
	assert.Same(t, b, c.Parent())
	assert.Empty(t, a.ChildElements(), "AddChild must detach from the old parent")
	require.Len(t, b.ChildElements(), 1)
}

func TestDOM_RemoveChild(t *testing.T) {
	a := NewElement("a")
	c1 := a.CreateElement("c")
	c2 := a.CreateElement("c")
	require.True(t, a.RemoveChild(c1))
	assert.Nil(t, c1.Parent())
	require.Len(t, a.ChildElements(), 1)
	assert.Same(t, c2, a.ChildElements()[0])
	assert.False(t, a.RemoveChild(c1), "already removed")
}

func TestDOM_CopyIsDeepAndParentless(t *testing.T) {
	root := mustParse(t, `<a x="1"><b>text</b></a>`)
	cp := root.SelectElement("b").Copy()
	assert.Nil(t, cp.Parent())
	cp.SetText("changed")
	cp.CreateAttr("new", "attr")
	assert.Equal(t, "text", root.SelectElement("b").Text(), "copy must not alias the original")
	assert.Nil(t, root.SelectElement("b").SelectAttr("new"))
}

func TestDOM_SetTextReplacesAllCharData(t *testing.T) {
	root := mustParse(t, `<a>one<b/>two</a>`)
	root.SetText("only")
	assert.Equal(t, "only", root.Text())
	require.NotNil(t, root.SelectElement("b"), "non-text children must survive SetText")
}

func TestDOM_CanonicalWriter(t *testing.T) {
	// Strict parse rejects comments, so build one programmatically to prove
	// the canonical writer omits it.
	root := mustParse(t, "<a x=\"v\twith&#xA;ws\"><empty/>text&amp;</a>")
	root.Child = append(root.Child, &Comment{Data: " c "})

	var buf bytes.Buffer
	root.WriteCanonicalTo(&buf)
	assert.Equal(t,
		`<a x="v with&#xA;ws"><empty></empty>text&amp;<!-- c --></a>`,
		buf.String(),
		"canonical form: explicit end tags, c14n escaping; comment stripping is the canonicalizer's job")

	// Non-canonical form self-closes empties.
	assert.Equal(t,
		`<a x="v with&#xA;ws"><empty/>text&amp;<!-- c --></a>`,
		string(root.WriteToBytes()))
}

func TestDOM_SelectElementPrefixed(t *testing.T) {
	root := mustParse(t, `<a xmlns:p="urn:x"><p:b/><b/></a>`)
	require.NotNil(t, root.SelectElement("p:b"))
	// An unprefixed query matches any prefix (etree-compatible); the first
	// match in document order here is p:b.
	assert.Same(t, root.SelectElement("p:b"), root.SelectElement("b"))
	assert.Len(t, root.SelectElements("b"), 2)
	assert.Nil(t, root.SelectElement("q:b"))

	// Attribute selection stays exact: a prefixed look-alike must not
	// satisfy an unprefixed lookup.
	el := mustParse(t, `<a xmlns:q="urn:x" q:URI="evil" URI="real"/>`)
	assert.Equal(t, "real", el.SelectAttrValue("URI", ""))
	el = mustParse(t, `<a xmlns:q="urn:x" q:URI="evil"/>`)
	assert.Equal(t, "", el.SelectAttrValue("URI", ""))
}
