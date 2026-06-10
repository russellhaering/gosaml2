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
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParse(t *testing.T, doc string) *Element {
	t.Helper()
	d, err := Parse([]byte(doc))
	require.NoError(t, err)
	return d.Root()
}

// ---------------------------------------------------------------------------
// Acceptance: constructs the strict profile must support
// ---------------------------------------------------------------------------

func TestParse_Accepts(t *testing.T) {
	cases := map[string]string{
		"minimal":                  `<a/>`,
		"explicit empty":           `<a></a>`,
		"xml declaration":          `<?xml version="1.0"?><a/>`,
		"decl with encoding":       `<?xml version="1.0" encoding="UTF-8"?><a/>`,
		"decl lowercase utf-8":     `<?xml version="1.0" encoding="utf-8"?><a/>`,
		"decl with standalone":     `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a/>`,
		"decl single quotes":       `<?xml version='1.0' encoding='UTF-8'?><a/>`,
		"prefixed namespaces":      `<p:a xmlns:p="urn:x"><p:b/></p:a>`,
		"default namespace":        `<a xmlns="urn:x"><b/></a>`,
		"default ns undeclared":    `<a xmlns="urn:x"><b xmlns=""/></a>`,
		"single-quoted attrs":      `<a x='1' y='2'/>`,
		"mixed quote styles":       `<a x='1' y="2"/>`,
		"predefined entities":      `<a x="&amp;&lt;&gt;&quot;&apos;">&amp;&lt;&gt;</a>`,
		"decimal charref":          `<a>&#65;</a>`,
		"hex charref":              `<a>&#x41;</a>`,
		"c14n whitespace charrefs": `<a x="&#x9;&#xA;&#xD;">&#xD;</a>`,
		"xml:lang":                 `<a xml:lang="en"/>`,
		"xsi type attr":            `<a xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string"/>`,
		"whitespace around root":   "\n  <a/>  \n",
		"crlf line endings":        "<a>line1\r\nline2</a>",
		"unicode text":             `<a>héllo wörld 你好</a>`,
		"supplementary plane text": `<a>𐀀</a>`,
		"same local diff ns ok":    `<a xmlns:p="urn:1" xmlns:q="urn:2" p:x="1" q:x="2"/>`,
		"tab and lf in attr":       "<a x=\"v1\tv2\nv3\"/>",
		"deep but legal nesting":   strings.Repeat("<a>", 50) + strings.Repeat("</a>", 50),
		"unprefixed attr not in default ns": `<a xmlns="urn:x" b="1"/>`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(doc))
			assert.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Rejection: every feature the strict profile excludes
// ---------------------------------------------------------------------------

func TestParse_Rejects(t *testing.T) {
	cases := map[string]struct {
		doc     string
		wantMsg string // substring the error must contain (names the construct)
	}{
		"BOM":                    {"\xEF\xBB\xBF<a/>", "byte-order mark"},
		"invalid utf-8":          {"<a>\xFF\xFE</a>", "UTF-8"},
		"doctype":                {`<!DOCTYPE a><a/>`, "DOCTYPE"},
		"doctype with entity":    {`<!DOCTYPE a [<!ENTITY x "y">]><a/>`, "DOCTYPE"},
		"processing instruction": {`<a><?php evil?></a>`, "processing instruction"},
		"pi before root":         {`<?xml-stylesheet href="x"?><a/>`, "processing instruction"},
		"comment":                {`<a><!-- c --></a>`, "comments are not allowed"},
		"comment before root":    {`<!-- c --><a/>`, "comments are not allowed"},
		"cdata":                  {`<a><![CDATA[x]]></a>`, "CDATA"},
		"named entity":           {`<a>&xxe;</a>`, "entity"},
		"html entity":            {`<a>&nbsp;</a>`, "entity"},
		"unterminated reference": {`<a>&amp</a>`, "unterminated reference"},
		"bare ampersand":         {`<a>a & b</a>`, "reference"},
		"charref invalid char":   {`<a>&#x0;</a>`, "not a valid XML character"},
		"charref surrogate":      {`<a>&#xD800;</a>`, "not a valid XML character"},
		"charref beyond unicode": {`<a>&#x110000;</a>`, "character reference"},
		"charref empty":          {`<a>&#;</a>`, "character reference"},
		"charref uppercase X":    {`<a>&#X41;</a>`, "character reference"},
		"non-utf8 encoding decl": {`<?xml version="1.0" encoding="ISO-8859-1"?><a/>`, "encoding"},
		"xml version 1.1":        {`<?xml version="1.1"?><a/>`, "version"},
		"decl missing version":   {`<?xml encoding="UTF-8"?><a/>`, "XML declaration"},
		"two roots":              {`<a/><b/>`, "root element"},
		"text outside root":      {`<a/>text`, "outside the root"},
		"text before root":       {`text<a/>`, "outside the root"},
		"no root":                {`   `, "no root element"},
		"empty input":            {``, "no root element"},
		"unclosed element":       {`<a><b></a>`, "mismatched end tag"},
		"mismatched end tag":     {`<a></b>`, "mismatched end tag"},
		"mismatched prefix":      {`<p:a xmlns:p="urn:x" xmlns:q="urn:x"></q:a>`, "mismatched end tag"},
		"unclosed start tag":     {`<a`, "unclosed start tag"},
		"truncated doc":          {`<a><b/>`, "unclosed element"},
		"unquoted attr value":    {`<a x=1/>`, "must be quoted"},
		"attr without value":     {`<a x/>`, "no value"},
		"lt in attr value":       {`<a x="<"/>`, "'<' is not allowed"},
		"duplicate attr":         {`<a x="1" x="2"/>`, "duplicate attribute"},
		"dup attr after ns resolution": {
			`<a xmlns:p="urn:1" xmlns:q="urn:1" p:x="1" q:x="2"/>`, "after namespace resolution"},
		"undeclared element prefix": {`<p:a/>`, "undeclared namespace prefix"},
		"undeclared attr prefix":    {`<a p:x="1"/>`, "undeclared namespace prefix"},
		"prefix undeclaration":      {`<a xmlns:p="urn:x"><b xmlns:p=""/></a>`, "cannot be undeclared"},
		"xmlns prefix declared":     {`<a xmlns:xmlns="urn:x"/>`, "xmlns prefix"},
		"xml prefix rebound":        {`<a xmlns:xml="urn:x"/>`, "xml prefix"},
		"other prefix to xml ns":    {`<a xmlns:p="http://www.w3.org/XML/1998/namespace"/>`, "xml prefix"},
		"cdata end in text":         {`<a>]]></a>`, "']]>'"},
		"double colon name":         {`<a::b/>`, "invalid element name"},
		"empty prefix":              {`<:a/>`, "invalid element name"},
		"empty local":               {`<a:/>`, "invalid element name"},
		"name starts with digit":    {`<1a/>`, "invalid name start"},
		"name starts with dash":     {`<-a/>`, "invalid name start"},
		"control char in text":      {"<a>\x01</a>", "invalid character"},
		"control char in attr":      {"<a x=\"\x01\"/>", "invalid character"},
		"missing attr space":        {`<a x="1"y="2"/>`, "expected whitespace"},
		"nesting too deep":          {strings.Repeat("<a>", maxDepth+1) + strings.Repeat("</a>", maxDepth+1), "depth limit"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg,
				"rejection error must name the offending construct")
		})
	}
}

// ParseMetadata relaxes exactly one thing: comments are tolerated (and
// dropped). Everything else stays rejected.
func TestParseMetadata_CommentHandling(t *testing.T) {
	d, err := ParseMetadata([]byte(`<!-- federation --><a><!-- x -->text<!-- y --><b/></a>`))
	require.NoError(t, err)
	root := d.Root()
	assert.Equal(t, "text", root.Text())
	for _, tok := range root.Child {
		_, isComment := tok.(*Comment)
		assert.False(t, isComment, "comments must be dropped, not preserved")
	}
	require.NotNil(t, root.SelectElement("b"))

	// Text split by a comment concatenates — no node-splitting confusion.
	d, err = ParseMetadata([]byte(`<a>admin@evil.com<!-- -->.example.com</a>`))
	require.NoError(t, err)
	assert.Equal(t, "admin@evil.com.example.com", d.Root().Text())

	// Everything else is still rejected.
	for name, doc := range map[string]string{
		"doctype": `<!DOCTYPE a><a/>`,
		"cdata":   `<a><![CDATA[x]]></a>`,
		"pi":      `<a><?pi x?></a>`,
		"entity":  `<a>&ent;</a>`,
		"unterminated comment": `<a><!-- x</a>`,
		"double dash comment":  `<a><!-- x -- y --></a>`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseMetadata([]byte(doc))
			assert.Error(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Semantics: normalization and decoding details
// ---------------------------------------------------------------------------

func TestParse_LineEndingNormalization(t *testing.T) {
	// XML 1.0 §2.11: CRLF and lone CR become LF in text.
	root := mustParse(t, "<a>x\r\ny\rz\n</a>")
	assert.Equal(t, "x\ny\nz\n", root.Text())

	// A character reference to CR survives.
	root = mustParse(t, "<a>x&#xD;y</a>")
	assert.Equal(t, "x\ry", root.Text())
}

func TestParse_AttrValueNormalization(t *testing.T) {
	// XML 1.0 §3.3.3 (CDATA attributes): literal TAB/LF/CR become spaces...
	root := mustParse(t, "<a x=\"v1\tv2\nv3\r\nv4\"/>")
	assert.Equal(t, "v1 v2 v3 v4", root.SelectAttrValue("x", ""))

	// ...but character-referenced whitespace is preserved.
	root = mustParse(t, `<a x="v1&#x9;v2&#xA;v3&#xD;v4"/>`)
	assert.Equal(t, "v1\tv2\nv3\rv4", root.SelectAttrValue("x", ""))
}

func TestParse_EntityDecoding(t *testing.T) {
	root := mustParse(t, `<a x="a&amp;b&lt;c&gt;d&quot;e&apos;f">&#65;&#x42;c</a>`)
	assert.Equal(t, `a&b<c>d"e'f`, root.SelectAttrValue("x", ""))
	assert.Equal(t, "ABc", root.Text())
}

func TestParse_TreeShape(t *testing.T) {
	root := mustParse(t, `<p:a xmlns:p="urn:x" id="1"> <b>text</b><p:c/></p:a>`)
	assert.Equal(t, "p", root.Space)
	assert.Equal(t, "a", root.Tag)
	assert.Equal(t, "p:a", root.FullTag())
	require.Len(t, root.Attr, 2)
	assert.Equal(t, Attr{Space: "xmlns", Key: "p", Value: "urn:x"}, root.Attr[0])
	assert.Equal(t, Attr{Space: "", Key: "id", Value: "1"}, root.Attr[1])

	// Whitespace between elements is preserved as character data.
	require.Len(t, root.Child, 3)
	cd, ok := root.Child[0].(*CharData)
	require.True(t, ok)
	assert.Equal(t, " ", cd.Data)

	b := root.SelectElement("b")
	require.NotNil(t, b)
	assert.Equal(t, "text", b.Text())
	assert.Same(t, root, b.Parent())

	c := root.SelectElement("p:c")
	require.NotNil(t, c)
	assert.Empty(t, c.Child)
}

func TestParse_RoundTripFixpoint(t *testing.T) {
	docs := []string{
		`<a/>`,
		`<p:a xmlns:p="urn:x" x="1&#x9;2"> text &amp; more <p:b/>tail</p:a>`,
		"<a>\r\nline</a>",
		`<a x='single'/>`,
	}
	for _, doc := range docs {
		d1, err := Parse([]byte(doc))
		require.NoError(t, err)
		s1, err := d1.WriteToBytes()
		require.NoError(t, err)

		d2, err := Parse(s1)
		require.NoError(t, err, "our own output must reparse: %s", s1)
		s2, err := d2.WriteToBytes()
		require.NoError(t, err)
		assert.Equal(t, string(s1), string(s2), "parse→serialize must be a fixpoint")
	}
}

func TestParse_NodeLimit(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("<a>")
	for range maxNodes {
		sb.WriteString("<b/>")
	}
	sb.WriteString("</a>")
	_, err := Parse([]byte(sb.String()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node limit")
}

func TestParse_AttrLimit(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("<a")
	for i := 0; i <= maxAttrs; i++ {
		sb.WriteString(" x" + strconv.Itoa(i) + `="1"`)
	}
	sb.WriteString("/>")
	_, err := Parse([]byte(sb.String()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attribute limit")
}

func TestParseError_ReportsLine(t *testing.T) {
	_, err := Parse([]byte("<a>\n<b>\n<!-- nope -->\n</b>\n</a>"))
	require.Error(t, err)
	var pe *ParseError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, 3, pe.Line)
}
