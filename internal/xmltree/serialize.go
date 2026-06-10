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

import "bytes"

// Serialization always uses XML-c14n §2 lexical conventions for escaping
// (& < > " and TAB/LF/CR in the positions where they would otherwise be
// destroyed by re-parsing). Emitting our only output format in canonical
// lexical form makes parse→serialize→parse lossless and keeps the writer
// shared between message building and canonicalization. The only mode
// difference: canonical form writes empty elements as start/end tag pairs.
// Comments are emitted in both modes (per c14n §2.2 comment serialization);
// canonicalizers that omit comments strip them from the tree before
// serializing.

// WriteToBytes serializes the document. No XML declaration is emitted —
// SAML messages travel base64-encoded inside other envelopes and gosaml2
// has never emitted one.
func (d *Document) WriteToBytes() ([]byte, error) {
	var buf bytes.Buffer
	if d.root != nil {
		d.root.write(&buf, false)
	}
	return buf.Bytes(), nil
}

// WriteToString serializes the document to a string.
func (d *Document) WriteToString() (string, error) {
	b, err := d.WriteToBytes()
	return string(b), err
}

// WriteToBytes serializes the element subtree.
func (e *Element) WriteToBytes() []byte {
	var buf bytes.Buffer
	e.write(&buf, false)
	return buf.Bytes()
}

// WriteCanonicalTo serializes the element subtree in XML-c14n lexical form:
// empty elements as start/end tag pairs, comments omitted. Structural
// canonicalization (namespace propagation and attribute ordering) is the
// caller's responsibility — gosaml2's canonicalizers prepare the tree
// first and rely on the writer only for lexical form.
func (e *Element) WriteCanonicalTo(buf *bytes.Buffer) {
	e.write(buf, true)
}

func (e *Element) write(buf *bytes.Buffer, canonical bool) {
	buf.WriteByte('<')
	buf.WriteString(e.FullTag())
	for _, a := range e.Attr {
		buf.WriteByte(' ')
		buf.WriteString(a.FullKey())
		buf.WriteString(`="`)
		escapeAttr(buf, a.Value)
		buf.WriteByte('"')
	}
	if len(e.Child) == 0 && !canonical {
		buf.WriteString("/>")
		return
	}
	buf.WriteByte('>')
	for _, t := range e.Child {
		switch c := t.(type) {
		case *Element:
			c.write(buf, canonical)
		case *CharData:
			escapeText(buf, c.Data)
		case *Comment:
			buf.WriteString("<!--")
			buf.WriteString(c.Data)
			buf.WriteString("-->")
		}
	}
	buf.WriteString("</")
	buf.WriteString(e.FullTag())
	buf.WriteByte('>')
}

// escapeAttr writes an attribute value per XML-c14n §2: & < " become entity
// references; TAB, LF, CR become character references so they survive
// attribute-value normalization on re-parse.
func escapeAttr(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		case '"':
			buf.WriteString("&quot;")
		case '\t':
			buf.WriteString("&#x9;")
		case '\n':
			buf.WriteString("&#xA;")
		case '\r':
			buf.WriteString("&#xD;")
		default:
			buf.WriteByte(c)
		}
	}
}

// escapeText writes character data per XML-c14n §2: & < > become entity
// references and CR a character reference (a literal CR would be destroyed
// by line-ending normalization on re-parse).
func escapeText(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		case '>':
			buf.WriteString("&gt;")
		case '\r':
			buf.WriteString("&#xD;")
		default:
			buf.WriteByte(c)
		}
	}
}
