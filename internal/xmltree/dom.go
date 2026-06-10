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

// Package xmltree is a purpose-built XML document model and strict parser
// for SAML processing. It deliberately implements only the XML subset that
// SAML documents use; see Parse for the accepted profile.
//
// The document model intentionally mirrors the small slice of the
// github.com/beevik/etree API that gosaml2 historically used (Space/Tag
// prefix-form names, a Child token slice, CreateElement/CreateAttr/...), so
// code written against etree ports mechanically.
package xmltree

import "strings"

// Token is a node in an element's child list: *Element, *CharData, or
// *Comment.
type Token interface {
	// CopyToken returns a deep copy of the token with no parent.
	CopyToken() Token
}

// Attr is a single attribute. Space is the namespace prefix ("" if none,
// "xmlns" for prefixed namespace declarations) and Key the local name; for
// a default namespace declaration Space is "" and Key is "xmlns". Names are
// stored in prefix form, not resolved URIs — namespace resolution is
// contextual and handled by the consumer (see internal/xmldsig's NSContext).
type Attr struct {
	Space string
	Key   string
	Value string
}

// FullKey returns the attribute name in prefix:local form.
func (a Attr) FullKey() string {
	if a.Space == "" {
		return a.Key
	}
	return a.Space + ":" + a.Key
}

// Element is an XML element. Space is the namespace prefix ("" if none) and
// Tag the local name.
type Element struct {
	Space  string
	Tag    string
	Attr   []Attr
	Child  []Token
	parent *Element
}

// CharData is a run of character data. Data holds the decoded text (entity
// and character references already resolved).
type CharData struct {
	Data string
}

// Comment is an XML comment. The strict parser never produces one (Parse
// rejects comments; ParseMetadata drops them) — the type exists so that
// canonicalization code and tests can represent and filter comments in
// programmatically built trees.
type Comment struct {
	Data string
}

// Document is a container for a single root element.
type Document struct {
	root *Element
}

// NewDocument returns an empty document.
func NewDocument() *Document {
	return &Document{}
}

// NewElement returns a parentless element. The tag may carry a namespace
// prefix ("samlp:Response").
func NewElement(tag string) *Element {
	space, local := splitQName(tag)
	return &Element{Space: space, Tag: local}
}

// SetRoot replaces the document's root element. The element is detached
// from any previous parent.
func (d *Document) SetRoot(el *Element) {
	if el.parent != nil {
		el.parent.RemoveChild(el)
	}
	d.root = el
}

// Root returns the document's root element, or nil.
func (d *Document) Root() *Element {
	return d.root
}

// FullTag returns the element name in prefix:local form.
func (e *Element) FullTag() string {
	if e.Space == "" {
		return e.Tag
	}
	return e.Space + ":" + e.Tag
}

// Parent returns the element's parent, or nil.
func (e *Element) Parent() *Element {
	return e.parent
}

// CreateElement creates an element with the given (possibly prefixed) tag,
// appends it to e's children, and returns it.
func (e *Element) CreateElement(tag string) *Element {
	child := NewElement(tag)
	child.parent = e
	e.Child = append(e.Child, child)
	return child
}

// CreateAttr sets the attribute with the given (possibly prefixed) key,
// replacing the value of an existing attribute with the same name.
func (e *Element) CreateAttr(key, value string) {
	space, local := splitQName(key)
	for i := range e.Attr {
		if e.Attr[i].Space == space && e.Attr[i].Key == local {
			e.Attr[i].Value = value
			return
		}
	}
	e.Attr = append(e.Attr, Attr{Space: space, Key: local, Value: value})
}

// SelectAttr returns the attribute with the given (possibly prefixed) key,
// or nil.
func (e *Element) SelectAttr(key string) *Attr {
	space, local := splitQName(key)
	for i := range e.Attr {
		if e.Attr[i].Space == space && e.Attr[i].Key == local {
			return &e.Attr[i]
		}
	}
	return nil
}

// SelectAttrValue returns the value of the attribute with the given
// (possibly prefixed) key, or dflt if no such attribute exists.
func (e *Element) SelectAttrValue(key, dflt string) string {
	if a := e.SelectAttr(key); a != nil {
		return a.Value
	}
	return dflt
}

// RemoveAttr removes the attribute with the given (possibly prefixed) key
// and reports whether one was removed.
func (e *Element) RemoveAttr(key string) bool {
	space, local := splitQName(key)
	for i := range e.Attr {
		if e.Attr[i].Space == space && e.Attr[i].Key == local {
			e.Attr = append(e.Attr[:i], e.Attr[i+1:]...)
			return true
		}
	}
	return false
}

// SelectElement returns the first child element matching the given
// (possibly prefixed) tag, or nil.
func (e *Element) SelectElement(tag string) *Element {
	space, local := splitQName(tag)
	for _, t := range e.Child {
		if c, ok := t.(*Element); ok && c.Space == space && c.Tag == local {
			return c
		}
	}
	return nil
}

// ChildElements returns the element children in document order.
func (e *Element) ChildElements() []*Element {
	var out []*Element
	for _, t := range e.Child {
		if c, ok := t.(*Element); ok {
			out = append(out, c)
		}
	}
	return out
}

// AddChild appends the token to e's children. An element child is first
// detached from any previous parent.
func (e *Element) AddChild(t Token) {
	if c, ok := t.(*Element); ok {
		if c.parent != nil {
			c.parent.RemoveChild(c)
		}
		c.parent = e
	}
	e.Child = append(e.Child, t)
}

// RemoveChild removes the given token (matched by identity) from e's
// children and reports whether it was found.
func (e *Element) RemoveChild(t Token) bool {
	for i, c := range e.Child {
		if c == t {
			e.RemoveChildAt(i)
			return true
		}
	}
	return false
}

// RemoveChildAt removes the child at index i.
func (e *Element) RemoveChildAt(i int) {
	if c, ok := e.Child[i].(*Element); ok {
		c.parent = nil
	}
	e.Child = append(e.Child[:i], e.Child[i+1:]...)
}

// Text returns the concatenation of all character data children of e.
// Unlike some XML libraries, it does not stop at the first non-text child:
// extracting a value must never depend on how text is split into nodes.
func (e *Element) Text() string {
	var sb strings.Builder
	for _, t := range e.Child {
		if cd, ok := t.(*CharData); ok {
			sb.WriteString(cd.Data)
		}
	}
	return sb.String()
}

// SetText replaces all character data children of e with a single text
// node, inserted before any other children.
func (e *Element) SetText(text string) {
	kept := e.Child[:0]
	for _, t := range e.Child {
		if _, ok := t.(*CharData); !ok {
			kept = append(kept, t)
		}
	}
	e.Child = append([]Token{&CharData{Data: text}}, kept...)
}

// CreateText appends a character data child to e.
func (e *Element) CreateText(text string) {
	e.Child = append(e.Child, &CharData{Data: text})
}

// Copy returns a deep copy of e with no parent.
func (e *Element) Copy() *Element {
	out := &Element{
		Space: e.Space,
		Tag:   e.Tag,
		Attr:  append([]Attr(nil), e.Attr...),
	}
	for _, t := range e.Child {
		c := t.CopyToken()
		if ce, ok := c.(*Element); ok {
			ce.parent = out
		}
		out.Child = append(out.Child, c)
	}
	return out
}

// CopyToken implements Token.
func (e *Element) CopyToken() Token { return e.Copy() }

// CopyToken implements Token.
func (c *CharData) CopyToken() Token { return &CharData{Data: c.Data} }

// CopyToken implements Token.
func (c *Comment) CopyToken() Token { return &Comment{Data: c.Data} }

// splitQName splits a possibly-prefixed XML name into prefix and local
// parts. A name with no colon has an empty prefix.
func splitQName(name string) (space, local string) {
	if before, after, found := strings.Cut(name, ":"); found {
		return before, after
	}
	return "", name
}
