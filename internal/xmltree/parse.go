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
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Resource limits enforced by the parser. SAML documents are small and
// shallow; these are set far above anything legitimate.
const (
	maxInputSize   = 16 << 20 // 16 MiB
	maxDepth       = 100      // element nesting depth
	maxNodes       = 500_000  // total elements + text nodes
	maxAttrs       = 256      // attributes per element (incl. xmlns)
	maxNameLen     = 1024     // bytes in an element/attribute name
	maxCharRefSize = 8        // digits in a character reference
)

// ParseError describes why a document was rejected, naming the offending
// construct so interop failures are debuggable from logs alone.
type ParseError struct {
	Offset int // byte offset into the (line-ending-normalized) input
	Line   int // 1-based line number
	Msg    string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("xmltree: line %d (offset %d): %s", e.Line, e.Offset, e.Msg)
}

// Parse parses a SAML protocol message under the strict profile:
//
//   - UTF-8 only: invalid UTF-8, byte-order marks, and non-UTF-8 encoding
//     declarations are rejected.
//   - An XML declaration is permitted; DOCTYPE declarations, processing
//     instructions, comments, and CDATA sections are rejected. SAML protocol
//     messages are machine-generated and use none of them.
//   - Only the five predefined entities and numeric character references
//     are recognized (gosaml2's own canonical output uses &#xD;-style
//     references, so those are required).
//   - Namespace well-formedness is enforced: every prefix in use must be
//     declared in scope, and duplicate attributes are rejected both by
//     literal name and by expanded (namespace URI, local) name.
//   - Exactly one root element; only whitespace is permitted outside it.
//
// Line endings are normalized (CRLF and lone CR become LF) per XML 1.0
// §2.11 before any other processing.
func Parse(data []byte) (*Document, error) {
	return parse(data, false)
}

// ParseMetadata parses a SAML metadata document. The profile matches Parse
// except that comments are tolerated and dropped: federation metadata is
// commonly hand-edited and annotated with comments, while dropping them at
// parse time (matching exclusive-c14n's omit-comments semantics) means no
// downstream consumer can be confused by text split across a comment.
func ParseMetadata(data []byte) (*Document, error) {
	return parse(data, true)
}

func parse(data []byte, allowComments bool) (*Document, error) {
	if len(data) > maxInputSize {
		return nil, &ParseError{Msg: fmt.Sprintf("document exceeds %d byte limit", maxInputSize)}
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return nil, &ParseError{Line: 1, Msg: "byte-order mark not allowed"}
	}
	if !utf8.Valid(data) {
		return nil, &ParseError{Line: 1, Msg: "document is not valid UTF-8"}
	}

	p := &parser{
		data:          normalizeLineEndings(string(data)),
		allowComments: allowComments,
		nsStack:       []nsBinding{{prefix: "xml", uri: xmlNamespaceURI}},
	}
	root, err := p.parseDocument()
	if err != nil {
		return nil, err
	}
	doc := NewDocument()
	doc.SetRoot(root)
	return doc, nil
}

const (
	xmlNamespaceURI   = "http://www.w3.org/XML/1998/namespace"
	xmlnsNamespaceURI = "http://www.w3.org/2000/xmlns/"
)

// normalizeLineEndings implements XML 1.0 §2.11: CRLF and lone CR are
// translated to a single LF before parsing.
func normalizeLineEndings(s string) string {
	if !strings.ContainsRune(s, '\r') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' {
			sb.WriteByte('\n')
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

type nsBinding struct {
	prefix string
	uri    string
}

type parser struct {
	data          string
	pos           int
	allowComments bool
	nodeCount     int

	// nsStack holds in-scope namespace bindings; frames records the stack
	// length at each element start so bindings pop with their element.
	nsStack []nsBinding
	frames  []int
}

func (p *parser) errf(format string, args ...any) *ParseError {
	return &ParseError{
		Offset: p.pos,
		Line:   1 + strings.Count(p.data[:p.pos], "\n"),
		Msg:    fmt.Sprintf(format, args...),
	}
}

func (p *parser) eof() bool { return p.pos >= len(p.data) }

func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.data[p.pos]
}

func (p *parser) consume(s string) bool {
	if strings.HasPrefix(p.data[p.pos:], s) {
		p.pos += len(s)
		return true
	}
	return false
}

func (p *parser) skipWhitespace() {
	for !p.eof() {
		switch p.data[p.pos] {
		case ' ', '\t', '\n': // \r was normalized away
			p.pos++
		default:
			return
		}
	}
}

// parseDocument parses [decl] misc* element misc* and returns the root.
func (p *parser) parseDocument() (*Element, error) {
	if strings.HasPrefix(p.data, "<?xml") && len(p.data) > 5 && isWhitespaceByte(p.data[5]) {
		if err := p.parseXMLDecl(); err != nil {
			return nil, err
		}
	}

	root, err := p.parseMisc(true)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, p.errf("document has no root element")
	}

	if extra, err := p.parseMisc(false); err != nil {
		return nil, err
	} else if extra != nil {
		return nil, p.errf("more than one root element")
	}
	return root, nil
}

// parseMisc consumes whitespace (and, in metadata mode, comments) and at
// most one element, which it returns. wantElement reports whether an
// element is expected (before the root) or forbidden (after it).
func (p *parser) parseMisc(wantElement bool) (*Element, error) {
	for {
		p.skipWhitespace()
		if p.eof() {
			return nil, nil
		}
		if p.data[p.pos] != '<' {
			return nil, p.errf("text outside the root element")
		}
		switch {
		case strings.HasPrefix(p.data[p.pos:], "<!--"):
			if err := p.parseComment(); err != nil {
				return nil, err
			}
		case strings.HasPrefix(p.data[p.pos:], "<!"):
			return nil, p.errf("DOCTYPE and other markup declarations are not allowed")
		case strings.HasPrefix(p.data[p.pos:], "<?"):
			return nil, p.errf("processing instructions are not allowed")
		default:
			if !wantElement {
				return nil, p.errf("content after the root element")
			}
			return p.parseElement(0)
		}
	}
}

// parseXMLDecl parses an XML declaration at the start of input. Only
// version 1.0, UTF-8 (or omitted) encoding, and a standalone flag are
// accepted.
func (p *parser) parseXMLDecl() error {
	p.pos = len("<?xml")
	seen := 0 // 1 = version parsed, 2 = encoding parsed, 3 = standalone parsed
	for {
		start := p.pos
		p.skipWhitespace()
		if p.consume("?>") {
			if seen < 1 {
				return p.errf("XML declaration is missing version")
			}
			return nil
		}
		if p.pos == start {
			return p.errf("malformed XML declaration")
		}
		name, err := p.parseRawName()
		if err != nil {
			return err
		}
		p.skipWhitespace()
		if !p.consume("=") {
			return p.errf("malformed XML declaration")
		}
		p.skipWhitespace()
		value, err := p.parseQuotedLiteral()
		if err != nil {
			return err
		}
		switch name {
		case "version":
			if seen >= 1 {
				return p.errf("duplicate version in XML declaration")
			}
			if value != "1.0" {
				return p.errf("unsupported XML version %q", value)
			}
			seen = 1
		case "encoding":
			if seen != 1 {
				return p.errf("misplaced encoding in XML declaration")
			}
			if !strings.EqualFold(value, "utf-8") {
				return p.errf("unsupported encoding %q (only UTF-8 is accepted)", value)
			}
			seen = 2
		case "standalone":
			if seen < 1 || seen > 2 {
				return p.errf("misplaced standalone in XML declaration")
			}
			if value != "yes" && value != "no" {
				return p.errf("invalid standalone value %q", value)
			}
			seen = 3
		default:
			return p.errf("unexpected %q in XML declaration", name)
		}
	}
}

// parseQuotedLiteral reads a single- or double-quoted literal with no
// reference processing (used only inside the XML declaration).
func (p *parser) parseQuotedLiteral() (string, error) {
	if p.eof() || (p.peek() != '"' && p.peek() != '\'') {
		return "", p.errf("expected quoted value")
	}
	quote := p.data[p.pos]
	p.pos++
	start := p.pos
	for !p.eof() && p.data[p.pos] != quote {
		p.pos++
	}
	if p.eof() {
		return "", p.errf("unterminated quoted value")
	}
	v := p.data[start:p.pos]
	p.pos++
	return v, nil
}

// parseComment consumes a comment. Comments are only reachable in metadata
// mode (strict mode rejects before calling); the content is validated and
// discarded.
func (p *parser) parseComment() error {
	if !p.allowComments {
		return p.errf("comments are not allowed")
	}
	p.pos += len("<!--")
	end := strings.Index(p.data[p.pos:], "--")
	if end < 0 {
		return p.errf("unterminated comment")
	}
	content := p.data[p.pos : p.pos+end]
	if err := p.validateChars(content); err != nil {
		return err
	}
	p.pos += end
	if !p.consume("-->") {
		return p.errf("'--' is not allowed within a comment")
	}
	return nil
}

// parseElement parses an element whose '<' is at the current position.
func (p *parser) parseElement(depth int) (*Element, error) {
	if depth >= maxDepth {
		return nil, p.errf("element nesting exceeds depth limit of %d", maxDepth)
	}
	p.nodeCount++
	if p.nodeCount > maxNodes {
		return nil, p.errf("document exceeds node limit of %d", maxNodes)
	}

	p.pos++ // consume '<'
	nameOff := p.pos
	name, err := p.parseRawName()
	if err != nil {
		return nil, err
	}
	space, local, err := p.splitElementName(name, nameOff)
	if err != nil {
		return nil, err
	}
	el := &Element{Space: space, Tag: local}

	// Push a namespace frame; bindings declared by this element's
	// attributes live until the element is closed.
	p.frames = append(p.frames, len(p.nsStack))
	defer func() {
		p.nsStack = p.nsStack[:p.frames[len(p.frames)-1]]
		p.frames = p.frames[:len(p.frames)-1]
	}()

	selfClosing, err := p.parseAttributes(el)
	if err != nil {
		return nil, err
	}
	if err := p.checkNamespaces(el); err != nil {
		return nil, err
	}
	if selfClosing {
		return el, nil
	}

	// Content until the matching end tag.
	for {
		if p.eof() {
			return nil, p.errf("unclosed element <%s>", name)
		}
		if p.data[p.pos] == '<' {
			rest := p.data[p.pos:]
			switch {
			case strings.HasPrefix(rest, "</"):
				p.pos += 2
				endName, err := p.parseRawName()
				if err != nil {
					return nil, err
				}
				if endName != name {
					return nil, p.errf("mismatched end tag </%s> for <%s>", endName, name)
				}
				p.skipWhitespace()
				if !p.consume(">") {
					return nil, p.errf("malformed end tag </%s>", endName)
				}
				return el, nil
			case strings.HasPrefix(rest, "<!--"):
				if err := p.parseComment(); err != nil {
					return nil, err
				}
			case strings.HasPrefix(rest, "<![CDATA["):
				return nil, p.errf("CDATA sections are not allowed")
			case strings.HasPrefix(rest, "<!"):
				return nil, p.errf("markup declarations are not allowed in content")
			case strings.HasPrefix(rest, "<?"):
				return nil, p.errf("processing instructions are not allowed")
			default:
				child, err := p.parseElement(depth + 1)
				if err != nil {
					return nil, err
				}
				child.parent = el
				el.Child = append(el.Child, child)
			}
			continue
		}
		text, err := p.parseText()
		if err != nil {
			return nil, err
		}
		p.nodeCount++
		if p.nodeCount > maxNodes {
			return nil, p.errf("document exceeds node limit of %d", maxNodes)
		}
		el.Child = append(el.Child, &CharData{Data: text})
	}
}

// parseAttributes parses attributes up to and including '>' or '/>',
// recording namespace declarations in scope. Returns whether the element
// was self-closing.
func (p *parser) parseAttributes(el *Element) (bool, error) {
	for {
		start := p.pos
		p.skipWhitespace()
		switch {
		case p.consume("/>"):
			return true, nil
		case p.consume(">"):
			return false, nil
		case p.eof():
			return false, p.errf("unclosed start tag <%s>", el.FullTag())
		}
		if p.pos == start {
			return false, p.errf("expected whitespace before attribute in <%s>", el.FullTag())
		}

		nameOff := p.pos
		name, err := p.parseRawName()
		if err != nil {
			return false, err
		}
		p.skipWhitespace()
		if !p.consume("=") {
			return false, p.errf("attribute %q has no value", name)
		}
		p.skipWhitespace()
		value, err := p.parseAttrValue()
		if err != nil {
			return false, err
		}

		space, local, err := p.splitAttrName(name, nameOff)
		if err != nil {
			return false, err
		}

		// Literal duplicate check.
		for _, a := range el.Attr {
			if a.Space == space && a.Key == local {
				return false, p.errf("duplicate attribute %q", name)
			}
		}
		if len(el.Attr) >= maxAttrs {
			return false, p.errf("element <%s> exceeds attribute limit of %d", el.FullTag(), maxAttrs)
		}

		// Namespace declarations get validated and recorded in scope.
		switch {
		case space == "" && local == "xmlns":
			if err := p.checkNamespaceURI("", value); err != nil {
				return false, err
			}
			p.nsStack = append(p.nsStack, nsBinding{prefix: "", uri: value})
		case space == "xmlns":
			if local == "xmlns" {
				return false, p.errf("the xmlns prefix cannot be declared")
			}
			if value == "" {
				return false, p.errf("namespace prefix %q cannot be undeclared", local)
			}
			if err := p.checkNamespaceURI(local, value); err != nil {
				return false, err
			}
			p.nsStack = append(p.nsStack, nsBinding{prefix: local, uri: value})
		}

		el.Attr = append(el.Attr, Attr{Space: space, Key: local, Value: value})
	}
}

// checkNamespaceURI enforces the reserved xml/xmlns bindings.
func (p *parser) checkNamespaceURI(prefix, uri string) error {
	if prefix == "xml" {
		if uri != xmlNamespaceURI {
			return p.errf("the xml prefix is bound to %q and cannot be redeclared", xmlNamespaceURI)
		}
		return nil
	}
	if uri == xmlNamespaceURI {
		return p.errf("only the xml prefix may be bound to %q", xmlNamespaceURI)
	}
	if uri == xmlnsNamespaceURI {
		return p.errf("nothing may be bound to %q", xmlnsNamespaceURI)
	}
	return nil
}

// lookupPrefix resolves a namespace prefix against the current scope.
func (p *parser) lookupPrefix(prefix string) (string, bool) {
	for i := len(p.nsStack) - 1; i >= 0; i-- {
		if p.nsStack[i].prefix == prefix {
			return p.nsStack[i].uri, true
		}
	}
	return "", false
}

// checkNamespaces verifies, with the element's own declarations in scope,
// that the element and attribute prefixes all resolve, and that no two
// attributes share an expanded (namespace URI, local) name.
func (p *parser) checkNamespaces(el *Element) error {
	if el.Space != "" {
		if _, ok := p.lookupPrefix(el.Space); !ok {
			return p.errf("undeclared namespace prefix %q on element <%s>", el.Space, el.FullTag())
		}
	}

	type expandedName struct{ uri, local string }
	seen := make(map[expandedName]bool, len(el.Attr))
	for _, a := range el.Attr {
		if a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns") {
			continue // namespace declarations are not subject to expansion
		}
		uri := ""
		if a.Space != "" {
			u, ok := p.lookupPrefix(a.Space)
			if !ok {
				return p.errf("undeclared namespace prefix %q on attribute %q", a.Space, a.FullKey())
			}
			uri = u
		}
		key := expandedName{uri, a.Key}
		if seen[key] {
			return p.errf("duplicate attribute %q after namespace resolution", a.FullKey())
		}
		seen[key] = true
	}
	return nil
}

// parseRawName reads a raw XML name (which may contain one colon).
func (p *parser) parseRawName() (string, error) {
	start := p.pos
	for !p.eof() {
		r, size := utf8.DecodeRuneInString(p.data[p.pos:])
		if p.pos == start {
			if !isNameStartChar(r) && r != ':' {
				return "", p.errf("invalid name start character %q", r)
			}
		} else if !isNameChar(r) && r != ':' {
			break
		}
		p.pos += size
		if p.pos-start > maxNameLen {
			return "", p.errf("name exceeds %d byte limit", maxNameLen)
		}
	}
	if p.pos == start {
		return "", p.errf("expected a name")
	}
	return p.data[start:p.pos], nil
}

// splitElementName splits and validates a possibly-prefixed element name.
func (p *parser) splitElementName(name string, off int) (space, local string, err error) {
	return p.splitName(name, off, "element")
}

// splitAttrName splits and validates a possibly-prefixed attribute name.
func (p *parser) splitAttrName(name string, off int) (space, local string, err error) {
	return p.splitName(name, off, "attribute")
}

func (p *parser) splitName(name string, off int, kind string) (space, local string, err error) {
	i := strings.IndexByte(name, ':')
	if i < 0 {
		return "", name, nil
	}
	space, local = name[:i], name[i+1:]
	if space == "" || local == "" || strings.Contains(local, ":") {
		saved := p.pos
		p.pos = off
		defer func() { p.pos = saved }()
		return "", "", p.errf("invalid %s name %q", kind, name)
	}
	return space, local, nil
}

// parseAttrValue reads a quoted attribute value, applying CDATA attribute
// value normalization (XML 1.0 §3.3.3): literal whitespace becomes a
// space; whitespace introduced via character references is preserved.
func (p *parser) parseAttrValue() (string, error) {
	if p.eof() || (p.peek() != '"' && p.peek() != '\'') {
		return "", p.errf("attribute value must be quoted")
	}
	quote := p.data[p.pos]
	p.pos++

	var sb strings.Builder
	for {
		if p.eof() {
			return "", p.errf("unterminated attribute value")
		}
		c := p.data[p.pos]
		switch {
		case c == quote:
			p.pos++
			return sb.String(), nil
		case c == '<':
			return "", p.errf("'<' is not allowed in attribute values")
		case c == '&':
			r, err := p.parseReference()
			if err != nil {
				return "", err
			}
			sb.WriteRune(r)
		case c == '\t' || c == '\n': // \r was normalized to \n
			sb.WriteByte(' ')
			p.pos++
		default:
			r, size := utf8.DecodeRuneInString(p.data[p.pos:])
			if !isXMLChar(r) {
				return "", p.errf("invalid character %U in attribute value", r)
			}
			sb.WriteString(p.data[p.pos : p.pos+size])
			p.pos += size
		}
	}
}

// parseText reads character data up to the next '<'.
func (p *parser) parseText() (string, error) {
	var sb strings.Builder
	for !p.eof() && p.data[p.pos] != '<' {
		c := p.data[p.pos]
		switch {
		case c == '&':
			r, err := p.parseReference()
			if err != nil {
				return "", err
			}
			sb.WriteRune(r)
		case c == ']' && strings.HasPrefix(p.data[p.pos:], "]]>"):
			return "", p.errf("']]>' is not allowed in character data")
		default:
			r, size := utf8.DecodeRuneInString(p.data[p.pos:])
			if !isXMLChar(r) {
				return "", p.errf("invalid character %U in character data", r)
			}
			sb.WriteString(p.data[p.pos : p.pos+size])
			p.pos += size
		}
	}
	return sb.String(), nil
}

// parseReference parses an entity or character reference at '&'. Only the
// five predefined entities and numeric character references are accepted.
func (p *parser) parseReference() (rune, error) {
	start := p.pos
	p.pos++ // consume '&'
	semi := strings.IndexByte(p.data[p.pos:], ';')
	if semi < 0 || semi > maxNameLen {
		p.pos = start
		return 0, p.errf("unterminated reference")
	}
	ref := p.data[p.pos : p.pos+semi]
	p.pos += semi + 1

	if strings.HasPrefix(ref, "#") {
		num := ref[1:]
		base := 10
		if strings.HasPrefix(num, "x") || strings.HasPrefix(num, "X") {
			if strings.HasPrefix(num, "X") {
				p.pos = start
				return 0, p.errf("invalid character reference &%s; (hex marker must be lowercase x)", ref)
			}
			num, base = num[1:], 16
		}
		if num == "" || len(num) > maxCharRefSize {
			p.pos = start
			return 0, p.errf("invalid character reference &%s;", ref)
		}
		n, err := strconv.ParseUint(num, base, 32)
		if err != nil {
			p.pos = start
			return 0, p.errf("invalid character reference &%s;", ref)
		}
		r := rune(n)
		if !isXMLChar(r) {
			p.pos = start
			return 0, p.errf("character reference &%s; is not a valid XML character", ref)
		}
		return r, nil
	}

	switch ref {
	case "amp":
		return '&', nil
	case "lt":
		return '<', nil
	case "gt":
		return '>', nil
	case "quot":
		return '"', nil
	case "apos":
		return '\'', nil
	}
	p.pos = start
	return 0, p.errf("unsupported entity &%s; (only predefined entities are allowed)", ref)
}

// validateChars checks every rune of s against the XML Char production.
func (p *parser) validateChars(s string) error {
	for _, r := range s {
		if !isXMLChar(r) {
			return p.errf("invalid character %U", r)
		}
	}
	return nil
}

func isWhitespaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// isXMLChar implements the XML 1.0 Char production.
func isXMLChar(r rune) bool {
	switch {
	case r == 0x9 || r == 0xA || r == 0xD:
		return true
	case r >= 0x20 && r <= 0xD7FF:
		return true
	case r >= 0xE000 && r <= 0xFFFD:
		// Includes U+FFFD, which is a legal XML character; invalid UTF-8 was
		// already rejected wholesale before parsing.
		return true
	case r >= 0x10000 && r <= 0x10FFFF:
		return true
	}
	return false
}

// isNameStartChar implements the XML 1.0 (5th ed) NameStartChar production,
// excluding ':' which the caller handles.
func isNameStartChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		return true
	case r >= 0xC0 && r <= 0xD6, r >= 0xD8 && r <= 0xF6, r >= 0xF8 && r <= 0x2FF:
		return true
	case r >= 0x370 && r <= 0x37D, r >= 0x37F && r <= 0x1FFF:
		return true
	case r >= 0x200C && r <= 0x200D, r >= 0x2070 && r <= 0x218F:
		return true
	case r >= 0x2C00 && r <= 0x2FEF, r >= 0x3001 && r <= 0xD7FF:
		return true
	case r >= 0xF900 && r <= 0xFDCF, r >= 0xFDF0 && r <= 0xFFFD:
		return true
	case r >= 0x10000 && r <= 0xEFFFF:
		return true
	}
	return false
}

// isNameChar implements the XML 1.0 (5th ed) NameChar production, excluding
// ':' which the caller handles.
func isNameChar(r rune) bool {
	if isNameStartChar(r) {
		return true
	}
	switch {
	case r == '-' || r == '.' || (r >= '0' && r <= '9') || r == 0xB7:
		return true
	case r >= 0x300 && r <= 0x36F, r >= 0x203F && r <= 0x2040:
		return true
	}
	return false
}
