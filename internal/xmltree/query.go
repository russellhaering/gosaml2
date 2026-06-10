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
	"strings"
)

// SingleElement returns the unique direct child element with the given tag,
// erroring if more than one exists. Callers use it to reject documents that
// repeat an element the schema permits at most once, rather than silently
// choosing one. Returns nil (no error) when the element is absent.
func (e *Element) SingleElement(tag string) (*Element, error) {
	matches := e.SelectElements(tag)
	if len(matches) > 1 {
		return nil, fmt.Errorf("xmltree: %d <%s> elements where at most one is allowed", len(matches), tag)
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return matches[0], nil
}

// FindElement / FindElements implement the small path-query subset that
// gosaml2's tests use to point at elements inside built documents:
//
//	"Tag"          — direct child (possibly "prefix:Tag")
//	"./A/B"        — chain of direct children
//	"//Tag"        — any descendant (depth-first, document order)
//	".//A/B"       — any descendant A, then child B
//	"A//B"         — child A, then any descendant B
//
// This is intentionally not XPath; predicates, attributes, and wildcards are
// not supported. Production code addresses elements via the namespace-aware
// helpers in internal/xmldsig instead.

// FindElement returns the first element matching the path, or nil.
func (e *Element) FindElement(path string) *Element {
	matches := e.findElements(path, true)
	if len(matches) == 0 {
		return nil
	}
	return matches[0]
}

// FindElements returns all elements matching the path in document order.
func (e *Element) FindElements(path string) []*Element {
	return e.findElements(path, false)
}

// FindElement returns the first element in the document matching the path.
func (d *Document) FindElement(path string) *Element {
	if d.root == nil {
		return nil
	}
	// Paths are evaluated against the document, whose only child is the root:
	// "//X" searches the whole tree (including the root itself), and "X"
	// matches the root element.
	holder := &Element{Child: []Token{d.root}}
	return holder.FindElement(path)
}

// FindElements returns all elements in the document matching the path.
func (d *Document) FindElements(path string) []*Element {
	if d.root == nil {
		return nil
	}
	holder := &Element{Child: []Token{d.root}}
	return holder.FindElements(path)
}

type pathStep struct {
	space, tag string
	descend    bool // match any descendant rather than only direct children
}

func parsePath(path string) []pathStep {
	descend := false
	switch {
	case strings.HasPrefix(path, ".//"):
		descend, path = true, path[3:]
	case strings.HasPrefix(path, "//"):
		descend, path = true, path[2:]
	case strings.HasPrefix(path, "./"):
		path = path[2:]
	}
	var steps []pathStep
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			// An empty segment is the "//" separator: the next named step
			// matches any descendant.
			descend = true
			continue
		}
		space, local := splitQName(part)
		steps = append(steps, pathStep{space: space, tag: local, descend: descend})
		descend = false
	}
	return steps
}

func (e *Element) findElements(path string, firstOnly bool) []*Element {
	steps := parsePath(path)
	if len(steps) == 0 {
		return nil
	}

	var out []*Element
	var walk func(el *Element, steps []pathStep)
	walk = func(el *Element, steps []pathStep) {
		if firstOnly && len(out) > 0 {
			return
		}
		step := steps[0]
		for _, t := range el.Child {
			c, ok := t.(*Element)
			if !ok {
				continue
			}
			if spaceMatch(step.space, c.Space) && c.Tag == step.tag {
				if len(steps) == 1 {
					out = append(out, c)
					if firstOnly {
						return
					}
				} else {
					walk(c, steps[1:])
				}
			}
			if step.descend {
				// Keep searching deeper for this same step.
				walk(c, steps)
			}
		}
	}
	walk(e, steps)
	return out
}

// SelectElements returns all direct child elements with the given tag. An
// unprefixed tag matches any namespace prefix; a prefixed tag matches
// exactly.
func (e *Element) SelectElements(tag string) []*Element {
	space, local := splitQName(tag)
	var out []*Element
	for _, t := range e.Child {
		if c, ok := t.(*Element); ok && spaceMatch(space, c.Space) && c.Tag == local {
			out = append(out, c)
		}
	}
	return out
}
