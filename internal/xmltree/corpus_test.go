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
	"compress/flate"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The corpus under testdata/corpus (see its PROVENANCE.md) is the
// acceptance bar for the strict profile: every legitimate document must
// parse, every _hostile document must be rejected. The legitimate documents
// are additionally compared structurally against beevik/etree (which
// tokenizes via encoding/xml), giving a differential oracle against two
// independent parsers.

func isMetadataDoc(path string) bool {
	return strings.Contains(strings.ToLower(filepath.Base(path)), "metadata")
}

func parseForPath(path string, data []byte) (*Document, error) {
	if isMetadataDoc(path) {
		return ParseMetadata(data)
	}
	return Parse(data)
}

func legitCorpusFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, glob := range []string{
		"../../testdata/corpus/*/*.xml",
		"../../testdata/*.xml",
	} {
		matches, err := filepath.Glob(glob)
		require.NoError(t, err)
		for _, m := range matches {
			if !strings.Contains(m, "_hostile") {
				files = append(files, m)
			}
		}
	}
	require.NotEmpty(t, files)
	return files
}

func TestCorpus_LegitDocumentsParse(t *testing.T) {
	for _, path := range legitCorpusFiles(t) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		if _, err := parseForPath(path, data); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func TestCorpus_HostileDocumentsRejected(t *testing.T) {
	matches, err := filepath.Glob("../../testdata/corpus/_hostile/*.xml")
	require.NoError(t, err)
	require.NotEmpty(t, matches)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		if _, err := parseForPath(path, data); err == nil {
			t.Errorf("%s: hostile document was accepted", path)
		} else {
			t.Logf("%s rejected: %v", filepath.Base(path), err)
		}
	}
}

// Provider fixtures are stored base64-encoded; decode and parse each.
func TestCorpus_ProviderFixturesParse(t *testing.T) {
	var paths []string
	for _, glob := range []string{
		"../../providertests/testdata/*.b64",
		"../../providertests/testdata/onelogin/*.b64",
		"../../providertests/testdata/pingfed/*.b64",
		"../../providertests/testdata/saml.oktadev.com/response_*",
		"../../providertests/testdata/*.xml",
	} {
		matches, err := filepath.Glob(glob)
		require.NoError(t, err)
		paths = append(paths, matches...)
	}
	require.NotEmpty(t, paths)

	parsed := 0
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		data := raw
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err == nil {
			data = dec
			// Redirect-binding fixtures are additionally DEFLATE-compressed.
			if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("<")) {
				if inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(data))); err == nil {
					data = inflated
				}
			}
		}
		if _, err := Parse(data); err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		parsed++
	}
	t.Logf("parsed %d provider fixtures", parsed)
}

// Our own canonicalizer output must always reparse (it escapes CR/TAB as
// numeric character references).
func TestCorpus_RoundTripFixpoint(t *testing.T) {
	for _, path := range legitCorpusFiles(t) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		d1, err := parseForPath(path, data)
		if err != nil {
			continue // reported by TestCorpus_LegitDocumentsParse
		}
		s1, err := d1.WriteToBytes()
		require.NoError(t, err)
		d2, err := Parse(s1)
		require.NoError(t, err, "%s: own serialization failed to reparse", path)
		s2, err := d2.WriteToBytes()
		require.NoError(t, err)
		assert.Equal(t, string(s1), string(s2), "%s: serialization not a fixpoint", path)
	}
}

// ---------------------------------------------------------------------------
// Differential oracle against beevik/etree (test-only dependency)
// ---------------------------------------------------------------------------

// normalizeText maps the line endings etree/encoding-xml may leave behind
// onto our (spec-normalized) form so the trees compare.
func normalizeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// normalizeAttr additionally applies the attribute-value normalization
// (whitespace → space) that we perform per spec and etree does not.
func normalizeAttr(s string) string {
	s = normalizeText(s)
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

// concatText returns all character data of an etree element, mirroring
// Element.Text in this package.
func etreeConcatText(el *etree.Element) string {
	var sb strings.Builder
	for _, tok := range el.Child {
		if cd, ok := tok.(*etree.CharData); ok {
			sb.WriteString(cd.Data)
		}
	}
	return sb.String()
}

// compareWithEtree recursively compares structure: names, attributes
// (order-sensitive), child element sequence, and concatenated text.
func compareWithEtree(t *testing.T, path string, ours *Element, theirs *etree.Element) {
	t.Helper()
	if ours.Space != theirs.Space || ours.Tag != theirs.Tag {
		t.Errorf("%s: element name mismatch: %s vs %s", path, ours.FullTag(), theirs.FullTag())
		return
	}
	ourAttrs := ours.Attr
	theirAttrs := theirs.Attr
	if len(ourAttrs) != len(theirAttrs) {
		t.Errorf("%s: <%s> attribute count %d vs %d", path, ours.FullTag(), len(ourAttrs), len(theirAttrs))
		return
	}
	for i := range ourAttrs {
		a, b := ourAttrs[i], theirAttrs[i]
		if a.Space != b.Space || a.Key != b.Key || normalizeAttr(a.Value) != normalizeAttr(b.Value) {
			t.Errorf("%s: <%s> attr %d: %s=%q vs %s=%q",
				path, ours.FullTag(), i, a.FullKey(), a.Value, b.Space+":"+b.Key, b.Value)
			return
		}
	}
	if normalizeText(ours.Text()) != normalizeText(etreeConcatText(theirs)) {
		t.Errorf("%s: <%s> text mismatch: %q vs %q",
			path, ours.FullTag(), ours.Text(), etreeConcatText(theirs))
		return
	}
	ourKids := ours.ChildElements()
	theirKids := theirs.ChildElements()
	if len(ourKids) != len(theirKids) {
		t.Errorf("%s: <%s> child element count %d vs %d", path, ours.FullTag(), len(ourKids), len(theirKids))
		return
	}
	for i := range ourKids {
		compareWithEtree(t, path, ourKids[i], theirKids[i])
	}
}

func TestCorpus_DifferentialAgainstEtree(t *testing.T) {
	compared := 0
	for _, path := range legitCorpusFiles(t) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		ours, err := parseForPath(path, data)
		if err != nil {
			continue // reported by TestCorpus_LegitDocumentsParse
		}
		theirs := etree.NewDocument()
		if err := theirs.ReadFromBytes(data); err != nil {
			t.Errorf("%s: etree rejected a document we accepted: %v", path, err)
			continue
		}
		compareWithEtree(t, path, ours.Root(), theirs.Root())
		compared++
	}
	t.Logf("differentially compared %d documents", compared)
}
