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

package types

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// attrWSReplacer applies XML 1.0 §3.3.3 CDATA attribute-value
// normalization (TAB/LF/CR become a single space). The strict parser does
// this; encoding/xml does not. Applying it symmetrically to both structs
// neutralizes that intentional difference without masking structural ones.
var attrWSReplacer = strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")

// normalizeWhitespace recursively rewrites every string field of v in place.
// Applied to both the encoding/xml and extractor results, it cancels the
// attribute-normalization difference. Chardata fields carry identical
// whitespace in both implementations, so rewriting them is harmless.
func normalizeWhitespace(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if !v.IsNil() {
			normalizeWhitespace(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.CanSet() {
				normalizeWhitespace(f)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			normalizeWhitespace(v.Index(i))
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(attrWSReplacer.Replace(v.String()))
		}
	}
}

// The hand-written extractors in extract.go replace encoding/xml on the
// trusted path. This harness proves they produce structurally identical
// results to encoding/xml across the whole real-world corpus, so the
// migration cannot silently change which claims the SP extracts.
//
// Two documented, intentional differences are normalized before comparison:
//
//   - xsi:type on AttributeValue: encoding/xml's `xml:"xsi:type,attr"` tag
//     never matched (Go resolves the attribute to its namespace URI, which
//     the prefix-form tag does not equal), so it always produced "". The
//     extractor reads the literal attribute and so populates it. This is a
//     fix, not a regression — normalized away here.
//   - Signature.SignatureDocument (",innerxml"): encoding/xml captures the
//     original inner bytes; the extractor re-serializes. Both are unused by
//     consumers. Compared structurally (presence), not byte-for-byte.

func corpusResponseFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	matches, err := filepath.Glob("../testdata/corpus/*/*.xml")
	require.NoError(t, err)
	for _, m := range matches {
		if strings.Contains(m, "_hostile") {
			continue
		}
		out = append(out, m)
	}
	more, _ := filepath.Glob("../testdata/*.xml")
	out = append(out, more...)
	require.NotEmpty(t, out)
	return out
}

// normalizeForCompare erases the two intentional extractor/encoding-xml
// differences so the rest of the struct can be compared exactly.
func normalizeResponse(r *Response) {
	for ai := range r.Assertions {
		normalizeAssertion(&r.Assertions[ai])
	}
}

func normalizeAssertion(a *Assertion) {
	if a.Signature != nil {
		// Both implementations populate this; the bytes differ by design.
		a.Signature = &Signature{}
	}
	for si := range a.AttributeStatements {
		for ai := range a.AttributeStatements[si].Attributes {
			for vi := range a.AttributeStatements[si].Attributes[ai].Values {
				a.AttributeStatements[si].Attributes[ai].Values[vi].Type = ""
			}
		}
	}
}

func TestExtractEquivalence_Response(t *testing.T) {
	compared := 0
	for _, path := range corpusResponseFiles(t) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)

		doc, err := xmltree.Parse(data)
		if err != nil {
			continue // not strict-parseable; covered by xmltree's own tests
		}
		root := doc.Root()
		if root.Tag != "Response" {
			continue
		}

		// encoding/xml reference.
		var want Response
		if err := xml.Unmarshal(data, &want); err != nil {
			continue // if stdlib can't parse it, it's not a fair comparison
		}

		got, err := ResponseFromElement(root)
		require.NoError(t, err, "%s", path)

		normalizeResponse(&want)
		normalizeResponse(got)
		normalizeWhitespace(reflect.ValueOf(&want))
		normalizeWhitespace(reflect.ValueOf(got))
		require.EqualValues(t, &want, got, "%s: extractor diverges from encoding/xml", path)
		compared++
	}
	t.Logf("compared %d Response documents", compared)
}

func TestExtractEquivalence_Assertion(t *testing.T) {
	compared := 0
	for _, path := range corpusResponseFiles(t) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		doc, err := xmltree.Parse(data)
		if err != nil {
			continue
		}
		root := doc.Root()
		if root.Tag != "Assertion" {
			continue
		}

		var want Assertion
		if err := xml.Unmarshal(data, &want); err != nil {
			continue
		}
		got, err := AssertionFromElement(root)
		require.NoError(t, err, "%s", path)

		normalizeAssertion(&want)
		normalizeAssertion(got)
		normalizeWhitespace(reflect.ValueOf(&want))
		normalizeWhitespace(reflect.ValueOf(got))
		require.EqualValues(t, &want, got, "%s: extractor diverges from encoding/xml", path)
		compared++
	}
	t.Logf("compared %d Assertion documents", compared)
}

func TestExtractEquivalence_Metadata_LogoutResponses(t *testing.T) {
	compared := 0
	for _, path := range corpusResponseFiles(t) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		doc, err := xmltree.Parse(data)
		if err != nil {
			continue
		}
		root := doc.Root()
		if root.Tag != "LogoutResponse" {
			continue
		}

		var want LogoutResponse
		if err := xml.Unmarshal(data, &want); err != nil {
			continue
		}
		got, err := LogoutResponseFromElement(root)
		require.NoError(t, err, "%s", path)
		normalizeWhitespace(reflect.ValueOf(&want))
		normalizeWhitespace(reflect.ValueOf(got))
		require.EqualValues(t, &want, got, "%s: extractor diverges from encoding/xml", path)
		compared++
	}
	t.Logf("compared %d LogoutResponse documents", compared)
}
