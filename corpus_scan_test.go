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

package saml2

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// These tests enforce the curation rules for testdata/corpus (see
// testdata/corpus/PROVENANCE.md). The corpus exists to validate the strict
// XML parser profile: documents in the per-provider directories must never
// use a feature the strict profile rejects, so that "every corpus document
// parses" remains a meaningful acceptance test. Documents in _hostile/ must
// each carry at least one rejected feature (or be malformed) so they remain
// meaningful rejection seeds.

const corpusDir = "testdata/corpus"

var namedEntityRe = regexp.MustCompile(`&([A-Za-z][A-Za-z0-9]*);`)

var predefinedEntities = map[string]bool{
	"amp": true, "lt": true, "gt": true, "quot": true, "apos": true,
}

// rejectedFeatures returns the strict-profile violations present in doc.
// Comments are reported separately because the metadata profile permits
// (and drops) them.
func rejectedFeatures(doc []byte) (features []string, hasComment bool) {
	if bytes.HasPrefix(doc, []byte{0xEF, 0xBB, 0xBF}) {
		features = append(features, "BOM")
	}
	if !utf8.Valid(doc) {
		features = append(features, "invalid UTF-8")
	}
	if bytes.Contains(doc, []byte("<!DOCTYPE")) {
		features = append(features, "DOCTYPE")
	}
	if bytes.Contains(doc, []byte("<!ENTITY")) {
		features = append(features, "ENTITY declaration")
	}
	if bytes.Contains(doc, []byte("<![CDATA[")) {
		features = append(features, "CDATA")
	}
	if bytes.Contains(doc, []byte("<!--")) {
		hasComment = true
	}
	// Processing instructions other than the XML declaration.
	for idx, rest := 0, doc; ; {
		i := bytes.Index(rest, []byte("<?"))
		if i < 0 {
			break
		}
		pi := rest[i:]
		if !(bytes.HasPrefix(pi, []byte("<?xml ")) || bytes.HasPrefix(pi, []byte("<?xml\t")) || bytes.HasPrefix(pi, []byte("<?xml?"))) {
			features = append(features, "processing instruction")
			break
		}
		idx += i + 2
		rest = doc[idx:]
	}
	for _, m := range namedEntityRe.FindAllSubmatch(doc, -1) {
		if !predefinedEntities[string(m[1])] {
			features = append(features, "named entity &"+string(m[1])+";")
		}
	}
	if m := regexp.MustCompile(`<\?xml[^?]*encoding=["']([^"']+)`).FindSubmatch(doc); m != nil {
		if enc := strings.ToLower(string(m[1])); enc != "utf-8" {
			features = append(features, "encoding declaration "+enc)
		}
	}
	return features, hasComment
}

func corpusFiles(t *testing.T, hostile bool) []string {
	t.Helper()
	var files []string
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("reading %s: %v", corpusDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() || (e.Name() == "_hostile") != hostile {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(corpusDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range sub {
			if strings.HasSuffix(f.Name(), ".xml") {
				files = append(files, filepath.Join(corpusDir, e.Name(), f.Name()))
			}
		}
	}
	if len(files) == 0 {
		t.Fatalf("no corpus files found (hostile=%v)", hostile)
	}
	return files
}

func TestCorpus_LegitDocsUseNoRejectedFeatures(t *testing.T) {
	files := corpusFiles(t, false)
	for _, path := range files {
		doc, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		features, hasComment := rejectedFeatures(doc)
		if len(features) > 0 {
			t.Errorf("%s uses strict-profile-rejected features %v; either re-curate the file or revisit the profile", path, features)
		}
		// Comments are tolerated only in metadata documents (metadata parse
		// profile accepts and drops them); protocol messages must have none.
		if hasComment && !strings.Contains(strings.ToLower(filepath.Base(path)), "metadata") {
			t.Errorf("%s is a protocol message containing an XML comment; protocol profile rejects comments", path)
		}
	}
	t.Logf("scanned %d legit corpus documents", len(files))
}

// Files in _hostile/ that are quarantined for being malformed rather than for
// carrying a scannable rejected feature.
var hostileMalformed = map[string]bool{
	"python3-saml_metadata_unparsed_metadata.xml": true,
}

func TestCorpus_HostileDocsEachCarryARejectedFeature(t *testing.T) {
	for _, path := range corpusFiles(t, true) {
		if hostileMalformed[filepath.Base(path)] {
			continue
		}
		doc, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		features, hasComment := rejectedFeatures(doc)
		isProtocol := !strings.Contains(strings.ToLower(filepath.Base(path)), "metadata")
		if len(features) == 0 && !(hasComment && isProtocol) {
			t.Errorf("%s is quarantined in _hostile/ but carries no rejected feature; re-curate it", path)
		}
	}
}
