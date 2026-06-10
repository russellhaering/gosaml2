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
	"os"
	"path/filepath"
	"testing"

	"github.com/beevik/etree"
)

func seedCorpus(f *testing.F) {
	f.Helper()
	for _, glob := range []string{
		"../../testdata/corpus/*/*.xml",
		"../../testdata/*.xml",
	} {
		matches, err := filepath.Glob(glob)
		if err != nil {
			f.Fatal(err)
		}
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(data)
		}
	}
	f.Add([]byte(`<?xml version="1.0" encoding="UTF-8"?><p:a xmlns:p="urn:x" x="1&#x9;2"> t &amp; <p:b/></p:a>`))
	f.Add([]byte(`<a x='1' xmlns="urn:y">&#xD;]]&gt;</a>`))
}

// FuzzParse checks that the parser never panics and that accepted input
// reaches a serialization fixpoint: parse→serialize→parse→serialize must
// reproduce the first serialization byte-for-byte.
func FuzzParse(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		d1, err := Parse(data)
		if err != nil {
			return
		}
		s1, err := d1.WriteToBytes()
		if err != nil {
			t.Fatalf("serialize failed on accepted input: %v", err)
		}
		d2, err := Parse(s1)
		if err != nil {
			t.Fatalf("own serialization failed to reparse: %v\ninput: %q\nserialized: %q", err, data, s1)
		}
		s2, err := d2.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		if string(s1) != string(s2) {
			t.Fatalf("serialization not a fixpoint:\nfirst:  %q\nsecond: %q", s1, s2)
		}
	})
}

// FuzzParseVsEtree is a differential oracle: anything the strict parser
// accepts must also be parseable by beevik/etree (which tokenizes via
// encoding/xml) and produce a structurally identical tree, modulo the
// whitespace normalizations the strict parser performs per spec and etree
// does not (see normalizeText/normalizeAttr).
func FuzzParseVsEtree(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		ours, err := Parse(data)
		if err != nil {
			return
		}
		theirs := etree.NewDocument()
		if err := theirs.ReadFromBytes(data); err != nil {
			t.Fatalf("etree rejected input the strict parser accepted: %v\ninput: %q", err, data)
		}
		if theirs.Root() == nil {
			t.Fatalf("etree produced no root for input the strict parser accepted: %q", data)
		}
		compareWithEtree(t, "fuzz-input", ours.Root(), theirs.Root())
	})
}
