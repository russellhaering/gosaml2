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
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

// The metadata extractor (types/metadata_extract.go) replaces encoding/xml
// for EntityDescriptor parsing. This harness proves it produces identical
// EntityDescriptor structs to encoding/xml across the corpus metadata
// fixtures. EntitiesDescriptor (a federation of multiple descriptors) is a
// different root element the library never parsed and is skipped.
func TestMetadataExtractEquivalence(t *testing.T) {
	matches, err := filepath.Glob("testdata/corpus/*/*.xml")
	require.NoError(t, err)

	compared := 0
	for _, path := range matches {
		if strings.Contains(path, "_hostile") {
			continue
		}
		data, err := os.ReadFile(path)
		require.NoError(t, err)

		// Only EntityDescriptor-rooted documents.
		doc, err := xmltree.ParseMetadata(data)
		if err != nil || doc.Root().Tag != "EntityDescriptor" {
			continue
		}

		var want types.EntityDescriptor
		if err := xml.Unmarshal(data, &want); err != nil {
			continue
		}

		got, err := types.EntityDescriptorFromElement(doc.Root())
		require.NoError(t, err, "%s", path)

		require.EqualValues(t, &want, got, "%s: metadata extractor diverges from encoding/xml", path)
		compared++
	}
	require.Positive(t, compared, "expected at least one EntityDescriptor fixture")
	t.Logf("compared %d EntityDescriptor documents", compared)
}
