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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// cleartextURL matches an http:// URL that is not a loopback address.
var cleartextURL = regexp.MustCompile(`"http://([^"]+)"`)

func isLoopback(host string) bool {
	return strings.HasPrefix(host, "localhost") ||
		strings.HasPrefix(host, "127.0.0.1") ||
		strings.HasPrefix(host, "[::1]")
}

// TestExamplesDoNotFetchOverCleartext guards the shipped examples against
// bootstrapping SAML trust over an unauthenticated channel.
//
// The examples are what integrators copy. gosaml2 does not verify metadata
// signatures, so whatever transport delivers the metadata is what establishes
// its authenticity: the certificates in it become the only trust anchors used
// to verify Response and Assertion signatures. Fetching it over plain HTTP lets
// an on-path attacker substitute their own certificate and mint assertions for
// any identity -- a full authentication bypass that starts from example code.
//
// Entity IDs and audience URIs are identifiers rather than things fetched, and
// loopback callback URLs are not remote, so both are allowed.
func TestExamplesDoNotFetchOverCleartext(t *testing.T) {
	roots := []string{filepath.Join("examples", "sp"), filepath.Join("examples", "idp")}

	checked := 0
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("reading %s: %v", root, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			path := filepath.Join(root, entry.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			checked++

			for _, line := range strings.Split(string(src), "\n") {
				// Only flag URLs that are actually retrieved.
				if !strings.Contains(line, "http.Get") &&
					!strings.Contains(line, "http.Post") &&
					!strings.Contains(line, "MetadataURL") &&
					!strings.Contains(line, "idpMetadataURL =") {
					continue
				}
				for _, m := range cleartextURL.FindAllStringSubmatch(line, -1) {
					if !isLoopback(m[1]) {
						t.Errorf("%s fetches over cleartext HTTP: %s\n"+
							"Metadata delivers the trust anchors used to verify all SAML "+
							"signatures, and gosaml2 does not verify metadata signatures, so "+
							"the transport must be authenticated (HTTPS) or the document must "+
							"come from a local operator-controlled file.", path, strings.TrimSpace(line))
					}
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("no example sources were checked")
	}
	t.Logf("checked %d example source files", checked)
}
