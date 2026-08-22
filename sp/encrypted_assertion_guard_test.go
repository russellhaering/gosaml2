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

package sp

import (
	"strings"
	"testing"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// TestEncryptedAssertionGuardFailsClosedOnTraversalLimit is the regression test
// for hasEncryptedAssertion discarding its traversal error. Padding a response
// past the bounded namespace traversal made the guard answer "no encrypted
// assertion" for a response that plainly contained one. The guard gates
// attacker-supplied ciphertext reaching the decrypter, so it must never
// silently report absence.
func TestEncryptedAssertionGuardFailsClosedOnTraversalLimit(t *testing.T) {
	var pad strings.Builder
	for i := 0; i < 1200; i++ {
		pad.WriteString(`<saml2p:Extensions/>`)
	}
	raw := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0">` +
		pad.String() +
		`<saml2:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml2:EncryptedAssertion>` +
		`</saml2p:Response>`

	doc, err := xmltree.Parse([]byte(raw))
	require.NoError(t, err)

	found, err := hasEncryptedAssertion(doc.Root())
	if err != nil {
		// Reporting why the scan stopped is a valid fail-closed outcome; the
		// caller turns it into a rejection.
		return
	}
	require.True(t, found,
		"hasEncryptedAssertion reported no EncryptedAssertion for a response containing one")
}

// TestEncryptedAssertionGuardStillDetectsSmallResponse pins the ordinary case,
// so the fix above cannot be satisfied by always erroring.
func TestEncryptedAssertionGuardStillDetectsSmallResponse(t *testing.T) {
	raw := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0">` +
		`<saml2:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml2:EncryptedAssertion>` +
		`</saml2p:Response>`

	doc, err := xmltree.Parse([]byte(raw))
	require.NoError(t, err)

	found, err := hasEncryptedAssertion(doc.Root())
	require.NoError(t, err)
	require.True(t, found)

	plain := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0"/>`
	doc, err = xmltree.Parse([]byte(plain))
	require.NoError(t, err)

	found, err = hasEncryptedAssertion(doc.Root())
	require.NoError(t, err)
	require.False(t, found)
}
