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
	"strings"
	"testing"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// Schema-single elements appearing more than once are malformed. The
// extractor rejects them rather than silently picking one, eliminating the
// parser-differential ambiguity of "which one does the consumer honor".
func TestRejectDuplicate_SchemaSingleElements(t *testing.T) {
	const (
		p = `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`
		a = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`
	)
	cases := map[string]string{
		"two Status in Response": `<samlp:Response ` + p + `>` +
			`<samlp:Status><samlp:StatusCode Value="x"/></samlp:Status>` +
			`<samlp:Status><samlp:StatusCode Value="y"/></samlp:Status>` +
			`</samlp:Response>`,
		"two Issuer in Response": `<samlp:Response ` + p + ` ` + a + `>` +
			`<saml:Issuer>a</saml:Issuer><saml:Issuer>b</saml:Issuer>` +
			`</samlp:Response>`,
		"two StatusCode in Status": `<samlp:Response ` + p + `>` +
			`<samlp:Status><samlp:StatusCode Value="x"/><samlp:StatusCode Value="y"/></samlp:Status>` +
			`</samlp:Response>`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, err := xmltree.Parse([]byte(doc))
			require.NoError(t, err)
			_, err = ResponseFromElement(parsed.Root())
			require.Error(t, err, "duplicate schema-single element must be rejected")
			require.Contains(t, err.Error(), "at most one")
		})
	}
}

func TestRejectDuplicate_WithinAssertion(t *testing.T) {
	const a = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`
	cases := map[string]string{
		"two Subject": `<saml:Assertion ` + a + ` Version="2.0">` +
			`<saml:Subject><saml:NameID>a</saml:NameID></saml:Subject>` +
			`<saml:Subject><saml:NameID>b</saml:NameID></saml:Subject>` +
			`</saml:Assertion>`,
		"two Conditions": `<saml:Assertion ` + a + ` Version="2.0">` +
			`<saml:Conditions NotOnOrAfter="2025-01-01T00:00:00Z"/>` +
			`<saml:Conditions NotOnOrAfter="2030-01-01T00:00:00Z"/>` +
			`</saml:Assertion>`,
		"two NameID in Subject": `<saml:Assertion ` + a + ` Version="2.0">` +
			`<saml:Subject><saml:NameID>a</saml:NameID><saml:NameID>b</saml:NameID></saml:Subject>` +
			`</saml:Assertion>`,
		"two SubjectConfirmationData": `<saml:Assertion ` + a + ` Version="2.0">` +
			`<saml:Subject><saml:SubjectConfirmation Method="m">` +
			`<saml:SubjectConfirmationData Recipient="a"/>` +
			`<saml:SubjectConfirmationData Recipient="b"/>` +
			`</saml:SubjectConfirmation></saml:Subject>` +
			`</saml:Assertion>`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, err := xmltree.Parse([]byte(doc))
			require.NoError(t, err)
			_, err = AssertionFromElement(parsed.Root())
			require.Error(t, err)
			require.Contains(t, err.Error(), "at most one")
		})
	}
}

// SubjectConfirmation, by contrast, is repeatable per the schema — multiple
// are extracted into the slice, not rejected.
func TestRejectDuplicate_SubjectConfirmationIsRepeatable(t *testing.T) {
	const a = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`
	doc := `<saml:Assertion ` + a + ` Version="2.0"><saml:Subject>` +
		`<saml:NameID>user</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<saml:SubjectConfirmationData Recipient="https://sp/acs"/></saml:SubjectConfirmation>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"/>` +
		`</saml:Subject></saml:Assertion>`

	parsed, err := xmltree.Parse([]byte(doc))
	require.NoError(t, err)
	assertion, err := AssertionFromElement(parsed.Root())
	require.NoError(t, err, "multiple SubjectConfirmations are schema-valid and must be accepted")
	require.Len(t, assertion.Subject.SubjectConfirmations, 2)
	require.Equal(t, "urn:oasis:names:tc:SAML:2.0:cm:bearer",
		assertion.Subject.SubjectConfirmations[0].Method)
	require.Equal(t, "https://sp/acs",
		assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient)
}

// The duplicate rejection fires regardless of namespace-prefix spelling: two
// Status elements under different prefixes bound to the protocol namespace
// still collide.
func TestRejectDuplicate_AcrossPrefixes(t *testing.T) {
	doc := `<a:Response xmlns:a="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:b="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<a:Status><a:StatusCode Value="x"/></a:Status>` +
		`<b:Status><b:StatusCode Value="y"/></b:Status>` +
		`</a:Response>`
	parsed, err := xmltree.Parse([]byte(doc))
	require.NoError(t, err)
	_, err = ResponseFromElement(parsed.Root())
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "at most one"))
}
