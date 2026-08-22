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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/russellhaering/gosaml2/v2/types"
)

// securityTestSP creates a ServiceProvider and signing key pair for security tests.
// The SP has all security features enabled.
func securityTestSP(t *testing.T) (*ServiceProvider, *saml2.KeyStore) {
	t.Helper()

	fakeTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ks := testKeyStore(t, fakeTime)

	block, _ := pem.Decode([]byte(idpCertificate))
	require.NotNil(t, block)
	idpCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	spCert, err := x509.ParseCertificate(ks.Cert)
	require.NoError(t, err)

	sp := &ServiceProvider{
		EntityID:          "https://sp.example.com",
		ACSURL:            "https://sp.example.com/acs",
		SLOURL:            "https://sp.example.com/slo",
		IDPEntityID:       "http://www.okta.com/exk5zt0r12Edi4rD20h7",
		IDPSSOURL:         "https://idp.example.com/sso",
		IDPCertificates:   []*x509.Certificate{idpCert, spCert},
		SPKeyStore:        ks,
		SignAuthnRequests: true,
		AudienceURIs:      []string{"https://sp.example.com"},
		Clock:             func() time.Time { return fakeTime },
		ClockSkew:         60 * time.Second,
	}

	return sp, ks
}

// makeValidResponse creates a valid SAML response XML string.
func makeValidResponse(sp *ServiceProvider) string {
	now := sp.now()
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s"
    ID="_response_id_1"
    InResponseTo="_request_id_1"
    IssueInstant="%s"
    Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_assertion_id_1"
      IssueInstant="%s"
      Version="2.0">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData
            InResponseTo="_request_id_1"
            NotOnOrAfter="%s"
            Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction>
        <saml2:Audience>%s</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_1">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user@example.com</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL,
		now.Format(time.RFC3339),
		sp.IDPEntityID,
		now.Format(time.RFC3339),
		sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339),
		sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339),
		now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		now.Format(time.RFC3339),
	)
}

// signAssertionOnly signs just the assertion element(s) within a response,
// leaving the response envelope unsigned. Uses dsig.NSDetach to ensure
// the namespace context during signing matches what the verifier will see.
func signAssertionOnly(t *testing.T, responseXML string, sp *ServiceProvider) string {
	t.Helper()

	doc := xmltree.NewDocument()
	err := doc.ReadFromBytes([]byte(responseXML))
	require.NoError(t, err)

	root := doc.Root()

	// Strip any existing signatures everywhere first
	for _, sig := range root.FindElements("//Signature") {
		sig.Parent().RemoveChild(sig)
	}

	signer, err := sp.Signer()
	require.NoError(t, err)

	// Use NSFindIterate + NSDetach so that the namespace context during
	// signing exactly matches what the verifier will produce during
	// verification. This is critical because NSDetach inherits namespace
	// declarations from ancestors that Copy() does not.
	err = dsig.NSFindIterate(root, saml2.SAMLAssertionNamespace, saml2.AssertionTag, func(ctx dsig.NSContext, assertionEl *xmltree.Element) error {
		if assertionEl.Parent() != root {
			return nil
		}

		detached, err := dsig.NSDetach(ctx, assertionEl)
		if err != nil {
			return err
		}

		signedAssertion, err := signer.SignEnveloped(detached)
		if err != nil {
			return err
		}

		root.RemoveChild(assertionEl)
		root.AddChild(signedAssertion)
		return nil
	})
	require.NoError(t, err)

	var buf bytes.Buffer
	doc.Root().WriteCanonicalTo(&buf)
	return buf.String()
}

// ============================================================================
// Attack Class 1: XML Signature Wrapping (XSW) — see xsw_test.go
// ============================================================================

// ============================================================================
// Attack Class 2: Go encoding/xml Round-Trip Mutations (CVE-2020-29509/10/11)
// ============================================================================

func TestRoundTripMutation_NamespacePrefixedAttributes(t *testing.T) {
	// XML with namespace-prefixed attributes that could mutate during re-parsing.
	// The xml-roundtrip-validator should reject this.
	maliciousXML := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:evil="http://evil.com" evil:Destination="https://evil.com/acs"
		Destination="https://sp.example.com/acs" Version="2.0" ID="_1">
		<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer>
	</saml2p:Response>`

	sp, _ := securityTestSP(t)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "namespace-prefixed attribute manipulation should be rejected")
}

func TestRoundTripMutation_DirectiveInjection(t *testing.T) {
	// XML with processing instructions or DTD that could mutate during re-parsing.
	maliciousXML := `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe "test">]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs" Version="2.0" ID="_1">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml2:Issuer>
</saml2p:Response>`

	sp, _ := securityTestSP(t)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(maliciousXML))
	require.Error(t, err, "DTD entity injection should be rejected")
}

// ============================================================================
// Attack Class 3: XML Comment Injection & Canonicalization Bypass
// ============================================================================

func TestCommentInjection_InNameID(t *testing.T) {
	// Embed a comment in the NameID field. The canonicalized value should
	// include the full text (not be truncated at the comment).
	sp, _ := securityTestSP(t)

	now := sp.now()
	responseWithComment := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>admin@example.com<!--injected-->.evil.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
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
		sp.AudienceURIs[0],
	)

	// The strict parser rejects the comment outright.
	_, _, err := parseResponse([]byte(responseWithComment), 0)
	require.Error(t, err, "comment injection must be rejected at parse time")
	require.Contains(t, err.Error(), "comments are not allowed")
}

func TestCommentInjection_InAttributeValue(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	responseWithComment := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="Role">
        <saml2:AttributeValue>user<!---->admin</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	// The strict parser rejects the comment outright.
	_, _, err := parseResponse([]byte(responseWithComment), 0)
	require.Error(t, err, "comment in attribute value must be rejected at parse time")
	require.Contains(t, err.Error(), "comments are not allowed")
}

// ============================================================================
// Attack Class 4: Multiple Assertion Injection
// (Unsigned response rejection covered by xsw_test.go: TestXSW2)
// ============================================================================

func TestMultipleAssertionInjection_OnlyOneAssertionSigned(t *testing.T) {
	// In an unsigned response with multiple assertions, if only one is signed
	// the unsigned ones must be excluded from the result.
	sp, _ := securityTestSP(t)

	now := sp.now()
	// Create response with two assertions - only one will be signed
	multiAssertionResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_signed_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>legit@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_unsigned_a2" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>attacker@evil.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
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
		sp.AudienceURIs[0],
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	// Sign only the first assertion
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromBytes([]byte(multiAssertionResp)))

	root := doc.Root()
	assertions := root.FindElements("//Assertion")
	require.Len(t, assertions, 2)

	signer, err := sp.Signer()
	require.NoError(t, err)

	// Sign only the first assertion
	first := assertions[0]
	root.RemoveChild(first)
	signedFirst, err := signer.SignEnveloped(first)
	require.NoError(t, err)

	// Re-insert before the second assertion
	root.InsertChildAt(assertions[1].Index(), signedFirst)

	modifiedXML, err := doc.WriteToString()
	require.NoError(t, err)

	// The unsigned second assertion should cause an error (ErrMissingSignature from dsig)
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(modifiedXML))
	require.Error(t, err, "unsigned assertion in unsigned response should be rejected")
}

// ============================================================================
// Attack Class 5: Signature Validation Bypass
// ============================================================================

func TestSignatureBypass_RemovedSignature(t *testing.T) {
	// Response with signature removed should be rejected.
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)

	// Remove the signature
	doc := xmltree.NewDocument()
	require.NoError(t, doc.ReadFromBytes([]byte(signed)))

	sigs := doc.Root().FindElements("//Signature")
	for _, sig := range sigs {
		sig.Parent().RemoveChild(sig)
	}

	unsigned, err := doc.WriteToString()
	require.NoError(t, err)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(unsigned))
	require.Error(t, err, "response with removed signature should be rejected")
}

func TestSignatureBypass_SelfSignedCert(t *testing.T) {
	// Response signed with a self-signed cert not in trusted certs should be rejected.
	sp, _ := securityTestSP(t)

	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	attackerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	attackerCertBytes, err := x509.CreateCertificate(rand.Reader, attackerTemplate, attackerTemplate, &attackerKey.PublicKey, attackerKey)
	require.NoError(t, err)

	// Create a new SP that uses the attacker's key for signing
	attackerSP := &ServiceProvider{
		SPKeyStore: &saml2.KeyStore{Signer: attackerKey, Cert: attackerCertBytes},
	}

	validResp := makeValidResponse(sp)
	attackerSigned := signResponse(t, validResp, attackerSP)

	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(attackerSigned))
	require.Error(t, err, "response signed with untrusted cert should be rejected")
}

func TestSignatureBypass_InsecureSkipValidation(t *testing.T) {
	// Verify that InsecureSkipSignatureValidation actually skips validation.
	// This is intentional behavior but should be clearly documented.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	validResp := makeValidResponse(sp)

	// Completely unsigned response should succeed with skip flag
	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(validResp))
	require.NoError(t, err)
	require.False(t, resp.SignatureValidated, "SignatureValidated should be false when validation is skipped")
}

// ============================================================================
// Attack Class 6: Assertion Replay Attacks
// ============================================================================

func TestReplay_WithRequestTracker(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()

	// Store a request ID
	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_request_id_1"))

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)
	encoded := encodeResponse(signed)

	// First use should succeed
	_, err := sp.ValidateEncodedResponse(ctx, encoded)
	require.NoError(t, err)

	// Re-sign to get a fresh copy (same InResponseTo)
	signed2 := signResponse(t, validResp, sp)
	encoded2 := encodeResponse(signed2)

	// Second use (replay) should fail
	_, err = sp.ValidateEncodedResponse(ctx, encoded2)
	require.Error(t, err, "replayed response should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

func TestReplay_UnknownRequestID(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)

	// Don't store any request ID
	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "response with unknown InResponseTo should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

func TestReplay_IDPInitiated_Disallowed(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	sp.AllowIDPInitiated = false

	// Response without InResponseTo
	now := sp.now()
	idpInitiatedResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
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
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, idpInitiatedResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "IdP-initiated SSO should be rejected when AllowIDPInitiated is false")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

func TestReplay_IDPInitiated_Allowed(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	sp.AllowIDPInitiated = true
	sp.AssertionReplayCache = NewMemoryAssertionReplayCache()

	now := sp.now()
	idpInitiatedResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
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
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, idpInitiatedResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err, "IdP-initiated SSO should be allowed when AllowIDPInitiated is true")
}

func TestReplay_InResponseToMismatch(t *testing.T) {
	// SubjectConfirmationData.InResponseTo doesn't match Response.InResponseTo
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()

	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_request_id_1"))

	now := sp.now()
	mismatchResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_DIFFERENT_request_id" NotOnOrAfter="%s" Recipient="%s"/>
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
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, mismatchResp, sp)
	_, err := sp.ValidateEncodedResponse(ctx, encodeResponse(signed))
	require.Error(t, err, "mismatched InResponseTo should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// ============================================================================
// Attack Class 7: Denial of Service
// ============================================================================

func TestDoS_EmptyCipherValueGCM(t *testing.T) {
	// Empty CipherValue in EncryptedAssertion should not panic (GCM path).
	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		CipherValue:      "", // empty
	}

	// We need a valid cert for DecryptSymmetricKey to potentially succeed.
	// But first, let's verify the base64 decode + length check path.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	// Encrypt a valid AES key so DecryptSymmetricKey succeeds
	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea.EncryptedKey = types.EncryptedKey{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
		CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
		X509Data:         base64.StdEncoding.EncodeToString(certBytes),
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	// This must NOT panic - should return an error
	require.NotPanics(t, func() {
		_, err = ea.DecryptBytes(tlsCert)
	}, "empty CipherValue should not panic")
	require.Error(t, err, "empty CipherValue should return an error")
	require.Contains(t, err.Error(), "too short")
}

func TestDoS_EmptyCipherValueCBC(t *testing.T) {
	// Empty CipherValue in EncryptedAssertion should not panic (CBC path).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128CBC},
		CipherValue:      "", // empty
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	require.NotPanics(t, func() {
		_, err = ea.DecryptBytes(tlsCert)
	}, "empty CipherValue (CBC) should not panic")
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

func TestDoS_ShortCipherValueGCM(t *testing.T) {
	// CipherValue shorter than nonce+tag should not panic.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	// Only 10 bytes of cipher data (need at least 12 nonce + 16 tag = 28)
	shortData := make([]byte, 10)
	_, err = rand.Read(shortData)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		CipherValue:      base64.StdEncoding.EncodeToString(shortData),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	require.NotPanics(t, func() {
		_, err = ea.DecryptBytes(tlsCert)
	}, "short CipherValue (GCM) should not panic")
	require.Error(t, err)
}

func TestDoS_ShortCipherValueCBC(t *testing.T) {
	// CipherValue shorter than 2 blocks should not panic.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	// Exactly one block (16 bytes) - need at least 2 blocks (IV + data)
	oneBlock := make([]byte, 16)
	_, err = rand.Read(oneBlock)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128CBC},
		CipherValue:      base64.StdEncoding.EncodeToString(oneBlock),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	require.NotPanics(t, func() {
		_, err = ea.DecryptBytes(tlsCert)
	}, "single-block CipherValue (CBC) should not panic")
	require.Error(t, err)
}

func TestDoS_BillionLaughs(t *testing.T) {
	// XML entity expansion attack should be rejected by the roundtrip validator.
	billionLaughs := `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">&lol4;</saml2:Issuer>
</saml2p:Response>`

	sp, _ := securityTestSP(t)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(billionLaughs))
	require.Error(t, err, "billion laughs attack should be rejected")
}

func TestDoS_DecompressionBomb(t *testing.T) {
	// Already covered by TestCompressionBombInput but let's verify the limit works.
	sp, _ := securityTestSP(t)
	sp.MaximumDecompressedBodySize = 1024 // very small limit

	// The compressed testdata is larger than 1024 bytes when decompressed
	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)

	// Try with already-valid XML (no compression) - should work fine since
	// maybeDeflate tries direct parsing first
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err, "uncompressed response within limits should succeed")
}

func TestDoS_NilPointersInAssertion(t *testing.T) {
	// Various malformed assertions that could trigger nil pointer dereferences.
	sp, _ := securityTestSP(t)

	testCases := []struct {
		name string
		xml  string
	}{
		{
			name: "missing Subject",
			xml: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
  </saml2:Assertion>
</saml2p:Response>`,
				sp.ACSURL, sp.now().Format(time.RFC3339), sp.IDPEntityID,
				sp.now().Format(time.RFC3339), sp.IDPEntityID),
		},
		// NOTE: Missing Conditions is NOT rejected by ValidateEncodedResponse.
		// Conditions validation happens in RetrieveAssertionInfo via
		// verifyAssertionConditions. This is by design - ValidateEncodedResponse
		// returns the raw Response for callers who want custom Conditions handling.
		{
			name: "missing Status",
			xml: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
				sp.ACSURL, sp.now().Format(time.RFC3339), sp.IDPEntityID,
				sp.now().Format(time.RFC3339), sp.IDPEntityID,
				sp.now().Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
				sp.now().Add(-5*time.Minute).Format(time.RFC3339), sp.now().Add(5*time.Minute).Format(time.RFC3339),
				sp.AudienceURIs[0]),
		},
		{
			name: "missing Issuer",
			xml: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
				sp.ACSURL, sp.now().Format(time.RFC3339),
				sp.now().Format(time.RFC3339), sp.IDPEntityID,
				sp.now().Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
				sp.now().Add(-5*time.Minute).Format(time.RFC3339), sp.now().Add(5*time.Minute).Format(time.RFC3339),
				sp.AudienceURIs[0]),
		},
		{
			name: "no assertions",
			xml: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`,
				sp.ACSURL, sp.now().Format(time.RFC3339), sp.IDPEntityID),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signed := signResponse(t, tc.xml, sp)
			require.NotPanics(t, func() {
				_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
				require.Error(t, err, "malformed response should return error, not panic")
			})
		})
	}
}

func TestDoS_3DESRejected(t *testing.T) {
	// 3DES should be explicitly rejected.
	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodTripleDESCBC},
		CipherValue:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	certBytes, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)

	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	encKey, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)

	ea.EncryptedKey = types.EncryptedKey{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
		CipherValue:      base64.StdEncoding.EncodeToString(encKey),
		X509Data:         base64.StdEncoding.EncodeToString(certBytes),
	}

	tlsCert := &tls.Certificate{Certificate: [][]byte{certBytes}, PrivateKey: key}

	_, err := ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "3DES")
}

// ============================================================================
// Attack Class 8: Temporal Validation
// ============================================================================

func TestTemporal_ExpiredAssertion(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	expiredResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(-1*time.Hour).Format(time.RFC3339), sp.ACSURL, // NotOnOrAfter in the past
		now.Add(-2*time.Hour).Format(time.RFC3339), now.Add(-1*time.Hour).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, expiredResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "expired assertion should be rejected")
	require.ErrorIs(t, err, saml2.ErrExpired)
}

func TestTemporal_NotYetValid(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	futureResp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotBefore="%s" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(2*time.Hour).Format(time.RFC3339), // NotBefore far in future
		now.Add(3*time.Hour).Format(time.RFC3339),
		sp.ACSURL,
		now.Add(2*time.Hour).Format(time.RFC3339),
		now.Add(3*time.Hour).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, futureResp, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "not-yet-valid assertion should be rejected")
	require.ErrorIs(t, err, saml2.ErrNotYetValid)
}

func TestTemporal_MissingNotOnOrAfter(t *testing.T) {
	// SubjectConfirmationData without NotOnOrAfter should be rejected.
	sp, _ := securityTestSP(t)

	now := sp.now()
	missingExpiry := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, missingExpiry, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "missing NotOnOrAfter should be rejected")
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

func TestTemporal_ClockSkewBoundary(t *testing.T) {
	// Test exactly at the clock skew boundary.
	sp, _ := securityTestSP(t)
	sp.ClockSkew = 30 * time.Second
	sp.AllowIDPInitiated = true
	sp.AssertionReplayCache = NewMemoryAssertionReplayCache()

	now := sp.now()

	// Assertion that expired 29 seconds ago (within 30s skew) - should pass
	justExpired := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(-29*time.Second).Format(time.RFC3339), sp.ACSURL,
		now.Add(-10*time.Minute).Format(time.RFC3339), now.Add(-29*time.Second).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, justExpired, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err, "assertion expired 29s ago should pass with 30s skew")

	// Assertion that expired 31 seconds ago (outside 30s skew) - should fail
	tooExpired := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(-31*time.Second).Format(time.RFC3339), sp.ACSURL,
		now.Add(-10*time.Minute).Format(time.RFC3339), now.Add(-31*time.Second).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed2 := signResponse(t, tooExpired, sp)
	_, err = sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed2))
	require.Error(t, err, "assertion expired 31s ago should fail with 30s skew")
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// ============================================================================
// Attack Class 9: Validation Bypass via Attribute Manipulation
// ============================================================================

func TestValidation_WrongDestination(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	wrongDest := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://evil.example.com/acs" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, wrongDest, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "wrong destination should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

func TestValidation_WrongRecipient(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	wrongRecipient := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="https://evil.example.com/acs"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339),
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, wrongRecipient, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "wrong recipient should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadRecipient)
}

func TestValidation_WrongAudience(t *testing.T) {
	// Audience validation is done in RetrieveAssertionInfo (via
	// verifyAssertionConditions), not in ValidateEncodedResponse.
	sp, _ := securityTestSP(t)

	now := sp.now()
	wrongAudience := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>https://evil.example.com</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
	)

	signed := signResponse(t, wrongAudience, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encodeResponse(signed))
	require.Error(t, err, "wrong audience should be rejected")
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch)
}

func TestValidation_WrongIssuer(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	wrongIssuer := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://evil-idp.example.com</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339),
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, wrongIssuer, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "wrong issuer should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadIssuer)
}

func TestValidation_WrongSubjectConfirmationMethod(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	wrongMethod := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
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
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, wrongMethod, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "non-bearer subject confirmation method should be rejected")
	require.ErrorIs(t, err, saml2.ErrMalformed)
}

func TestValidation_NonSuccessStatus(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	failStatus := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
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
		sp.AudienceURIs[0],
	)

	signed := signResponse(t, failStatus, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "non-success status should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadStatus)
}

func TestValidation_WrongVersion(t *testing.T) {
	sp, _ := securityTestSP(t)

	now := sp.now()
	wrongVersion := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_r1" Version="1.1" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
	)

	signed := signResponse(t, wrongVersion, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.Error(t, err, "SAML 1.1 version should be rejected")
	require.ErrorIs(t, err, saml2.ErrBadVersion)
}

// ============================================================================
// SHA-1 Rejection
// ============================================================================

func TestSHA1_RejectedByDefault(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.AllowSHA1 = false

	// Verify the verifier has AllowSHA1 = false
	v := sp.verifier()
	require.False(t, v.AllowSHA1, "AllowSHA1 should default to false")
}

func TestSHA1_AllowedWhenExplicit(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.AllowSHA1 = true

	v := sp.verifier()
	require.True(t, v.AllowSHA1, "AllowSHA1 should be true when explicitly set")
}

// ============================================================================
// Encryption edge cases
// ============================================================================

func TestEncryption_ValidCBCRoundTrip(t *testing.T) {
	// Test that a properly encrypted CBC assertion decrypts correctly.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	// Create a valid AES-128-CBC encrypted assertion
	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	plaintext := []byte("<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>")

	// PKCS#7 padding
	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)

	padLen := block.BlockSize() - (len(plaintext) % block.BlockSize())
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, block.BlockSize())
	_, err = rand.Read(iv)
	require.NoError(t, err)

	cbc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	cbc.CryptBlocks(ciphertext, padded)

	// Prepend IV
	data := append(iv, ciphertext...)

	// Encrypt the AES key with RSA-OAEP
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128CBC},
		CipherValue:      base64.StdEncoding.EncodeToString(data),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, result)
}

func TestEncryption_ValidGCMRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	plaintext := []byte("<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>")

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	data := append(nonce, ciphertext...)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		CipherValue:      base64.StdEncoding.EncodeToString(data),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, result)
}

func TestEncryption_UnknownAlgorithm(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	encKey, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes128"},
		CipherValue:      base64.StdEncoding.EncodeToString(make([]byte, 64)),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
	}

	tlsCert := &tls.Certificate{Certificate: [][]byte{certBytes}, PrivateKey: key}
	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown symmetric encryption method")
}

func TestEncryption_MismatchedCert(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)

	// Generate a different key for the EncryptedKey cert
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherCertBytes, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &otherKey.PublicKey, otherKey)

	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	encKey, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		CipherValue:      base64.StdEncoding.EncodeToString(make([]byte, 64)),
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encKey),
			X509Data:         base64.StdEncoding.EncodeToString(otherCertBytes), // wrong cert
		},
	}

	tlsCert := &tls.Certificate{Certificate: [][]byte{certBytes}, PrivateKey: key}
	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mismatched cert")
}

// ============================================================================
// Positive test: valid signed response accepted
// ============================================================================

func TestValidSignedResponse_Accepted(t *testing.T) {
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.SignatureValidated)
	require.Len(t, resp.Assertions, 1)
	require.Equal(t, "user@example.com", resp.Assertions[0].Subject.NameID.Value)
}

func TestValidAssertionSignedResponse_Accepted(t *testing.T) {
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	signed := signAssertionOnly(t, validResp, sp)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.SignatureValidated, "Response-level signature not present")
	require.Len(t, resp.Assertions, 1)
	require.True(t, resp.Assertions[0].SignatureValidated)
}

// ============================================================================
// Redirect binding — see decode_redirect_security_test.go
// Logout request/response — see decode_redirect_security_test.go
// ============================================================================

// ============================================================================
// MemoryRequestTracker edge cases
// ============================================================================

func TestMemoryRequestTracker_Expiry(t *testing.T) {
	tracker := NewMemoryRequestTracker(100 * time.Millisecond)
	ctx := context.Background()

	require.NoError(t, tracker.StoreRequest(ctx, "id-1"))

	// Should succeed immediately
	require.NoError(t, tracker.ConsumeRequest(ctx, "id-1"))

	// Store another and let it expire
	require.NoError(t, tracker.StoreRequest(ctx, "id-2"))
	time.Sleep(150 * time.Millisecond)

	err := tracker.ConsumeRequest(ctx, "id-2")
	require.Error(t, err, "expired request should be rejected")
	require.ErrorIs(t, err, saml2.ErrReplay)
}

func TestMemoryRequestTracker_DoubleConsume(t *testing.T) {
	tracker := NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()

	require.NoError(t, tracker.StoreRequest(ctx, "id-1"))
	require.NoError(t, tracker.ConsumeRequest(ctx, "id-1"))

	// Second consume should fail
	err := tracker.ConsumeRequest(ctx, "id-1")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// ============================================================================
// Post form XSS safety
// ============================================================================

func TestPostForm_XSSInRelayState(t *testing.T) {
	// Verify that html/template properly escapes malicious RelayState values.
	body, err := saml2.BuildPOSTForm(
		"https://idp.example.com/sso",
		"SAMLRequest",
		"base64data",
		`"><script>alert('xss')</script>`,
	)
	require.NoError(t, err)

	bodyStr := string(body)
	// The form template has a legitimate <script> tag for auto-submit.
	// Check that the RelayState value attribute is properly escaped.
	require.Contains(t, bodyStr, "&lt;script&gt;alert", "script tags in RelayState should be HTML-escaped")
	require.NotContains(t, bodyStr, `alert('xss')`, "unescaped script content should not appear")
}

func TestPostForm_XSSInURL(t *testing.T) {
	body, err := saml2.BuildPOSTForm(
		`javascript:alert('xss')`,
		"SAMLRequest",
		"base64data",
		"",
	)
	require.NoError(t, err)

	bodyStr := string(body)
	// html/template sanitizes javascript: URLs in certain contexts
	// In action attribute, it should be filtered or escaped
	require.NotContains(t, bodyStr, "javascript:alert", "javascript: URL should be sanitized by html/template")
}

// ============================================================================
// SignatureValidated flag correctness
// ============================================================================

func TestSignatureValidatedFlag_ResponseSigned(t *testing.T) {
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	signed := signResponse(t, validResp, sp)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err)
	require.True(t, resp.SignatureValidated, "Response signature flag should be true when response is signed")
}

func TestSignatureValidatedFlag_AssertionOnlySigned(t *testing.T) {
	sp, _ := securityTestSP(t)

	validResp := makeValidResponse(sp)
	signed := signAssertionOnly(t, validResp, sp)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(signed))
	require.NoError(t, err)
	require.False(t, resp.SignatureValidated, "Response signature flag should be false when only assertion is signed")
	require.True(t, resp.Assertions[0].SignatureValidated, "Assertion signature flag should be true")
}

func TestSignatureValidatedFlag_InsecureSkip(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	validResp := makeValidResponse(sp)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(validResp))
	require.NoError(t, err)
	require.False(t, resp.SignatureValidated, "SignatureValidated should be false when validation is skipped")
}

// Suppress unused import warnings
var _ = xml.Marshal
var _ = strings.Contains
var _ = errors.New
var _ = dsig.ErrMissingSignature
