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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
)

// buildCustomResponse builds a fully-formed SAML response XML with valid
// defaults derived from the ServiceProvider, then applies option functions
// to mutate the XML string before returning it.
func buildCustomResponse(sp *ServiceProvider, opts ...func(string) string) string {
	now := sp.now()
	resp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_1">
      <saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="Email"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user@example.com</saml2:AttributeValue></saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0], now.Format(time.RFC3339))
	for _, opt := range opts {
		resp = opt(resp)
	}
	return resp
}

// signAndEncode is a shorthand that signs the response envelope and base64-encodes it.
func signAndEncode(t *testing.T, xml string, sp *ServiceProvider) string {
	t.Helper()
	return encodeResponse(signResponse(t, xml, sp))
}

// signAssertionAndEncode signs only the assertion within the response and base64-encodes it.
func signAssertionAndEncode(t *testing.T, xml string, sp *ServiceProvider) string {
	t.Helper()
	return encodeResponse(signAssertionOnly(t, xml, sp))
}

// setupSPWithTracker creates an SP with a request tracker and stores the
// standard request ID used in buildCustomResponse.
func setupSPWithTracker(t *testing.T) *ServiceProvider {
	t.Helper()
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	require.NoError(t, sp.RequestTracker.StoreRequest(context.Background(), "_request_id_1"))
	return sp
}

// ============================================================================
// Tests 1-10: Time Boundary / Clock Skew
// ============================================================================

// Test 1a: NotOnOrAfter at exact boundary (now - clockSkew) should still be valid
// because the check is: now-skew > notOnOrAfter  (strictly after).
// When notOnOrAfter == now-skew, now-skew is NOT after notOnOrAfter, so valid.
func TestSecurityConditions_NotOnOrAfterExactBoundaryValid(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	skew := sp.clockSkew()

	// Conditions.NotOnOrAfter = now - skew  =>  now-skew == notOnOrAfter  => NOT expired
	boundary := now.Add(-skew)
	responseXML := buildCustomResponse(sp, func(s string) string {
		// Replace Conditions NotOnOrAfter
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s">`, boundary.Format(time.RFC3339)),
			1) // only the Conditions one (first occurrence)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "NotOnOrAfter exactly at now-skew boundary should still be valid")
}

// Test 1b: NotOnOrAfter 1 second before boundary should be expired.
func TestSecurityConditions_NotOnOrAfterPastBoundaryExpired(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	skew := sp.clockSkew()

	// Conditions.NotOnOrAfter = now - skew - 1s => now-skew > notOnOrAfter => expired
	pastBoundary := now.Add(-skew - time.Second)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s">`, pastBoundary.Format(time.RFC3339)),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// Test 2: NotBefore exactly at now + clockSkew + 1s should be not-yet-valid.
func TestSecurityConditions_NotBeforeBeyondSkew(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	skew := sp.clockSkew()

	futureNotBefore := now.Add(skew + time.Second)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`NotBefore="%s"`, now.Add(-5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotBefore="%s"`, futureNotBefore.Format(time.RFC3339)),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrNotYetValid)
}

// Test 3: Missing NotBefore in Conditions should be allowed.
func TestSecurityConditions_MissingNotBeforeAllowed(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(` NotBefore="%s"`, now.Add(-5*time.Minute).Format(time.RFC3339)),
			"",
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "Missing NotBefore should be allowed")
}

// Test 4: Far-future NotOnOrAfter (100 years) should be accepted.
func TestSecurityConditions_FarFutureNotOnOrAfter(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	farFuture := now.Add(100 * 365 * 24 * time.Hour)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s">`, farFuture.Format(time.RFC3339)),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "Far-future NotOnOrAfter should be accepted")
}

// Test 5: Missing NotOnOrAfter in Conditions should error with ErrMissingElement.
func TestSecurityConditions_MissingNotOnOrAfterError(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(` NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			`>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

// Test 6: NotOnOrAfter in non-RFC3339 format should error.
func TestSecurityConditions_NotOnOrAfterBadFormat(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	// Use space instead of T and no timezone
	badTime := "2025-01-01 00:05:00"
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s">`, badTime),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMalformed)
}

// Test 7: NotOnOrAfter with positive timezone offset (+05:00) should work.
func TestSecurityConditions_NotOnOrAfterPositiveTimezone(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	// now is 2025-01-01T00:00:00Z. A NotOnOrAfter of 2025-01-01T10:00:00+05:00
	// equals 2025-01-01T05:00:00Z, which is 5 hours in the future from now - valid.
	futureWithTZ := "2025-01-01T10:00:00+05:00"
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s">`, futureWithTZ),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "NotOnOrAfter with positive timezone offset should work")
}

// Test 8: NotOnOrAfter with negative timezone offset (-05:00) should work.
func TestSecurityConditions_NotOnOrAfterNegativeTimezone(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	// now is 2025-01-01T00:00:00Z. A NotOnOrAfter of 2024-12-31T20:00:00-05:00
	// equals 2025-01-01T01:00:00Z, which is 1 hour in the future from now - valid.
	futureWithNegTZ := "2024-12-31T20:00:00-05:00"
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s">`, futureWithNegTZ),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "NotOnOrAfter with negative timezone offset should work")
}

// Test 9: Clock skew set to zero uses the default 60s.
func TestSecurityConditions_ZeroClockSkewUsesDefault(t *testing.T) {
	sp := setupSPWithTracker(t)
	sp.ClockSkew = 0 // should default to 60s
	now := sp.now()

	// Set NotOnOrAfter to 30s ago. With 60s default skew, now-60s is NOT after
	// notOnOrAfter, so it should be valid.
	notOnOrAfter := now.Add(-30 * time.Second)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s">`, notOnOrAfter.Format(time.RFC3339)),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "Zero ClockSkew should default to 60s allowing 30s-ago NotOnOrAfter")
}

// Test 10: Extremely large clock skew (24h), assertion expired 23h ago should pass.
func TestSecurityConditions_LargeClockSkew(t *testing.T) {
	sp := setupSPWithTracker(t)
	sp.ClockSkew = 24 * time.Hour
	now := sp.now()

	// Expired 23h ago - with 24h skew, now-24h is NOT after notOnOrAfter
	expired23hAgo := now.Add(-23 * time.Hour)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s">`, expired23hAgo.Format(time.RFC3339)),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "24h clock skew should accept assertion expired 23h ago")
}

// ============================================================================
// Tests 11-14: SubjectConfirmationData Time
// ============================================================================

// Test 11: SCD.NotOnOrAfter expired but Conditions.NotOnOrAfter valid.
// ValidateEncodedResponse checks SCD time; should fail.
func TestSecurityConditions_SCDExpiredConditionsValid(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	skew := sp.clockSkew()

	// SCD expired (beyond skew) but Conditions still valid
	scdExpired := now.Add(-skew - 5*time.Second)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s" Recipient`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s" Recipient`, scdExpired.Format(time.RFC3339)),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// Test 12: SCD.NotOnOrAfter valid but Conditions.NotOnOrAfter expired.
func TestSecurityConditions_SCDValidConditionsExpired(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	skew := sp.clockSkew()

	// Conditions expired (beyond skew)
	condExpired := now.Add(-skew - 5*time.Second)
	responseXML := buildCustomResponse(sp, func(s string) string {
		// The Conditions NotOnOrAfter is the one that ends with ">
		// (closing the Conditions tag), while SCD NotOnOrAfter is followed by Recipient
		s = strings.Replace(s,
			fmt.Sprintf(`NotOnOrAfter="%s">`, now.Add(5*time.Minute).Format(time.RFC3339)),
			fmt.Sprintf(`NotOnOrAfter="%s">`, condExpired.Format(time.RFC3339)),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// Test 13: SCD missing NotOnOrAfter entirely should error.
func TestSecurityConditions_SCDMissingNotOnOrAfter(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(` NotOnOrAfter="%s" Recipient`, now.Add(5*time.Minute).Format(time.RFC3339)),
			` Recipient`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

// Test 14: SCD NotBefore in the future (beyond clock skew) should error.
func TestSecurityConditions_SCDNotBeforeFuture(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	skew := sp.clockSkew()

	futureNotBefore := now.Add(skew + 5*time.Second)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2:SubjectConfirmationData InResponseTo="_request_id_1"`,
			fmt.Sprintf(`<saml2:SubjectConfirmationData NotBefore="%s" InResponseTo="_request_id_1"`, futureNotBefore.Format(time.RFC3339)),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrNotYetValid)
}

// ============================================================================
// Tests 15-21: Audience Restriction
// ============================================================================

// Test 15: Empty AudienceRestriction element (with zero Audience children) should fail.
func TestSecurityConditions_EmptyAudienceRestriction(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2:AudienceRestriction><saml2:Audience>https://sp.example.com</saml2:Audience></saml2:AudienceRestriction>`,
			`<saml2:AudienceRestriction></saml2:AudienceRestriction>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch)
}

// Test 16: No AudienceRestriction elements at all. An assertion with no
// AudienceRestriction is not scoped to any SP, so with AudienceURIs configured
// it must be rejected rather than treated as "nothing to check" -- otherwise an
// assertion the IdP never bound to this SP satisfies the audience policy. This
// also keeps it consistent with Test 15, which rejects an empty
// <AudienceRestriction/>.
func TestSecurityConditions_NoAudienceRestrictionRejected(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2:AudienceRestriction><saml2:Audience>https://sp.example.com</saml2:Audience></saml2:AudienceRestriction>`,
			``,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch)
}

// Test 17: SP has empty AudienceURIs slice - should skip audience validation.
func TestSecurityConditions_EmptyAudienceURIsSkipsValidation(t *testing.T) {
	sp := setupSPWithTracker(t)

	// Build the response first (before clearing AudienceURIs, since buildCustomResponse uses it)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2:Audience>https://sp.example.com</saml2:Audience>`,
			`<saml2:Audience>https://wrong.example.com</saml2:Audience>`,
			1)
		return s
	})

	// Now clear AudienceURIs - audience validation should be skipped
	sp.AudienceURIs = []string{}

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "Empty AudienceURIs should skip audience validation entirely")
}

// Test 18: Multiple AudienceRestriction elements - AND semantics.
// Each AudienceRestriction must have at least one matching Audience.
func TestSecurityConditions_MultipleAudienceRestrictionsANDSemantics(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	// Two AudienceRestrictions: first matches, second does not => should fail (AND)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2:AudienceRestriction><saml2:Audience>https://sp.example.com</saml2:Audience></saml2:AudienceRestriction>`,
			fmt.Sprintf(`<saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
      <saml2:AudienceRestriction><saml2:Audience>https://other-sp.example.com</saml2:Audience></saml2:AudienceRestriction>`,
				sp.AudienceURIs[0]),
			1)
		_ = now
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch,
		"Multiple AudienceRestriction elements use AND semantics; second has no match")
}

// Test 19: Single AudienceRestriction with both legitimate and attacker audience - OR semantics.
func TestSecurityConditions_SingleRestrictionMultipleAudiencesOR(t *testing.T) {
	sp := setupSPWithTracker(t)

	// One AudienceRestriction with two Audiences: one matches => should pass (OR within restriction)
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2:AudienceRestriction><saml2:Audience>https://sp.example.com</saml2:Audience></saml2:AudienceRestriction>`,
			fmt.Sprintf(`<saml2:AudienceRestriction><saml2:Audience>https://attacker.example.com</saml2:Audience><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>`,
				sp.AudienceURIs[0]),
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "Single AudienceRestriction with multiple Audience values uses OR semantics")
}

// Test 20: Audience URI with trailing slash mismatch.
func TestSecurityConditions_AudienceTrailingSlashMismatch(t *testing.T) {
	sp := setupSPWithTracker(t)
	// SP has "https://sp.example.com" (no trailing slash)
	// Assertion has "https://sp.example.com/" (with trailing slash)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2:Audience>https://sp.example.com</saml2:Audience>`,
			`<saml2:Audience>https://sp.example.com/</saml2:Audience>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch,
		"Audience comparison is exact; trailing slash should cause mismatch")
}

// Test 21: Audience URI case sensitivity.
func TestSecurityConditions_AudienceCaseSensitivity(t *testing.T) {
	sp := setupSPWithTracker(t)
	// SP has "https://sp.example.com", assertion has "https://SP.Example.Com"

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2:Audience>https://sp.example.com</saml2:Audience>`,
			`<saml2:Audience>https://SP.Example.Com</saml2:Audience>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch,
		"Audience comparison is case-sensitive")
}

// ============================================================================
// Tests 22-25: Subject Confirmation
// ============================================================================

// Test 22: SubjectConfirmation Method not bearer (holder-of-key).
func TestSecurityConditions_SubjectConfirmationNotBearer(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"`,
			`Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMalformed)
}

// Test 23: SubjectConfirmation Method empty string.
func TestSecurityConditions_SubjectConfirmationEmptyMethod(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"`,
			`Method=""`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMalformed)
}

// Test 24: InResponseTo mismatch between Response and SubjectConfirmationData.
func TestSecurityConditions_InResponseToMismatchResponseVsSCD(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		// Change SCD InResponseTo but keep Response InResponseTo
		s = strings.Replace(s,
			`<saml2:SubjectConfirmationData InResponseTo="_request_id_1"`,
			`<saml2:SubjectConfirmationData InResponseTo="_different_id"`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 24b: Request-correlated responses require bearer SubjectConfirmationData.InResponseTo.
func TestSecurityConditions_MissingSCDInResponseToRejected(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		return strings.Replace(s,
			`<saml2:SubjectConfirmationData InResponseTo="_request_id_1"`,
			`<saml2:SubjectConfirmationData`,
			1)
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 24c: The unsigned-response/signed-assertion path must not let an
// attacker bind an old assertion to a fresh Response.InResponseTo wrapper.
func TestSecurityConditions_SignedAssertionMissingSCDInResponseToRejected(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		return strings.Replace(s,
			`<saml2:SubjectConfirmationData InResponseTo="_request_id_1"`,
			`<saml2:SubjectConfirmationData`,
			1)
	})

	encoded := signAssertionAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)

	// The invalid response should not consume the pending request ID.
	err = sp.RequestTracker.ConsumeRequest(context.Background(), "_request_id_1")
	require.NoError(t, err)
}

// Test 25: InResponseTo present in SCD but empty in Response (IDP-initiated with SCD InResponseTo).
func TestSecurityConditions_InResponseToPresentInSCDButEmptyInResponse(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	sp.AllowIDPInitiated = true
	sp.AssertionReplayCache = NewMemoryAssertionReplayCache()
	now := sp.now()

	// Response has no InResponseTo, but SCD has one
	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_1">
      <saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0], now.Format(time.RFC3339))

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// ============================================================================
// Tests 26-27: InResponseTo / Replay
// ============================================================================

// Test 26: Empty InResponseTo with AllowIDPInitiated=false and RequestTracker should fail.
func TestSecurityConditions_EmptyInResponseToDisallowed(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	sp.AllowIDPInitiated = false
	now := sp.now()

	// Response with no InResponseTo
	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_1">
      <saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0], now.Format(time.RFC3339))

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// Test 27: Same InResponseTo used twice (replay).
func TestSecurityConditions_ReplayWithSameInResponseTo(t *testing.T) {
	sp := setupSPWithTracker(t)
	ctx := context.Background()

	responseXML := buildCustomResponse(sp)
	encoded := signAndEncode(t, responseXML, sp)

	// First use should succeed
	_, err := sp.RetrieveAssertionInfo(ctx, encoded)
	require.NoError(t, err)

	// Store another request ID and create a new response with same InResponseTo
	// Actually the ID was already consumed. Re-sign and try again.
	encoded2 := signAndEncode(t, responseXML, sp)
	_, err = sp.RetrieveAssertionInfo(ctx, encoded2)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay, "Same InResponseTo used twice should be replay")
}

// ============================================================================
// Tests 28-31: Destination / Recipient
// ============================================================================

// Test 28: Recipient mismatch in SCD.
func TestSecurityConditions_RecipientMismatch(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`Recipient="%s"`, sp.ACSURL),
			`Recipient="https://attacker.example.com/acs"`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadRecipient)
}

// Test 29: Recipient with extra path component.
func TestSecurityConditions_RecipientExtraPath(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`Recipient="%s"`, sp.ACSURL),
			`Recipient="https://sp.example.com/acs/extra"`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadRecipient)
}

// Test 30: Empty destination in Response (allowed - optional per spec).
func TestSecurityConditions_EmptyDestination(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`Destination="%s"`, sp.ACSURL),
			`Destination=""`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.NoError(t, err, "Empty Destination should be allowed")
}

// Test 31: Destination mismatch.
func TestSecurityConditions_DestinationMismatch(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			fmt.Sprintf(`Destination="%s"`, sp.ACSURL),
			`Destination="https://attacker.example.com/acs"`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadDestination)
}

// ============================================================================
// Tests 32-34: Issuer
// ============================================================================

// Test 32: Response Issuer mismatch.
func TestSecurityConditions_ResponseIssuerMismatch(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		// Replace the first Issuer (Response-level)
		s = strings.Replace(s,
			fmt.Sprintf(`<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>`, sp.IDPEntityID),
			`<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://evil-idp.example.com</saml2:Issuer>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadIssuer)
}

// Test 33: Response Issuer matches but Assertion Issuer differs.
func TestSecurityConditions_AssertionIssuerMismatch(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		// Replace the assertion-level Issuer (the one without xmlns declaration)
		s = strings.Replace(s,
			fmt.Sprintf(`<saml2:Issuer>%s</saml2:Issuer>`, sp.IDPEntityID),
			`<saml2:Issuer>https://evil-idp.example.com</saml2:Issuer>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadIssuer)
}

// Test 34: Empty IDPEntityID skips issuer validation.
func TestSecurityConditions_EmptyIDPEntityIDSkipsIssuerValidation(t *testing.T) {
	sp := setupSPWithTracker(t)
	sp.IDPEntityID = ""

	// Use a completely different issuer
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.ReplaceAll(s,
			`http://www.okta.com/exk5zt0r12Edi4rD20h7`,
			`https://any-idp.example.com`)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.NoError(t, err, "Empty IDPEntityID should skip issuer validation")
}

// ============================================================================
// Tests 35-37: Status
// ============================================================================

// Test 35: StatusCode not Success (Responder).
func TestSecurityConditions_StatusCodeResponder(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`Value="urn:oasis:names:tc:SAML:2.0:status:Success"`,
			`Value="urn:oasis:names:tc:SAML:2.0:status:Responder"`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadStatus)
}

// Test 36: Missing Status element entirely.
func TestSecurityConditions_MissingStatus(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>`,
			``,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

// Test 37: Missing StatusCode element.
func TestSecurityConditions_MissingStatusCode(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>`,
			`<saml2p:Status></saml2p:Status>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

// ============================================================================
// Tests 38-41: Version / Multiple Assertions
// ============================================================================

// Test 38: Assertion Version not "2.0".
func TestSecurityConditions_AssertionBadVersion(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		// Replace assertion version (the one in the Assertion tag, not the Response)
		s = strings.Replace(s,
			`ID="_a1" Version="2.0"`,
			`ID="_a1" Version="1.1"`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadVersion)
}

// Test 39: Multiple assertions with different subjects.
func TestSecurityConditions_MultipleAssertionsDifferentSubjects(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	// Build a response with two assertions with different subjects
	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_1">
      <saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a2" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">bob@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_2">
      <saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		// Assertion 1
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0], now.Format(time.RFC3339),
		// Assertion 2
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0], now.Format(time.RFC3339))

	// Sign the response envelope (both assertions will be covered).
	encoded := signAndEncode(t, responseXML, sp)

	// ValidateEncodedResponse validates BOTH assertions and returns them.
	resp, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.NoError(t, err, "both validly-conditioned assertions should pass ValidateEncodedResponse")
	require.Len(t, resp.Assertions, 2, "both assertions should be present and validated")

	// RetrieveAssertionInfo extracts a single subject and must refuse an
	// ambiguous multi-assertion response rather than silently using the first.
	sp = setupSPWithTracker(t)
	encoded = signAndEncode(t, responseXML, sp)
	_, err = sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrMultipleAssertions,
		"RetrieveAssertionInfo must reject responses carrying multiple assertions")
}

// Test 40: Assertion without Subject element.
func TestSecurityConditions_AssertionWithoutSubject(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0])

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

// Test 41: Subject without NameID.
func TestSecurityConditions_SubjectWithoutNameID(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()

	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_request_id_1" NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_1">
      <saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext>
    </saml2:AuthnStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0], now.Format(time.RFC3339))

	encoded := signAndEncode(t, responseXML, sp)
	// ValidateEncodedResponse should succeed (no NameID check there)
	// but RetrieveAssertionInfo should fail
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

// ============================================================================
// Tests 42-46: NameID / Attribute Injection
// ============================================================================

// Test 42: NameID with XML special characters.
func TestSecurityConditions_NameIDWithSpecialCharacters(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`>user@example.com</saml2:NameID>`,
			`>&lt;script&gt;&amp;alert(1)&lt;/script&gt;</saml2:NameID>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "NameID with XML special characters should be accepted after XML entity decoding")
	require.Equal(t, `<script>&alert(1)</script>`, info.NameID,
		"NameID should contain the decoded XML entities")
}

// Test 43: NameID with null bytes. XML parsers reject null bytes, which is a
// security property preventing null-byte injection attacks.
func TestSecurityConditions_NameIDWithNullBytes(t *testing.T) {
	sp := setupSPWithTracker(t)

	// Build a valid response and embed a null byte entity reference directly
	// into the XML. The XML parser should reject this at parse time.
	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`>user@example.com</saml2:NameID>`,
			`>user&#x0;@example.com</saml2:NameID>`,
			1)
		return s
	})

	// Null byte entity in XML is illegal per the XML spec. The parser should
	// reject it, so we skip signing (which also parses XML) and submit the
	// raw XML directly to validate that the SP rejects it at the parsing layer.
	encoded := encodeResponse(responseXML)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err, "Null bytes in XML should be rejected by the parser")
}

// Test 44: Duplicate attribute names in AttributeStatement.
func TestSecurityConditions_DuplicateAttributeNames(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`<saml2:Attribute Name="Email"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user@example.com</saml2:AttributeValue></saml2:Attribute>`,
			`<saml2:Attribute Name="Email"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user@example.com</saml2:AttributeValue></saml2:Attribute>
      <saml2:Attribute Name="Email"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">admin@example.com</saml2:AttributeValue></saml2:Attribute>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "Duplicate attribute names should not cause an error")

	// The second attribute with the same name should overwrite the first in the Values map
	emailVal := info.Values.Get("Email")
	require.NotEmpty(t, emailVal, "Email attribute should be present")
	// Last writer wins in the map
	require.Equal(t, "admin@example.com", emailVal,
		"Duplicate attribute names: last value wins in the map")
}

// Test 45: Extra attributes via additional AttributeStatement.
func TestSecurityConditions_ExtraAttributeStatement(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`</saml2:AttributeStatement>`,
			`</saml2:AttributeStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="Role"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">admin</saml2:AttributeValue></saml2:Attribute>
    </saml2:AttributeStatement>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "Extra AttributeStatement should not cause an error")
	require.Equal(t, "admin", info.Values.Get("Role"),
		"Attributes from additional AttributeStatements should be available")
	require.Equal(t, "user@example.com", info.Values.Get("Email"),
		"Original attributes should still be present")
}

// Test 46: AttributeValue with xsi:type=xs:boolean.
func TestSecurityConditions_AttributeValueBooleanType(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`</saml2:AttributeStatement>`,
			`<saml2:Attribute Name="IsAdmin"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:boolean">true</saml2:AttributeValue></saml2:Attribute>
    </saml2:AttributeStatement>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "Boolean attribute should be accepted")
	require.Equal(t, "true", info.Values.Get("IsAdmin"),
		"Boolean attribute value should be returned as string")
}

// ============================================================================
// Tests 47-50: OneTimeUse / ProxyRestriction / ID
// ============================================================================

// Test 47: OneTimeUse condition present (informational, no enforcement).
func TestSecurityConditions_OneTimeUsePresent(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`</saml2:AudienceRestriction>`,
			`</saml2:AudienceRestriction>
      <saml2:OneTimeUse/>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "OneTimeUse should be accepted without enforcement error")
	require.True(t, info.OneTimeUse, "OneTimeUse flag should be set in AssertionInfo")
}

// Test 48: ProxyRestriction Count="0" (not enforced but recorded).
func TestSecurityConditions_ProxyRestrictionZero(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s,
			`</saml2:AudienceRestriction>`,
			`</saml2:AudienceRestriction>
      <saml2:ProxyRestriction Count="0"/>`,
			1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err, "ProxyRestriction with Count=0 should not be rejected")
	require.NotNil(t, info.ProxyRestriction, "ProxyRestriction should be recorded")
	require.Equal(t, 0, info.ProxyRestriction.Count, "ProxyRestriction count should be 0")
}

// Test 49: Same Assertion ID across different responses (no assertion ID dedup).
func TestSecurityConditions_SameAssertionIDDifferentResponses(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()

	// First response
	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_request_id_1"))
	responseXML1 := buildCustomResponse(sp)
	encoded1 := signAndEncode(t, responseXML1, sp)
	_, err := sp.RetrieveAssertionInfo(ctx, encoded1)
	require.NoError(t, err)

	// Second response with a different Response ID and InResponseTo but same Assertion ID (_a1)
	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_request_id_2"))
	responseXML2 := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s, `ID="_resp_1"`, `ID="_resp_2"`, 1)
		s = strings.ReplaceAll(s, `InResponseTo="_request_id_1"`, `InResponseTo="_request_id_2"`)
		// Keep the same Assertion ID="_a1"
		return s
	})
	encoded2 := signAndEncode(t, responseXML2, sp)
	_, err = sp.RetrieveAssertionInfo(ctx, encoded2)
	require.NoError(t, err, "Same assertion ID across different responses should not be rejected (no assertion-level dedup)")
}

// Test 50: Empty or duplicate Response ID (not validated at the SP level).
func TestSecurityConditions_EmptyResponseID(t *testing.T) {
	sp := setupSPWithTracker(t)

	responseXML := buildCustomResponse(sp, func(s string) string {
		s = strings.Replace(s, `ID="_resp_1"`, `ID=""`, 1)
		return s
	})

	encoded := signAndEncode(t, responseXML, sp)
	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	// The SP does not validate Response ID - it only uses InResponseTo
	require.NoError(t, err, "Empty Response ID should not be rejected by the SP (not validated)")
}
