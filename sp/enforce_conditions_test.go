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

// This suite exhaustively exercises the consolidated Conditions/Audience
// enforcement that now runs inside Validate (reached by ValidateEncodedResponse)
// for EVERY assertion, plus the multi-assertion policy of RetrieveAssertionInfo.
//
// Prior to the fix these checks lived only in verifyAssertionConditions, which
// was reachable solely via RetrieveAssertionInfo and only for Assertions[0].

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// replaceConditionsAudience swaps the single <Audience> value emitted by
// buildCustomResponse.
func replaceAudience(sp *ServiceProvider, newAudience string) func(string) string {
	return func(s string) string {
		return strings.Replace(s,
			"<saml2:Audience>"+sp.AudienceURIs[0]+"</saml2:Audience>",
			"<saml2:Audience>"+newAudience+"</saml2:Audience>",
			1)
	}
}

// rewriteConditionsAttr rewrites an attribute value inside the <saml2:Conditions>
// tag only, leaving the (mirrored) SubjectConfirmationData attribute untouched.
func rewriteConditionsTag(old, new string) func(string) string {
	return func(s string) string {
		idx := strings.Index(s, "<saml2:Conditions")
		if idx < 0 {
			return s
		}
		head, tail := s[:idx], s[idx:]
		return head + strings.Replace(tail, old, new, 1)
	}
}

func rfc3339(t time.Time) string { return t.Format("2006-01-02T15:04:05Z07:00") }

// appendSecondAssertion injects a second, envelope-covered assertion before the
// closing Response tag. The caller supplies the Conditions window and audience
// so individual assertions can be made invalid.
func appendSecondAssertion(sp *ServiceProvider, notBefore, notOnOrAfter, audience string) func(string) string {
	now := sp.now()
	return func(s string) string {
		second := fmt.Sprintf(`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a2" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">second@example.com</saml2:NameID>
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
			rfc3339(now), sp.IDPEntityID,
			rfc3339(now.Add(5*time.Minute)), sp.ACSURL,
			notBefore, notOnOrAfter, audience,
			rfc3339(now))
		return strings.Replace(s, "</saml2p:Response>", second, 1)
	}
}

// ---------------------------------------------------------------------------
// #1: Audience enforcement via ValidateEncodedResponse
// ---------------------------------------------------------------------------

func TestEnforce_Audience_RejectedByValidateEncodedResponse_SignedResponse(t *testing.T) {
	sp := setupSPWithTracker(t)
	encoded := signAndEncode(t, buildCustomResponse(sp, replaceAudience(sp, "https://attacker.example.com")), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch)
}

func TestEnforce_Audience_RejectedByValidateEncodedResponse_SignedAssertion(t *testing.T) {
	sp := setupSPWithTracker(t)
	encoded := signAssertionAndEncode(t, buildCustomResponse(sp, replaceAudience(sp, "https://attacker.example.com")), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch)
}

func TestEnforce_Audience_AcceptedWhenMatchesAnyConfiguredURI(t *testing.T) {
	sp := setupSPWithTracker(t)
	// SP trusts several audiences; assertion names the second one.
	sp.AudienceURIs = []string{"https://other.example.com", "https://sp.example.com"}
	encoded := signAndEncode(t, buildCustomResponse(sp, replaceAudience(sp, "https://sp.example.com")), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.NoError(t, err)
}

// An unset AudienceURIs is a missing control, not a policy of "nothing to
// check": the zero value used to disable audience validation silently, with no
// error and no opt-in, while the documented default claimed enforcement.
func TestEnforce_Audience_RejectedWhenNoAudienceURIsConfigured(t *testing.T) {
	sp := setupSPWithTracker(t)
	encoded := signAndEncode(t, buildCustomResponse(sp, replaceAudience(sp, "https://anything.example.com")), sp)
	sp.AudienceURIs = nil

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch)
}

// The escape hatch is explicit and named, for deployments relying on
// SubjectConfirmationData.Recipient alone.
func TestEnforce_Audience_SkippedOnlyWithExplicitOptIn(t *testing.T) {
	sp := setupSPWithTracker(t)
	encoded := signAndEncode(t, buildCustomResponse(sp, replaceAudience(sp, "https://anything.example.com")), sp)
	sp.AudienceURIs = nil
	sp.InsecureSkipAudienceValidation = true

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.NoError(t, err)
}

// Multiple <AudienceRestriction> elements use AND semantics: each must contain
// a configured URI. The second restriction here names only a foreign audience.
func TestEnforce_Audience_MultipleRestrictions_AllMustMatch(t *testing.T) {
	sp := setupSPWithTracker(t)
	addForeignRestriction := func(s string) string {
		return strings.Replace(s,
			"</saml2:AudienceRestriction>",
			"</saml2:AudienceRestriction><saml2:AudienceRestriction><saml2:Audience>https://foreign.example.com</saml2:Audience></saml2:AudienceRestriction>",
			1)
	}
	encoded := signAndEncode(t, buildCustomResponse(sp, addForeignRestriction), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch)
}

// ---------------------------------------------------------------------------
// #1: Conditions time-window enforcement via ValidateEncodedResponse
// ---------------------------------------------------------------------------

func TestEnforce_Conditions_ExpiredNotOnOrAfter_Rejected(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	past := rfc3339(now.Add(-5 * time.Minute))
	future := rfc3339(now.Add(5 * time.Minute))
	encoded := signAndEncode(t, buildCustomResponse(sp, rewriteConditionsTag(future, past)), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

func TestEnforce_Conditions_FutureNotBefore_Rejected(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	// buildCustomResponse sets Conditions NotBefore to now-5m; push it to now+5m.
	pastNB := rfc3339(now.Add(-5 * time.Minute))
	futureNB := rfc3339(now.Add(5 * time.Minute))
	encoded := signAndEncode(t, buildCustomResponse(sp, rewriteConditionsTag(pastNB, futureNB)), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrNotYetValid)
}

func TestEnforce_Conditions_MissingNotOnOrAfter_Rejected(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	future := rfc3339(now.Add(5 * time.Minute))
	dropNOA := func(s string) string {
		return rewriteConditionsTag(` NotOnOrAfter="`+future+`"`, "")(s)
	}
	encoded := signAndEncode(t, buildCustomResponse(sp, dropNOA), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

func TestEnforce_Conditions_Malformed_Rejected(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	future := rfc3339(now.Add(5 * time.Minute))
	encoded := signAndEncode(t, buildCustomResponse(sp, rewriteConditionsTag(future, "not-a-timestamp")), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrMalformed)
}

// Conditions must be enforced even when signature validation is skipped, since
// Validate runs in that path too.
func TestEnforce_Conditions_EnforcedUnderInsecureSkipSignature(t *testing.T) {
	sp := setupSPWithTracker(t)
	sp.InsecureSkipSignatureValidation = true
	now := sp.now()
	past := rfc3339(now.Add(-5 * time.Minute))
	future := rfc3339(now.Add(5 * time.Minute))
	// No signature needed; just encode.
	encoded := encodeResponse(buildCustomResponse(sp, rewriteConditionsTag(future, past)))

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// ---------------------------------------------------------------------------
// #1: "every assertion" — a bad SECOND assertion must fail the whole response
// ---------------------------------------------------------------------------

func TestEnforce_SecondAssertionExpired_RejectsWholeResponse(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	// First assertion is valid (from buildCustomResponse); second is expired
	// well beyond the 60s clock skew.
	opt := appendSecondAssertion(sp,
		rfc3339(now.Add(-10*time.Minute)),
		rfc3339(now.Add(-5*time.Minute)), // expired by 5m > skew
		sp.AudienceURIs[0])
	encoded := signAndEncode(t, buildCustomResponse(sp, opt), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrExpired,
		"an expired second assertion must reject the whole response")
}

func TestEnforce_SecondAssertionWrongAudience_RejectsWholeResponse(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	opt := appendSecondAssertion(sp,
		rfc3339(now.Add(-5*time.Minute)),
		rfc3339(now.Add(5*time.Minute)),
		"https://attacker.example.com") // wrong audience
	encoded := signAndEncode(t, buildCustomResponse(sp, opt), sp)

	_, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch,
		"a wrong-audience second assertion must reject the whole response")
}

func TestEnforce_BothAssertionsValid_Accepted(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	opt := appendSecondAssertion(sp,
		rfc3339(now.Add(-5*time.Minute)),
		rfc3339(now.Add(5*time.Minute)),
		sp.AudienceURIs[0])
	encoded := signAndEncode(t, buildCustomResponse(sp, opt), sp)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encoded)
	require.NoError(t, err)
	require.Len(t, resp.Assertions, 2)
}

// ---------------------------------------------------------------------------
// #2: multi-assertion policy in RetrieveAssertionInfo
// ---------------------------------------------------------------------------

func TestEnforce_RetrieveAssertionInfo_RejectsMultipleAssertions(t *testing.T) {
	sp := setupSPWithTracker(t)
	now := sp.now()
	opt := appendSecondAssertion(sp,
		rfc3339(now.Add(-5*time.Minute)),
		rfc3339(now.Add(5*time.Minute)),
		sp.AudienceURIs[0])
	encoded := signAndEncode(t, buildCustomResponse(sp, opt), sp)

	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrMultipleAssertions)
}

func TestEnforce_RetrieveAssertionInfo_AcceptsSingleAssertion(t *testing.T) {
	sp := setupSPWithTracker(t)
	encoded := signAndEncode(t, buildCustomResponse(sp), sp)

	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err)
	require.Equal(t, "user@example.com", info.NameID)
}
