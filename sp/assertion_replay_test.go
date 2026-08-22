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
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
)

// unsolicitedResponse strips both the envelope InResponseTo and the signed
// SubjectConfirmationData.InResponseTo, as an IdP-initiated response has.
func unsolicitedResponse(t *testing.T, sp *ServiceProvider) string {
	t.Helper()
	resp := makeValidResponse(sp)
	resp = strings.Replace(resp, `InResponseTo="_request_id_1"
            NotOnOrAfter=`, `NotOnOrAfter=`, 1)
	resp = strings.Replace(resp, `InResponseTo="_request_id_1"`, "", 1)
	require.False(t, strings.Contains(resp, "InResponseTo"), "should have no InResponseTo left")
	return resp
}

// withAssertionID rewrites the assertion ID so a test can present a second,
// distinct assertion.
func withAssertionID(resp, id string) string {
	return strings.Replace(resp, `ID="_assertion_id_1"`, `ID="`+id+`"`, 1)
}

// --- IdP-initiated replay --------------------------------------------------

// TestIDPInitiatedRequiresReplayCache is the regression test for unsolicited
// responses having nothing consumed. A RequestTracker only bounds solicited
// flows by consuming the request ID a response answers; an unsolicited response
// answers none, so without an assertion cache a captured response mints a fresh
// session on every submission until its validity window closes.
func TestIDPInitiatedRequiresReplayCache(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.AllowIDPInitiated = true
	sp.AssertionReplayCache = nil

	encoded := signAssertionAndEncode(t, unsolicitedResponse(t, sp), sp)

	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
	require.Contains(t, err.Error(), "AssertionReplayCache")
}

// TestIDPInitiatedAcceptedOnceWithCache is the positive case plus the actual
// replay rejection.
func TestIDPInitiatedAcceptedOnceWithCache(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.AllowIDPInitiated = true
	cache := NewMemoryAssertionReplayCache()
	cache.Clock = sp.Clock
	sp.AssertionReplayCache = cache

	encoded := signAssertionAndEncode(t, unsolicitedResponse(t, sp), sp)

	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err)
	require.Equal(t, "user@example.com", info.NameID)

	// The same captured bytes, presented again.
	_, err = sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// TestReplayCacheAllowsDistinctAssertions confirms the cache keys on assertion
// identity and does not reject unrelated logins.
func TestReplayCacheAllowsDistinctAssertions(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.AllowIDPInitiated = true
	cache := NewMemoryAssertionReplayCache()
	cache.Clock = sp.Clock
	sp.AssertionReplayCache = cache

	base := unsolicitedResponse(t, sp)
	for _, id := range []string{"_a1", "_a2", "_a3"} {
		_, err := sp.RetrieveAssertionInfo(context.Background(),
			signAssertionAndEncode(t, withAssertionID(base, id), sp))
		require.NoError(t, err, "assertion %s should be accepted", id)
	}
	// ...but each only once.
	_, err := sp.RetrieveAssertionInfo(context.Background(),
		signAssertionAndEncode(t, withAssertionID(base, "_a2"), sp))
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// TestInsecureAllowIDPInitiatedReplayOptOut documents the escape hatch: replay
// is permitted only when explicitly accepted.
func TestInsecureAllowIDPInitiatedReplayOptOut(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.AllowIDPInitiated = true
	sp.InsecureAllowIDPInitiatedReplay = true

	encoded := signAssertionAndEncode(t, unsolicitedResponse(t, sp), sp)
	for i := 0; i < 3; i++ {
		_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
		require.NoError(t, err, "replay %d should be permitted by the opt-out", i)
	}
}

// TestSolicitedResponseAlsoConsumed confirms the cache is not limited to the
// unsolicited path.
func TestSolicitedResponseAlsoConsumed(t *testing.T) {
	sp := setupSPWithTracker(t)
	cache := NewMemoryAssertionReplayCache()
	cache.Clock = sp.Clock
	sp.AssertionReplayCache = cache

	encoded := signAssertionAndEncode(t, makeValidResponse(sp), sp)

	_, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err)

	_, err = sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// --- OneTimeUse ------------------------------------------------------------

// oneTimeUseResponse adds a saml:OneTimeUse condition to the assertion.
func oneTimeUseResponse(t *testing.T, sp *ServiceProvider, base string) string {
	t.Helper()
	out := strings.Replace(base, `<saml2:AudienceRestriction>`,
		`<saml2:OneTimeUse/><saml2:AudienceRestriction>`, 1)
	require.True(t, strings.Contains(out, "OneTimeUse"), "failed to inject OneTimeUse")
	return out
}

// TestOneTimeUseRejectedWhenNothingBoundsReuse is the regression test for the
// OneTimeUse condition being extracted as advisory and never enforced.
func TestOneTimeUseRejectedWhenNothingBoundsReuse(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = nil
	sp.AssertionReplayCache = nil

	resp := oneTimeUseResponse(t, sp, makeValidResponse(sp))

	_, err := sp.RetrieveAssertionInfo(context.Background(), signAssertionAndEncode(t, resp, sp))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
	require.Contains(t, err.Error(), "OneTimeUse")
}

// TestOneTimeUseHonouredWithCache accepts it once and rejects the repeat.
func TestOneTimeUseHonouredWithCache(t *testing.T) {
	sp, _ := securityTestSP(t)
	cache := NewMemoryAssertionReplayCache()
	cache.Clock = sp.Clock
	sp.AssertionReplayCache = cache

	encoded := signAssertionAndEncode(t, oneTimeUseResponse(t, sp, makeValidResponse(sp)), sp)

	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err)
	require.True(t, info.OneTimeUse)

	_, err = sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// TestOneTimeUseAcceptedWhenRequestTrackerBoundsReuse confirms the check does
// not fire when a solicited flow already guarantees single use, so it is not a
// false positive for the common deployment.
func TestOneTimeUseAcceptedWhenRequestTrackerBoundsReuse(t *testing.T) {
	sp := setupSPWithTracker(t)
	sp.AssertionReplayCache = nil

	encoded := signAssertionAndEncode(t, oneTimeUseResponse(t, sp, makeValidResponse(sp)), sp)

	info, err := sp.RetrieveAssertionInfo(context.Background(), encoded)
	require.NoError(t, err)
	require.True(t, info.OneTimeUse)
}

// --- InResponseTo correlation without a tracker ----------------------------

// TestFabricatedInResponseToRejectedWithoutTracker is the regression test for
// AllowIDPInitiated=false being satisfiable by inventing an envelope
// InResponseTo. The cross-check against the signed
// SubjectConfirmationData needs no RequestTracker, but used to be gated on one.
func TestFabricatedInResponseToRejectedWithoutTracker(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.AllowIDPInitiated = false
	sp.RequestTracker = nil

	// An unsolicited assertion, presented with an envelope InResponseTo the SP
	// never issued.
	resp := unsolicitedResponse(t, sp)
	resp = strings.Replace(resp, `ID="_response_id_1"`,
		`ID="_response_id_1" InResponseTo="_never-issued-by-this-sp"`, 1)

	_, err := sp.RetrieveAssertionInfo(context.Background(), signAssertionAndEncode(t, resp, sp))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// TestMismatchedInResponseToRejectedWithoutTracker covers the other direction:
// a signed assertion bound to one request presented as the answer to another.
func TestMismatchedInResponseToRejectedWithoutTracker(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.RequestTracker = nil

	resp := strings.Replace(makeValidResponse(sp),
		`ID="_response_id_1"
    InResponseTo="_request_id_1"`,
		`ID="_response_id_1"
    InResponseTo="_a-totally-different-request"`, 1)
	require.True(t, strings.Contains(resp, "_a-totally-different-request"))

	_, err := sp.RetrieveAssertionInfo(context.Background(), signAssertionAndEncode(t, resp, sp))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// TestUnsolicitedConfirmationStillRejected keeps the converse: a response
// claiming to be unsolicited whose assertion names a request.
func TestUnsolicitedConfirmationStillRejected(t *testing.T) {
	sp, _ := securityTestSP(t)
	sp.AllowIDPInitiated = true
	cache := NewMemoryAssertionReplayCache()
	cache.Clock = sp.Clock
	sp.AssertionReplayCache = cache

	// Envelope InResponseTo removed, but the signed confirmation still names one.
	resp := strings.Replace(makeValidResponse(sp), `InResponseTo="_request_id_1"`, "", 1)

	_, err := sp.RetrieveAssertionInfo(context.Background(), signAssertionAndEncode(t, resp, sp))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// --- cache behavior --------------------------------------------------------

// TestMemoryAssertionReplayCacheExpiry confirms entries are forgotten once the
// assertion could no longer be valid, so the cache does not grow without bound.
func TestMemoryAssertionReplayCacheExpiry(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := NewMemoryAssertionReplayCache()
	cache.Clock = func() time.Time { return now }

	ctx := context.Background()
	require.NoError(t, cache.ConsumeAssertion(ctx, "_a", now.Add(time.Minute)))
	require.Error(t, cache.ConsumeAssertion(ctx, "_a", now.Add(time.Minute)))

	// Past the assertion's validity window the entry is swept, and the
	// assertion's own Conditions are what reject it thereafter.
	now = now.Add(2 * time.Minute)
	require.NoError(t, cache.ConsumeAssertion(ctx, "_a", now.Add(time.Minute)))
	require.Equal(t, 1, len(cache.entries))
}

// TestMemoryAssertionReplayCacheConcurrent exercises the lock under parallel use.
func TestMemoryAssertionReplayCacheConcurrent(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := NewMemoryAssertionReplayCache()
	cache.Clock = func() time.Time { return now }

	const workers = 16
	ctx := context.Background()
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() { results <- cache.ConsumeAssertion(ctx, "_contended", now.Add(time.Minute)) }()
	}

	accepted := 0
	for i := 0; i < workers; i++ {
		if err := <-results; err == nil {
			accepted++
		}
	}
	require.Equal(t, 1, accepted, "exactly one concurrent consumer should win")
}
