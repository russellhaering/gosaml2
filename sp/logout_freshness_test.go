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
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	"github.com/russellhaering/gosaml2/v2/types"
)

// logoutFreshnessSP returns an SP with a fixed clock for age arithmetic.
func logoutFreshnessSP(t *testing.T) (*ServiceProvider, time.Time) {
	t.Helper()
	sp, _ := securityTestSP(t)
	return sp, sp.now()
}

func decodedLogoutRequest(issuer string, issueInstant time.Time, destination string) *saml2.LogoutRequest {
	return &saml2.LogoutRequest{
		ID:           "_lo1",
		Version:      "2.0",
		IssueInstant: issueInstant,
		Destination:  destination,
		Issuer:       &types.Issuer{Value: issuer},
	}
}

func decodedLogoutResponse(issuer string, issueInstant time.Time, destination string) *types.LogoutResponse {
	return &types.LogoutResponse{
		ID:           "_lr1",
		Version:      "2.0",
		IssueInstant: issueInstant,
		Destination:  destination,
		InResponseTo: "_lo1",
		Issuer:       &types.Issuer{Value: issuer},
		Status:       &types.Status{StatusCode: &types.StatusCode{Value: saml2.StatusCodeSuccess}},
	}
}

// TestLogoutRequestStaleIssueInstantRejected is the regression test for logout
// messages having no upper bound on age. NotOnOrAfter is optional, so when the
// peer omits it a captured signed request previously verified forever -- and the
// redirect binding puts the whole signed message in a URL, which persists in
// browser history and access logs.
func TestLogoutRequestStaleIssueInstantRejected(t *testing.T) {
	sp, now := logoutFreshnessSP(t)

	req := decodedLogoutRequest(sp.IDPEntityID, now.Add(-24*time.Hour), sp.SLOURL)
	require.Equal(t, "", req.NotOnOrAfter) // no expiry supplied: age is the only bound

	err := sp.ValidateDecodedLogoutRequest(req)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// TestLogoutRequestFreshIssueInstantAccepted confirms the bound is a window and
// not a blanket rejection.
func TestLogoutRequestFreshIssueInstantAccepted(t *testing.T) {
	sp, now := logoutFreshnessSP(t)
	require.NoError(t, sp.ValidateDecodedLogoutRequest(
		decodedLogoutRequest(sp.IDPEntityID, now, sp.SLOURL)))
}

// TestLogoutRequestFutureIssueInstantRejected covers the other direction.
func TestLogoutRequestFutureIssueInstantRejected(t *testing.T) {
	sp, now := logoutFreshnessSP(t)
	err := sp.ValidateDecodedLogoutRequest(
		decodedLogoutRequest(sp.IDPEntityID, now.Add(time.Hour), sp.SLOURL))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrNotYetValid)
}

// TestLogoutRequestMissingIssueInstantRejected: IssueInstant is required on
// every SAML protocol message, and treating an absent one as the zero time would
// make an unbounded message look infinitely old.
func TestLogoutRequestMissingIssueInstantRejected(t *testing.T) {
	sp, _ := logoutFreshnessSP(t)
	req := decodedLogoutRequest(sp.IDPEntityID, time.Time{}, sp.SLOURL)
	err := sp.ValidateDecodedLogoutRequest(req)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

// TestLogoutRequestAgeBoundaryHonoursSkew checks the window edges, including
// clock skew, so the bound is not off by the skew allowance.
func TestLogoutRequestAgeBoundaryHonoursSkew(t *testing.T) {
	sp, now := logoutFreshnessSP(t)
	sp.MaxIssueInstantAge = 5 * time.Minute
	sp.ClockSkew = time.Minute

	// Just inside the window (age < max + skew).
	require.NoError(t, sp.ValidateDecodedLogoutRequest(
		decodedLogoutRequest(sp.IDPEntityID, now.Add(-(5*time.Minute+30*time.Second)), sp.SLOURL)))

	// Just outside it.
	err := sp.ValidateDecodedLogoutRequest(
		decodedLogoutRequest(sp.IDPEntityID, now.Add(-(6*time.Minute + 30*time.Second)), sp.SLOURL))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// TestLogoutRequestConfigurableMaxAge confirms the window is tunable.
func TestLogoutRequestConfigurableMaxAge(t *testing.T) {
	sp, now := logoutFreshnessSP(t)
	sp.ClockSkew = time.Second
	req := decodedLogoutRequest(sp.IDPEntityID, now.Add(-time.Hour), sp.SLOURL)

	sp.MaxIssueInstantAge = 5 * time.Minute
	require.ErrorIs(t, sp.ValidateDecodedLogoutRequest(req), saml2.ErrExpired)

	sp.MaxIssueInstantAge = 24 * time.Hour
	require.NoError(t, sp.ValidateDecodedLogoutRequest(req))
}

// TestLogoutRequestNotOnOrAfterStillEnforced keeps the pre-existing expiry check
// working alongside the new age bound.
func TestLogoutRequestNotOnOrAfterStillEnforced(t *testing.T) {
	sp, now := logoutFreshnessSP(t)
	req := decodedLogoutRequest(sp.IDPEntityID, now, sp.SLOURL)
	req.NotOnOrAfter = now.Add(-time.Hour).Format(time.RFC3339)

	err := sp.ValidateDecodedLogoutRequest(req)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// TestLogoutResponseStaleIssueInstantRejected: an old signed success response
// could otherwise be replayed to complete a pending logout flow.
func TestLogoutResponseStaleIssueInstantRejected(t *testing.T) {
	sp, now := logoutFreshnessSP(t)
	err := sp.ValidateDecodedLogoutResponse(
		decodedLogoutResponse(sp.IDPEntityID, now.Add(-24*time.Hour), sp.SLOURL))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// TestLogoutResponseFreshAccepted is the positive case.
func TestLogoutResponseFreshAccepted(t *testing.T) {
	sp, now := logoutFreshnessSP(t)
	require.NoError(t, sp.ValidateDecodedLogoutResponse(
		decodedLogoutResponse(sp.IDPEntityID, now, sp.SLOURL)))
}

// TestLogoutResponseMissingIssueInstantRejected mirrors the request side.
func TestLogoutResponseMissingIssueInstantRejected(t *testing.T) {
	sp, _ := logoutFreshnessSP(t)
	err := sp.ValidateDecodedLogoutResponse(
		decodedLogoutResponse(sp.IDPEntityID, time.Time{}, sp.SLOURL))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}
