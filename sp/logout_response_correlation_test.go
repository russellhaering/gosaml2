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
	"crypto"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
)

// correlationSP returns a redirect-capable SP with a RequestTracker whose clock
// matches the SP's, plus the key to sign redirect parameters with.
func correlationSP(t *testing.T) (*ServiceProvider, *rsa.PrivateKey) {
	t.Helper()
	sp, key := redirectTestSP(t)
	tracker := NewMemoryRequestTracker(5 * time.Minute)
	tracker.Clock = sp.Clock
	sp.RequestTracker = tracker
	return sp, key
}

// logoutResponseWithInResponseTo builds a signed-parameter redirect
// LogoutResponse naming the given request ID.
func logoutResponseWithInResponseTo(t *testing.T, sp *ServiceProvider, key *rsa.PrivateKey, inResponseTo string) (string, string, string) {
	t.Helper()
	xmlMsg := makeLogoutResponseXML(sp.IDPEntityID, sp.SLOURL, saml2.StatusCodeSuccess)
	if inResponseTo == "" {
		xmlMsg = strings.Replace(xmlMsg, ` InResponseTo="_req1"`, "", 1)
		require.False(t, strings.Contains(xmlMsg, "InResponseTo"))
	} else {
		xmlMsg = strings.Replace(xmlMsg, `InResponseTo="_req1"`,
			fmt.Sprintf(`InResponseTo="%s"`, inResponseTo), 1)
	}
	encoded := deflateAndEncode(t, xmlMsg)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")
	return encoded, sigAlg, sig
}

// TestLogoutResponseConsumedOnce is the regression test for a LogoutResponse
// being accepted on the strength of its signature alone. A captured response
// could complete a pending logout flow repeatedly; the request ID it names is
// now consumed, mirroring the login path.
func TestLogoutResponseConsumedOnce(t *testing.T) {
	sp, key := correlationSP(t)
	ctx := context.Background()

	// The application records the request it sent, exactly as for an AuthnRequest.
	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_logout_req_1"))

	encoded, sigAlg, sig := logoutResponseWithInResponseTo(t, sp, key, "_logout_req_1")

	resp, err := sp.ValidateEncodedLogoutResponseRedirect(ctx, encoded, "", sigAlg, sig)
	require.NoError(t, err)
	require.Equal(t, "_logout_req_1", resp.InResponseTo)

	// Replaying the identical signed message must not complete the flow again.
	_, err = sp.ValidateEncodedLogoutResponseRedirect(ctx, encoded, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// TestLogoutResponseUnknownRequestRejected covers a response naming a request
// this SP never sent.
func TestLogoutResponseUnknownRequestRejected(t *testing.T) {
	sp, key := correlationSP(t)
	ctx := context.Background()

	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_logout_req_1"))

	encoded, sigAlg, sig := logoutResponseWithInResponseTo(t, sp, key, "_never_sent")

	_, err := sp.ValidateEncodedLogoutResponseRedirect(ctx, encoded, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// TestLogoutResponseMissingInResponseToRejected: a LogoutResponse always answers
// a LogoutRequest, so one that names none cannot be correlated.
func TestLogoutResponseMissingInResponseToRejected(t *testing.T) {
	sp, key := correlationSP(t)
	ctx := context.Background()

	encoded, sigAlg, sig := logoutResponseWithInResponseTo(t, sp, key, "")

	_, err := sp.ValidateEncodedLogoutResponseRedirect(ctx, encoded, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}

// TestLogoutResponseWithoutTrackerUnchanged pins the posture for deployments
// with no RequestTracker: correlation is impossible without one, exactly as on
// the login path, so behavior is unchanged rather than failing closed.
func TestLogoutResponseWithoutTrackerUnchanged(t *testing.T) {
	sp, key := redirectTestSP(t)
	require.Nil(t, sp.RequestTracker)
	ctx := context.Background()

	encoded, sigAlg, sig := logoutResponseWithInResponseTo(t, sp, key, "_whatever")

	_, err := sp.ValidateEncodedLogoutResponseRedirect(ctx, encoded, "", sigAlg, sig)
	require.NoError(t, err)
}

// TestLogoutResponseCorrelationOnPOSTBinding confirms the POST entry point
// enforces the same correlation, so the binding cannot be switched to avoid it.
func TestLogoutResponseCorrelationOnPOSTBinding(t *testing.T) {
	sp, _ := securityTestSP(t)
	tracker := NewMemoryRequestTracker(5 * time.Minute)
	tracker.Clock = sp.Clock
	sp.RequestTracker = tracker
	ctx := context.Background()

	require.NoError(t, sp.RequestTracker.StoreRequest(ctx, "_logout_req_1"))

	xmlMsg := fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr1" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="_logout_req_1"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status></samlp:LogoutResponse>`,
		sp.now().Format(time.RFC3339), sp.SLOURL, sp.IDPEntityID, saml2.StatusCodeSuccess)

	encoded := encodeResponse(signResponse(t, xmlMsg, sp))

	resp, err := sp.ValidateEncodedLogoutResponsePOST(ctx, encoded)
	require.NoError(t, err)
	require.Equal(t, "_logout_req_1", resp.InResponseTo)

	_, err = sp.ValidateEncodedLogoutResponsePOST(ctx, encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrReplay)
}
