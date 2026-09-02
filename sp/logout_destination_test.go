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
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
)

// destinationAttr renders a Destination attribute, or nothing at all when the
// IdP omits it -- the case that used to skip the check entirely.
func destinationAttr(destination string) string {
	if destination == "" {
		return ""
	}
	return fmt.Sprintf(` Destination="%s"`, destination)
}

func postLogoutResponseXML(t *testing.T, sp *ServiceProvider, destination string) string {
	t.Helper()
	return fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr1" Version="2.0" IssueInstant="%s"%s InResponseTo="_logout_req_1"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status></samlp:LogoutResponse>`,
		sp.now().Format(time.RFC3339), destinationAttr(destination), sp.IDPEntityID, saml2.StatusCodeSuccess)
}

func postLogoutRequestXML(t *testing.T, sp *ServiceProvider, destination string) string {
	t.Helper()
	return fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lq1" Version="2.0" IssueInstant="%s"%s><saml:Issuer>%s</saml:Issuer><saml:NameID>user@example.com</saml:NameID></samlp:LogoutRequest>`,
		sp.now().Format(time.RFC3339), destinationAttr(destination), sp.IDPEntityID)
}

// TestLogoutDestinationRequiredOnPOSTBinding covers the POST half of the
// Destination check, so the binding cannot be switched to avoid it. A signed
// message that names no endpoint is not bound to this SP at all, which is what
// let a message the IdP signed for a sibling SP be forwarded here.
func TestLogoutDestinationRequiredOnPOSTBinding(t *testing.T) {
	ctx := context.Background()

	t.Run("LogoutResponse", func(t *testing.T) {
		sp, _ := securityTestSP(t)
		encoded := encodeResponse(signResponse(t, postLogoutResponseXML(t, sp, ""), sp))

		_, err := sp.ValidateEncodedLogoutResponsePOST(ctx, encoded)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no Destination attribute")

		sp.InsecureAllowMissingLogoutDestination = true
		_, err = sp.ValidateEncodedLogoutResponsePOST(ctx, encoded)
		require.NoError(t, err)
	})

	t.Run("LogoutRequest", func(t *testing.T) {
		sp, _ := securityTestSP(t)
		encoded := encodeResponse(signResponse(t, postLogoutRequestXML(t, sp, ""), sp))

		_, err := sp.ValidateEncodedLogoutRequestPOST(ctx, encoded)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no Destination attribute")

		sp.InsecureAllowMissingLogoutDestination = true
		_, err = sp.ValidateEncodedLogoutRequestPOST(ctx, encoded)
		require.NoError(t, err)
	})
}

// TestLogoutDestinationMatchingStillAccepted pins the normal case: an IdP that
// sends the attribute, naming this SP's SLO endpoint, is unaffected.
func TestLogoutDestinationMatchingStillAccepted(t *testing.T) {
	ctx := context.Background()
	sp, _ := securityTestSP(t)

	encoded := encodeResponse(signResponse(t, postLogoutRequestXML(t, sp, sp.SLOURL), sp))
	_, err := sp.ValidateEncodedLogoutRequestPOST(ctx, encoded)
	require.NoError(t, err)

	encoded = encodeResponse(signResponse(t, postLogoutResponseXML(t, sp, sp.SLOURL), sp))
	_, err = sp.ValidateEncodedLogoutResponsePOST(ctx, encoded)
	require.NoError(t, err)
}

// TestLogoutDestinationUnsignedUnaffected documents the gate: the requirement
// exists to stop a signed message being forwarded to an endpoint it was not
// signed for. With signature validation disabled there is no signature to
// forward, so the caller's own trust decision governs.
func TestLogoutDestinationUnsignedUnaffected(t *testing.T) {
	ctx := context.Background()
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	encoded := encodeResponse(postLogoutRequestXML(t, sp, ""))
	_, err := sp.ValidateEncodedLogoutRequestPOST(ctx, encoded)
	require.NoError(t, err)
}
