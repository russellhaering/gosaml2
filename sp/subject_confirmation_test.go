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

// bearerConfirmation builds a valid bearer SubjectConfirmation for the SP.
func bearerConfirmation(sp *ServiceProvider) types.SubjectConfirmation {
	notOnOrAfter := sp.now().Add(5 * time.Minute).Format(time.RFC3339)
	return types.SubjectConfirmation{
		Method: SubjMethodBearer,
		SubjectConfirmationData: &types.SubjectConfirmationData{
			Recipient:    sp.ACSURL,
			NotOnOrAfter: notOnOrAfter,
		},
	}
}

// validResponseWithConfirmations builds a fully valid decoded Response whose
// single assertion carries the given SubjectConfirmations.
func validResponseWithConfirmations(sp *ServiceProvider, confs ...types.SubjectConfirmation) *types.Response {
	now := sp.now()
	return &types.Response{
		Version: "2.0",
		Status:  &types.Status{StatusCode: &types.StatusCode{Value: saml2.StatusCodeSuccess}},
		Issuer:  &types.Issuer{Value: sp.IDPEntityID},
		Assertions: []types.Assertion{{
			Version: "2.0",
			Issuer:  &types.Issuer{Value: sp.IDPEntityID},
			Subject: &types.Subject{
				NameID:               &types.NameID{Value: "user@example.com"},
				SubjectConfirmations: confs,
			},
			Conditions: &types.Conditions{
				NotBefore:    now.Add(-5 * time.Minute).Format(time.RFC3339),
				NotOnOrAfter: now.Add(5 * time.Minute).Format(time.RFC3339),
				AudienceRestrictions: []types.AudienceRestriction{{
					Audiences: []types.Audience{{Value: sp.AudienceURIs[0]}},
				}},
			},
		}},
	}
}

// A subject with multiple SubjectConfirmations is confirmed if at least one
// is a valid bearer confirmation, even when others use unsupported methods or
// are invalid.
func TestSubjectConfirmation_MultipleAcceptsAnyValid(t *testing.T) {
	sp, _ := securityTestSP(t)

	holderOfKey := types.SubjectConfirmation{
		Method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
		SubjectConfirmationData: &types.SubjectConfirmationData{
			Recipient:    sp.ACSURL,
			NotOnOrAfter: sp.now().Add(5 * time.Minute).Format(time.RFC3339),
		},
	}

	// Unsupported method first, valid bearer second → accepted.
	resp := validResponseWithConfirmations(sp, holderOfKey, bearerConfirmation(sp))
	require.NoError(t, sp.Validate(resp),
		"assertion must be confirmed by the valid bearer confirmation despite the unsupported one")

	// Order independence: valid bearer first.
	resp = validResponseWithConfirmations(sp, bearerConfirmation(sp), holderOfKey)
	require.NoError(t, sp.Validate(resp))
}

// If no SubjectConfirmation is a valid bearer confirmation, the assertion is
// rejected — multiple non-bearer confirmations don't get accepted.
func TestSubjectConfirmation_NoneValidRejected(t *testing.T) {
	sp, _ := securityTestSP(t)

	holderOfKey := types.SubjectConfirmation{
		Method:                  "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
		SubjectConfirmationData: &types.SubjectConfirmationData{Recipient: sp.ACSURL},
	}
	senderVouches := types.SubjectConfirmation{
		Method:                  "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches",
		SubjectConfirmationData: &types.SubjectConfirmationData{Recipient: sp.ACSURL},
	}

	resp := validResponseWithConfirmations(sp, holderOfKey, senderVouches)
	err := sp.Validate(resp)
	require.Error(t, err, "an assertion with no acceptable bearer confirmation must be rejected")
}

// A bearer confirmation whose Recipient does not match the SP is rejected,
// even when presented alongside other confirmations.
func TestSubjectConfirmation_WrongRecipientRejected(t *testing.T) {
	sp, _ := securityTestSP(t)

	wrongRecipient := types.SubjectConfirmation{
		Method: SubjMethodBearer,
		SubjectConfirmationData: &types.SubjectConfirmationData{
			Recipient:    "https://attacker.example.com/acs",
			NotOnOrAfter: sp.now().Add(5 * time.Minute).Format(time.RFC3339),
		},
	}
	resp := validResponseWithConfirmations(sp, wrongRecipient)
	err := sp.Validate(resp)
	require.ErrorIs(t, err, saml2.ErrBadRecipient)
}

// The single-confirmation case still surfaces the specific failure reason
// (the loop reports the first failure verbatim).
func TestSubjectConfirmation_SingleExpiredReportsExpiry(t *testing.T) {
	sp, _ := securityTestSP(t)

	expired := types.SubjectConfirmation{
		Method: SubjMethodBearer,
		SubjectConfirmationData: &types.SubjectConfirmationData{
			Recipient:    sp.ACSURL,
			NotOnOrAfter: sp.now().Add(-1 * time.Hour).Format(time.RFC3339),
		},
	}
	resp := validResponseWithConfirmations(sp, expired)
	require.ErrorIs(t, sp.Validate(resp), saml2.ErrExpired)
}

// A missing SubjectConfirmation is still a missing-element error.
func TestSubjectConfirmation_NoneAtAllRejected(t *testing.T) {
	sp, _ := securityTestSP(t)
	resp := validResponseWithConfirmations(sp) // empty slice
	require.ErrorIs(t, sp.Validate(resp), saml2.ErrMissingElement)
}
