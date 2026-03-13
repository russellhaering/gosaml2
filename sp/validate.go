// Copyright 2016 Russell Haering et al.
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
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/types"
)

// Well-known methods of subject confirmation
const (
	SubjMethodBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

// verifyAssertionConditions inspects an assertion's Conditions element and
// enforces all SAML2 constraints.
func (sp *ServiceProvider) verifyAssertionConditions(assertion *types.Assertion, info *AssertionInfo) error {
	now := sp.now()
	skew := sp.clockSkew()

	conditions := assertion.Conditions
	if conditions == nil {
		return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "Conditions"}
	}

	if conditions.NotBefore != "" {
		notBefore, err := time.Parse(time.RFC3339, conditions.NotBefore)
		if err != nil {
			return &saml2.ValidationError{Reason: saml2.ErrMalformed, Detail: fmt.Sprintf("cannot parse NotBefore %q as time", conditions.NotBefore)}
		}

		if now.Add(skew).Before(notBefore) {
			return &saml2.ValidationError{
				Reason: saml2.ErrNotYetValid,
				Detail: fmt.Sprintf("NotBefore %s, now %s", conditions.NotBefore, now.Format(time.RFC3339)),
			}
		}
	}

	if conditions.NotOnOrAfter == "" {
		return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "NotOnOrAfter attribute on Conditions"}
	}

	notOnOrAfter, err := time.Parse(time.RFC3339, conditions.NotOnOrAfter)
	if err != nil {
		return &saml2.ValidationError{Reason: saml2.ErrMalformed, Detail: fmt.Sprintf("cannot parse NotOnOrAfter %q as time", conditions.NotOnOrAfter)}
	}

	if now.Add(-skew).After(notOnOrAfter) {
		return &saml2.ValidationError{
			Reason: saml2.ErrExpired,
			Detail: fmt.Sprintf("Conditions.NotOnOrAfter %s, now %s", conditions.NotOnOrAfter, now.Format(time.RFC3339)),
		}
	}

	if len(sp.AudienceURIs) > 0 {
		for _, audienceRestriction := range conditions.AudienceRestrictions {
			matched := false

			for _, audience := range audienceRestriction.Audiences {
				for _, uri := range sp.AudienceURIs {
					if audience.Value == uri {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}

			if !matched {
				return &saml2.ValidationError{Reason: saml2.ErrAudienceMismatch}
			}
		}
	}

	if conditions.OneTimeUse != nil {
		info.OneTimeUse = true
	}

	proxyRestriction := conditions.ProxyRestriction
	if proxyRestriction != nil {
		proxyRestrictionInfo := &ProxyRestriction{
			Count:    proxyRestriction.Count,
			Audience: []string{},
		}

		for _, audience := range proxyRestriction.Audience {
			proxyRestrictionInfo.Audience = append(proxyRestrictionInfo.Audience, audience.Value)
		}

		info.ProxyRestriction = proxyRestrictionInfo
	}

	return nil
}

// Validate ensures that the assertion passed is valid for the current Service
// Provider.
func (sp *ServiceProvider) Validate(response *types.Response) error {
	err := sp.validateResponseAttributes(response)
	if err != nil {
		return err
	}

	if len(response.Assertions) == 0 {
		return &saml2.ValidationError{Reason: saml2.ErrMissingAssertion}
	}

	issuer := response.Issuer
	if issuer == nil {
		return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "Issuer"}
	}

	if sp.IDPEntityID != "" && response.Issuer.Value != sp.IDPEntityID {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadIssuer,
			Detail: fmt.Sprintf("expected %s, got %s", sp.IDPEntityID, response.Issuer.Value),
		}
	}

	status := response.Status
	if status == nil {
		return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "Status"}
	}

	statusCode := status.StatusCode
	if statusCode == nil {
		return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "StatusCode"}
	}

	if statusCode.Value != saml2.StatusCodeSuccess {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadStatus,
			Detail: fmt.Sprintf("expected %s, got %s", saml2.StatusCodeSuccess, statusCode.Value),
		}
	}

	skew := sp.clockSkew()
	now := sp.now()

	for _, assertion := range response.Assertions {
		if assertion.Version != "2.0" {
			return &saml2.ValidationError{
				Reason: saml2.ErrBadVersion,
				Detail: fmt.Sprintf("expected assertion version 2.0, got %s", assertion.Version),
			}
		}

		issuer = assertion.Issuer
		if issuer == nil {
			return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "Issuer"}
		}
		if sp.IDPEntityID != "" && assertion.Issuer.Value != sp.IDPEntityID {
			return &saml2.ValidationError{
				Reason: saml2.ErrBadIssuer,
				Detail: fmt.Sprintf("expected %s, got %s", sp.IDPEntityID, issuer.Value),
			}
		}

		subject := assertion.Subject
		if subject == nil {
			return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "Subject"}
		}

		subjectConfirmation := subject.SubjectConfirmation
		if subjectConfirmation == nil {
			return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "SubjectConfirmation"}
		}

		if subjectConfirmation.Method != SubjMethodBearer {
			return &saml2.ValidationError{
				Reason: saml2.ErrMalformed,
				Detail: fmt.Sprintf("unsupported SubjectConfirmation method %s", subjectConfirmation.Method),
			}
		}

		subjectConfirmationData := subjectConfirmation.SubjectConfirmationData
		if subjectConfirmationData == nil {
			return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "SubjectConfirmationData"}
		}

		if subjectConfirmationData.Recipient != sp.ACSURL {
			return &saml2.ValidationError{
				Reason: saml2.ErrBadRecipient,
				Detail: fmt.Sprintf("expected %s, got %s", sp.ACSURL, subjectConfirmationData.Recipient),
			}
		}

		if subjectConfirmationData.NotBefore != "" {
			notBefore, err := time.Parse(time.RFC3339, subjectConfirmationData.NotBefore)
			if err != nil {
				return &saml2.ValidationError{
					Reason: saml2.ErrMalformed,
					Detail: fmt.Sprintf("cannot parse SubjectConfirmationData.NotBefore %q as time", subjectConfirmationData.NotBefore),
				}
			}
			if now.Add(skew).Before(notBefore) {
				return &saml2.ValidationError{
					Reason: saml2.ErrNotYetValid,
					Detail: fmt.Sprintf("SubjectConfirmationData.NotBefore %s, now %s", subjectConfirmationData.NotBefore, now.Format(time.RFC3339)),
				}
			}
		}

		if subjectConfirmationData.NotOnOrAfter == "" {
			return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "NotOnOrAfter attribute on SubjectConfirmationData"}
		}

		notOnOrAfter, err := time.Parse(time.RFC3339, subjectConfirmationData.NotOnOrAfter)
		if err != nil {
			return &saml2.ValidationError{
				Reason: saml2.ErrMalformed,
				Detail: fmt.Sprintf("cannot parse SubjectConfirmationData.NotOnOrAfter %q as time", subjectConfirmationData.NotOnOrAfter),
			}
		}

		if now.Add(-skew).After(notOnOrAfter) {
			return &saml2.ValidationError{
				Reason: saml2.ErrExpired,
				Detail: fmt.Sprintf("NotOnOrAfter %s, now %s", subjectConfirmationData.NotOnOrAfter, now.Format(time.RFC3339)),
			}
		}

	}

	return nil
}

func (sp *ServiceProvider) ValidateDecodedLogoutResponse(response *types.LogoutResponse) error {
	err := sp.validateLogoutResponseAttributes(response)
	if err != nil {
		return err
	}

	issuer := response.Issuer
	if issuer == nil {
		return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "Issuer"}
	}

	if sp.IDPEntityID != "" && response.Issuer.Value != sp.IDPEntityID {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadIssuer,
			Detail: fmt.Sprintf("expected %s, got %s", sp.IDPEntityID, response.Issuer.Value),
		}
	}

	status := response.Status
	if status == nil {
		return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "Status"}
	}

	statusCode := status.StatusCode
	if statusCode == nil {
		return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "StatusCode"}
	}

	if statusCode.Value != saml2.StatusCodeSuccess {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadStatus,
			Detail: fmt.Sprintf("expected %s, got %s", saml2.StatusCodeSuccess, statusCode.Value),
		}
	}

	return nil
}

func (sp *ServiceProvider) ValidateDecodedLogoutRequest(request *saml2.LogoutRequest) error {
	err := sp.validateLogoutRequestAttributes(request)
	if err != nil {
		return err
	}

	issuer := request.Issuer
	if issuer == nil {
		return &saml2.ValidationError{Reason: saml2.ErrMissingElement, Detail: "Issuer"}
	}

	if sp.IDPEntityID != "" && request.Issuer.Value != sp.IDPEntityID {
		return &saml2.ValidationError{
			Reason: saml2.ErrBadIssuer,
			Detail: fmt.Sprintf("expected %s, got %s", sp.IDPEntityID, request.Issuer.Value),
		}
	}

	if request.NotOnOrAfter != "" {
		notOnOrAfter, err := time.Parse(time.RFC3339, request.NotOnOrAfter)
		if err != nil {
			return &saml2.ValidationError{
				Reason: saml2.ErrMalformed,
				Detail: fmt.Sprintf("cannot parse LogoutRequest.NotOnOrAfter %q as time", request.NotOnOrAfter),
			}
		}
		skew := sp.clockSkew()
		now := sp.now()
		if now.Add(-skew).After(notOnOrAfter) {
			return &saml2.ValidationError{
				Reason: saml2.ErrExpired,
				Detail: fmt.Sprintf("LogoutRequest.NotOnOrAfter %s, now %s", request.NotOnOrAfter, now.Format(time.RFC3339)),
			}
		}
	}

	return nil
}

// validateInResponseTo checks the InResponseTo attribute against the
// configured RequestTracker.
func (sp *ServiceProvider) validateInResponseTo(ctx context.Context, response *types.Response) error {
	if sp.RequestTracker == nil {
		return nil
	}

	inResponseTo := response.InResponseTo

	if inResponseTo == "" {
		if sp.AllowIDPInitiated {
			return nil
		}
		return &saml2.ValidationError{
			Reason: saml2.ErrReplay,
			Detail: "missing InResponseTo and IdP-initiated SSO is not allowed",
		}
	}

	if err := sp.RequestTracker.ConsumeRequest(ctx, inResponseTo); err != nil {
		return err
	}

	for _, assertion := range response.Assertions {
		if assertion.Subject == nil || assertion.Subject.SubjectConfirmation == nil {
			continue
		}
		scd := assertion.Subject.SubjectConfirmation.SubjectConfirmationData
		if scd == nil {
			continue
		}
		if scd.InResponseTo != "" && scd.InResponseTo != inResponseTo {
			return &saml2.ValidationError{
				Reason: saml2.ErrReplay,
				Detail: fmt.Sprintf("SubjectConfirmationData.InResponseTo %s does not match Response.InResponseTo %s", scd.InResponseTo, inResponseTo),
			}
		}
	}

	return nil
}
