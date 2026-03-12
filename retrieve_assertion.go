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

package saml2

import (
	"context"
	"fmt"
)

// RetrieveAssertionInfo takes an encoded response and returns the AssertionInfo
// contained, or an error message if an error has been encountered.
func (sp *ServiceProvider) RetrieveAssertionInfo(ctx context.Context, encodedResponse string) (*AssertionInfo, error) {
	assertionInfo := &AssertionInfo{
		Values: make(Values),
	}

	response, err := sp.ValidateEncodedResponse(ctx, encodedResponse)
	if err != nil {
		return nil, fmt.Errorf("error validating response: %w", err)
	}

	// TODO: Support multiple assertions
	if len(response.Assertions) == 0 {
		return nil, &ValidationError{Reason: ErrMissingAssertion}
	}

	assertion := response.Assertions[0]
	assertionInfo.Assertions = response.Assertions
	assertionInfo.ResponseSignatureValidated = response.SignatureValidated

	err = sp.verifyAssertionConditions(&assertion, assertionInfo)
	if err != nil {
		return nil, err
	}

	//Get the NameID
	subject := assertion.Subject
	if subject == nil {
		return nil, &ValidationError{Reason: ErrMissingElement, Detail: "Subject"}
	}

	nameID := subject.NameID
	if nameID == nil {
		return nil, &ValidationError{Reason: ErrMissingElement, Detail: "NameID"}
	}

	assertionInfo.NameID = nameID.Value
	assertionInfo.NameIDFormat = nameID.Format

	//Get the actual assertion attributes
	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attribute := range attributeStatement.Attributes {
			assertionInfo.Values[attribute.Name] = attribute
		}
	}

	if assertion.AuthnStatement != nil {
		if assertion.AuthnStatement.AuthnInstant != nil {
			assertionInfo.AuthnInstant = assertion.AuthnStatement.AuthnInstant
		}
		if assertion.AuthnStatement.SessionNotOnOrAfter != nil {
			assertionInfo.SessionNotOnOrAfter = assertion.AuthnStatement.SessionNotOnOrAfter
		}

		assertionInfo.SessionIndex = assertion.AuthnStatement.SessionIndex
	}

	return assertionInfo, nil
}
