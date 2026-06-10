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

package providertests

import (
	"fmt"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/v2/sp"
)

var oktaScenarioErrors = map[int]string{
	1:  "error validating response: dsig: missing signature referencing the top-level element",
	3:  "error validating response: dsig: signing certificate not in trusted set",
	4:  "error validating response: saml: destination mismatch: expected http://dba9a5fc.ngrok.io/v1/_saml_callback, got fake.identifier.example.com",
	5:  "error validating response: saml: issuer mismatch: expected http://example.com/saml/acs/example, got fake.identifier.example.com",
	6:  "error validating response: saml: audience mismatch",
	7:  "error validating response: saml: missing required element: Issuer",
	8:  "error validating response: saml: missing required element: NotOnOrAfter attribute on SubjectConfirmationData",
	9:  "error validating response: saml: missing required element: NotOnOrAfter attribute on Conditions",
	10: "error validating response: saml: missing required element: NotOnOrAfter attribute on Conditions",
	11: "error validating response: saml: assertion expired: Conditions.NotOnOrAfter 2004-07-25T22:18:00.000Z, now 2017-04-04T17:54:00Z",
	12: "error validating response: dsig: missing signature referencing the top-level element",
	13: "error validating response: dsig: computed digest does not match signed digest value",
	14: "error validating response: saml: response status not success: expected urn:oasis:names:tc:SAML:2.0:status:Success, got Failure",
	15: "error validating response: saml: response status not success: expected urn:oasis:names:tc:SAML:2.0:status:Success, got urn:oasis:names:tc:SAML:2.0:status:Requester",
}

func TestOktaDevCasesLocally(t *testing.T) {
	serviceProv := &sp.ServiceProvider{
		IDPSSOURL:        "http://example.com/saml/acs/example",
		IDPEntityID:      "http://example.com/saml/acs/example",
		ACSURL:           "http://dba9a5fc.ngrok.io/v1/_saml_callback",
		AudienceURIs:     []string{"http://example.com/saml/acs/example"},
		IDPCertificates:  LoadCertificates("./testdata/saml.oktadev.com/oktadev.pem"),
		AllowSHA1:        true,
		Clock:            fakeClock(time.Date(2017, 4, 4, 17, 54, 0, 0, time.UTC)),
	}

	scenarios := []ProviderTestScenario{}

	for i := 0; i < 17; i++ {
		response := LoadRawResponse(fmt.Sprintf("./testdata/saml.oktadev.com/response_%d", i))
		scenarios = append(scenarios, ProviderTestScenario{
			ScenarioName:    fmt.Sprintf("Scenario_%d", i),
			Response:        response,
			ServiceProvider: serviceProv,
			CheckError:      scenarioErrorChecker(i, oktaScenarioErrors),
		})
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
