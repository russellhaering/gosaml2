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

	"github.com/russellhaering/gosaml2/v2"
)

var pingFedScenarioErrors = map[int]string{
	01: "",
	02: "",
	03: "",
	05: "",
}

var pingFedAtTimes = map[int]string{}

func TestPingFedCasesLocally(t *testing.T) {
	sp := &saml2.ServiceProvider{
		IDPSSOURL:              "https://saml.test.nope:9031/eid/sxpmrhbkzn",
		IDPEntityID:            "https://saml.test.nope:9031/eid/sxpmrhbkzn",
		ACSURL:                 "https://saml.test.nope/session/sso/saml/acs/hp24dqnpvq",
		AudienceURIs:           []string{"https://saml.test.nope/session/sso/saml/spentityid/hp24dqnpvq"},
		IDPCertificates:        LoadCertificates("./testdata/pingfed/idp.signing.cert"),
		SPKeyStore:             LoadKeyStore("./testdata/pingfed/sp.encryption.cert", "./testdata/pingfed/sp.encryption.key"),
		SPSigningKeyStore:      LoadKeyStore("./testdata/pingfed/sp.signing.cert", "./testdata/pingfed/sp.signing.key"),
		ValidateEncryptionCert: true,
	}

	scenarios := []ProviderTestScenario{}
	for _, idx := range scenarioIndexes(pingFedScenarioErrors) {
		response := LoadRawResponse(fmt.Sprintf("./testdata/pingfed/pfed11_response_%02d.b64", idx))
		scenarios = append(scenarios, ProviderTestScenario{
			ScenarioName:    fmt.Sprintf("Scenario_%02d", idx),
			Response:        response,
			ServiceProvider: spAtTime(sp, getAtTime(idx, pingFedAtTimes), response),
			CheckError:      scenarioErrorChecker(idx, pingFedScenarioErrors),
		})
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
