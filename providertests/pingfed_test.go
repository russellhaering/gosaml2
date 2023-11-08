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

	"github.com/russellhaering/gosaml2"
)

var pingFedScenarioErrors = map[int]string{
	// 01 - signed(Response(Assertion)) - no KeyInfo (no IDP signing certificate included)
	// By default, PingFed does not include the KeyInfo element (which would include the
	// IDP signing certificate) in Response.  Most other IDPs include KeyInfo element.
	// gosaml2 is ok with this as long as the SP has only one IDP signing certificate
	// for this relationship (it does not have to guess at to which cert to use).
	// Note: Response.Destination is set.
	01: "",
	// 02 - signed(Response(Assertion)) - with KeyInfo (including IDP signing certificate)
	// Same as pfed11_response_01 except KeyInfo is included.
	// Note: Response.Destination is set.
	02: "",
	// 03 - Response(signed(Assertion))
	// As with 01, KeyInfo element is not included (not a bug).  Unlike 01,
	// Response.Destination is NOT set.  Most IDPs (including PingOne) always includes Response.Destination.
	// PingFed only includes Response.Destination when the Response is signed.
	// SAML Core 2.0 defines Response.Destination as [Optional].
	// Thus, PingFed is not in not including Destination.  Before a fix, gosaml2 required
	// Response.Destination.  gosaml2 now only checks the value of Response.Destination if it
	// is set (mandated by SAML Core 2.0).
	03: "",
	// 05 - signed(Response(encrypted(Assertion))) - no encryption certificate included in Assertion.
	// PingFed and ADFS do not include the SP encryption certificate and do not provide an option to include it in Response.
	// OneLogin (see olgn09/olgn09_response_05.b64) also does not include SP encryption certificate by default.
	// OneLogin and PingFed also do not include DigestMethod (default to http://www.w3.org/2000/09/xmldsig#sha1).
	05: "",
}

var pingFedScenarioWarnings = map[int]scenarioWarnings{}

var pingFedAtTimes = map[int]string{}

func TestPingFedCasesLocally(t *testing.T) {
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      "https://saml.test.nope:9031/eid/sxpmrhbkzn", // not required for these tests
		IdentityProviderIssuer:      "https://saml.test.nope:9031/eid/sxpmrhbkzn",
		AssertionConsumerServiceURL: "https://saml.test.nope/session/sso/saml/acs/hp24dqnpvq",
		AudienceURI:                 "https://saml.test.nope/session/sso/saml/spentityid/hp24dqnpvq",
		IDPCertificateStore:         LoadCertificateStore("./testdata/pingfed/idp.signing.cert"),
		SPKeyStore:                  LoadKeyStore("./testdata/pingfed/sp.encryption.cert", "./testdata/pingfed/sp.encryption.key"),
		SPSigningKeyStore:           LoadKeyStore("./testdata/pingfed/sp.signing.cert", "./testdata/pingfed/sp.signing.key"),
		ValidateEncryptionCert:      true,
	}

	scenarios := []ProviderTestScenario{}
	for _, idx := range scenarioIndexes(pingFedScenarioErrors, pingFedScenarioWarnings) {
		response := LoadRawResponse(fmt.Sprintf("./testdata/pingfed/pfed11_response_%02d.b64", idx))
		scenarios = append(scenarios, ProviderTestScenario{
			ScenarioName:     fmt.Sprintf("Scenario_%02d", idx),
			Response:         response,
			ServiceProvider:  spAtTime(sp, getAtTime(idx, pingFedAtTimes), response),
			CheckError:       scenarioErrorChecker(idx, pingFedScenarioErrors),
			CheckWarningInfo: scenarioWarningChecker(idx, pingFedScenarioWarnings),
		})
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
