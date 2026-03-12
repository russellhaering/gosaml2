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

	saml2 "github.com/russellhaering/gosaml2/v2"
)

var oneLoginScenarioErrors = map[int]string{
	99: "error validating response: dsig: missing signature referencing the top-level element",
	98: "error validating response: dsig: missing signature referencing the top-level element",
	1: "",
	3: "",
	4: "",
	5: "",
	6: "",
	7: "",
	8: "",
	9: "",
	11: "error validating response: dsig: computed digest does not match signed digest value",
	12: "error validating response: dsig: computed digest does not match signed digest value",
	13: "error validating response: dsig: computed digest does not match signed digest value",
	14: "error validating response: dsig: computed digest does not match signed digest value",
	15: "error validating response: dsig: computed digest does not match signed digest value",
	16: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: rsa internal error: crypto/rsa: decryption error",
	17: "error validating response: dsig: computed digest does not match signed digest value",
	18: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: rsa internal error: crypto/rsa: decryption error",
	81: "error validating response: dsig: missing signature referencing the top-level element",
	82: "error validating response: dsig: missing signature referencing the top-level element",
	91: "error validating response: dsig: missing signature referencing the top-level element",
	92: "error validating response: dsig: missing signature referencing the top-level element",
	21: "error validating response: dsig: certificate not valid at current time",
	22: "error validating response: dsig: certificate not valid at current time",
	93: "error validating response: dsig: certificate not valid at current time",
	94: "error validating response: dsig: certificate not valid at current time",
	83: "",
	84: "",
	23: "error validating response: unable to get decryption certificate: decryption cert is not valid at this time",
	24: "error validating response: unable to get decryption certificate: decryption cert is not valid at this time",
	26: "error validating response: saml: assertion expired: NotOnOrAfter 2017-08-30T23:19:41.379Z, now 2017-08-30T23:55:00Z",
	28: "error validating response: saml: assertion expired: NotOnOrAfter 2017-08-30T23:19:41.379Z, now 2017-08-30T23:55:00Z",
	31: "error validating response: dsig: signing certificate not in trusted set",
	33: "error validating response: dsig: signing certificate not in trusted set",
	34: "error validating response: dsig: signing certificate not in trusted set",
	36: "error validating response: dsig: signing certificate not in trusted set",
	37: "error validating response: dsig: signing certificate not in trusted set",
	38: "error validating response: dsig: signing certificate not in trusted set",
	97: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: key decryption attempted with mismatched cert, SP cert(cd:f6:7c:e9), assertion cert(42:99:58:b8)",
	46: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: key decryption attempted with mismatched cert, SP cert(cd:f6:7c:e9), assertion cert(42:99:58:b8)",
	47: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: key decryption attempted with mismatched cert, SP cert(cd:f6:7c:e9), assertion cert(42:99:58:b8)",
	48: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: key decryption attempted with mismatched cert, SP cert(cd:f6:7c:e9), assertion cert(42:99:58:b8)",
	85: "error validating response: dsig: missing signature referencing the top-level element",
	86: "error validating response: dsig: missing signature referencing the top-level element",
	87: "error validating response: dsig: missing signature referencing the top-level element",
	88: "error validating response: dsig: missing signature referencing the top-level element",
	89: "error validating response: dsig: missing signature referencing the top-level element",
	25: "saml: assertion not yet valid: NotBefore 2017-08-30T23:09:41.379Z, now 2017-08-30T23:00:00Z",
	27: "saml: assertion not yet valid: NotBefore 2017-08-30T23:09:41.379Z, now 2017-08-30T23:00:00Z",
	50: "",
	51: "error validating response: saml: destination mismatch: expected https://saml.sp.nope/session/sso/saml/acs/rq5jwkvb8z, got https://saml.sp.nope/session/sso/saml/acs/incorrect",
	52: "error validating response: saml: issuer mismatch: expected https://saml.idp.nope/h9gkjzvb3e, got https://saml.idp.nope/incorrect",
	53: "saml: audience mismatch",
	54: "error validating response: saml: issuer mismatch: expected https://saml.idp.nope/h9gkjzvb3e, got https://saml.idp.nope/incorrect",
	55: "",
	56: "error validating response: saml: destination mismatch: expected https://saml.sp.nope/session/sso/saml/acs/rq5jwkvb8z, got https://saml.sp.nope/session/sso/saml/acs/incorrect",
	57: "error validating response: saml: issuer mismatch: expected https://saml.idp.nope/h9gkjzvb3e, got https://saml.idp.nope/incorrect",
	58: "saml: audience mismatch",
	59: "error validating response: saml: issuer mismatch: expected https://saml.idp.nope/h9gkjzvb3e, got https://saml.idp.nope/incorrect",
	155: "",
	156: "error validating response: saml: destination mismatch: expected https://saml.sp.nope/session/sso/saml/acs/rq5jwkvb8z, got https://saml.sp.nope/session/sso/saml/acs/incorrect",
	157: "error validating response: saml: issuer mismatch: expected https://saml.idp.nope/h9gkjzvb3e, got https://saml.idp.nope/incorrect",
	158: "saml: audience mismatch",
	159: "error validating response: saml: issuer mismatch: expected https://saml.idp.nope/h9gkjzvb3e, got https://saml.idp.nope/incorrect",
}

var oneLoginAtTimes = map[int]string{
	25: "2017-08-30T23:00:00Z",
	26: "2017-08-30T23:55:00Z",
	27: "2017-08-30T23:00:00Z",
	28: "2017-08-30T23:55:00Z",
}

func TestOneLoginCasesLocally(t *testing.T) {
	sp := &saml2.ServiceProvider{
		IDPSSOURL:              "https://saml.idp.nope/h9gkjzvb3e",
		IDPEntityID:            "https://saml.idp.nope/h9gkjzvb3e",
		ACSURL:                 "https://saml.sp.nope/session/sso/saml/acs/rq5jwkvb8z",
		AudienceURIs:           []string{"https://saml.sp.nope/session/sso/saml/spentityid/rq5jwkvb8z"},
		IDPCertificates:        LoadCertificates("./testdata/onelogin/idp.signing.cert"),
		SPKeyStore:             LoadKeyStore("./testdata/onelogin/sp.encryption.cert", "./testdata/onelogin/sp.encryption.key"),
		SPSigningKeyStore:      LoadKeyStore("./testdata/onelogin/sp.signing.cert", "./testdata/onelogin/sp.signing.key"),
		ValidateEncryptionCert: true,
		AllowSHA1:              true,
	}

	scenarios := []ProviderTestScenario{}
	for _, idx := range scenarioIndexes(oneLoginScenarioErrors) {
		response := LoadRawResponse(fmt.Sprintf("./testdata/onelogin/olgn09_response_%02d.b64", idx))
		scenarios = append(scenarios, ProviderTestScenario{
			ScenarioName:    fmt.Sprintf("Scenario_%02d", idx),
			Response:        response,
			ServiceProvider: spAtTime(sp, getAtTime(idx, oneLoginAtTimes), response),
			CheckError:      scenarioErrorChecker(idx, oneLoginScenarioErrors),
		})
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
