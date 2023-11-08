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

var oneLoginScenarioErrors = map[int]string{
	// 99 - Response(Assertion) - no signature
	99: "error validating response: response and/or assertions must be signed",
	// 98 - Response(encrypted(Assertion)) - no signature
	98: "error validating response: response and/or assertions must be signed",
	// 01 - signed(Response(Assertion))
	1: "",
	// 03 - Response(signed(Assertion))
	3: "",
	// 04 - signed(Response(signed(Assertion)))
	4: "",
	// 05 - Response(encrypted(signed(Assertion))), no encryption certificate included in Assertion.
	// OneLogin does not include SP encryption certificate by default.  ADFS and PingFed also do not
	// include the SP encryption certificate and they do not provide an option to include it in Response.
	// OneLogin and PingFed also do not include DigestMethod (default to http://www.w3.org/2000/09/xmldsig#sha1).
	5: "",
	// 06 - Response(encrypted(signed(Assertion)))
	6: "",
	// 07 - signed(Response(encrypted(Assertion)))
	7: "",
	// 08 - signed(Response(encrypted(signed(Assertion))))
	8: "",
	// 09 - signed(Response(encrypted(signed(Assertion)))), no encryption certificate included in Assertion.
	// OneLogin does not include SP encryption certificate by default.  ADFS and PingFed also do not
	// include the SP encryption certificate and they do not provide an option to include it in Response.
	// OneLogin and PingFed also do not include DigestMethod (default to http://www.w3.org/2000/09/xmldsig#sha1).
	9: "",
	// 11 - signed(Response(Assertion)) - 01 Assertion content changed slightly
	11: "error validating response: Signature could not be verified",
	// 12 - signed(Response(Assertion)) - 01 Response content changed slightly
	12: "error validating response: Signature could not be verified",
	// 13 - Response(signed(Assertion)) - 03 Assertion content changed slightly
	13: "error validating response: Signature could not be verified",
	// 14 - signed(Response(signed(Assertion)) - 04 Assertion content changed slightly
	14: "error validating response: Signature could not be verified",
	// 15 - signed(Response(signed(Assertion))) - 04 Response content changed slightly
	15: "error validating response: Signature could not be verified",
	// 16 - Response(encrypted(signed(Assertion))) - 06 CipherValue of EncryptedKey changed slightly
	16: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: rsa internal error: crypto/rsa: decryption error",
	// 17 - signed(Response(encrypted(Assertion))) - 07 Response content changed slightly
	17: "error validating response: Signature could not be verified",
	// 18 - signed(Response(encrypted(signed(Assertion)))) - 16 signed (signature valid, still cannot decrypt)
	18: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: rsa internal error: crypto/rsa: decryption error",
	// 81 - Response(Assertion) - 99 set IssueInstant before EncryptionCertTime
	// Note: signatures are being checked before IssueInstant (which is correct)
	81: "error validating response: response and/or assertions must be signed",
	// 82 - Response(Assertion) - 99 set IssueInstant after EncryptionCertTime
	// Note: signatures are being checked before IssueInstant (which is correct)
	82: "error validating response: response and/or assertions must be signed",
	// 91 - Response(Assertion) - 99 set IssueInstant before CertTime
	// Note: signatures are being checked before IssueInstant (which is correct)
	91: "error validating response: response and/or assertions must be signed",
	// 92 - Response(Assertion) - 99 set IssueInstant after CertTime
	// Note: signatures are being checked before IssueInstant (which is correct)
	92: "error validating response: response and/or assertions must be signed",
	// 21 - signed(Response(Assertion)) - 91 sign Response, IssueInstant before SigningCertTime
	21: "error validating response: Cert is not valid at this time",
	// 22 - signed(Response(Assertion)) - 92 sign Response, IssueInstant after SigningCertTime
	22: "error validating response: Cert is not valid at this time",
	// 93 - Response(signed(Assertion)) - 91 sign Assertion, IssueInstant before SigningCertTime
	93: "error validating response: Cert is not valid at this time",
	// 94 - Response(signed(Assertion)) - 92 sign Assertion, IssueInstant after SigningCertTime
	94: "error validating response: Cert is not valid at this time",
	// 83 - Response(signed(Assertion)) - 81 sign Assertion IssueInstant before EncryptionCertTime
	//                                    (Success, EncryptionCertTime is not a factor in this case)
	83: "",
	// 84 - Response(signed(Assertion)) - 82 sign Assertion, IssueInstant after EncryptionCertTime
	//	                                  (Success, EncryptionCertTime is not a factor in this case)
	84: "",
	// 23 - Response(encrypted(signed(Assertion))) - 83 encrypt Assertion, IssueInstant before EncryptionCertTime
	23: "error validating response: unable to get decryption certificate: decryption cert is not valid at this time",
	// 24 - Response(encrypted(signed(Assertion))) - 84 encrypt Assertion, IssueInstant after EncryptionCertTime
	24: "error validating response: unable to get decryption certificate: decryption cert is not valid at this time",
	// 26 - signed(Response(Assertion)) - 01 with AtTime after IssueInstant
	26: "error validating response: Expired NotOnOrAfter value, Expected: 2017-08-30T23:55:00Z, Actual: 2017-08-30T23:19:41.379Z",
	// 28 - Response(encrypted(signed(Assertion))) - 06 with AtTime after IssueInstant
	28: "error validating response: Expired NotOnOrAfter value, Expected: 2017-08-30T23:55:00Z, Actual: 2017-08-30T23:19:41.379Z",
	// 31 - signed(Response(Assertion)) - 01 wrong IDP signing cert
	31: "error validating response: Could not verify certificate against trusted certs",
	// 33 - Response(signed(Assertion)) - 03 wrong IDP signing cert
	33: "error validating response: Could not verify certificate against trusted certs",
	// 34 - signed(Response(signed(Assertion))) - 04 wrong IDP signing cert
	34: "error validating response: Could not verify certificate against trusted certs",
	// 36 - Response(encrypted(signed(Assertion))) - 06 wrong IDP signing cert, correct SP encryption cert
	36: "error validating response: Could not verify certificate against trusted certs",
	// 37 - signed(Response(encrypted(Assertion))) - 07 wrong IDP signing cert, correct SP encryption cert
	37: "error validating response: Could not verify certificate against trusted certs",
	// 38 - signed(Response(encrypted(signed(Assertion)))) - 08 wrong IDP signing cert, correct SP encryption cert
	38: "error validating response: Could not verify certificate against trusted certs",
	// 97 - Response(encrypted(Assertion)) - 99 wrong SP encryption cert
	97: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: key decryption attempted with mismatched cert, SP cert(cd:f6:7c:e9), assertion cert(42:99:58:b8)",
	// 46 - Response(encrypted(signed(Assertion))) - 06 wrong SP encryption cert, correct IDP signing cert
	46: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: key decryption attempted with mismatched cert, SP cert(cd:f6:7c:e9), assertion cert(42:99:58:b8)",
	// 47 - signed(Response(encrypted(Assertion))) - 07 wrong SP encryption cert, correct IDP signing cert
	47: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: key decryption attempted with mismatched cert, SP cert(cd:f6:7c:e9), assertion cert(42:99:58:b8)",
	// 48 - signed(Response(encrypted(signed(Assertion)))) - 08 wrong SP encryption cert, correct IDP signing cert
	48: "error validating response: unable to decrypt encrypted assertion: cannot decrypt, error retrieving private key: key decryption attempted with mismatched cert, SP cert(cd:f6:7c:e9), assertion cert(42:99:58:b8)",
	// 85 - Response(Assertion) - 99 empty Response Destination (empty is ok, Destination is optional)
	// Note: gosaml2 is correctly checking signature before contents
	85: "error validating response: response and/or assertions must be signed",
	// 86 - Response(Assertion) - 99 wrong Response Destination (SP acs)
	// Note: gosaml2 is correctly checking signature before contents
	86: "error validating response: response and/or assertions must be signed",
	// 87 - Response(Assertion) - 99 wrong Response Issuer (IDP endpoint id)
	// Note: gosaml2 is correctly checking signature before contents
	87: "error validating response: response and/or assertions must be signed",
	// 88 - Response(Assertion) - 99 wrong Assertion Audience (SP entity id)
	// Note: gosaml2 is correctly checking signature before contents
	88: "error validating response: response and/or assertions must be signed",
	// 89 - Response(Assertion) - 99 wrong Assertion Issuer (IDP endpoint id)
	// Note: gosaml2 is correctly checking signature before contents
	89: "error validating response: response and/or assertions must be signed",
	// 50 - signed(Response(Assertion)) - 85 signed Response, empty Response Destination (success, optional)
	50: "",
	// 51 - signed(Response(Assertion)) - 86 signed Response, wrong Response Destination (SP acs)
	51: "error validating response: Unrecognized Destination value, Expected: https://saml.sp.nope/session/sso/saml/acs/rq5jwkvb8z, Actual: https://saml.sp.nope/session/sso/saml/acs/incorrect",
	// 52 - signed(Response(Assertion)) - 87 signed Response, wrong Response Issuer (IDP endpoint id)
	52: "error validating response: Unrecognized Issuer value, Expected: https://saml.idp.nope/h9gkjzvb3e, Actual: https://saml.idp.nope/incorrect",
	// 54 - signed(Response(Assertion)) - 89 signed Response, wrong Assertion Issuer (IDP endpoint id)
	54: "error validating response: Unrecognized Issuer value, Expected: https://saml.idp.nope/h9gkjzvb3e, Actual: https://saml.idp.nope/incorrect",
	// 55 - Response(signed(Assertion)) - 85 signed Assertion, empty Response Destination (success, optional)
	55: "",
	// 56 - Response(signed(Assertion)) - 86 signed Assertion, wrong Response Destination (SP acs)
	56: "error validating response: Unrecognized Destination value, Expected: https://saml.sp.nope/session/sso/saml/acs/rq5jwkvb8z, Actual: https://saml.sp.nope/session/sso/saml/acs/incorrect",
	// 57 - error validating response: Response(signed(Assertion)) - 87 signed Assertion, wrong Response Issuer (IDP endpoint id)
	57: "error validating response: Unrecognized Issuer value, Expected: https://saml.idp.nope/h9gkjzvb3e, Actual: https://saml.idp.nope/incorrect",
	// 59 - Response(signed(Assertion)) - 89 signed Assertion, wrong Assertion Issuer (IDP endpoint id)
	59: "error validating response: Unrecognized Issuer value, Expected: https://saml.idp.nope/h9gkjzvb3e, Actual: https://saml.idp.nope/incorrect",
	// 155 - Response(encrypted(signed(Assertion))) - 85 encrypted signed Assertion, empty Response Destination (success, optional)
	155: "",
	// 156 - Response(encrypted(signed(Assertion))) - 86 encrypted signed Assertion, wrong Response Destination (SP acs)
	156: "error validating response: Unrecognized Destination value, Expected: https://saml.sp.nope/session/sso/saml/acs/rq5jwkvb8z, Actual: https://saml.sp.nope/session/sso/saml/acs/incorrect",
	// 157 - Response(encrypted(signed(Assertion))) - 87 encrypted signed Assertion, wrong Response Issuer (IDP endpoint id)
	157: "error validating response: Unrecognized Issuer value, Expected: https://saml.idp.nope/h9gkjzvb3e, Actual: https://saml.idp.nope/incorrect",
	// 159 - Response(encrypted(signed(Assertion))) - 89 encrypted signed Assertion, wrong Assertion Issuer (IDP endpoint id)
	159: "error validating response: Unrecognized Issuer value, Expected: https://saml.idp.nope/h9gkjzvb3e, Actual: https://saml.idp.nope/incorrect",
}

var oneLoginScenarioWarnings = map[int]scenarioWarnings{
	// 25 - signed(Response(Assertion)) - 01 with AtTime before IssueInstant
	25: scenarioWarnings{
		InvalidTime: true,
	},
	// 27 - Response(encrypted(signed(Assertion))) - 06 with AtTime before IssueInstant
	27: scenarioWarnings{
		InvalidTime: true,
	},
	// 53 - signed(Response(Assertion)) - 88 signed Response, wrong Assertion Audience (SP entity id)
	53: scenarioWarnings{
		NotInAudience: true,
	},
	// 58 - Response(signed(Assertion)) - 88 signed Assertion, wrong Assertion Audience (SP entity id)
	58: scenarioWarnings{
		NotInAudience: true,
	},
	// 158 - Response(encrypted(signed(Assertion))) - 88 encrypted signed Assertion, wrong Assertion Audience (SP entity id)
	158: scenarioWarnings{
		NotInAudience: true,
	},
}

var oneLoginAtTimes = map[int]string{
	25: "2017-08-30T23:00:00Z",
	26: "2017-08-30T23:55:00Z",
	27: "2017-08-30T23:00:00Z",
	28: "2017-08-30T23:55:00Z",
}

func TestOneLoginCasesLocally(t *testing.T) {
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      "https://saml.idp.nope/h9gkjzvb3e", // not required for these tests
		IdentityProviderIssuer:      "https://saml.idp.nope/h9gkjzvb3e",
		AssertionConsumerServiceURL: "https://saml.sp.nope/session/sso/saml/acs/rq5jwkvb8z",
		AudienceURI:                 "https://saml.sp.nope/session/sso/saml/spentityid/rq5jwkvb8z",
		IDPCertificateStore:         LoadCertificateStore("./testdata/onelogin/idp.signing.cert"),
		SPKeyStore:                  LoadKeyStore("./testdata/onelogin/sp.encryption.cert", "./testdata/onelogin/sp.encryption.key"),
		SPSigningKeyStore:           LoadKeyStore("./testdata/onelogin/sp.signing.cert", "./testdata/onelogin/sp.signing.key"),
		ValidateEncryptionCert:      true,
	}

	scenarios := []ProviderTestScenario{}
	for _, idx := range scenarioIndexes(oneLoginScenarioErrors, oneLoginScenarioWarnings) {
		response := LoadRawResponse(fmt.Sprintf("./testdata/onelogin/olgn09_response_%02d.b64", idx))
		scenarios = append(scenarios, ProviderTestScenario{
			ScenarioName:     fmt.Sprintf("Scenario_%02d", idx),
			Response:         response,
			ServiceProvider:  spAtTime(sp, getAtTime(idx, oneLoginAtTimes), response),
			CheckError:       scenarioErrorChecker(idx, oneLoginScenarioErrors),
			CheckWarningInfo: scenarioWarningChecker(idx, oneLoginScenarioWarnings),
		})
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
