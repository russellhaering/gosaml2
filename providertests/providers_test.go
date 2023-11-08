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
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/russellhaering/gosaml2"
	"github.com/russellhaering/goxmldsig"
)

func TestValidateResponses(t *testing.T) {
	scenarios := []ProviderTestScenario{
		{
			ScenarioName: "Auth0",
			Response:     LoadXMLResponse("./testdata/auth0_response.xml"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://scaleft-test.auth0.com/samlp/rlXOZ4kOUTQaTV8icSXrfZUd1qtD1NhK",
				IdentityProviderIssuer:      "urn:scaleft-test.auth0.com",
				AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
				AudienceURI:                 "urn:scaleft-test.auth0.com",
				IDPCertificateStore:         LoadCertificateStore("./testdata/auth0_cert.pem"),
				Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2016, 7, 25, 18, 30, 0, 0, time.UTC))),
			},
		},
		{
			ScenarioName: "Adfs",
			Response:     LoadRawResponse("./testdata/adfs_response.b64"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://do.not.need/this/not/sending/authn",
				IdentityProviderIssuer:      "http://fs.spstest2.com/adfs/services/trust",
				AssertionConsumerServiceURL: "https://saml.test.nope/session/sso/saml/acs/dknhyszjl7",
				SignAuthnRequests:           false,
				AudienceURI:                 "https://saml.test.nope/session/sso/saml/spentityid/dknhyszjl7",
				IDPCertificateStore:         LoadCertificateStore("./testdata/adfs_idp_signing_cert.pem"),
				SPKeyStore:                  LoadKeyStore("./testdata/adfs_sp_encryption_cert.pem", "./testdata/adfs_sp_encryption_key.pem"),
				SPSigningKeyStore:           LoadKeyStore("./testdata/adfs_sp_signing_cert.pem", "./testdata/adfs_sp_signing_key.pem"),
				Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2017, 9, 21, 23, 28, 0, 0, time.UTC))),
			},
		},
		{
			ScenarioName: "AdfsEncrypted",
			Response:     LoadRawResponse("./testdata/adfs_response_enc.b64"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://do.not.need/this/not/sending/authn",
				IdentityProviderIssuer:      "http://fs.spstest2.com/adfs/services/trust",
				AssertionConsumerServiceURL: "https://saml.test.nope/session/sso/saml/acs/dknhyszjl7",
				SignAuthnRequests:           false,
				AudienceURI:                 "https://saml.test.nope/session/sso/saml/spentityid/dknhyszjl7",
				IDPCertificateStore:         LoadCertificateStore("./testdata/adfs_idp_signing_cert.pem"),
				SPKeyStore:                  LoadKeyStore("./testdata/adfs_sp_encryption_cert.pem", "./testdata/adfs_sp_encryption_key.pem"),
				SPSigningKeyStore:           LoadKeyStore("./testdata/adfs_sp_signing_cert.pem", "./testdata/adfs_sp_signing_key.pem"),
				Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2017, 9, 21, 23, 20, 0, 0, time.UTC))),
			},
		},
		{
			// Okta uses detached EncryptedKey element (sibling of EncryptedData).  See:
			// https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-Extensions-to-KeyInfo
			ScenarioName: "OktaEncrypted",
			Response:     LoadRawResponse("./testdata/oktaenc_response.b64"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://do.not.need/this/not/sending/authn",
				IdentityProviderIssuer:      "http://www.okta.com/exkbb59wb20X96NY20h7",
				AssertionConsumerServiceURL: "https://saml.test.nope/session/sso/saml/acs/skv8dv26wh",
				SignAuthnRequests:           false,
				AudienceURI:                 "https://saml.test.nope/session/sso/saml/spentityid/skv8dv26wh",
				IDPCertificateStore:         LoadCertificateStore("./testdata/oktaenc_idp_signing_cert.pem"),
				SPKeyStore:                  LoadKeyStore("./testdata/oktaenc_sp_encryption_cert.pem", "./testdata/oktaenc_sp_encryption_key.pem"),
				SPSigningKeyStore:           LoadKeyStore("./testdata/oktaenc_sp_signing_cert.pem", "./testdata/oktaenc_sp_signing_key.pem"),
				Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2017, 9, 06, 22, 14, 0, 0, time.UTC))),
			},
		},
		{
			ScenarioName: "Okta",
			Response:     LoadXMLResponse("./testdata/okta_response.xml"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://dev-116807.oktapreview.com/app/scaleftdev116807_test_1/exk659aytfMeNI49v0h7/sso/saml",
				IdentityProviderIssuer:      "http://www.okta.com/exk659aytfMeNI49v0h7",
				AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
				SignAuthnRequests:           true,
				AudienceURI:                 "\"123\"",
				IDPCertificateStore:         LoadCertificateStore("./testdata/okta_cert.pem"),
				Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2016, 7, 25, 23, 16, 0, 0, time.UTC))),
			},
		},
		{
			ScenarioName: "OneLogin",
			Response:     LoadXMLResponse("./testdata/onelogin_response.xml"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://launchdarkly-dev.onelogin.com/trust/saml2/http-post/sso/634027",
				IdentityProviderIssuer:      "https://app.onelogin.com/saml/metadata/634027",
				AssertionConsumerServiceURL: "http://884d40bf.ngrok.io/api/sso/saml2/acs/58af624473d4f375b8e70d81",
				IDPCertificateStore:         LoadCertificateStore("./testdata/onelogin_cert.pem"),
				AudienceURI:                 "{audience}",
				SkipSignatureValidation:     false,
				AllowMissingAttributes:      true,
				Clock: dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2017, 3, 8, 7, 51, 0, 0, time.UTC))),
			},
		},
		{
			ScenarioName: "OracleAccessManager",
			Response:     LoadXMLResponse("./testdata/oam_response.xml"),
			ServiceProvider: &saml2.SAMLServiceProvider{
				IdentityProviderSSOURL:      "https://deaoam-dev02.jpl.nasa.gov:14101/oam/fed",
				IdentityProviderIssuer:      "https://deaoam-dev02.jpl.nasa.gov:14101/oam/fed",
				AssertionConsumerServiceURL: "http://127.0.0.1:5556/callback",
				IDPCertificateStore:         LoadCertificateStore("./testdata/oam_cert.pem"),
				AudienceURI:                 "JSAuth",
				SkipSignatureValidation:     false,
				AllowMissingAttributes:      true,
				Clock: dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2016, 12, 12, 16, 55, 0, 0, time.UTC))),
			},
		},
	}

	ExerciseProviderTestScenarios(t, scenarios)
}
