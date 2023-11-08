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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

const (
	idpCert = `
-----BEGIN CERTIFICATE-----
MIIDODCCAiCgAwIBAgIUQH54kyyeacU69J2iwz9bzeLmMaswDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSY29sbGVnZS5jY2N0Y2EuZWR1MB4XDTE1MDYwNDIyMTAz
MVoXDTM1MDYwNDIyMTAzMVowHTEbMBkGA1UEAwwSY29sbGVnZS5jY2N0Y2EuZWR1
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlJhN20ng2VN/cTrWtqUI
NaUsrHCkYXbm2y1PTN4b6fJI5hbvcv+LWCuLkLi3+iPGlBpcHHfrdJcyhmBHRHQ9
Sos3RIH5Lsn1IgjWe3hxQQmVeEi5xVxnw2YZGHaeX4YnI1TEBJwhtJmyitk74LHy
bPGEqOJdApUnLz54L7I+252G/cOfEqUHMbxxtmHSc/9chF8bBxQ8OzIbJsByHnqi
awQHwtsttre7n328gVqmf1VHE27cfAYiSjuK5pCsx/1kuJMBN+kg/3Gg9oi6aR50
WX1VUF3IBcnTDeiAXRz3PgsT8FlVZou6Ik9NT/Y5IHOZVGk64SRDaG8FuGxLexXr
swIDAQABo3AwbjAdBgNVHQ4EFgQUjQwaAoY3u/iToIE3ADeNEW+Uu34wTQYDVR0R
BEYwRIISY29sbGVnZS5jY2N0Y2EuZWR1hi5odHRwczovL2NvbGxlZ2UuY2NjdGNh
LmVkdTo4NDQzL2lkcC9zaGliYm9sZXRoMA0GCSqGSIb3DQEBCwUAA4IBAQB26rdx
phN1YKad3yDhLg6Y1ZwbmAjc+l4QB1KSL+cLqhDn5iMy4VdWh8HpSKRqCwofLtlw
3qOwospj+mJaguXRMpjYODRQaKRkTrCGxJhuNrQxDXL/b6FOEIJnUYenbPevuNgR
Jc1VnREhWUUXT44KN5YUz9FEiG0BsBK8ecCPKBzTQ/hwaczhpqw6uqVMqxJaTGcn
lCUHJAhVHiA8lWJ7vaNPsJ86xBFs/F76EwyFXIKQaruvcvChU7GNNSYdNJBa6HO9
9QWdGbr5aNQ4diunnBQdrdjgbQIwyhKTfbFWa2l5vbqEKDc0dwuPa6c25l8ruqxq
CQ1CF8ZDDJ0XV6Ab
-----END CERTIFICATE-----
`

	oktaCert = `
-----BEGIN CERTIFICATE-----
MIIDPDCCAiQCCQDydJgOlszqbzANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJVUzETMB
EGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEQMA4GA1UEChMH
SmFua3lDbzESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE0MDMxMjE5NDYzM1oXDTI3MTExOT
E5NDYzM1owYDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DVNhbiBGcmFuY2lzY28xEDAOBgNVBAoTB0phbmt5Q28xEjAQBgNVBAMTCWxvY2FsaG9zdD
CCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMGvJpRTTasRUSPqcbqCG+ZnTAur
nu0vVpIG9lzExnh11o/BGmzu7lB+yLHcEdwrKBBmpepDBPCYxpVajvuEhZdKFx/Fdy6j5m
H3rrW0Bh/zd36CoUNjbbhHyTjeM7FN2yF3u9lcyubuvOzr3B3gX66IwJlU46+wzcQVhSOl
Mk2tXR+fIKQExFrOuK9tbX3JIBUqItpI+HnAow509CnM134svw8PTFLkR6/CcMqnDfDK1m
993PyoC1Y+N4X9XkhSmEQoAlAHPI5LHrvuujM13nvtoVYvKYoj7ScgumkpWNEvX652LfXO
nKYlkB8ZybuxmFfIkzedQrbJsyOhfL03cMECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAeH
wzqwnzGEkxjzSD47imXaTqtYyETZow7XwBc0ZaFS50qRFJUgKTAmKS1xQBP/qHpStsROT3
5DUxJAE6NY1Kbq3ZbCuhGoSlY0L7VzVT5tpu4EY8+Dq/u2EjRmmhoL7UkskvIZ2n1DdERt
d+YUMTeqYl9co43csZwDno/IKomeN5qaPc39IZjikJ+nUC6kPFKeu/3j9rgHNlRtocI6S1
FdtFz9OZMQlpr0JbUt2T3xS/YoQJn6coDmJL5GTiiKM6cOe+Ur1VwzS1JEDbSS2TWWhzq8
ojLdrotYLGd9JOsoQhElmz+tMfCFQUFLExinPAyy7YHlSiVX13QH2XTu/iQQ==
-----END CERTIFICATE-----
`

	oktaCert2 = `
-----BEGIN CERTIFICATE-----
MIIDpDCCAoygAwIBAgIGAWxzAwX1MA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi05MDUyNTExHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTkwODA4MjA1MzMzWhcNMjkwODA4MjA1NDMzWjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtOTA1MjUxMRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
m+ZZF6aEG6ehLLIV6RPA+i1z6ss3HBG2bZD3efwKCDDXYUkp59AE7JsjVHMtpJPHhzHuScuHDMlu
HmkBQTW7j9XpnaRn8SfZXkwlCUHTo+HAC9lwbQxO4d4wnwgnm6FAjm1I/gbfFAobd8BR9pDxHuXE
MQ0DtQu/W3WbDUrz/bhSxPJAoVy2koQn9G0y3unm7eRwYWHeuW6GdPWV2szTtDS0c3qtUXVF5Ugg
iQYlwQu6xkfy4l8iGJL7ETa2BmJzwCFecMIct87SqNhYQwCBH54MBaHcaSsCKyimNvMY9B7RmC+H
4+awePPA1q3R/UQ3Pfom8mx6yDdKIWqlkG3MsQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAiURCZ
P4oJWcf1o5nm4yG15UH01g/S6Y4OUWMi6BFJy9fCrJ0h/2BZKi68SQ0uMAbdK6anxCzq3Rr5MSzW
OWPQ1Zljn3LGPsiTFdFca/GVRen5IYQ7Dr2Mvhtm+QVscEY9TDjtETbTAHEVEjwXmB21wtdIhizv
sQS7wz0A8LV+Atpbev45RiV6COmB6T6vJuFQ7ZsDZMSHZriTYiETTJvHBGd7PtbCxYNc6LRB2JDb
wlekRhVEjR0UhnM+nn2sqqbv7tDEPs63lZSDXCnR1PhscHrEuQ04rHI3OL0gCULVQFvJrj85IAZF
1QQuGUK8ozfOyFpQWAJUW71INnF/SLWv
-----END CERTIFICATE-----
`

	badInput = `<saml2:Assertion ID="id1684056077776386493060641"IssueInstant="2019-08-12T12:00:52.718Z"Version="2.0"xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"xmlns="">http://www.okta.com/exk133onomIuOW98z357</l><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id1684056077776386493060641"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="xs"xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></m></s><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>dC1cm0pLLjIWZC6G2Pmf0JogmqHztp9W1euXPd/TUHo=</e></e></o><ds:SignatureValue>YRSCFLIkIgjbbYLyfCIc8jsP2MUJPjn+nYWRdlVIDdXtYXXxklYqdBXQsxDwNcsOAIGS75PeVGryml3oBkUDg/MfK7z/fFPLXX7c7xgh7/DBAFlSXbwlJQxuXQ5eZcGesgG6nYRwU1hpW+yN7C2ODN9KHi5TUdiEhvy8vdlFSfxdy4Mn68nG/UZBqmHHIZdRG2/Hpcs29YyaVVZUCZ0w22b7zsPuOXHuStOSTQ6isxI2R268+ZNKERYaNMCAGX4zNlT3mHBV0NnZkbO3wmlOfKksL+Qx7L64xFc3PaervxWuPqh2FoWpTCqFdliLdvUfFDszKXJKhO0bj1U0aSrdzg==</e><s><s><s></X></X></o></e><saml2:Subject xmlns=""><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">steven.james.johnstone@gmail.com</l><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_40a419f5-5c1c-43d0-5834-5caf268a5f01"NotOnOrAfter="2019-08-12T12:05:52.718Z"Recipient="https://127.0.0.1/login"/></l></l><saml2:Conditions NotBefore="2019-08-12T11:55:52.718Z"NotOnOrAfter="2019-08-12T12:05:52.718Z"xmlns=""><saml2:AudienceRestriction><saml2:Audience>37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f.jazznetworks.com</l></l></l><saml2:AuthnStatement AuthnInstant="2019-08-12T12:00:52.718Z"SessionIndex="_40a419f5-5c1c-43d0-5834-5caf268a5f01"xmlns=""><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</l></l></l><saml2:AttributeStatement xmlns=""><saml2:Attribute Name="FirstName"NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns=""xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"xsi:type="xs:string">Steven</l></l><saml2:Attribute Name="LastName"NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns=""xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"xsi:type="xs:string">Johnstone</l></l><saml2:Attribute Name="Email"NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns=""xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"xsi:type="xs:string">steven.james.johnstone@gmail.com`
)

func testEncryptedAssertion(t *testing.T, validateEncryptionCert bool) {
	var err error
	cert, err := tls.LoadX509KeyPair("./testdata/test.crt", "./testdata/test.key")
	require.NoError(t, err, "could not load x509 key pair")

	block, _ := pem.Decode([]byte(idpCert))

	idpCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse idp cert pem block")

	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: "https://saml2.test.astuart.co/sso/saml2",
		SPKeyStore:                  dsig.TLSCertKeyStore(cert),
		ValidateEncryptionCert:      validateEncryptionCert,
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{idpCert},
		},
		Clock: dsig.NewFakeClockAt(time.Date(2016, 04, 28, 22, 00, 00, 00, time.UTC)),
	}

	bs, err := ioutil.ReadFile("./testdata/saml.post")
	require.NoError(t, err, "couldn't read post")

	_, err = sp.RetrieveAssertionInfo(string(bs))
	if validateEncryptionCert {
		require.Error(t, err)
		require.Equal(t, "error validating response: unable to get decryption certificate: decryption cert is not valid at this time", err.Error())
	} else {
		require.NoError(t, err, "Assertion info should be retrieved with no error")
	}
}

func TestEncryptedAssertion(t *testing.T) {
	testEncryptedAssertion(t, false)
}

func TestEncryptedAssertionInvalidCert(t *testing.T) {
	testEncryptedAssertion(t, true)
}

func TestCompressedResponse(t *testing.T) {
	bs, err := ioutil.ReadFile("./testdata/saml_compressed.post")
	require.NoError(t, err, "couldn't read compressed post")

	block, _ := pem.Decode([]byte(oktaCert))

	idpCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse okta cert pem block")

	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: "https://f1f51ddc.ngrok.io/api/sso/saml2/acs/58cafd0573d4f375b8e70e8e",
		SPKeyStore:                  dsig.TLSCertKeyStore(cert),
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{idpCert},
		},
		Clock: dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2017, 3, 17, 20, 00, 0, 0, time.UTC))),
	}

	_, err = sp.RetrieveAssertionInfo(string(bs))
	require.NoError(t, err, "Assertion info should be retrieved with no error")
}

func TestDecodeColonsInLocalNames(t *testing.T) {
	// Handling of double colons was improved in Go 1.7 such that this test no longer fails.
	// See: https://go-review.googlesource.com/c/go/+/277892
	if rtvalidator.Validate(bytes.NewReader([]byte(`<x::Root/>`))) == nil {
		t.Skip()
	}

	_, _, err := parseResponse([]byte(`<x::Root/>`), 0)
	require.Error(t, err)
}

func TestDecodeDoubleColonInjectionAttackResponse(t *testing.T) {
	// Handling of double colons was improved in Go 1.7 such that this test no longer fails.
	// See: https://go-review.googlesource.com/c/go/+/277892
	if rtvalidator.Validate(bytes.NewReader([]byte(`<x::Root/>`))) == nil {
		t.Skip()
	}

	_, _, err := parseResponse([]byte(doubleColonAssertionInjectionAttackResponse), 0)
	require.Error(t, err)
}

func TestMalFormedInput(t *testing.T) {
	block, _ := pem.Decode([]byte(oktaCert2))
	idpCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse okta cert pem block")

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	}

	sp := &SAMLServiceProvider{
		Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2019, 8, 12, 12, 00, 52, 718, time.UTC))),
		AssertionConsumerServiceURL: "https://saml2.test.astuart.co/sso/saml2",
		SignAuthnRequests:           true,
		IDPCertificateStore:         &certStore,
		ValidateEncryptionCert:      true,
	}
	base64Input := base64.StdEncoding.EncodeToString([]byte(badInput))
	_, err = sp.RetrieveAssertionInfo(base64Input)
	require.Errorf(t, err, "parent is nil")
}

func TestCompressionBombInput(t *testing.T) {
	bs, err := ioutil.ReadFile("./testdata/saml_compressed.post")
	require.NoError(t, err, "couldn't read compressed post")

	block, _ := pem.Decode([]byte(oktaCert))

	idpCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse okta cert pem block")

	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: "https://f1f51ddc.ngrok.io/api/sso/saml2/acs/58cafd0573d4f375b8e70e8e",
		SPKeyStore:                  dsig.TLSCertKeyStore(cert),
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{idpCert},
		},
		Clock:                       dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2017, 3, 17, 20, 00, 0, 0, time.UTC))),
		MaximumDecompressedBodySize: 2048,
	}

	_, err = sp.RetrieveAssertionInfo(string(bs))
	require.Error(t, err, "error validating response: deflated response exceeds maximum size of 2048 bytes")
}
