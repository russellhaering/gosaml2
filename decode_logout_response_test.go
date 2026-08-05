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
	"encoding/base64"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

const unsignedLogoutResponseXML = `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1b2c3" Version="2.0" IssueInstant="2020-01-01T00:00:00Z" Destination="https://sp.example.com/slo" InResponseTo="_req123">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:LogoutResponse>`

func TestValidateEncodedLogoutResponsePOSTRejectsUnsigned(t *testing.T) {
	sp := &SAMLServiceProvider{
		ServiceProviderSLOURL:  "https://sp.example.com/slo",
		IdentityProviderIssuer: "https://idp.example.com",
		IDPCertificateStore:    &dsig.MemoryX509CertificateStore{},
		Clock:                  dsig.NewFakeClock(clockwork.NewFakeClockAt(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))),
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(unsignedLogoutResponseXML))

	_, err := sp.ValidateEncodedLogoutResponsePOST(encoded)
	require.Error(t, err)
	require.Equal(t, "logout response is not signed", err.Error())
}
