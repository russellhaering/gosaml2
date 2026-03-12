// Copyright 2025 Russell Haering et al.
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

package fuzz

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"testing"

	saml2 "github.com/russellhaering/gosaml2/v2"
)

func FuzzDecodeResponse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		encodedResponse := base64.StdEncoding.EncodeToString(data)

		_, err := saml2.DecodeUnverifiedBaseResponse(encodedResponse)
		if err != nil {
			return
		}

		sp := &saml2.ServiceProvider{}
		_, _ = sp.ValidateEncodedResponse(context.Background(), encodedResponse)
	})
}

func FuzzLogoutResponse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		encodedResponse := base64.StdEncoding.EncodeToString(data)

		_, err := saml2.DecodeUnverifiedLogoutResponse(encodedResponse)
		if err != nil {
			return
		}

		sp := &saml2.ServiceProvider{}
		_, _ = sp.ValidateEncodedLogoutResponsePOST(context.Background(), encodedResponse)
	})
}

func FuzzBuildRequest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 8 {
			return
		}

		idValue := binary.LittleEndian.Uint64(data[:8])
		relayState := string(data[8:])

		if len(relayState) == 0 {
			return
		}

		sp := &saml2.ServiceProvider{
			IDPSSOURL:        "https://idp.example.com/sso",
			IDPEntityID:      "https://idp.example.com/",
			ACSURL:           "https://sp.example.com/acs",
			AudienceURIs:     []string{"https://sp.example.com/audience"},
			EntityID:         "https://sp.example.com",
			SignAuthnRequests: idValue%2 == 0,
			ForceAuthn:       idValue%3 == 0,
			IsPassive:        idValue%5 == 0,
		}

		_, _ = sp.BuildAuthURL(relayState)
		_, _ = sp.BuildAuthRequest()
	})
}
