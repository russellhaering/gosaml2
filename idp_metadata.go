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

package saml2

import (
	"encoding/base64"
	"time"

	"github.com/russellhaering/gosaml2/v2/types"
)

// Metadata generates an EntityDescriptor for this IdP.
func (idp *IdentityProvider) Metadata() (*types.EntityDescriptor, error) {
	var keyDescriptors []types.KeyDescriptor

	if idp.SigningKeyStore != nil {
		keyDescriptors = append(keyDescriptors, types.KeyDescriptor{
			Use: "signing",
			KeyInfo: types.KeyInfo{
				X509Data: types.X509Data{
					X509Certificates: []types.X509Certificate{{
						Data: base64.StdEncoding.EncodeToString(idp.SigningKeyStore.Cert),
					}},
				},
			},
		})
	}

	validDuration := idp.MetadataValidDuration
	if validDuration == 0 {
		validDuration = 7 * 24 * time.Hour
	}

	nameIDFormats := idp.NameIDFormats
	if len(nameIDFormats) == 0 {
		nameIDFormats = []string{NameIdFormatTransient}
	}

	formats := make([]types.NameIDFormat, len(nameIDFormats))
	for i, f := range nameIDFormats {
		formats[i] = types.NameIDFormat{Value: f}
	}

	ssoServices := []types.SingleSignOnService{
		{Binding: BindingHttpPost, Location: idp.SSOURL},
		{Binding: BindingHttpRedirect, Location: idp.SSOURL},
	}

	desc := &types.EntityDescriptor{
		ValidUntil: idp.now().UTC().Add(validDuration),
		EntityID:   idp.EntityID,
		IDPSSODescriptor: &types.IDPSSODescriptor{
			ProtocolSupportEnumeration: SAMLProtocolNamespace,
			WantAuthnRequestsSigned:    true,
			KeyDescriptors:             keyDescriptors,
			NameIDFormats:              formats,
			SingleSignOnServices:       ssoServices,
		},
	}

	if idp.SLOURL != "" {
		desc.IDPSSODescriptor.SingleLogoutServices = []types.SingleLogoutService{
			{Binding: BindingHttpPost, Location: idp.SLOURL},
			{Binding: BindingHttpRedirect, Location: idp.SLOURL},
		}
	}

	return desc, nil
}
