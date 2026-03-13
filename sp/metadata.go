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

package sp

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/types"
)

// ConfigureFromMetadata populates the ServiceProvider's IdP-related fields
// from an EntityDescriptor. It extracts the entity ID, SSO/SLO endpoints,
// and signing certificates from the IDPSSODescriptor.
//
// For SSO endpoints it prefers HTTP-POST, falling back to HTTP-Redirect.
// For SLO endpoints it prefers HTTP-POST, falling back to HTTP-Redirect.
func (sp *ServiceProvider) ConfigureFromMetadata(ed *types.EntityDescriptor) error {
	sp.IDPEntityID = ed.EntityID

	idp := ed.IDPSSODescriptor
	if idp == nil {
		return fmt.Errorf("entity descriptor does not contain an IDPSSODescriptor")
	}

	// Extract SSO endpoint.
	ssoURL, ssoBinding := saml2.SelectEndpoint(idp.SingleSignOnServices)
	if ssoURL == "" {
		return fmt.Errorf("no SingleSignOnService endpoint found in IdP metadata")
	}
	sp.IDPSSOURL = ssoURL
	sp.IDPSSOBinding = ssoBinding

	// Extract SLO endpoint (optional).
	if len(idp.SingleLogoutServices) > 0 {
		sloURL, sloBinding := saml2.SelectSLOEndpoint(idp.SingleLogoutServices)
		sp.IDPSLOURL = sloURL
		sp.IDPSLOBinding = sloBinding
	}

	// Extract signing certificates.
	var certs []*x509.Certificate
	for _, kd := range idp.KeyDescriptors {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for _, x509Cert := range kd.KeyInfo.X509Data.X509Certificates {
			certData, err := base64.StdEncoding.DecodeString(x509Cert.Data)
			if err != nil {
				return fmt.Errorf("error decoding IdP certificate: %w", err)
			}
			cert, err := x509.ParseCertificate(certData)
			if err != nil {
				return fmt.Errorf("error parsing IdP certificate: %w", err)
			}
			certs = append(certs, cert)
		}
	}
	sp.IDPCertificates = certs

	return nil
}
