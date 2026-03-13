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
	"encoding/xml"
	"fmt"

	"github.com/russellhaering/gosaml2/v2/types"
)

// ParseEntityDescriptor parses a SAML EntityDescriptor from raw XML bytes.
func ParseEntityDescriptor(data []byte) (*types.EntityDescriptor, error) {
	ed := &types.EntityDescriptor{}
	if err := xml.Unmarshal(data, ed); err != nil {
		return nil, fmt.Errorf("error parsing entity descriptor: %w", err)
	}
	return ed, nil
}

// SelectEndpoint picks the best SSO endpoint, preferring HTTP-POST over HTTP-Redirect.
func SelectEndpoint(services []types.SingleSignOnService) (string, string) {
	var fallbackURL, fallbackBinding string
	for _, svc := range services {
		if svc.Binding == BindingHttpPost {
			return svc.Location, svc.Binding
		}
		if fallbackURL == "" {
			fallbackURL = svc.Location
			fallbackBinding = svc.Binding
		}
	}
	return fallbackURL, fallbackBinding
}

// SelectSLOEndpoint picks the best SLO endpoint, preferring HTTP-POST over HTTP-Redirect.
func SelectSLOEndpoint(services []types.SingleLogoutService) (string, string) {
	var fallbackURL, fallbackBinding string
	for _, svc := range services {
		if svc.Binding == BindingHttpPost {
			return svc.Location, svc.Binding
		}
		if fallbackURL == "" {
			fallbackURL = svc.Location
			fallbackBinding = svc.Binding
		}
	}
	return fallbackURL, fallbackBinding
}
