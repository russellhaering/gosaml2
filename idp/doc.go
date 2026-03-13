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

// Package idp implements a SAML 2.0 Identity Provider.
//
// [IdentityProvider] is the main entry point. Configure it with your IdP's
// entity ID, SSO URL, signing key, and known Service Providers, then use it to:
//
//   - Validate AuthnRequests with [IdentityProvider.ValidateEncodedAuthnRequestPOST]
//     or [IdentityProvider.ValidateEncodedAuthnRequestRedirect]
//   - Build SAML responses with [IdentityProvider.BuildResponseDocument] or
//     [IdentityProvider.BuildResponseBodyPost]
//   - Generate IdP metadata with [IdentityProvider.Metadata]
//   - Handle single logout with the BuildLogout*/ValidateEncodedLogout* methods
//
// Use [ConfigureFromSPMetadata] to create an [SPConfig] from a parsed
// [types.EntityDescriptor].
package idp
