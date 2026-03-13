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

// Package sp implements a SAML 2.0 Service Provider.
//
// [ServiceProvider] is the main entry point. Configure it with your SP's
// entity ID, ACS URL, and IdP settings, then use it to:
//
//   - Build AuthnRequests with [ServiceProvider.BuildAuthURL] or [ServiceProvider.BuildAuthBodyPost]
//   - Validate SAML responses with [ServiceProvider.ValidateEncodedResponse]
//   - Extract user attributes with [ServiceProvider.RetrieveAssertionInfo]
//   - Generate SP metadata with [ServiceProvider.Metadata]
//   - Handle single logout with the BuildLogout*/ValidateEncodedLogout* methods
//
// Use [ServiceProvider.ConfigureFromMetadata] to populate IdP settings from
// a parsed [types.EntityDescriptor].
//
// For replay prevention, set [ServiceProvider.RequestTracker] to a
// [MemoryRequestTracker] or your own implementation.
package sp
