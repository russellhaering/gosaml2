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

// Package saml2 provides shared types and utilities for SAML 2.0 Service
// Provider and Identity Provider implementations.
//
// The core types in this package — [KeyStore], [ValidationError], sentinel
// errors, and metadata parsing — are used by both the [sp] and [idp]
// sub-packages. Application code typically imports this package alongside
// one of those sub-packages.
//
// Key types:
//
//   - [KeyStore] holds a signing key and its certificate for XML-DSig operations.
//   - [ValidationError] wraps sentinel errors (e.g. [ErrExpired], [ErrBadSignature])
//     with human-readable detail. Use [errors.Is] for programmatic matching.
//   - [ParseEntityDescriptor] parses SAML metadata XML into a [types.EntityDescriptor].
//
// See the sp and idp packages for the primary SP and IdP implementations.
package saml2
