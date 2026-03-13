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

import "errors"

// Sentinel errors for use with errors.Is().
var (
	ErrExpired          = errors.New("saml: assertion expired")
	ErrNotYetValid      = errors.New("saml: assertion not yet valid")
	ErrAudienceMismatch = errors.New("saml: audience mismatch")
	ErrBadRecipient     = errors.New("saml: recipient mismatch")
	ErrBadDestination   = errors.New("saml: destination mismatch")
	ErrBadIssuer        = errors.New("saml: issuer mismatch")
	ErrBadSignature     = errors.New("saml: signature verification failed")
	ErrMissingSignature = errors.New("saml: required signature missing")
	ErrBadStatus        = errors.New("saml: response status not success")
	ErrReplay           = errors.New("saml: request ID not recognized")
	ErrMissingAssertion = errors.New("saml: missing assertion")
	ErrMissingElement   = errors.New("saml: missing required element")
	ErrBadVersion       = errors.New("saml: unsupported SAML version")
	ErrMalformed        = errors.New("saml: malformed SAML document")
	ErrUnknownSP        = errors.New("saml: unknown service provider")
	ErrBadACSURL        = errors.New("saml: invalid assertion consumer service URL")
	ErrEncryptionFailed = errors.New("saml: assertion encryption failed")
)

// ValidationError wraps a sentinel error with human-readable context.
// Use errors.Is(err, ErrBadDestination) etc. for programmatic matching.
type ValidationError struct {
	Reason error  // sentinel for errors.Is()
	Detail string // human-readable context
}

func (e *ValidationError) Error() string {
	if e.Detail == "" {
		return e.Reason.Error()
	}
	return e.Reason.Error() + ": " + e.Detail
}

func (e *ValidationError) Unwrap() error {
	return e.Reason
}
