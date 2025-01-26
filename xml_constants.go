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

// SAML tags
const (
	AssertionTag               = "Assertion"
	AttributeStatementTag      = "AttributeStatement"
	AttributeValueTag          = "AttributeValue"
	AudienceRestrictionTag     = "AudienceRestriction"
	AudienceTag                = "Audience"
	ConditionsTag              = "Conditions"
	EncryptedAssertionTag      = "EncryptedAssertion"
	EndpointTag                = "Endpoint"
	IssuerTag                  = "Issuer"
	NameIdTag                  = "NameID"
	OneTimeUseTag              = "OneTimeUse"
	ProxyRestrictionTag        = "ProxyRestriction"
	ResponseTag                = "Response"
	StatusTag                  = "Status"
	StatusCodeTag              = "StatusCode"
	StatusMessageTag           = "StatusMessage"
	SubjectTag                 = "Subject"
	SubjectConfirmationTag     = "SubjectConfirmation"
	SubjectConfirmationDataTag = "SubjectConfirmationData"
)

// SAML attributes
const (
	AssertionConsumerServiceURLAttr = "AssertionConsumerServiceURL"
	AuthnInstantAttr                = "AuthnInstant"
	CountAttr                       = "Count"
	DestinationAttr                 = "Destination"
	FormatAttr                      = "Format"
	IDAttr                          = "ID"
	InResponseToAttr                = "InResponseTo"
	IssueInstantAttr                = "IssueInstant"
	MethodAttr                      = "Method"
	NameAttr                        = "Name"
	NotBeforeAttr                   = "NotBefore"
	NotOnOrAfterAttr                = "NotOnOrAfter"
	SessionNotOnOrAfterAttr         = "SessionNotOnOrAfter"
	RecipientAttr                   = "Recipient"
	ResponseLocationAttr            = "ResponseLocation"
	ValueAttr                       = "Value"
	VersionAttr                     = "Version"
)

const (
	AuthnPolicyMatchExact   = "exact"
	AuthnPolicyMatchMinimum = "minimum"
	AuthnPolicyMatchMaximum = "maximum"
	AuthnPolicyMatchBetter  = "better"
)

// SAML namespaces
const (
	SAMLAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	SAMLProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	SAMLMetadataNamespace  = "urn:oasis:names:tc:SAML:2.0:metadata"

	NameIDFormatPersistent      = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatEntity          = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	NameIDFormatTransient       = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDFormatEmailAddress    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatUnspecified     = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDFormatX509SubjectName = "urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName"

	StatusCodeSuccess          = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusCodeDenied           = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	StatusCodePartialLogout    = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	StatusCodeUnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
	StatusCodeRequester        = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusCodeResponder        = "urn:oasis:names:tc:SAML:2.0:status:Responder"

	MethodBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

	BindingHttpPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BindingHttpRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

	ClassesAuthnContextPassword            = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
	AuthnContextPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
)
