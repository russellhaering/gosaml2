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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"html/template"
	"net/url"
	"time"

	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	"github.com/russellhaering/gosaml2/v2/types"
)

// KeyStore holds a signing key and its associated certificate.
type KeyStore struct {
	Signer crypto.Signer
	Cert   []byte
}

// RequestedAuthnContext controls which authentication mechanisms are requested of
// the identity provider. It is generally sufficient to omit this and let the
// identity provider select an authentication mechanism.
type RequestedAuthnContext struct {
	// The RequestedAuthnContext comparison policy to use. See the section 3.3.2.2.1
	// of the SAML 2.0 specification for details. Constants named AuthnPolicyMatch*
	// contain standardized values.
	Comparison string

	// Contexts will be passed as AuthnContextClassRefs. For example, to force password
	// authentication on some identity providers, Contexts should have a value of
	// []string{AuthnContextPasswordProtectedTransport}, and Comparison should have a
	// value of AuthnPolicyMatchExact.
	Contexts []string
}

// AuthNRequest is the go struct representation of an authentication request
type AuthNRequest struct {
	ID                          string `xml:",attr"`
	Version                     string `xml:",attr"`
	ProtocolBinding             string `xml:",attr"`
	AssertionConsumerServiceURL string `xml:",attr"`

	IssueInstant time.Time `xml:",attr"`

	Destination string `xml:",attr"`
	Issuer      string
}

// LogoutRequest is the go struct representation of a logout request
type LogoutRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID      string   `xml:"ID,attr"`
	Version string   `xml:"Version,attr"`

	IssueInstant time.Time `xml:"IssueInstant,attr"`
	NotOnOrAfter string    `xml:"NotOnOrAfter,attr,omitempty"`

	Destination string        `xml:"Destination,attr"`
	Issuer      *types.Issuer `xml:"Issuer"`

	NameID             *types.NameID `xml:"NameID"`
	SignatureValidated bool          `xml:"-"` // not read, not dumped
}

// IssueInstantFormat is the time format used for SAML timestamps.
const IssueInstantFormat = "2006-01-02T15:04:05Z"

// SignatureAlgorithmHash returns the crypto.Hash for a given signature method URI.
// Returns 0 if unrecognized or empty.
func SignatureAlgorithmHash(algorithm string) crypto.Hash {
	switch algorithm {
	case dsig.RSASHA1SignatureMethod, dsig.ECDSASHA1SignatureMethod:
		return crypto.SHA1
	case dsig.RSASHA256SignatureMethod, dsig.ECDSASHA256SignatureMethod:
		return crypto.SHA256
	case dsig.RSASHA384SignatureMethod, dsig.ECDSASHA384SignatureMethod:
		return crypto.SHA384
	case dsig.RSASHA512SignatureMethod, dsig.ECDSASHA512SignatureMethod:
		return crypto.SHA512
	default:
		return 0
	}
}

// SignatureAlgorithmKeyType returns the public-key algorithm (RSA or ECDSA)
// implied by a signature method URI, or x509.UnknownPublicKeyAlgorithm if the
// URI is unrecognized. It is used to ensure a redirect-binding SigAlg's declared
// key family matches the verifying certificate's actual key type.
func SignatureAlgorithmKeyType(algorithm string) x509.PublicKeyAlgorithm {
	switch algorithm {
	case dsig.RSASHA1SignatureMethod, dsig.RSASHA256SignatureMethod,
		dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod:
		return x509.RSA
	case dsig.ECDSASHA1SignatureMethod, dsig.ECDSASHA256SignatureMethod,
		dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod:
		return x509.ECDSA
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// SignatureMethodIdentifier returns the XML-DSig signature method URI for the
// given key and hash algorithm. This is needed for the HTTP-Redirect binding
// where the SigAlg query parameter must be set.
func SignatureMethodIdentifier(key crypto.Signer, hash crypto.Hash) string {
	if hash == 0 {
		hash = crypto.SHA256
	}
	switch key.Public().(type) {
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			return dsig.RSASHA1SignatureMethod
		case crypto.SHA256:
			return dsig.RSASHA256SignatureMethod
		case crypto.SHA384:
			return dsig.RSASHA384SignatureMethod
		case crypto.SHA512:
			return dsig.RSASHA512SignatureMethod
		}
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			return dsig.ECDSASHA1SignatureMethod
		case crypto.SHA256:
			return dsig.ECDSASHA256SignatureMethod
		case crypto.SHA384:
			return dsig.ECDSASHA384SignatureMethod
		case crypto.SHA512:
			return dsig.ECDSASHA512SignatureMethod
		}
	}
	return dsig.RSASHA256SignatureMethod
}

// SignatureInputString constructs the string to be fed into the signature algorithm, as described
// in section 3.4.4.1 of
// https://www.oasis-open.org/committees/download.php/56779/sstc-saml-bindings-errata-2.0-wd-06.pdf
func SignatureInputString(samlRequest, relayState, sigAlg string) string {
	var params [][2]string
	if relayState == "" {
		params = [][2]string{{"SAMLRequest", samlRequest}, {"SigAlg", sigAlg}}
	} else {
		params = [][2]string{{"SAMLRequest", samlRequest}, {"RelayState", relayState}, {"SigAlg", sigAlg}}
	}

	var buf bytes.Buffer
	for _, kv := range params {
		k, v := kv[0], kv[1]
		if buf.Len() > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(url.QueryEscape(k) + "=" + url.QueryEscape(v))
	}
	return buf.String()
}

// IsSignatureMissing returns true when err is dsig.ErrMissingSignature,
// and returns (false, err) for any other non-nil error.
func IsSignatureMissing(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	if errors.Is(err, dsig.ErrMissingSignature) {
		return true, nil
	}
	return false, err
}

var postFormTemplate = template.Must(template.New("saml-post-form").Parse(
	`<form method="POST" action="{{.URL}}" id="SAMLForm">` +
		`<input type="hidden" name="{{.ParamName}}" value="{{.ParamValue}}" />` +
		`{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}" />{{end}}` +
		`<input id="SAMLSubmitButton" type="submit" value="Submit" />` +
		`</form>` +
		`<script>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLForm').submit();</script>`))

// BuildPOSTForm generates an HTML auto-submitting POST form for SAML messages.
func BuildPOSTForm(actionURL, paramName, paramValue, relayState string) ([]byte, error) {
	data := struct {
		URL        string
		ParamName  string
		ParamValue string
		RelayState string
	}{
		URL:        actionURL,
		ParamName:  paramName,
		ParamValue: paramValue,
		RelayState: relayState,
	}
	var buf bytes.Buffer
	if err := postFormTemplate.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
