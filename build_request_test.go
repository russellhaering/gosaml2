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
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestRedirect(t *testing.T) {
	r := &http.Request{URL: &url.URL{Path: "/"}}
	w := httptest.NewRecorder()

	spURL := "https://sp.test"

	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: spURL,
		AudienceURI:                 spURL,
		IdentityProviderIssuer:      spURL,
		IdentityProviderSSOURL:      "https://idp.test/saml/sso",
		SignAuthnRequests:           false,
	}

	require.NoError(t, sp.AuthRedirect(w, r, "foobar"))
	require.Len(t, w.HeaderMap, 1, "wrong number of headers was set")
	require.Equal(t, http.StatusFound, w.Code, "wrong http status was set")

	u, err := url.Parse(w.HeaderMap.Get("Location"))
	require.NoError(t, err, "invalid url used for redirect")

	require.Equal(t, "idp.test", u.Host)
	require.Equal(t, "https", u.Scheme)
	require.Equal(t, "foobar", u.Query().Get("RelayState"))

	bs, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	require.NoError(t, err, "error base64 decoding SAMLRequest query param")

	fr := flate.NewReader(bytes.NewReader(bs))

	req := AuthNRequest{}
	require.NoError(t, xml.NewDecoder(fr).Decode(&req), "Error reading/decoding from flate-compressed URL")

	iss, err := url.Parse(req.Issuer)
	require.NoError(t, err, "error parsing request issuer URL")

	require.Equal(t, "sp.test", iss.Host)
	require.WithinDuration(t, time.Now(), req.IssueInstant, time.Second, "IssueInstant was not within the expected time frame")

	dst, err := url.Parse(req.Destination)
	require.NoError(t, err, "error parsing request destination")
	require.Equal(t, "https", dst.Scheme)
	require.Equal(t, "idp.test", dst.Host)

	//Require that the destination is the same as the redirected URL, except params
	require.Equal(t, fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path), dst.String())
}

func TestRequestedAuthnContextOmitted(t *testing.T) {
	spURL := "https://sp.test"
	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: spURL,
		AudienceURI:                 spURL,
		IdentityProviderIssuer:      spURL,
		IdentityProviderSSOURL:      "https://idp.test/saml/sso",
		SignAuthnRequests:           false,
	}

	request, err := sp.BuildAuthRequest()
	require.NoError(t, err)

	doc := etree.NewDocument()
	err = doc.ReadFromString(request)
	require.NoError(t, err)

	el := doc.FindElement("./AuthnRequest/RequestedAuthnContext")
	require.Nil(t, el)
}

func TestRequestedAuthnContextIncluded(t *testing.T) {
	spURL := "https://sp.test"
	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: spURL,
		AudienceURI:                 spURL,
		IdentityProviderIssuer:      spURL,
		IdentityProviderSSOURL:      "https://idp.test/saml/sso",
		RequestedAuthnContext: &RequestedAuthnContext{
			Comparison: AuthnPolicyMatchExact,
			Contexts: []string{
				AuthnContextPasswordProtectedTransport,
			},
		},
		SignAuthnRequests: false,
	}

	request, err := sp.BuildAuthRequest()
	require.NoError(t, err)

	doc := etree.NewDocument()
	err = doc.ReadFromString(request)
	require.NoError(t, err)

	el := doc.FindElement("./AuthnRequest/RequestedAuthnContext")
	require.Equal(t, el.SelectAttrValue("Comparison", ""), "exact")
	require.Len(t, el.ChildElements(), 1)
	el = el.ChildElements()[0]
	require.Equal(t, el.Tag, "AuthnContextClassRef")
	require.Equal(t, el.Text(), AuthnContextPasswordProtectedTransport)
}

func TestForceAuthnOmitted(t *testing.T) {
	spURL := "https://sp.test"
	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: spURL,
		AudienceURI:                 spURL,
		IdentityProviderIssuer:      spURL,
		IdentityProviderSSOURL:      "https://idp.test/saml/sso",
	}

	request, err := sp.BuildAuthRequest()
	require.NoError(t, err)

	doc := etree.NewDocument()
	err = doc.ReadFromString(request)
	require.NoError(t, err)

	attr := doc.Root().SelectAttr("ForceAuthn")
	require.Nil(t, attr)
}

func TestForceAuthnIncluded(t *testing.T) {
	spURL := "https://sp.test"
	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: spURL,
		AudienceURI:                 spURL,
		IdentityProviderIssuer:      spURL,
		IdentityProviderSSOURL:      "https://idp.test/saml/sso",
		ForceAuthn:                  true,
	}

	request, err := sp.BuildAuthRequest()
	require.NoError(t, err)

	doc := etree.NewDocument()
	err = doc.ReadFromString(request)
	require.NoError(t, err)

	attr := doc.Root().SelectAttr("ForceAuthn")
	require.NotNil(t, attr)
	require.Equal(t, "true", attr.Value)
}

func TestIsPassiveOmitted(t *testing.T) {
	spURL := "https://sp.test"
	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: spURL,
		AudienceURI:                 spURL,
		IdentityProviderIssuer:      spURL,
		IdentityProviderSSOURL:      "https://idp.test/saml/sso",
	}

	request, err := sp.BuildAuthRequest()
	require.NoError(t, err)

	doc := etree.NewDocument()
	err = doc.ReadFromString(request)
	require.NoError(t, err)

	attr := doc.Root().SelectAttr("IsPassive")
	require.Nil(t, attr)
}

func TestIsPassiveIncluded(t *testing.T) {
	spURL := "https://sp.test"
	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: spURL,
		AudienceURI:                 spURL,
		IdentityProviderIssuer:      spURL,
		IdentityProviderSSOURL:      "https://idp.test/saml/sso",
		IsPassive:                   true,
	}

	request, err := sp.BuildAuthRequest()
	require.NoError(t, err)

	doc := etree.NewDocument()
	err = doc.ReadFromString(request)
	require.NoError(t, err)

	attr := doc.Root().SelectAttr("IsPassive")
	require.NotNil(t, attr)
	require.Equal(t, "true", attr.Value)
}
