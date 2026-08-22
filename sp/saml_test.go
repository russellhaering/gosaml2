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

package sp

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/russellhaering/gosaml2/v2/types"
)

var cert tls.Certificate
var pk crypto.PrivateKey

func init() {
	var err error
	pfx := "../testdata/test"
	cert, err = tls.LoadX509KeyPair(fmt.Sprintf("%s.crt", pfx), fmt.Sprintf("%s.key", pfx))
	if err != nil {
		log.Fatal(err)
	}
	pk = cert.PrivateKey
}

func TestDecode(t *testing.T) {
	f, err := ioutil.ReadFile("../testdata/saml.post")
	if err != nil {
		t.Fatalf("could not open test file: %v\n", err)
	}
	decoded := make([]byte, len(f))

	base64.StdEncoding.Decode(decoded, f)
	response := &types.Response{}

	err = xml.Unmarshal(decoded, response)
	if err != nil {
		t.Fatalf("error decoding test saml: %v", err)
	}

	ea := response.EncryptedAssertions[0]

	k, err := ea.EncryptedKey.DecryptSymmetricKey(&cert)
	if err != nil {
		t.Fatalf("could not get symmetric key: %v\n", err)
	}

	if k == nil {
		t.Fatalf("no symmetric key")
	}

	assertion, err := ea.Decrypt(&cert)
	if err != nil {
		t.Fatalf("error decrypting saml data: %v\n", err)
	}

	f2, err := ioutil.ReadFile("../testdata/saml.xml")
	if err != nil {
		t.Fatalf("could not read expected output")
	}

	expectedDoc, err := xmltree.Parse(f2)
	require.NoError(t, err)
	expected, err := types.AssertionFromElement(expectedDoc.Root())
	require.NoError(t, err)

	// The extractor populates xsi:type, which encoding/xml never matched
	// (stdlib prefix-form attribute tags don't match namespace-resolved
	// attributes) — assert the improvement explicitly.
	require.Equal(t, "xsd:string",
		assertion.AttributeStatements[0].Attributes[0].Values[0].Type)

	require.EqualValues(t, expected, assertion, "decrypted assertion did not match expectation")
}

// testKeyStore generates an RSA key pair with a certificate valid at the given
// time, suitable for use with a fake clock in tests.
func testKeyStore(t *testing.T, validAt time.Time) *saml2.KeyStore {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		NotBefore:             validAt.Add(-time.Hour),
		NotAfter:              validAt.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return &saml2.KeyStore{Signer: key, Cert: certBytes}
}

func signResponse(t *testing.T, resp string, sp *ServiceProvider) string {
	doc := xmltree.NewDocument()
	err := doc.ReadFromBytes([]byte(resp))
	require.NoError(t, err)

	el := doc.Root()

	// Strip existing signatures
	signatures := el.FindElements("//Signature")
	for _, sig := range signatures {
		parent := sig.Parent()
		parent.RemoveChild(sig)
	}

	signer, err := sp.Signer()
	require.NoError(t, err)
	el, err = signer.SignEnveloped(el)
	require.NoError(t, err)

	var buf bytes.Buffer
	el.WriteCanonicalTo(&buf)
	return buf.String()
}

// getServiceProvider returns a ServiceProvider that needs to either
// set SPKeyStore or call SetSPKeyStore.
func getServiceProvider(t *testing.T, _cert []byte) *ServiceProvider {
	t.Helper()

	block, _ := pem.Decode([]byte(idpCertificate))
	require.NotEmpty(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.NotEmpty(t, cert)

	cert0, err := x509.ParseCertificate(_cert)
	require.NoError(t, err)
	require.NotEmpty(t, cert0)

	fakeTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	return &ServiceProvider{
		// This fixture-based round trip validates the same captured responses
		// more than once and asserts that a OneTimeUse assertion is accepted
		// with OneTimeUse surfaced as advisory info, so it opts out of replay
		// protection explicitly. Enforcement with a cache configured is covered
		// by assertion_replay_test.go.
		InsecureAllowIDPInitiatedReplay: true,
		IDPSSOURL:                       "https://dev-116807.oktapreview.com/app/scaleftdev116807_scaleft_1/exk5zt0r12Edi4rD20h7/sso/saml",
		IDPEntityID:                     "http://www.okta.com/exk5zt0r12Edi4rD20h7",
		ACSURL:                          "http://localhost:8080/v1/_saml_callback",
		SignAuthnRequests:               true,
		AudienceURIs:                    []string{"123"},
		IDPCertificates:                 []*x509.Certificate{cert, cert0},
		NameIDFormat:                    saml2.NameIdFormatPersistent,
		EntityID:                        "http://localhost:8080",
		Clock:                           func() time.Time { return fakeTime },
	}
}

func TestSAML(t *testing.T) {
	ks := testKeyStore(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))

	sp := getServiceProvider(t, ks.Cert)
	sp.SPKeyStore = ks
	testServiceProvider(t, sp)
}

func testServiceProvider(t *testing.T, sp *ServiceProvider) {
	t.Helper()

	ctx := context.Background()

	authRequestURL, err := sp.BuildAuthURL("/some/link/here")
	require.NoError(t, err)
	require.NotEmpty(t, authRequestURL)

	authRequestString, err := sp.BuildAuthRequest()
	require.NoError(t, err)
	require.NotEmpty(t, authRequestString)

	// Note (Phoebe): The sample responses we acquired expired fairly quickly, meaning that our validation will fail
	// because we check the expiration time;
	// I've modified them to expire in ~100 years and removed their signatures, since those hash values are no longer
	// valid. We have to re-sign them here before validating them
	raw := signResponse(t, rawResponse, sp)

	el, err := sp.ValidateEncodedResponse(ctx, base64.StdEncoding.EncodeToString([]byte(raw)))
	require.NoError(t, err)
	require.NotEmpty(t, el)

	assertionInfo, err := sp.RetrieveAssertionInfo(ctx, base64.StdEncoding.EncodeToString([]byte(raw)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.False(t, assertionInfo.OneTimeUse)
	require.Nil(t, assertionInfo.ProxyRestriction)

	require.Equal(t, "phoebe.simon@scaleft.com", assertionInfo.NameID)
	require.Equal(t, "phoebe.simon@scaleft.com", assertionInfo.Values.Get("Email"))
	require.Equal(t, "Phoebe", assertionInfo.Values.Get("FirstName"))
	require.Equal(t, "Simon", assertionInfo.Values.Get("LastName"))
	require.Equal(t, "phoebesimon", assertionInfo.Values.Get("Login"))

	assertionInfoModifiedAudience := signResponse(t, assertionInfoModifiedAudienceResponse, sp)

	_, err = sp.RetrieveAssertionInfo(ctx, base64.StdEncoding.EncodeToString([]byte(assertionInfoModifiedAudience)))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrAudienceMismatch)

	assertionInfoOneTimeUse := signResponse(t, assertionInfoOneTimeUseResponse, sp)

	assertionInfo, err = sp.RetrieveAssertionInfo(ctx, base64.StdEncoding.EncodeToString([]byte(assertionInfoOneTimeUse)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.True(t, assertionInfo.OneTimeUse)

	assertionInfoProxyRestriction := signResponse(t, assertionInfoProxyRestrictionResponse, sp)

	assertionInfo, err = sp.RetrieveAssertionInfo(ctx, base64.StdEncoding.EncodeToString([]byte(assertionInfoProxyRestriction)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.NotNil(t, assertionInfo.ProxyRestriction)
	require.Equal(t, 3, assertionInfo.ProxyRestriction.Count)
	require.Equal(t, []string{"123"}, assertionInfo.ProxyRestriction.Audience)

	assertionInfoProxyRestrictionNoCount := signResponse(t, assertionInfoProxyRestrictionNoCountResponse, sp)

	assertionInfo, err = sp.RetrieveAssertionInfo(ctx, base64.StdEncoding.EncodeToString([]byte(assertionInfoProxyRestrictionNoCount)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.NotNil(t, assertionInfo.ProxyRestriction)
	require.Equal(t, 0, assertionInfo.ProxyRestriction.Count)
	require.Equal(t, []string{"123"}, assertionInfo.ProxyRestriction.Audience)

	assertionInfoProxyRestrictionNoAudience := signResponse(t, assertionInfoProxyRestrictionNoAudienceResponse, sp)

	assertionInfo, err = sp.RetrieveAssertionInfo(ctx, base64.StdEncoding.EncodeToString([]byte(assertionInfoProxyRestrictionNoAudience)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.NotNil(t, assertionInfo.ProxyRestriction)
	require.Equal(t, 3, assertionInfo.ProxyRestriction.Count)
	require.Equal(t, []string{}, assertionInfo.ProxyRestriction.Audience)

	assertionInfoResp := signResponse(t, assertionInfoResponse, sp)

	assertionInfo, err = sp.RetrieveAssertionInfo(ctx, base64.StdEncoding.EncodeToString([]byte(assertionInfoResp)))
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo)
	require.NotEmpty(t, assertionInfo.Values)
	require.Equal(t, "phoebe.simon@scaleft.com", assertionInfo.Values.Get("Email"))
	require.Equal(t, "Phoebe", assertionInfo.Values.Get("FirstName"))
	require.Equal(t, "Simon", assertionInfo.Values.Get("LastName"))
	require.Equal(t, "phoebe.simon@scaleft.com", assertionInfo.Values.Get("Login"))

	_, err = sp.ValidateEncodedResponse(ctx, base64.StdEncoding.EncodeToString([]byte(manInTheMiddledResponse)))
	require.Error(t, err)
	require.Equal(t, "dsig: computed digest does not match signed digest value", err.Error())

	_, err = sp.ValidateEncodedResponse(ctx, base64.StdEncoding.EncodeToString([]byte(alteredReferenceURIResponse)))
	require.Error(t, err)
	require.Equal(t, "dsig: signing certificate not in trusted set", err.Error())

	_, err = sp.ValidateEncodedResponse(ctx, base64.StdEncoding.EncodeToString([]byte(alteredSignedInfoResponse)))
	require.Error(t, err)
	require.Equal(t, "dsig: signing certificate not in trusted set", err.Error())

	alteredRecipient := signResponse(t, alteredRecipientResponse, sp)
	_, err = sp.ValidateEncodedResponse(ctx, base64.StdEncoding.EncodeToString([]byte(alteredRecipient)))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadRecipient)

	alteredDestination := signResponse(t, alteredDestinationResponse, sp)
	_, err = sp.ValidateEncodedResponse(ctx, base64.StdEncoding.EncodeToString([]byte(alteredDestination)))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadDestination)

	alteredSubjectConfirmationMethod := signResponse(t, alteredSubjectConfirmationMethodResponse, sp)
	_, err = sp.ValidateEncodedResponse(ctx, base64.StdEncoding.EncodeToString([]byte(alteredSubjectConfirmationMethod)))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMalformed)

	alteredVersion := signResponse(t, alteredVersionResponse, sp)
	_, err = sp.ValidateEncodedResponse(ctx, base64.StdEncoding.EncodeToString([]byte(alteredVersion)))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadVersion)

	_, err = sp.ValidateEncodedResponse(ctx, base64.StdEncoding.EncodeToString([]byte(missingIDResponse)))
	require.Error(t, err)
	require.Equal(t, "dsig: computed digest does not match signed digest value", err.Error())
}

func TestInvalidResponseBadBase64(t *testing.T) {
	sp := &ServiceProvider{}

	response, err := sp.ValidateEncodedResponse(context.Background(), "invalid-base64")
	require.EqualError(t, err, "illegal base64 data at input byte 7")
	require.Nil(t, response)
}

func TestInvalidResponseBadCompression(t *testing.T) {
	sp := &ServiceProvider{}

	// Value from: https://github.com/golang/go/blob/23416315060bf7601e5779c3a6a2529d4d604584/src/compress/flate/flate_test.go#L219
	// This input is neither valid XML nor a valid DEFLATE stream. maybeDeflate
	// tries the bytes as XML first (the primary, uncompressed format) and, when
	// the DEFLATE fallback also fails, surfaces the original XML decode error
	// rather than the less-informative inflate error.
	rawResponse, err := hex.DecodeString("33180700")
	require.NoError(t, err)

	b64Response := base64.StdEncoding.EncodeToString(rawResponse)

	response, err := sp.ValidateEncodedResponse(context.Background(), b64Response)
	require.EqualError(t, err, "xmltree: line 1 (offset 0): text outside the root element")
	require.Nil(t, response)
}

func TestInvalidResponseBadXML(t *testing.T) {
	sp := &ServiceProvider{}

	compressed := &bytes.Buffer{}

	compressor, err := flate.NewWriter(compressed, flate.BestCompression)
	require.NoError(t, err)

	compressor.Write([]byte(">Definitely&Invalid XML"))
	compressor.Close()

	b64Response := base64.StdEncoding.EncodeToString(compressed.Bytes())

	response, err := sp.ValidateEncodedResponse(context.Background(), b64Response)
	require.EqualError(t, err, "xmltree: line 1 (offset 0): text outside the root element")
	require.Nil(t, response)
}

func TestInvalidResponseNoElement(t *testing.T) {
	sp := &ServiceProvider{}

	b64Response := base64.StdEncoding.EncodeToString([]byte("no-element-here"))

	response, err := sp.ValidateEncodedResponse(context.Background(), b64Response)
	require.EqualError(t, err, "xmltree: line 1 (offset 0): text outside the root element")
	require.Nil(t, response)
}
func TestSAMLCommentInjection(t *testing.T) {
	// The strict parser rejects comment-bearing documents outright, so a
	// comment-splitting NameID injection can no longer even be ingested.
	_, _, err := parseResponse([]byte(commentInjectionAttackResponse), 0)
	require.Error(t, err, "comment injection must be rejected at parse time")
	require.Contains(t, err.Error(), "comments are not allowed")
}
