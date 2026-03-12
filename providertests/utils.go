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

package providertests

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"sort"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	"github.com/stretchr/testify/require"
)

func scenarioIndexes(errs map[int]string, warns map[int]scenarioWarnings) (idxs []int) {
	for idx, _ := range errs {
		idxs = append(idxs, idx)
	}
	for idx, _ := range warns {
		idxs = append(idxs, idx)
	}
	sort.Ints(idxs)
	return
}

type scenarioWarnings struct {
	InvalidTime   bool
	NotInAudience bool
}

func scenarioErrorChecker(i int, scenarioErrors map[int]string) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		if msg, ok := scenarioErrors[i]; ok && msg != "" {
			require.EqualError(t, err, msg, "Expected error message")
		} else {
			require.NoError(t, err)
		}
	}
}

func scenarioWarningChecker(i int, scenarioWarns map[int]scenarioWarnings) func(*testing.T, *saml2.WarningInfo) {
	return func(t *testing.T, warningInfo *saml2.WarningInfo) {
		expectedWarnings := scenarioWarns[i]
		require.Equal(t, expectedWarnings.InvalidTime, warningInfo.InvalidTime, "InvalidTime mismatch")
		require.Equal(t, expectedWarnings.NotInAudience, warningInfo.NotInAudience, "NotInAudience mismatch")
	}
}

func LoadXMLResponse(path string) string {
	xml, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(xml)
}

func LoadRawResponse(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return string(data)
}

func LoadKeyStore(certPath, keyPath string) *saml2.KeyStore {
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		panic(fmt.Errorf("%v: cannot read: %v", certPath, err))
	}
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(fmt.Errorf("%v: cannot read: %v", keyPath, err))
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		panic(fmt.Errorf("%v: no PEM block found", keyPath))
	}

	privateKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		panic(fmt.Errorf("%v: cannot parse key: %v", keyPath, err))
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		panic(fmt.Errorf("%v: no PEM block found", certPath))
	}

	return &saml2.KeyStore{
		Signer: privateKey,
		Cert:   certBlock.Bytes,
	}
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	// Try PKCS8 first, then PKCS1, then EC
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to parse private key")
}

func LoadCertificates(path string) []*x509.Certificate {
	encoded, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(encoded)
	if block == nil {
		panic("no certificate block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	return []*x509.Certificate{cert}
}

type ProviderTestScenario struct {
	ScenarioName     string
	Response         string
	ServiceProvider  *saml2.SAMLServiceProvider
	CheckError       func(*testing.T, error)
	CheckWarningInfo func(*testing.T, *saml2.WarningInfo)
}

func getAtTime(idx int, scenarioAtTimes map[int]string) (atTime time.Time) {
	if strAtTime, ok := scenarioAtTimes[idx]; ok && strAtTime != "" {
		if atm, err := time.Parse(time.RFC3339, strAtTime); err == nil {
			return atm
		}
	}
	return // zero time
}

func spAtTime(template *saml2.SAMLServiceProvider, atTime time.Time, rawResp string) *saml2.SAMLServiceProvider {
	resp := &types.Response{}
	if rawResp == "" {
		panic(fmt.Errorf("empty rawResp"))
	}
	var respBytes []byte
	var err error
	if respBytes, err = base64.StdEncoding.DecodeString(rawResp); err != nil {
		respBytes = []byte(rawResp)
	}
	if err := xml.Unmarshal(respBytes, resp); err != nil {
		panic(fmt.Errorf("cannot parse Response XML: %v", err))
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      template.IdentityProviderSSOURL,
		IdentityProviderSSOBinding:  template.IdentityProviderSSOBinding,
		IdentityProviderSLOURL:      template.IdentityProviderSLOURL,
		IdentityProviderSLOBinding:  template.IdentityProviderSLOBinding,
		IdentityProviderIssuer:      template.IdentityProviderIssuer,
		AssertionConsumerServiceURL: template.AssertionConsumerServiceURL,
		ServiceProviderSLOURL:       template.ServiceProviderSLOURL,
		ServiceProviderIssuer:       template.ServiceProviderIssuer,
		SignAuthnRequests:           template.SignAuthnRequests,
		AudienceURI:                 template.AudienceURI,
		IDPCertificates:             template.IDPCertificates,
		NameIdFormat:                template.NameIdFormat,
		ValidateEncryptionCert:      template.ValidateEncryptionCert,
		SkipSignatureValidation:     template.SkipSignatureValidation,
		AllowMissingAttributes:      template.AllowMissingAttributes,
		AllowSHA1:                   template.AllowSHA1,
		SPKeyStore:                  template.SPKeyStore,
		SPSigningKeyStore:           template.SPSigningKeyStore,
	} // copy fields from template, we only set the clock below
	if atTime.IsZero() {
		// Prefer more official Assertion IssueInstant over Response IssueIntant
		// (Assertion will be signed, either individually or as part of Response)
		if len(resp.Assertions) > 0 && !resp.Assertions[0].IssueInstant.IsZero() {
			atTime = resp.Assertions[0].IssueInstant
		} else if !resp.IssueInstant.IsZero() {
			atTime = resp.IssueInstant
		} else {
			panic(fmt.Errorf("could not determine atTime"))
		}
	}
	clockTime := atTime
	sp.Clock = func() time.Time { return clockTime }
	return sp
}
