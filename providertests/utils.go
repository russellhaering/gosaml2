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

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/sp"
	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

func scenarioIndexes(errs map[int]string) (idxs []int) {
	for idx := range errs {
		idxs = append(idxs, idx)
	}
	sort.Ints(idxs)
	return
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
	ScenarioName    string
	Response        string
	ServiceProvider *sp.ServiceProvider
	CheckError      func(*testing.T, error)
}

func getAtTime(idx int, scenarioAtTimes map[int]string) (atTime time.Time) {
	if strAtTime, ok := scenarioAtTimes[idx]; ok && strAtTime != "" {
		if atm, err := time.Parse(time.RFC3339, strAtTime); err == nil {
			return atm
		}
	}
	return // zero time
}

func spAtTime(template *sp.ServiceProvider, atTime time.Time, rawResp string) *sp.ServiceProvider {
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

	spCopy := &sp.ServiceProvider{
		IDPSSOURL:                       template.IDPSSOURL,
		IDPSSOBinding:                   template.IDPSSOBinding,
		IDPSLOURL:                       template.IDPSLOURL,
		IDPSLOBinding:                   template.IDPSLOBinding,
		IDPEntityID:                     template.IDPEntityID,
		ACSURL:                          template.ACSURL,
		SLOURL:                          template.SLOURL,
		EntityID:                        template.EntityID,
		SignAuthnRequests:               template.SignAuthnRequests,
		AudienceURIs:                    template.AudienceURIs,
		IDPCertificates:                 template.IDPCertificates,
		NameIDFormat:                    template.NameIDFormat,
		ValidateEncryptionCert:          template.ValidateEncryptionCert,
		InsecureSkipSignatureValidation: template.InsecureSkipSignatureValidation,
		AllowSHA1:                       template.AllowSHA1,
		SPKeyStore:                      template.SPKeyStore,
		SPSigningKeyStore:               template.SPSigningKeyStore,
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
	spCopy.Clock = func() time.Time { return clockTime }
	return spCopy
}
