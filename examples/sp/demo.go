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

// demo is a minimal SAML Service Provider example. It authenticates users
// against an Okta IdP using the HTTP-Redirect binding and displays the
// returned assertion attributes.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/sp"
	"github.com/russellhaering/gosaml2/v2/types"
)

// idpMetadataURL is where this demo reads its IdP metadata from.
//
// The certificates in this document become the only trust anchors used to
// verify signatures on incoming Responses and Assertions, and its SSO Location
// becomes the URL users are sent to in order to log in. Substituting it is
// therefore a complete authentication bypass: an attacker who can rewrite the
// response inserts their own certificate and then mints assertions for any
// identity.
//
// gosaml2 does not verify metadata signatures, so the transport is what
// establishes authenticity. It must be HTTPS with certificate verification (as
// here), or a local operator-controlled file. Never plain HTTP: an on-path
// attacker or DNS spoofing is then enough to take over the SP.
const idpMetadataURL = "https://idp.oktadev.com/metadata"

func main() {
	// Step 1: Fetch IdP metadata over an authenticated channel. In production
	// this XML would typically be loaded from a file or configuration store --
	// see the note on idpMetadataURL about why the source must be trustworthy.
	res, err := http.Get(idpMetadataURL)
	if err != nil {
		log.Fatalf("Error fetching IdP metadata: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Fatalf("Error fetching IdP metadata: unexpected status %s", res.Status)
	}

	rawMetadata, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Error reading IdP metadata: %v", err)
	}

	// Step 2: Parse IdP metadata to extract SSO URLs and signing certificates.
	metadata := &types.EntityDescriptor{}
	if err := xml.Unmarshal(rawMetadata, metadata); err != nil {
		log.Fatalf("Error parsing IdP metadata: %v", err)
	}

	var idpCerts []*x509.Certificate
	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				log.Fatalf("Metadata certificate(%d) must not be empty", idx)
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				log.Fatalf("Error decoding certificate(%d): %v", idx, err)
			}
			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				log.Fatalf("Error parsing certificate(%d): %v", idx, err)
			}
			idpCerts = append(idpCerts, idpCert)
		}
	}

	// Step 3: Generate a random signing key for this demo. In production,
	// use a persistent key pair loaded from a file or secret store.
	randomKeyStore := randomKeyStoreForDemo()

	// Step 4: Configure the Service Provider.
	s := &sp.ServiceProvider{
		IDPSSOURL:        metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IDPEntityID:      metadata.EntityID,
		EntityID:         "http://example.com/saml/acs/example",
		ACSURL:           "http://localhost:8080/v1/_saml_callback",
		SignAuthnRequests: true,
		AudienceURIs:     []string{"http://example.com/saml/acs/example"},
		IDPCertificates:  idpCerts,
		SPKeyStore:       randomKeyStore,
		// RequestTracker enables InResponseTo validation to prevent replay
		// attacks. Entries expire after 5 minutes.
		RequestTracker: sp.NewMemoryRequestTracker(5 * time.Minute),
		// ClockSkew allows some tolerance for clock differences between the
		// SP and IdP when validating assertion timestamps.
		ClockSkew: 30 * time.Second,
	}

	// Step 5: Handle the SAML callback (ACS endpoint).
	http.HandleFunc("/v1/_saml_callback", func(rw http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		assertionInfo, err := s.RetrieveAssertionInfo(context.Background(), req.FormValue("SAMLResponse"))
		if err != nil {
			log.Printf("SAML validation error: %v", err)
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		fmt.Fprintf(rw, "NameID: %s\n", assertionInfo.NameID)
		fmt.Fprintf(rw, "Assertions:\n")
		for key, val := range assertionInfo.Values {
			fmt.Fprintf(rw, "  %s: %+v\n", key, val)
		}
	})

	// Step 6: Build the SSO URL and start the server.
	fmt.Println("Visit this URL to authenticate:")
	authURL, err := s.BuildAuthURL("")
	if err != nil {
		log.Fatalf("Error building auth URL: %v", err)
	}
	fmt.Println(authURL)

	fmt.Printf("  SP ACS URL      : %s\n", s.ACSURL)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

func randomKeyStoreForDemo() *saml2.KeyStore {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("Error creating self-signed certificate: %v", err)
	}

	return &saml2.KeyStore{
		Signer: key,
		Cert:   certBytes,
	}
}
