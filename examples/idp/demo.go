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

// demo is a minimal SAML Identity Provider example. It handles AuthnRequests
// from a configured Service Provider and returns SAML responses with a
// hardcoded user identity. In production, the user would be authenticated
// against a real user store.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"log"
	"math/big"
	"net/http"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/idp"
	"github.com/russellhaering/gosaml2/v2/types"
)

func main() {
	// Step 1: Generate a signing key for this demo. In production, use a
	// persistent key pair loaded from a file or secret store.
	signingKey := generateKeyStoreForDemo()

	// Step 2: Configure the Identity Provider with a known SP.
	identity := &idp.IdentityProvider{
		EntityID:       "http://localhost:9090/metadata",
		SSOURL:         "http://localhost:9090/sso",
		SigningKeyStore: signingKey,
		SignResponses:   true,
		SignAssertions:  true,
		ServiceProviders: map[string]*idp.SPConfig{
			// Register the SP that will send AuthnRequests to this IdP.
			"http://example.com/saml/acs/example": {
				EntityID: "http://example.com/saml/acs/example",
				ACSURLs:  []string{"http://localhost:8080/v1/_saml_callback"},
			},
		},
	}

	// Step 3: Metadata endpoint — SPs fetch this to configure themselves.
	http.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		md, err := identity.Metadata()
		if err != nil {
			http.Error(w, "Error generating metadata", http.StatusInternalServerError)
			return
		}
		xmlBytes, err := xml.MarshalIndent(md, "", "  ")
		if err != nil {
			http.Error(w, "Error serializing metadata", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Write(xmlBytes)
	})

	// Step 4: SSO endpoint — handles AuthnRequests via POST and Redirect bindings.
	http.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		var reqInfo *idp.AuthnRequestInfo
		var err error

		switch r.Method {
		case http.MethodPost:
			// HTTP-POST binding: AuthnRequest is base64-encoded in the form body.
			reqInfo, err = identity.ValidateEncodedAuthnRequestPOST(
				context.Background(), r.FormValue("SAMLRequest"))
		case http.MethodGet:
			// HTTP-Redirect binding: AuthnRequest is in query parameters.
			reqInfo, err = identity.ValidateEncodedAuthnRequestRedirect(
				context.Background(),
				r.URL.Query().Get("SAMLRequest"),
				r.URL.Query().Get("RelayState"),
				r.URL.Query().Get("SigAlg"),
				r.URL.Query().Get("Signature"))
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if err != nil {
			log.Printf("AuthnRequest validation error: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// In production, authenticate the user here (check session, show
		// login form, etc.). For this demo, we use a hardcoded identity.
		params := &idp.AssertionParams{
			NameID:       "demo-user@example.com",
			InResponseTo: reqInfo.ID,
			Recipient:    reqInfo.ACSURL,
			Attributes: []types.Attribute{
				{
					Name: "email",
					Values: []types.AttributeValue{
						{Type: "xs:string", Value: "demo-user@example.com"},
					},
				},
				{
					Name: "displayName",
					Values: []types.AttributeValue{
						{Type: "xs:string", Value: "Demo User"},
					},
				},
			},
		}

		// Build the SAML response as an HTML auto-submit POST form.
		body, err := identity.BuildResponseBodyPost(
			reqInfo.SP.EntityID, params, r.FormValue("RelayState"))
		if err != nil {
			log.Printf("Error building SAML response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write(body)
	})

	fmt.Println("IdP running on http://localhost:9090")
	fmt.Println("  Metadata: http://localhost:9090/metadata")
	fmt.Println("  SSO:      http://localhost:9090/sso")

	if err := http.ListenAndServe(":9090", nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

func generateKeyStoreForDemo() *saml2.KeyStore {
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
