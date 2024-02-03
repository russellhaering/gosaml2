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

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"

	"encoding/base64"
	"encoding/pem"
	"encoding/xml"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

func main() {
	res, err := http.Get("http://idp.oktadev.com/metadata")
	if err != nil {
		panic(err)
	}

	rawMetadata, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	metadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, metadata)
	if err != nil {
		panic(err)
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				panic(fmt.Errorf("metadata certificate(%d) must not be empty", idx))
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				panic(err)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				panic(err)
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	// We sign the AuthnRequest with a random key because Okta doesn't seem
	// to verify these.
	randomKeyStore := dsig.RandomKeyStoreForTest()

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       "http://example.com/saml/acs/example",
		AssertionConsumerServiceURL: "http://localhost:8080/v1/_saml_callback",
		SignAuthnRequests:           true,
		AudienceURI:                 "http://example.com/saml/acs/example",
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  randomKeyStore,
		IdentityProviderSLOURL: metadata.IDPSSODescriptor.SingleLogoutServices[0].Location,
		ServiceProviderSLOURL: "http://localhost:8080/v1/_logout",
	}
	
	
//  generate sp private key, certificate this is used to sign the slo request for logout
	keystore, err := loadKeystore("<private key path>","<certificate path>")
	if err!=nil {
		fmt.Printf("Error loading keystore")
	}

	sp.SetSPSigningKeyStore(keystore)

	sessionIndex := ""
	nameID := ""

	http.HandleFunc("/v1/_saml_callback", func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		rw.Header().Add("Content-Type", "text/html")

		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		assertionInfo, err := sp.RetrieveAssertionInfo(req.FormValue("SAMLResponse"))
		
		sessionIndex = assertionInfo.SessionIndex
		nameID = assertionInfo.NameID

		if err != nil {
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		if assertionInfo.WarningInfo.InvalidTime {
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		if assertionInfo.WarningInfo.NotInAudience {
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		fmt.Fprintf(rw, "NameID: %s\n", assertionInfo.NameID)

		fmt.Fprintf(rw, "Assertions:\n")

		for key, val := range assertionInfo.Values {
			fmt.Fprintf(rw, "  %s: %+v\n", key, val)
		}

		fmt.Fprintf(rw, "\n")

		fmt.Fprintf(rw, "Warnings:\n")
		fmt.Fprintf(rw, "%+v\n", assertionInfo.WarningInfo)

		logoutRequest, err := sp.BuildLogoutRequestDocument(nameID, sessionIndex)

		logouturl , _ := sp.BuildLogoutURLRedirect("", logoutRequest)

		fmt.Fprintf(rw, " Click to logout <a href=%s> Logout </a>\n", logouturl)
	})

	http.HandleFunc("/v1/_logout", func(rw http.ResponseWriter, req *http.Request) {
		
		err := req.ParseForm()
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}


		response , err := sp.ValidateEncodedLogoutResponsePOST(req.FormValue("SAMLResponse"))
		fmt.Printf("the logout response %v\n", response.Status.StatusCode.Value)

		
		if err!=nil {
			fmt.Printf("Failed to logout %s \n", err)
			fmt.Fprintf(rw, "Couldn't log out %s due to some internal error",nameID)
		}else if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success"{
			fmt.Fprintf(rw, "Couldn't log out %s due to invalid request", nameID)
		}else{
			fmt.Fprintf(rw, "%s logged out successfully",nameID)
		}

	})

	println("Visit this URL To Authenticate:")
	authURL, err := sp.BuildAuthURL("")
	if err != nil {
		panic(err)
	}

	println(authURL)

	println("Supply:")
	fmt.Printf("  SP ACS URL      : %s\n", sp.AssertionConsumerServiceURL)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}


func loadKeystore(privateKeyPath, publicCertificate string) (*saml2.KeyStore, error){
	privateKeyBytes, err := os.ReadFile(privateKeyPath)

	if err != nil {
		fmt.Printf("There is some error reading the private key %v \n", err)
		return nil, err
	}

	certBytes, err := os.ReadFile(publicCertificate)

	if err != nil {
		fmt.Printf("There is some error reading the cert key %v \n", err)
		return nil, err
	}

	block, _ := pem.Decode(privateKeyBytes)

	if block == nil {
		fmt.Printf("Invalid Pem private key")
		panic("Invalid Pem private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err!=nil {
		fmt.Printf("There is some error signing parsing the private key: %v\n", err)
		return nil, err
	}

	keystore := &saml2.KeyStore{
		Signer: privateKey.(*rsa.PrivateKey),
		Cert: certBytes,
	}

	return keystore, nil
}