package saml2

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestMakeEncryptedAssertion(t *testing.T) {
	var err error
	cert, err := tls.LoadX509KeyPair("./testdata/test.crt", "./testdata/test.key")
	require.NoError(t, err, "could not load x509 key pair")

	block, _ := pem.Decode([]byte(idpCert))

	idpCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse idp cert pem block")

	sp := SAMLServiceProvider{
		SPKeyStore:             dsig.TLSCertKeyStore(cert),
		ValidateEncryptionCert: false,
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{idpCert},
		},
		Clock: dsig.NewFakeClockAt(time.Date(2016, 04, 28, 22, 00, 00, 00, time.UTC)),
	}

	responseData := SAMLResponseData{
		Picker:               "MyPicker",
		ZipCode:              "12345",
		SiteID:               "TV_Cust_01",
		RequestID:            "RequestID",
		ConcurrencyRule:      "ConcurrencyRule",
		EToken:               "EToken",
		SPID:                 "SPID",
		Email:                "Email",
		AssertionConsumerURL: "AssertionConsumerURL",
		IssuerName:           "issuer.test.org",
	}

	doc, err := sp.BuildResponseDocument(responseData)
	require.NoError(t, err, "SAML Response should be generated with no error")

	s, _ := doc.WriteToString()
	fmt.Println(s)
}
