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

package fuzz

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2/v2"
	spkg "github.com/russellhaering/gosaml2/v2/sp"
	"github.com/russellhaering/gosaml2/v2/types"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
)

// fuzzKeyMaterial holds pre-generated cryptographic material for fuzz tests
// that need signature verification. Generated once per fuzz target.
type fuzzKeyMaterial struct {
	rsaKey     *rsa.PrivateKey
	ecKey      *ecdsa.PrivateKey
	rsaCert    *x509.Certificate
	ecCert     *x509.Certificate
	rsaCertDER []byte
	ecCertDER  []byte
	tlsCert    *tls.Certificate
	fakeTime   time.Time
}

func newFuzzKeyMaterial(f *testing.F) *fuzzKeyMaterial {
	f.Helper()
	fakeTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    fakeTime.Add(-time.Hour),
		NotAfter:     fakeTime.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	rsaCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		f.Fatal(err)
	}
	rsaCert, _ := x509.ParseCertificate(rsaCertDER)

	tmpl.SerialNumber = big.NewInt(2)
	ecCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		f.Fatal(err)
	}
	ecCert, _ := x509.ParseCertificate(ecCertDER)

	return &fuzzKeyMaterial{
		rsaKey:     rsaKey,
		ecKey:      ecKey,
		rsaCert:    rsaCert,
		ecCert:     ecCert,
		rsaCertDER: rsaCertDER,
		ecCertDER:  ecCertDER,
		tlsCert: &tls.Certificate{
			Certificate: [][]byte{rsaCertDER},
			PrivateKey:  rsaKey,
		},
		fakeTime: fakeTime,
	}
}

// signXML signs an etree element using the given key and cert, returning the signed element.
func signXML(el *etree.Element, key crypto.Signer, certs []*x509.Certificate) (*etree.Element, error) {
	signer := &dsig.Signer{
		Key:   key,
		Certs: certs,
		Hash:  crypto.SHA256,
	}
	return signer.SignEnveloped(el)
}

// makeResponseXML builds a valid SAML response XML for fuzzing.
func makeResponseXML(km *fuzzKeyMaterial) string {
	now := km.fakeTime
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://sp.example.com/acs"
    ID="_response_id_1"
    InResponseTo="_request_id_1"
    IssueInstant="%s"
    Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_assertion_id_1"
      IssueInstant="%s"
      Version="2.0">
    <saml2:Issuer>https://idp.example.com/</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData
            InResponseTo="_request_id_1"
            NotOnOrAfter="%s"
            Recipient="https://sp.example.com/acs"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction>
        <saml2:Audience>https://sp.example.com</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="%s" SessionIndex="_session_1">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
        <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user@example.com</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>`,
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
		now.Add(5*time.Minute).Format(time.RFC3339),
		now.Add(-5*time.Minute).Format(time.RFC3339),
		now.Add(5*time.Minute).Format(time.RFC3339),
		now.Format(time.RFC3339),
	)
}

// signedResponseB64 signs a response at the Response level and returns the base64-encoded result.
func signedResponseB64(f *testing.F, xml string, km *fuzzKeyMaterial) string {
	f.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes([]byte(xml)); err != nil {
		f.Fatal(err)
	}
	signed, err := signXML(doc.Root(), km.rsaKey, []*x509.Certificate{km.rsaCert})
	if err != nil {
		f.Fatal(err)
	}
	d2 := etree.NewDocument()
	d2.SetRoot(signed)
	b, _ := d2.WriteToBytes()
	return base64.StdEncoding.EncodeToString(b)
}

// fuzzSP creates a configured SP for fuzz tests that require validation.
func fuzzSP(km *fuzzKeyMaterial) *spkg.ServiceProvider {
	return &spkg.ServiceProvider{
		EntityID:        "https://sp.example.com",
		ACSURL:          "https://sp.example.com/acs",
		SLOURL:          "https://sp.example.com/slo",
		IDPEntityID:     "https://idp.example.com/",
		IDPSSOURL:       "https://idp.example.com/sso",
		IDPCertificates: []*x509.Certificate{km.rsaCert, km.ecCert},
		SPKeyStore: &saml2.KeyStore{
			Signer: km.rsaKey,
			Cert:   km.rsaCertDER,
		},
		AudienceURIs:     []string{"https://sp.example.com"},
		Clock:            func() time.Time { return km.fakeTime },
		ClockSkew:        60 * time.Second,
		AllowIDPInitiated: true,
	}
}

// seedResponseFiles adds the contents of files matching glob as seed corpus entries.
func seedResponseFiles(f *testing.F, glob string) {
	f.Helper()
	matches, err := filepath.Glob(glob)
	if err != nil {
		f.Fatal(err)
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
}

// deflateEncode DEFLATE-compresses and base64-encodes data for HTTP-Redirect binding.
func deflateEncode(data []byte) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(data)
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func FuzzDecodeResponse(f *testing.F) {
	// Seed with valid SAML-like structures to help the fuzzer
	f.Add([]byte(`<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer></saml2p:Response>`))
	f.Add([]byte(`<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0"><saml2:Issuer>test</saml2:Issuer><saml2:Subject><saml2:NameID>user@test.com</saml2:NameID></saml2:Subject></saml2:Assertion></saml2p:Response>`))

	// Seed with real-world SAML responses from various IdPs, plus the harvested
	// OSS corpus (responses, metadata, logout messages, and the _hostile
	// XML-attack documents alike — all interesting decoder inputs).
	seedResponseFiles(f, "../../testdata/*_response.xml")
	seedResponseFiles(f, "../../testdata/corpus/*/*.xml")

	f.Fuzz(func(t *testing.T, data []byte) {
		encodedResponse := base64.StdEncoding.EncodeToString(data)

		_, err := spkg.DecodeUnverifiedBaseResponse(encodedResponse)
		if err != nil {
			return
		}

		sp := &spkg.ServiceProvider{}
		_, _ = sp.ValidateEncodedResponse(context.Background(), encodedResponse)
	})
}

func FuzzLogoutResponse(f *testing.F) {
	f.Add([]byte(`<saml2p:LogoutResponse xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status></saml2p:LogoutResponse>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		encodedResponse := base64.StdEncoding.EncodeToString(data)

		_, err := spkg.DecodeUnverifiedLogoutResponse(encodedResponse)
		if err != nil {
			return
		}

		sp := &spkg.ServiceProvider{}
		_, _ = sp.ValidateEncodedLogoutResponsePOST(context.Background(), encodedResponse)
	})
}

func FuzzLogoutRequest(f *testing.F) {
	f.Add([]byte(`<saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer><saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">user@test.com</saml2:NameID></saml2p:LogoutRequest>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		encodedRequest := base64.StdEncoding.EncodeToString(data)

		sp := &spkg.ServiceProvider{
			InsecureSkipSignatureValidation: true,
		}
		_, _ = sp.ValidateEncodedLogoutRequestPOST(context.Background(), encodedRequest)
	})
}

func FuzzBuildRequest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 8 {
			return
		}

		idValue := binary.LittleEndian.Uint64(data[:8])
		relayState := string(data[8:])

		if len(relayState) == 0 {
			return
		}

		sp := &spkg.ServiceProvider{
			IDPSSOURL:        "https://idp.example.com/sso",
			IDPEntityID:      "https://idp.example.com/",
			ACSURL:           "https://sp.example.com/acs",
			AudienceURIs:     []string{"https://sp.example.com/audience"},
			EntityID:         "https://sp.example.com",
			SignAuthnRequests: idValue%2 == 0,
			ForceAuthn:       idValue%3 == 0,
			IsPassive:        idValue%5 == 0,
		}

		_, _ = sp.BuildAuthURL(relayState)
		_, _ = sp.BuildAuthRequest()
	})
}

// FuzzDecryptBytes exercises the EncryptedAssertion decryption path with
// arbitrary ciphertext. The RSA key decryption is expected to fail for random
// data, but this verifies no panics occur on any input.
func FuzzDecryptBytes(f *testing.F) {
	// Seed with various sizes
	f.Add([]byte{}, byte(0))
	f.Add(make([]byte, 1), byte(0))
	f.Add(make([]byte, 15), byte(0))
	f.Add(make([]byte, 16), byte(0))
	f.Add(make([]byte, 32), byte(0))
	f.Add(make([]byte, 64), byte(1))
	f.Add(make([]byte, 128), byte(2))

	// Generate a test RSA key once for the fuzz corpus
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		f.Fatal(err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	certB64 := base64.StdEncoding.EncodeToString(certBytes)

	// Pre-encrypt a valid AES key for the seed corpus
	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	encryptedKey, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	encKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)

	algorithms := []string{
		types.MethodAES128GCM,
		types.MethodAES192GCM,
		types.MethodAES256GCM,
		types.MethodAES128CBC,
		types.MethodAES256CBC,
		types.MethodTripleDESCBC,
		"",
		"http://unknown",
	}

	f.Fuzz(func(t *testing.T, cipherData []byte, algIdx byte) {
		alg := algorithms[int(algIdx)%len(algorithms)]

		ea := &types.EncryptedAssertion{
			EncryptionMethod: types.EncryptionMethod{Algorithm: alg},
			CipherValue:      base64.StdEncoding.EncodeToString(cipherData),
			EncryptedKey: types.EncryptedKey{
				EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
				CipherValue:      encKeyB64,
				X509Data:         certB64,
			},
		}

		// Must not panic
		_, _ = ea.DecryptBytes(tlsCert)
	})
}

// FuzzDecryptBytesValidKey exercises the decryption path where the symmetric
// key decryption succeeds but the ciphertext is fuzzed. This specifically
// targets the slice operations in the GCM/CBC code paths.
func FuzzDecryptBytesValidKey(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		f.Fatal(err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	certB64 := base64.StdEncoding.EncodeToString(certBytes)

	// Create a valid encrypted AES-128 key
	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	encryptedKey, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	encKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)

	// Seed: valid GCM ciphertext
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	validGCM := append(nonce, gcm.Seal(nil, nonce, []byte("<test/>"), nil)...)

	// Seed: valid CBC ciphertext
	iv := make([]byte, block.BlockSize())
	rand.Read(iv)
	padded := []byte("<test/>xxxxxxxxx") // 16 bytes, last byte = 9 (pad)
	padded[15] = 9
	cbcEnc := cipher.NewCBCEncrypter(block, iv)
	cbcCipher := make([]byte, 16)
	cbcEnc.CryptBlocks(cbcCipher, padded)
	validCBC := append(iv, cbcCipher...)

	f.Add(validGCM, true)
	f.Add(validCBC, false)
	f.Add([]byte{}, true)
	f.Add([]byte{}, false)
	f.Add(make([]byte, 1), true)
	f.Add(make([]byte, 16), false)
	f.Add(make([]byte, 28), true)  // GCM nonce(12) + tag(16) minimum
	f.Add(make([]byte, 32), false) // CBC minimum 2 blocks

	f.Fuzz(func(t *testing.T, cipherData []byte, useGCM bool) {
		alg := types.MethodAES128CBC
		if useGCM {
			alg = types.MethodAES128GCM
		}

		ea := &types.EncryptedAssertion{
			EncryptionMethod: types.EncryptionMethod{Algorithm: alg},
			CipherValue:      base64.StdEncoding.EncodeToString(cipherData),
			EncryptedKey: types.EncryptedKey{
				EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
				CipherValue:      encKeyB64,
				X509Data:         certB64,
			},
		}

		// Must not panic
		_, _ = ea.DecryptBytes(tlsCert)
	})
}

// FuzzRedirectBinding exercises the HTTP-Redirect binding signature verification
// and message decoding with arbitrary data.
func FuzzRedirectBinding(f *testing.F) {
	f.Add("dGVzdA==", "relay", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "dGVzdA==")
	f.Add("", "", "", "")
	f.Add("dGVzdA==", "", "", "")

	f.Fuzz(func(t *testing.T, encodedMessage, relayState, sigAlg, signature string) {
		sp := &spkg.ServiceProvider{
			InsecureSkipSignatureValidation: true,
		}

		_, _ = sp.ValidateEncodedLogoutResponseRedirect(
			context.Background(), encodedMessage, relayState, sigAlg, signature,
		)
		_, _ = sp.ValidateEncodedLogoutRequestRedirect(
			context.Background(), encodedMessage, relayState, sigAlg, signature,
		)
	})
}

// FuzzSignedResponse exercises the full ValidateEncodedResponse path with real
// XML signature verification enabled. The seed corpus contains a properly signed
// response; the fuzzer mutates the base64-encoded, signed XML. This is the most
// security-critical fuzz target — it covers signature wrapping attacks and
// xmldsig integration.
func FuzzSignedResponse(f *testing.F) {
	km := newFuzzKeyMaterial(f)
	sp := fuzzSP(km)

	// Build and sign a valid response as seed.
	validXML := makeResponseXML(km)
	validB64 := signedResponseB64(f, validXML, km)

	f.Add([]byte(validB64))
	// Also seed with the unsigned version.
	f.Add([]byte(base64.StdEncoding.EncodeToString([]byte(validXML))))

	f.Fuzz(func(t *testing.T, data []byte) {
		encoded := string(data)
		// Must not panic on any input, even with full validation enabled.
		_, _ = sp.ValidateEncodedResponse(context.Background(), encoded)
	})
}

// FuzzRetrieveAssertionInfo exercises the full RetrieveAssertionInfo path,
// which includes response validation, conditions checking, audience restriction,
// and attribute extraction. Uses real signature verification.
func FuzzRetrieveAssertionInfo(f *testing.F) {
	km := newFuzzKeyMaterial(f)
	sp := fuzzSP(km)

	validXML := makeResponseXML(km)
	validB64 := signedResponseB64(f, validXML, km)

	f.Add([]byte(validB64))
	f.Add([]byte(base64.StdEncoding.EncodeToString([]byte(validXML))))

	f.Fuzz(func(t *testing.T, data []byte) {
		encoded := string(data)
		// Must not panic. This exercises: ValidateEncodedResponse -> Validate ->
		// verifyAssertionConditions -> attribute extraction.
		_, _ = sp.RetrieveAssertionInfo(context.Background(), encoded)
	})
}

// FuzzParseEntityDescriptor exercises metadata XML parsing with arbitrary input.
func FuzzParseEntityDescriptor(f *testing.F) {
	// Seed with a realistic IdP metadata document.
	f.Add([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.example.com/">
  <IDPSSODescriptor WantAuthnRequestsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIB</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.com/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.com/sso-redirect"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.com/slo"/>
  </IDPSSODescriptor>
</EntityDescriptor>`))

	// Seed with an SP metadata document.
	f.Add([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://sp.example.com">
  <SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://sp.example.com/acs" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>`))

	// Empty and malformed inputs.
	f.Add([]byte{})
	f.Add([]byte(`<not-xml`))
	f.Add([]byte(`<EntityDescriptor/>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		ed, err := saml2.ParseEntityDescriptor(data)
		if err != nil {
			return
		}

		// Also exercise ConfigureFromMetadata to catch panics in endpoint selection.
		sp := &spkg.ServiceProvider{}
		_ = sp.ConfigureFromMetadata(ed)
	})
}

// FuzzDecryptSymmetricKey directly fuzzes EncryptedKey.DecryptSymmetricKey with
// various RSA key transport algorithms and digest methods.
func FuzzDecryptSymmetricKey(f *testing.F) {
	km := newFuzzKeyMaterial(f)

	// Seed: valid OAEP-encrypted key.
	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	validOAEP, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &km.rsaKey.PublicKey, aesKey, nil)

	// Seed: valid PKCS1v15-encrypted key.
	validPKCS, _ := rsa.EncryptPKCS1v15(rand.Reader, &km.rsaKey.PublicKey, aesKey)

	certB64 := base64.StdEncoding.EncodeToString(km.rsaCertDER)

	algorithms := []string{
		types.MethodRSAOAEP,
		types.MethodRSAOAEP2,
		types.MethodRSAv1_5,
		"",
		"http://unknown",
	}
	digests := []string{
		"",
		types.MethodSHA1,
		types.MethodSHA256,
		types.MethodSHA512,
		"http://unknown-digest",
	}

	f.Add(validOAEP, byte(0), byte(0), true)
	f.Add(validPKCS, byte(2), byte(0), true)
	f.Add([]byte{}, byte(0), byte(0), false)
	f.Add(make([]byte, 256), byte(1), byte(2), true)

	f.Fuzz(func(t *testing.T, cipherData []byte, algIdx, digestIdx byte, includeCert bool) {
		alg := algorithms[int(algIdx)%len(algorithms)]
		digest := digests[int(digestIdx)%len(digests)]

		ek := &types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{
				Algorithm: alg,
			},
			CipherValue: base64.StdEncoding.EncodeToString(cipherData),
		}

		if digest != "" {
			ek.EncryptionMethod.DigestMethod = &types.DigestMethod{Algorithm: digest}
		}

		if includeCert {
			ek.X509Data = certB64
		}

		// Must not panic.
		_, _ = ek.DecryptSymmetricKey(km.tlsCert)
	})
}

// FuzzRedirectSignatureVerification exercises the HTTP-Redirect binding with
// real RSA and ECDSA signature verification. The fuzzer mutates the signed
// query parameters to test the signature verification path.
func FuzzRedirectSignatureVerification(f *testing.F) {
	km := newFuzzKeyMaterial(f)

	rsaSP := &spkg.ServiceProvider{
		IDPCertificates: []*x509.Certificate{km.rsaCert},
		SLOURL:          "https://sp.example.com/slo",
		IDPEntityID:     "https://idp.example.com/",
		Clock:           func() time.Time { return km.fakeTime },
	}

	ecSP := &spkg.ServiceProvider{
		IDPCertificates: []*x509.Certificate{km.ecCert},
		SLOURL:          "https://sp.example.com/slo",
		IDPEntityID:     "https://idp.example.com/",
		Clock:           func() time.Time { return km.fakeTime },
	}

	// Build a valid DEFLATE-encoded logout response.
	logoutResp := fmt.Sprintf(`<saml2p:LogoutResponse xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
		Version="2.0" ID="_lr1" Destination="https://sp.example.com/slo"
		IssueInstant="%s">
		<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/</saml2:Issuer>
		<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
	</saml2p:LogoutResponse>`, km.fakeTime.Format(time.RFC3339))
	encodedMsg := deflateEncode([]byte(logoutResp))

	// Generate a valid RSA signature over the correct query string.
	sigAlgRSA := "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	signedString := "SAMLResponse=" + encodedMsg + "&SigAlg=" + sigAlgRSA
	h := sha256.Sum256([]byte(signedString))
	rsaSig, _ := rsa.SignPKCS1v15(rand.Reader, km.rsaKey, crypto.SHA256, h[:])
	rsaSigB64 := base64.StdEncoding.EncodeToString(rsaSig)

	// Generate a valid ECDSA signature.
	sigAlgEC := "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	signedStringEC := "SAMLResponse=" + encodedMsg + "&SigAlg=" + sigAlgEC
	hEC := sha256.Sum256([]byte(signedStringEC))
	ecSig, _ := ecdsa.SignASN1(rand.Reader, km.ecKey, hEC[:])
	ecSigB64 := base64.StdEncoding.EncodeToString(ecSig)

	f.Add(encodedMsg, "", sigAlgRSA, rsaSigB64, true)
	f.Add(encodedMsg, "relay", sigAlgRSA, rsaSigB64, true)
	f.Add(encodedMsg, "", sigAlgEC, ecSigB64, false)
	f.Add("", "", "", "", true)
	f.Add("dGVzdA==", "test", sigAlgRSA, "dGVzdA==", true)

	f.Fuzz(func(t *testing.T, encodedMessage, relayState, sigAlg, signature string, useRSA bool) {
		sp := rsaSP
		if !useRSA {
			sp = ecSP
		}

		// Must not panic with real signature verification.
		_, _ = sp.ValidateEncodedLogoutResponseRedirect(
			context.Background(), encodedMessage, relayState, sigAlg, signature,
		)
		_, _ = sp.ValidateEncodedLogoutRequestRedirect(
			context.Background(), encodedMessage, relayState, sigAlg, signature,
		)
	})
}

// FuzzResponseWithSignedAssertions exercises the unsigned-response +
// signed-assertions code path, which is a separate and complex branch
// in ValidateEncodedResponse.
func FuzzResponseWithSignedAssertions(f *testing.F) {
	km := newFuzzKeyMaterial(f)
	sp := fuzzSP(km)

	// Build a response and sign only the assertion (not the response envelope).
	validXML := makeResponseXML(km)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes([]byte(validXML)); err != nil {
		f.Fatal(err)
	}

	root := doc.Root()
	for _, child := range root.ChildElements() {
		if child.Tag == "Assertion" {
			signed, err := signXML(child.Copy(), km.rsaKey, []*x509.Certificate{km.rsaCert})
			if err != nil {
				f.Fatal(err)
			}
			root.RemoveChild(child)
			root.AddChild(signed)
		}
	}

	d2 := etree.NewDocument()
	d2.SetRoot(root)
	assertionSignedXML, _ := d2.WriteToBytes()
	assertionSignedB64 := base64.StdEncoding.EncodeToString(assertionSignedXML)

	f.Add([]byte(assertionSignedB64))

	f.Fuzz(func(t *testing.T, data []byte) {
		encoded := string(data)
		// Must not panic.
		_, _ = sp.ValidateEncodedResponse(context.Background(), encoded)
	})
}

// FuzzResponseXMLMutation specifically targets XML round-trip mutation attacks
// by providing valid responses with various XML constructs that might confuse
// parsers: comments, processing instructions, CDATA, entity references, and
// namespace redeclarations.
func FuzzResponseXMLMutation(f *testing.F) {
	km := newFuzzKeyMaterial(f)
	sp := fuzzSP(km)
	sp.InsecureSkipSignatureValidation = true // focus on XML parsing, not sig

	seeds := []string{
		// Normal response
		makeResponseXML(km),
		// With XML comments in assertion
		`<?xml version="1.0"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1" Destination="https://sp.example.com/acs"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z"><saml2:Issuer>https://idp.example.com/</saml2:Issuer><!-- comment --><saml2:Subject><saml2:NameID>user@example.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="2025-01-01T00:05:00Z" Recipient="https://sp.example.com/acs"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2024-12-31T23:55:00Z" NotOnOrAfter="2025-01-01T00:05:00Z"><saml2:AudienceRestriction><saml2:Audience>https://sp.example.com</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions></saml2:Assertion></saml2p:Response>`,
		// With namespace redeclaration
		`<?xml version="1.0"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_a1" Version="2.0"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion></saml2p:Response>`,
	}

	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	// Seed with real-world SAML responses from various IdPs, plus the harvested
	// OSS corpus (responses, metadata, logout messages, and the _hostile
	// XML-attack documents alike — all interesting decoder inputs).
	seedResponseFiles(f, "../../testdata/*_response.xml")
	seedResponseFiles(f, "../../testdata/corpus/*/*.xml")

	f.Fuzz(func(t *testing.T, data []byte) {
		encoded := base64.StdEncoding.EncodeToString(data)
		_, _ = sp.ValidateEncodedResponse(context.Background(), encoded)
		_, _ = sp.RetrieveAssertionInfo(context.Background(), encoded)
	})
}

// FuzzMetadataConfigureRoundTrip exercises the Metadata() -> ParseEntityDescriptor
// -> ConfigureFromMetadata round-trip with various SP configurations.
func FuzzMetadataConfigureRoundTrip(f *testing.F) {
	km := newFuzzKeyMaterial(f)

	f.Add("https://sp.example.com", "https://sp.example.com/acs", "https://sp.example.com/slo", true, true)
	f.Add("", "", "", false, false)
	f.Add("https://sp.test", "https://sp.test/acs", "", true, false)

	f.Fuzz(func(t *testing.T, entityID, acsURL, sloURL string, signRequests, wantEnc bool) {
		sp := &spkg.ServiceProvider{
			EntityID:         entityID,
			ACSURL:           acsURL,
			SLOURL:           sloURL,
			SignAuthnRequests: signRequests,
			Clock:            func() time.Time { return km.fakeTime },
		}

		if signRequests {
			sp.SPSigningKeyStore = &saml2.KeyStore{
				Signer: km.rsaKey,
				Cert:   km.rsaCertDER,
			}
		}
		if wantEnc {
			sp.SPKeyStore = &saml2.KeyStore{
				Signer: km.rsaKey,
				Cert:   km.rsaCertDER,
			}
		}

		// Must not panic.
		md, err := sp.Metadata()
		if err != nil {
			return
		}

		sp2 := &spkg.ServiceProvider{}
		_ = sp2.ConfigureFromMetadata(md)
	})
}

// FuzzEncryptedAssertionRoundTrip builds valid encrypted assertions with fuzzed
// plaintext XML, exercising the full decrypt -> unmarshal pipeline.
func FuzzEncryptedAssertionRoundTrip(f *testing.F) {
	km := newFuzzKeyMaterial(f)

	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	encryptedKey, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &km.rsaKey.PublicKey, aesKey, nil)
	encKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)
	certB64 := base64.StdEncoding.EncodeToString(km.rsaCertDER)

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)

	// Seed with valid assertion XML.
	assertionXML := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0"><saml2:Issuer>test</saml2:Issuer><saml2:Subject><saml2:NameID>user@test.com</saml2:NameID></saml2:Subject></saml2:Assertion>`
	f.Add([]byte(assertionXML))
	f.Add([]byte(`<not-assertion/>`))
	f.Add([]byte{})
	f.Add([]byte(`<?xml version="1.0"?><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a2" Version="2.0"><saml2:Issuer>test</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">test@test.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="2025-01-01T00:05:00Z" Recipient="https://sp.test/acs"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2024-12-31T23:55:00Z" NotOnOrAfter="2025-01-01T00:05:00Z"><saml2:AudienceRestriction><saml2:Audience>https://sp.test</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions></saml2:Assertion>`))

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		// Encrypt the fuzzed plaintext with GCM.
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)
		ciphertext := append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...)

		ea := &types.EncryptedAssertion{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
			CipherValue:      base64.StdEncoding.EncodeToString(ciphertext),
			EncryptedKey: types.EncryptedKey{
				EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
				CipherValue:      encKeyB64,
				X509Data:         certB64,
			},
		}

		// Must not panic on any plaintext content.
		_, _ = ea.Decrypt(km.tlsCert)
	})
}

// FuzzBuildLogoutRequest exercises logout request construction with fuzzed
// NameID and SessionIndex values.
func FuzzBuildLogoutRequest(f *testing.F) {
	km := newFuzzKeyMaterial(f)

	f.Add("user@test.com", "_session_1", "relay", true)
	f.Add("", "", "", false)
	f.Add("<script>alert(1)</script>", "'; DROP TABLE--", "&relay=evil", true)

	f.Fuzz(func(t *testing.T, nameID, sessionIndex, relayState string, sign bool) {
		sp := &spkg.ServiceProvider{
			EntityID:         "https://sp.example.com",
			ACSURL:           "https://sp.example.com/acs",
			SLOURL:           "https://sp.example.com/slo",
			IDPEntityID:      "https://idp.example.com/",
			IDPSLOURL:        "https://idp.example.com/slo",
			SignAuthnRequests: sign,
			Clock:            func() time.Time { return km.fakeTime },
		}

		if sign {
			sp.SPKeyStore = &saml2.KeyStore{
				Signer: km.rsaKey,
				Cert:   km.rsaCertDER,
			}
		}

		// Must not panic.
		doc, err := sp.BuildLogoutRequestDocument(nameID, sessionIndex)
		if err != nil {
			return
		}

		if relayState != "" {
			_, _ = sp.BuildLogoutBodyPostFromDocument(relayState, doc)
			_, _ = sp.BuildLogoutURLRedirect(relayState, doc)
		}
	})
}

// FuzzBuildLogoutResponse exercises logout response construction with fuzzed
// status codes and request IDs.
func FuzzBuildLogoutResponse(f *testing.F) {
	km := newFuzzKeyMaterial(f)

	f.Add("urn:oasis:names:tc:SAML:2.0:status:Success", "_req_1", "relay")
	f.Add("", "", "")
	f.Add("urn:oasis:names:tc:SAML:2.0:status:PartialLogout", "_req_2", "<script>")

	f.Fuzz(func(t *testing.T, status, reqID, relayState string) {
		sp := &spkg.ServiceProvider{
			EntityID:    "https://sp.example.com",
			SLOURL:      "https://sp.example.com/slo",
			IDPEntityID: "https://idp.example.com/",
			IDPSLOURL:   "https://idp.example.com/slo",
			SPKeyStore: &saml2.KeyStore{
				Signer: km.rsaKey,
				Cert:   km.rsaCertDER,
			},
			Clock: func() time.Time { return km.fakeTime },
		}

		doc, err := sp.BuildLogoutResponseDocument(status, reqID)
		if err != nil {
			return
		}

		if relayState != "" {
			_, _ = sp.BuildLogoutResponseBodyPostFromDocument(relayState, doc)
		}
	})
}

// FuzzValidateEncodedResponseWithEncryption exercises the full response
// validation path including encrypted assertions with a properly configured SP.
func FuzzValidateEncodedResponseWithEncryption(f *testing.F) {
	km := newFuzzKeyMaterial(f)

	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	encryptedKeyBytes, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &km.rsaKey.PublicKey, aesKey, nil)

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)

	// Build a response with an encrypted assertion seed.
	assertionXML := fmt.Sprintf(`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" IssueInstant="%s" Version="2.0"><saml2:Issuer>https://idp.example.com/</saml2:Issuer><saml2:Subject><saml2:NameID>user@example.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="https://sp.example.com/acs"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml2:AudienceRestriction><saml2:Audience>https://sp.example.com</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions></saml2:Assertion>`,
		km.fakeTime.Format(time.RFC3339),
		km.fakeTime.Add(5*time.Minute).Format(time.RFC3339),
		km.fakeTime.Add(-5*time.Minute).Format(time.RFC3339),
		km.fakeTime.Add(5*time.Minute).Format(time.RFC3339),
	)

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ciphertext := append(nonce, gcm.Seal(nil, nonce, []byte(assertionXML), nil)...)

	encResponse := fmt.Sprintf(`<?xml version="1.0"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    Destination="https://sp.example.com/acs" ID="_r1" Version="2.0"
    IssueInstant="%s">
  <saml2:Issuer>https://idp.example.com/</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="%s"/>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="%s"/>
          <ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
          <xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData>
        </xenc:EncryptedKey>
      </ds:KeyInfo>
      <xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData>
    </xenc:EncryptedData>
  </saml2:EncryptedAssertion>
</saml2p:Response>`,
		km.fakeTime.Format(time.RFC3339),
		types.MethodAES128GCM,
		types.MethodRSAOAEP,
		base64.StdEncoding.EncodeToString(km.rsaCertDER),
		base64.StdEncoding.EncodeToString(encryptedKeyBytes),
		base64.StdEncoding.EncodeToString(ciphertext),
	)

	f.Add([]byte(encResponse))

	sp := &spkg.ServiceProvider{
		EntityID:    "https://sp.example.com",
		ACSURL:      "https://sp.example.com/acs",
		IDPEntityID: "https://idp.example.com/",
		SPKeyStore: &saml2.KeyStore{
			Signer: km.rsaKey,
			Cert:   km.rsaCertDER,
		},
		AudienceURIs:                    []string{"https://sp.example.com"},
		InsecureSkipSignatureValidation: true,
		Clock:                           func() time.Time { return km.fakeTime },
		ClockSkew:                       60 * time.Second,
		AllowIDPInitiated:               true,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		encoded := base64.StdEncoding.EncodeToString(data)
		// Must not panic. Exercises decryptAssertions path.
		_, _ = sp.ValidateEncodedResponse(context.Background(), encoded)
	})
}
