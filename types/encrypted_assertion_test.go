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

package types

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func newTestTLSCert(t *testing.T) *tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gosaml2 test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %s", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

// newTestEncryptedAssertion builds an EncryptedAssertion whose EncryptedKey
// decrypts successfully against cert, so that DecryptBytes reaches the
// symmetric decryption branch under test with cipherValue as the raw
// (not base64-encoded) EncryptedData CipherValue.
func newTestEncryptedAssertion(t *testing.T, cert *tls.Certificate, algorithm string, cipherValue []byte) *EncryptedAssertion {
	t.Helper()

	pub := cert.PrivateKey.(*rsa.PrivateKey).Public().(*rsa.PublicKey)

	aesKey := make([]byte, 16)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("generating AES key: %s", err)
	}

	wrappedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		t.Fatalf("wrapping AES key: %s", err)
	}

	return &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{Algorithm: algorithm},
		EncryptedKey: EncryptedKey{
			CipherValue:      base64.StdEncoding.EncodeToString(wrappedKey),
			EncryptionMethod: EncryptionMethod{Algorithm: MethodRSAOAEP},
		},
		CipherValue: base64.StdEncoding.EncodeToString(cipherValue),
	}
}

func TestDecryptBytesShortCipherTextDoesNotPanic(t *testing.T) {
	cert := newTestTLSCert(t)

	tests := []struct {
		name        string
		algorithm   string
		cipherValue []byte
	}{
		{"GCM empty", MethodAES128GCM, []byte{}},
		{"GCM shorter than nonce", MethodAES128GCM, []byte{0x01, 0x02, 0x03}},
		{"CBC empty", MethodAES128CBC, []byte{}},
		{"CBC shorter than block size", MethodAES128CBC, []byte{0x01, 0x02, 0x03}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := newTestEncryptedAssertion(t, cert, tt.algorithm, tt.cipherValue)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DecryptBytes panicked: %v", r)
				}
			}()

			_, err := ea.DecryptBytes(cert)
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
		})
	}
}
