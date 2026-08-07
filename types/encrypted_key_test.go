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
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"hash"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testCertificate generates a test RSA key pair and certificate for testing
func testCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year from now
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	return cert, certBytes
}

func TestEncryptedKeyXMLNamespaceDigestMethods(t *testing.T) {
	cert, certBytes := testCertificate(t)

	testCases := []struct {
		name           string
		digestMethod   string
		shouldSucceed  bool
		description    string
	}{
		{
			name:           "xmldsig SHA-256",
			digestMethod:   MethodSHA256,
			shouldSucceed:  true,
			description:    "Original xmldsig namespace should work",
		},
		{
			name:           "xmldsig SHA-512",
			digestMethod:   MethodSHA512,
			shouldSucceed:  true,
			description:    "Original xmldsig namespace should work",
		},
		{
			name:           "xmlenc SHA-256",
			digestMethod:   MethodSHA256Enc,
			shouldSucceed:  true,
			description:    "xmlenc namespace variant should work (RFC 9231)",
		},
		{
			name:           "xmlenc SHA-512",
			digestMethod:   MethodSHA512Enc,
			shouldSucceed:  true,
			description:    "xmlenc namespace variant should work (RFC 9231)",
		},
		{
			name:           "xmldsig SHA-1",
			digestMethod:   MethodSHA1,
			shouldSucceed:  true,
			description:    "SHA-1 should still work for backwards compatibility",
		},
		{
			name:           "unsupported digest method",
			digestMethod:   "http://example.com/unsupported",
			shouldSucceed:  false,
			description:    "Unsupported methods should fail",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a minimal encrypted key with the specified digest method
			encryptedKey := EncryptedKey{
				X509Data: base64.StdEncoding.EncodeToString(certBytes),
				EncryptionMethod: EncryptionMethod{
					Algorithm: MethodRSAOAEP,
					DigestMethod: &DigestMethod{
						Algorithm: tc.digestMethod,
					},
				},
			}

			// Create dummy cipher data (we're not actually decrypting, just testing digest method handling)
			encryptedKey.CipherValue = base64.StdEncoding.EncodeToString([]byte("dummy-cipher-data-for-testing"))

			_, err := encryptedKey.DecryptSymmetricKey(&cert)

			if tc.shouldSucceed {
				// We expect this to fail at the decryption stage (not digest method stage)
				// The important thing is it shouldn't fail with "unsupported digest algorithm"
				if err != nil {
					require.NotContains(t, err.Error(), "unsupported digest algorithm",
						"%s: should not reject supported digest method - %s", tc.description, tc.digestMethod)
				}
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "unsupported digest algorithm",
					"%s: should reject unsupported digest method - %s", tc.description, tc.digestMethod)
			}
		})
	}
}

func TestEncryptedKeyNilDigestMethod(t *testing.T) {
	cert, certBytes := testCertificate(t)

	encryptedKey := EncryptedKey{
		X509Data: base64.StdEncoding.EncodeToString(certBytes),
		EncryptionMethod: EncryptionMethod{
			Algorithm:    MethodRSAOAEP,
			DigestMethod: nil, // nil digest method should default to SHA-1
		},
	}
	encryptedKey.CipherValue = base64.StdEncoding.EncodeToString([]byte("dummy-cipher-data-for-testing"))

	_, err := encryptedKey.DecryptSymmetricKey(&cert)
	// Should fail at decryption stage, not digest method stage
	if err != nil {
		require.NotContains(t, err.Error(), "unsupported digest algorithm",
			"nil digest method should default to SHA-1 without error")
	}
}

func TestEncryptedKeyEmptyStringDigestMethod(t *testing.T) {
	cert, certBytes := testCertificate(t)

	encryptedKey := EncryptedKey{
		X509Data: base64.StdEncoding.EncodeToString(certBytes),
		EncryptionMethod: EncryptionMethod{
			Algorithm: MethodRSAOAEP,
			DigestMethod: &DigestMethod{
				Algorithm: "", // empty string should be treated as SHA-1
			},
		},
	}
	encryptedKey.CipherValue = base64.StdEncoding.EncodeToString([]byte("dummy-cipher-data-for-testing"))

	_, err := encryptedKey.DecryptSymmetricKey(&cert)
	// Should fail at decryption stage, not digest method stage
	if err != nil {
		require.NotContains(t, err.Error(), "unsupported digest algorithm",
			"empty string digest method should be treated as SHA-1 without error")
	}
}

func TestEncryptedKeyEndToEndEncryptionDecryption(t *testing.T) {
	cert, certBytes := testCertificate(t)

	// Test that the correct hash function is selected by performing actual RSA-OAEP encryption/decryption
	testCases := []struct {
		name         string
		digestMethod string
		hashFunc     func() hash.Hash
	}{
		{
			name:         "xmldsig SHA-256",
			digestMethod: MethodSHA256,
			hashFunc:     sha256.New,
		},
		{
			name:         "xmlenc SHA-256",
			digestMethod: MethodSHA256Enc,
			hashFunc:     sha256.New,
		},
		{
			name:         "xmldsig SHA-512",
			digestMethod: MethodSHA512,
			hashFunc:     sha512.New,
		},
		{
			name:         "xmlenc SHA-512",
			digestMethod: MethodSHA512Enc,
			hashFunc:     sha512.New,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a random plaintext
			plaintext := make([]byte, 32)
			_, err := rand.Read(plaintext)
			require.NoError(t, err)

			// Encrypt using RSA-OAEP with the specified hash function
			rsaKey := cert.PrivateKey.(*rsa.PrivateKey)
			ciphertext, err := rsa.EncryptOAEP(tc.hashFunc(), rand.Reader, &rsaKey.PublicKey, plaintext, nil)
			require.NoError(t, err, "encryption should succeed with hash function %s", tc.digestMethod)

			// Create an encrypted key that would use the specified digest method for decryption
			encryptedKey := EncryptedKey{
				X509Data: base64.StdEncoding.EncodeToString(certBytes),
				EncryptionMethod: EncryptionMethod{
					Algorithm: MethodRSAOAEP,
					DigestMethod: &DigestMethod{
						Algorithm: tc.digestMethod,
					},
				},
				CipherValue: base64.StdEncoding.EncodeToString(ciphertext),
			}

			// Decrypt - this should succeed because we're using the same hash function
			block, err := encryptedKey.DecryptSymmetricKey(&cert)
			require.NoError(t, err, "decryption should succeed with digest method %s", tc.digestMethod)
			require.NotNil(t, block, "should return a valid cipher block")
		})
	}
}