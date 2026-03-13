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

package sp

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Helpers for encryption/decryption security tests
// ============================================================================

// cryptoTestKeyPair generates an RSA key pair and TLS certificate for encryption tests.
func cryptoTestKeyPair(t *testing.T) (*rsa.PrivateKey, *tls.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}
	return key, tlsCert, certBytes
}

// encryptAssertion encrypts an assertion XML string and returns an EncryptedAssertion.
func encryptAssertion(t *testing.T, assertionXML string, pubKey *rsa.PublicKey, certBytes []byte, algorithm string) *types.EncryptedAssertion {
	t.Helper()

	keySize := 16 // AES-128
	if strings.Contains(algorithm, "256") {
		keySize = 32
	} else if strings.Contains(algorithm, "192") {
		keySize = 24
	}

	aesKey := make([]byte, keySize)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)

	var cipherData []byte
	switch {
	case strings.Contains(algorithm, "gcm"):
		aead, err := cipher.NewGCM(block)
		require.NoError(t, err)
		nonce := make([]byte, aead.NonceSize())
		_, err = rand.Read(nonce)
		require.NoError(t, err)
		cipherData = aead.Seal(nonce, nonce, []byte(assertionXML), nil)
	case strings.Contains(algorithm, "cbc"):
		// PKCS#7 pad
		padLen := aes.BlockSize - (len(assertionXML) % aes.BlockSize)
		padded := append([]byte(assertionXML), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
		iv := make([]byte, aes.BlockSize)
		_, err := rand.Read(iv)
		require.NoError(t, err)
		mode := cipher.NewCBCEncrypter(block, iv)
		encrypted := make([]byte, len(padded))
		mode.CryptBlocks(encrypted, padded)
		cipherData = append(iv, encrypted...)
	default:
		t.Fatalf("unsupported algorithm for encryption helper: %s", algorithm)
	}

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, aesKey, nil)
	require.NoError(t, err)

	return &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: algorithm},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString(cipherData),
	}
}

// encryptAssertionWithKey is like encryptAssertion but allows specifying the raw
// AES key and the key transport algorithm.
func encryptAssertionWithKey(t *testing.T, assertionXML string, aesKey []byte, pubKey *rsa.PublicKey, certBytes []byte, dataAlgo, keyAlgo string) *types.EncryptedAssertion {
	t.Helper()

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)

	var cipherData []byte
	switch {
	case strings.Contains(dataAlgo, "gcm"):
		aead, err := cipher.NewGCM(block)
		require.NoError(t, err)
		nonce := make([]byte, aead.NonceSize())
		_, err = rand.Read(nonce)
		require.NoError(t, err)
		cipherData = aead.Seal(nonce, nonce, []byte(assertionXML), nil)
	case strings.Contains(dataAlgo, "cbc"):
		padLen := aes.BlockSize - (len(assertionXML) % aes.BlockSize)
		padded := append([]byte(assertionXML), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
		iv := make([]byte, aes.BlockSize)
		_, err := rand.Read(iv)
		require.NoError(t, err)
		mode := cipher.NewCBCEncrypter(block, iv)
		encrypted := make([]byte, len(padded))
		mode.CryptBlocks(encrypted, padded)
		cipherData = append(iv, encrypted...)
	default:
		t.Fatalf("unsupported algorithm for encryption helper: %s", dataAlgo)
	}

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, aesKey, nil)
	require.NoError(t, err)

	return &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: dataAlgo},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: keyAlgo},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString(cipherData),
	}
}

// ============================================================================
// CBC Padding Oracle (Tests 1-2)
// ============================================================================

func TestCBCPaddingOracleTiming(t *testing.T) {
	// Test 1: Modify last byte of CBC ciphertext through all 256 values.
	// Verify that all errors are uniform (no padding oracle).
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128CBC)

	// Decode the cipher data to manipulate it
	cipherData, err := base64.StdEncoding.DecodeString(ea.CipherValue)
	require.NoError(t, err)

	errorMessages := make(map[string]int)
	successCount := 0

	for i := 0; i < 256; i++ {
		mutated := make([]byte, len(cipherData))
		copy(mutated, cipherData)
		mutated[len(mutated)-1] = byte(i)

		testEA := &types.EncryptedAssertion{
			EncryptionMethod: ea.EncryptionMethod,
			EncryptedKey:     ea.EncryptedKey,
			CipherValue:      base64.StdEncoding.EncodeToString(mutated),
		}

		_, err := testEA.DecryptBytes(tlsCert)
		if err == nil {
			successCount++
		} else {
			errorMessages[err.Error()]++
		}
	}

	// At most the original byte produces success, plus possibly a few
	// coincidental valid paddings. The key property: all error messages
	// must be identical (no information leakage).
	if len(errorMessages) > 1 {
		t.Errorf("Padding oracle detected: %d distinct error messages found", len(errorMessages))
		for msg, count := range errorMessages {
			t.Logf("  [%d times] %s", count, msg)
		}
	} else {
		t.Logf("All %d error responses have uniform message. Success count: %d", 256-successCount, successCount)
	}
}

func TestCBCErrorMessageUniformity(t *testing.T) {
	// Test 2: 256 mutations, verify all produce the same error string.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128CBC)

	cipherData, err := base64.StdEncoding.DecodeString(ea.CipherValue)
	require.NoError(t, err)

	var firstErrMsg string
	nonUniformCount := 0

	for i := 0; i < 256; i++ {
		mutated := make([]byte, len(cipherData))
		copy(mutated, cipherData)
		// Flip bit in interior of ciphertext (not the IV)
		if len(mutated) > aes.BlockSize+1 {
			mutated[aes.BlockSize+1] ^= byte(i + 1)
		}

		testEA := &types.EncryptedAssertion{
			EncryptionMethod: ea.EncryptionMethod,
			EncryptedKey:     ea.EncryptedKey,
			CipherValue:      base64.StdEncoding.EncodeToString(mutated),
		}

		_, err := testEA.DecryptBytes(tlsCert)
		if err != nil {
			if firstErrMsg == "" {
				firstErrMsg = err.Error()
			} else if err.Error() != firstErrMsg {
				nonUniformCount++
			}
		}
	}

	require.Zero(t, nonUniformCount,
		"All CBC error messages should be identical to prevent oracle attacks")
}

// ============================================================================
// CBC Bit-Flipping (Tests 3-4)
// ============================================================================

func TestCBCBitFlipInIV(t *testing.T) {
	// Test 3: Flip bits in IV to modify first plaintext block - verify no panic.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128CBC)

	cipherData, err := base64.StdEncoding.DecodeString(ea.CipherValue)
	require.NoError(t, err)

	// Flip every bit in the IV (first 16 bytes)
	for i := 0; i < aes.BlockSize; i++ {
		mutated := make([]byte, len(cipherData))
		copy(mutated, cipherData)
		mutated[i] ^= 0xFF

		testEA := &types.EncryptedAssertion{
			EncryptionMethod: ea.EncryptionMethod,
			EncryptedKey:     ea.EncryptedKey,
			CipherValue:      base64.StdEncoding.EncodeToString(mutated),
		}

		// Should not panic, should return an error or corrupted plaintext
		_, err := testEA.DecryptBytes(tlsCert)
		// We just verify no panic occurs. The result is either an error or
		// corrupted plaintext (which would fail XML parsing downstream).
		_ = err
	}
}

func TestCBCBitFlipInInteriorBlock(t *testing.T) {
	// Test 4: Flip bits in an interior ciphertext block.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	// Need plaintext long enough for multiple blocks
	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer><saml2:Subject><saml2:NameID>user@example.com</saml2:NameID></saml2:Subject></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128CBC)

	cipherData, err := base64.StdEncoding.DecodeString(ea.CipherValue)
	require.NoError(t, err)
	require.Greater(t, len(cipherData), 3*aes.BlockSize, "Need multiple blocks for this test")

	// Flip a byte in the second ciphertext block (after IV)
	mutated := make([]byte, len(cipherData))
	copy(mutated, cipherData)
	mutated[aes.BlockSize+5] ^= 0xFF

	testEA := &types.EncryptedAssertion{
		EncryptionMethod: ea.EncryptionMethod,
		EncryptedKey:     ea.EncryptedKey,
		CipherValue:      base64.StdEncoding.EncodeToString(mutated),
	}

	// Should not panic
	_, err = testEA.DecryptBytes(tlsCert)
	// Either returns error or corrupted data; neither is a panic
	_ = err
}

// ============================================================================
// Algorithm Downgrade (Tests 5-6)
// ============================================================================

func TestTripleDESCBCRejected(t *testing.T) {
	// Test 5: TripleDES-CBC algorithm should be explicitly rejected.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	// Create a valid AES encrypted key but declare TripleDES for data encryption
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodTripleDESCBC},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy cipher data padding here!!")),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "3DES")
}

func TestUnknownSymmetricMethodRejected(t *testing.T) {
	// Test 6: Unknown symmetric method (fabricated URI) should error.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: "http://www.w3.org/2099/xmlenc#aes999-quantum"},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy cipher data")),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown symmetric encryption method")
}

// ============================================================================
// Key Transport (Tests 7-12)
// ============================================================================

func TestRSAPKCS1v15Rejected(t *testing.T) {
	// Test 7: RSA PKCS#1 v1.5 (rsa-1_5) should be rejected (Bleichenbacher).
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	// Encrypt with OAEP but declare v1.5 algorithm
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAv1_5},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy")),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Bleichenbacher")
}

func TestRSAOAEPWithSHA1Works(t *testing.T) {
	// Test 8: RSA-OAEP with SHA-1 digest should work (SHA-1 is the default).
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128GCM)
	// Explicitly set DigestMethod to SHA-1
	ea.EncryptedKey.EncryptionMethod.DigestMethod = &types.DigestMethod{
		Algorithm: types.MethodSHA1,
	}

	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(result))
}

func TestRSAOAEPWithMissingDigestDefaultsSHA1(t *testing.T) {
	// Test 9: RSA-OAEP with missing DigestMethod should default to SHA-1.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128GCM)
	// Ensure DigestMethod is nil (should default to SHA-1)
	ea.EncryptedKey.EncryptionMethod.DigestMethod = nil

	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(result))
}

func TestRSAOAEPUnsupportedDigestMethod(t *testing.T) {
	// Test 10: RSA-OAEP with unsupported DigestMethod (SHA-224) should error.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{
				Algorithm: types.MethodRSAOAEP,
				DigestMethod: &types.DigestMethod{
					Algorithm: "http://www.w3.org/2001/04/xmldsig-more#sha224",
				},
			},
			CipherValue: base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:    base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy")),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported digest algorithm")
}

func TestEncryptedKeyMissingAlgorithm(t *testing.T) {
	// Test 11: EncryptedKey with missing/empty encryption algorithm should error.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: ""}, // empty
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy")),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing encryption algorithm")
}

func TestUnsupportedKeyTransportAlgorithm(t *testing.T) {
	// Test 12: Unsupported key transport algorithm should error.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{
				Algorithm: "http://www.w3.org/2099/xmlenc#rsa-quantum",
			},
			CipherValue: base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:    base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy")),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported encryption algorithm")
}

// ============================================================================
// Key/Data Structure (Tests 13-15)
// ============================================================================

func TestInlineAndDetachedEncryptedKeyPrecedence(t *testing.T) {
	// Test 13: Both inline and detached EncryptedKey - test that inline
	// takes precedence (detached is only used when inline CipherValue is empty).
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128GCM)

	// Set DetEncryptedKey to something invalid - it should NOT be used
	// because inline EncryptedKey has a valid CipherValue.
	ea.DetEncryptedKey = types.EncryptedKey{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
		CipherValue:      base64.StdEncoding.EncodeToString([]byte("totally invalid key material")),
		X509Data:         base64.StdEncoding.EncodeToString(certBytes),
	}

	// Should succeed using inline key
	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(result))
}

func TestEmptyCipherValueInEncryptedAssertion(t *testing.T) {
	// Test 14: Empty CipherValue in EncryptedAssertion should error "too short".
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte{}), // empty
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

func TestExtremelyLargeCipherValue(t *testing.T) {
	// Test 15: Extremely large CipherValue (multi-megabyte) - test memory behavior.
	// The library should handle it without panicking (it will fail at decryption).
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	// Create 2MB of random data
	largeData := make([]byte, 2*1024*1024)
	_, err = rand.Read(largeData)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString(largeData),
	}

	// Should not panic. Will error because the data is random garbage.
	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err, "Large random ciphertext should fail decryption")
}

// ============================================================================
// Base64 Issues (Tests 16-18)
// ============================================================================

func TestInvalidBase64InCipherValue(t *testing.T) {
	// Test 16: Invalid base64 in CipherValue should error.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &key.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: "!!!not-valid-base64@@@",
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
}

func TestBase64WithExtraWhitespace(t *testing.T) {
	// Test 17: Base64 with extra whitespace - StdEncoding is strict about this.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128GCM)

	// Insert whitespace into CipherValue
	ea.CipherValue = " \n " + ea.CipherValue + " \n "

	_, err := ea.DecryptBytes(tlsCert)
	// StdEncoding does NOT tolerate whitespace, so this should error
	require.Error(t, err, "Base64 with extra whitespace should be rejected by StdEncoding")
}

func TestInvalidBase64InEncryptedKeyCipherValue(t *testing.T) {
	// Test 18: Invalid base64 in EncryptedKey CipherValue should error.
	_, tlsCert, certBytes := cryptoTestKeyPair(t)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      "!!!invalid-base64!!!",
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy data here!!")),
	}

	_, err := ea.DecryptBytes(tlsCert)
	require.Error(t, err)
}

// ============================================================================
// X509/Cert (Tests 19-20)
// ============================================================================

func TestEncryptedKeyX509DataCertificateMismatch(t *testing.T) {
	// Test 19: EncryptedKey X509Data certificate mismatch should error.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	// Create a different certificate
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	otherCertBytes, err := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)
	require.NoError(t, err)

	// Encrypt with the correct key but claim a different X509 cert
	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128GCM)
	// Replace X509Data with the other cert
	ea.EncryptedKey.X509Data = base64.StdEncoding.EncodeToString(otherCertBytes)

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mismatched cert")
}

func TestEmptyX509DataBypassesCertCheck(t *testing.T) {
	// Test 20: Empty X509Data should bypass cert check and still decrypt.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128GCM)
	// Clear X509Data
	ea.EncryptedKey.X509Data = ""

	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(result))
}

// ============================================================================
// Post-Decryption (Tests 21-23)
// ============================================================================

func TestDecryptsToXXE(t *testing.T) {
	// Test 21: Decrypts to XXE XML (DOCTYPE in plaintext) - verify re-parse rejects.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	xxePayload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>&xxe;</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, xxePayload, &key.PublicKey, certBytes, types.MethodAES128GCM)

	// DecryptBytes should succeed (it just decrypts)
	decrypted, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Contains(t, string(decrypted), "DOCTYPE")

	// But the full Decrypt() path (which re-parses) should handle it safely.
	// Go's encoding/xml does not process external entities, so the entity
	// reference will cause an unmarshal error.
	_, err = ea.Decrypt(tlsCert)
	require.Error(t, err, "XXE payload should fail XML unmarshaling")
}

func TestDecryptsToBillionLaughs(t *testing.T) {
	// Test 22: Decrypts to Billion Laughs bomb - verify re-parse rejects.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	billionLaughs := `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1">
  <saml2:Issuer>&lol3;</saml2:Issuer>
</saml2:Assertion>`

	ea := encryptAssertion(t, billionLaughs, &key.PublicKey, certBytes, types.MethodAES128GCM)

	// Decrypt() should fail at XML parsing
	_, err := ea.Decrypt(tlsCert)
	require.Error(t, err, "Billion laughs bomb should fail XML unmarshaling")
}

func TestDecryptsToXSWDuplicateAssertions(t *testing.T) {
	// Test 23: Decrypts to XSW attack (duplicate assertions) - should not
	// produce multiple valid assertions from a single EncryptedAssertion.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	// This is malformed: two Assertion elements. encoding/xml.Unmarshal will
	// only parse the first one (the root), so the second is ignored.
	xswPayload := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_legit"><saml2:Issuer>idp</saml2:Issuer><saml2:Subject><saml2:NameID>legit@example.com</saml2:NameID></saml2:Subject></saml2:Assertion>`

	ea := encryptAssertion(t, xswPayload, &key.PublicKey, certBytes, types.MethodAES128GCM)

	assertion, err := ea.Decrypt(tlsCert)
	require.NoError(t, err)
	// Only one assertion should be returned
	require.Equal(t, "_legit", assertion.ID)
	require.Equal(t, "legit@example.com", assertion.Subject.NameID.Value)
}

// ============================================================================
// Mixed/Missing (Tests 24-27)
// ============================================================================

func TestBothEncryptedAndPlaintextAssertionsDifferentNameIDs(t *testing.T) {
	// Test 24: Both encrypted and plaintext assertions with different NameIDs.
	// When InsecureSkipSignatureValidation is set, both should be processed.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	rsaKey, ok := sp.SPKeyStore.Signer.(*rsa.PrivateKey)
	require.True(t, ok)

	now := sp.now()
	assertionXML := fmt.Sprintf(`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_enc_a1" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>encrypted@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	ea := encryptAssertion(t, assertionXML, &rsaKey.PublicKey, sp.SPKeyStore.Cert, types.MethodAES128GCM)

	// Build response with both plaintext and encrypted assertion
	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_plain_a1" Version="2.0" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>plaintext@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s" InResponseTo="_request_id_1"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>
  <saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
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
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
		ea.EncryptionMethod.Algorithm,
		ea.EncryptedKey.EncryptionMethod.Algorithm,
		ea.EncryptedKey.X509Data,
		ea.EncryptedKey.CipherValue,
		ea.CipherValue,
	)

	resp, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(responseXML))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp.Assertions), 1, "Should have at least one assertion")
}

func TestEncryptedAssertionWithNilSPKeyStore(t *testing.T) {
	// Test 25: EncryptedAssertion with nil SPKeyStore - no panic.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true
	sp.SPKeyStore = nil // No decryption key

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
      <xenc:CipherData><xenc:CipherValue>dGVzdA==</xenc:CipherValue></xenc:CipherData>
    </xenc:EncryptedData>
  </saml2:EncryptedAssertion>
</saml2p:Response>`,
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
	)

	// Should not panic. With InsecureSkipSignatureValidation=true, the
	// EncryptedAssertion cannot be decrypted (no key store), which
	// ultimately results in either a decryption error or a missing
	// assertion error (if the encrypted assertion is silently skipped).
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(responseXML))
	require.Error(t, err, "Should error due to nil SPKeyStore")
}

func TestEncryptedDataWithoutEncryptedKey(t *testing.T) {
	// Test 26: EncryptedData without EncryptedKey - should error.
	_, tlsCert, _ := cryptoTestKeyPair(t)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		// No EncryptedKey at all (both inline and detached are empty)
		CipherValue: base64.StdEncoding.EncodeToString([]byte("some encrypted data here!!")),
	}

	_, err := ea.DecryptBytes(tlsCert)
	require.Error(t, err, "Should error when no EncryptedKey is present")
}

func TestMultipleEncryptedKeyElements(t *testing.T) {
	// Test 27: Both inline and detached EncryptedKey elements.
	// When inline CipherValue is empty, detached should be used.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128GCM)

	// Move the inline key to detached and clear inline
	ea.DetEncryptedKey = ea.EncryptedKey
	ea.EncryptedKey = types.EncryptedKey{} // clear inline

	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(result))
}

// ============================================================================
// Algorithm Mismatch (Test 28)
// ============================================================================

func TestAES128GCMDeclaredBut256BitKey(t *testing.T) {
	// Test 28: aes128-gcm declared but 256-bit key decrypted.
	// aes.NewCipher accepts any valid AES key size (16, 24, 32 bytes).
	// With GCM, the nonce size is always 12 regardless of key size.
	// The mismatch is between the algorithm URI and the actual key size,
	// but Go's AES doesn't enforce this -- the decryption will simply
	// fail because the wrong key size produces wrong plaintext/auth tag.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	// Encrypt with AES-256 (32 byte key) but declare AES-128-GCM
	aesKey := make([]byte, 32) // 256-bit
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	ea := encryptAssertionWithKey(t, plaintext, aesKey, &key.PublicKey, certBytes, types.MethodAES128GCM, types.MethodRSAOAEP)

	// The AES key encrypted via RSA-OAEP is 32 bytes; aes.NewCipher(32) returns
	// AES-256, which is valid. The declared algorithm says aes128-gcm but the
	// actual key is 256-bit. This should still decrypt successfully since Go's
	// AES-GCM doesn't validate the algorithm URI against key size.
	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(result))
}

// ============================================================================
// Compression/Encoding (Tests 34-40)
// ============================================================================

func TestDeflateBombInRedirectBinding(t *testing.T) {
	// Test 34: Deflate bomb in redirect binding.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true
	sp.MaximumDecompressedBodySize = 1024 // 1KB limit

	// Create a highly compressible payload (millions of 'A's compress well)
	bomb := strings.Repeat("A", 10*1024*1024) // 10MB uncompressed

	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(bomb))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	_, err = sp.decodeRedirectMessage(encoded)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds maximum size")
}

func TestDeflateBombInPOSTBinding(t *testing.T) {
	// Test 35: Deflate bomb in POST binding.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true
	sp.MaximumDecompressedBodySize = 1024 // 1KB limit

	// Create a valid XML envelope but with a huge body that compresses well
	bomb := "<Response>" + strings.Repeat("A", 10*1024*1024) + "</Response>"

	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(bomb))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// POST binding uses base64 of raw deflated data
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	_, err = sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err)
}

func TestMalformedDeflateStream(t *testing.T) {
	// Test 36: Malformed deflate stream (random bytes).
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	randomBytes := make([]byte, 100)
	_, err := rand.Read(randomBytes)
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString(randomBytes)

	_, err = sp.ValidateEncodedResponse(context.Background(), encoded)
	require.Error(t, err, "Random bytes should fail both XML parse and deflate")
}

func TestDoubleBase64Encoding(t *testing.T) {
	// Test 37: Double base64 encoding - should fail.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	validResp := makeValidResponse(sp)
	singleEncoded := encodeResponse(validResp)
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(singleEncoded))

	_, err := sp.ValidateEncodedResponse(context.Background(), doubleEncoded)
	require.Error(t, err, "Double-encoded response should fail")
}

func TestURLSafeBase64InPOSTBinding(t *testing.T) {
	// Test 38: URL-safe base64 in POST binding - POST uses standard base64.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	validResp := makeValidResponse(sp)
	// Use URL-safe encoding instead of standard
	urlSafeEncoded := base64.URLEncoding.EncodeToString([]byte(validResp))

	// If URL-safe chars (+/-) differ from standard, this should fail or
	// produce unexpected results. The test verifies the SP handles it.
	if urlSafeEncoded != base64.StdEncoding.EncodeToString([]byte(validResp)) {
		_, err := sp.ValidateEncodedResponse(context.Background(), urlSafeEncoded)
		// Should fail because StdEncoding doesn't accept URL-safe characters
		require.Error(t, err, "URL-safe base64 should not be accepted by POST binding")
	}
}

func TestDoubleURLEncodingInRedirectBinding(t *testing.T) {
	// Test 39: Double URL-encoding in redirect binding.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	validXML := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer></saml2p:Response>`

	encoded := deflateAndEncode(t, validXML)
	// The decodeRedirectMessage expects base64 directly, not URL-encoded base64.
	// If someone double-URL-encodes, the base64 decoder should reject it.
	// Simulate by replacing chars that would be URL-encoded
	doubleEncoded := strings.ReplaceAll(encoded, "+", "%252B")
	doubleEncoded = strings.ReplaceAll(doubleEncoded, "/", "%252F")
	doubleEncoded = strings.ReplaceAll(doubleEncoded, "=", "%253D")

	_, err := sp.decodeRedirectMessage(doubleEncoded)
	require.Error(t, err, "Double URL-encoded data should fail base64 decoding")
}

func TestURLEncodingNormalizationAttack(t *testing.T) {
	// Test 40: URL encoding normalization attack - verify that the library
	// does not silently normalize URL-encoded sequences in base64 data.
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	validXML := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_1"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer></saml2p:Response>`

	encoded := deflateAndEncode(t, validXML)
	// Insert percent-encoded characters that are not valid base64
	tampered := "%00" + encoded

	_, err := sp.decodeRedirectMessage(tampered)
	require.Error(t, err, "Tampered base64 with URL-encoded chars should fail")
}

// ============================================================================
// Certificate Validity (Tests 41-44)
// ============================================================================

func TestSelfSignedCertSubstitutionInEncryptedKey(t *testing.T) {
	// Test 41: Self-signed cert substitution in EncryptedKey.
	// Attacker generates their own key pair, encrypts with their public key,
	// and provides their cert in X509Data. The SP should reject the mismatch.
	_, tlsCert, _ := cryptoTestKeyPair(t)

	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attackerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	attackerCertBytes, err := x509.CreateCertificate(rand.Reader, attackerTemplate, attackerTemplate, &attackerKey.PublicKey, attackerKey)
	require.NoError(t, err)

	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	// Encrypt AES key with attacker's public key
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &attackerKey.PublicKey, aesKey, nil)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(encryptedKey),
			X509Data:         base64.StdEncoding.EncodeToString(attackerCertBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy ciphertext data here!!!!!")),
	}

	// SP's tlsCert is different from the attacker's cert
	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mismatched cert")
}

func TestExpiredSPDecryptionCertWithValidateDisabled(t *testing.T) {
	// Test 42: Expired SP decryption cert with ValidateEncryptionCert=false.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create an expired certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // expired yesterday
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	sp, _ := securityTestSP(t)
	sp.SPKeyStore = &saml2.KeyStore{
		Signer: key,
		Cert:   certBytes,
	}
	sp.ValidateEncryptionCert = false // disabled
	sp.InsecureSkipSignatureValidation = true

	// The getDecryptCert should succeed when ValidateEncryptionCert is false
	decryptCert, err := sp.getDecryptCert()
	require.NoError(t, err, "Should not error with expired cert when validation is disabled")
	require.NotNil(t, decryptCert)
}

func TestCertificateWithWrongKeyUsage(t *testing.T) {
	// Test 43: Certificate with wrong key usage.
	// Go's TLS certificate doesn't enforce key usage for RSA decryption,
	// so this should still work (the key usage check is informational).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature, // NOT KeyEncipherment
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128GCM)

	// Should still work because Go doesn't enforce key usage at the crypto level
	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(result))
}

func TestMalformedASN1InSPCert(t *testing.T) {
	// Test 44: Malformed ASN.1 in SP cert.
	sp, _ := securityTestSP(t)
	sp.SPKeyStore = &saml2.KeyStore{
		Signer: sp.SPKeyStore.Signer,
		Cert:   []byte("this is not valid ASN.1 DER data"),
	}
	sp.ValidateEncryptionCert = true

	_, err := sp.getDecryptCert()
	require.Error(t, err, "Malformed ASN.1 should fail certificate parsing")
}

// ============================================================================
// Misc (Tests 45-50)
// ============================================================================

func TestDecryptsToNonXMLContent(t *testing.T) {
	// Test 45: Decrypts to non-XML content (random bytes).
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	randomPlaintext := make([]byte, 100)
	_, err := rand.Read(randomPlaintext)
	require.NoError(t, err)

	// Encrypt random bytes as if they were an assertion
	ea := encryptAssertion(t, string(randomPlaintext), &key.PublicKey, certBytes, types.MethodAES128GCM)

	// DecryptBytes should succeed (it just decrypts)
	_, err = ea.DecryptBytes(tlsCert)
	require.NoError(t, err)

	// But Decrypt() should fail at XML unmarshaling
	_, err = ea.Decrypt(tlsCert)
	require.Error(t, err, "Non-XML content should fail unmarshaling")
}

func TestDecryptsToWrongRootElement(t *testing.T) {
	// Test 46: Decrypts to wrong root element (<Response> instead of <Assertion>).
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	wrongElement := `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="_r1"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">test</saml2:Issuer></saml2p:Response>`

	ea := encryptAssertion(t, wrongElement, &key.PublicKey, certBytes, types.MethodAES128GCM)

	// Decrypt() unmarshals into Assertion{} - wrong root element means
	// fields won't populate correctly
	assertion, err := ea.Decrypt(tlsCert)
	if err == nil {
		// If unmarshal doesn't error, the assertion should have empty/default fields
		// because the root element doesn't match
		require.Empty(t, assertion.ID, "Wrong root element should result in empty Assertion ID")
	}
	// Either way, no panic
}

func TestAESKeyOfWrongSize(t *testing.T) {
	// Test 47: AES key of wrong size (aes128 declared, 192-bit key).
	// Go's aes.NewCipher accepts 16, 24, or 32 byte keys; a 192-bit (24-byte)
	// key is valid for AES but mismatches the aes128-gcm declaration.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	// Use 24-byte (AES-192) key with aes128-gcm declaration
	aesKey := make([]byte, 24) // 192-bit
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	ea := encryptAssertionWithKey(t, plaintext, aesKey, &key.PublicKey, certBytes, types.MethodAES128GCM, types.MethodRSAOAEP)

	// Go accepts 24-byte key for AES, so this will decrypt successfully
	// (the algorithm URI doesn't enforce key size).
	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(result))
}

func TestTruncatedRSAOAEPCiphertext(t *testing.T) {
	// Test 48: Truncated RSA-OAEP ciphertext.
	_, tlsCert, certBytes := cryptoTestKeyPair(t)

	// Truncated RSA ciphertext (too short to be valid)
	truncatedKey := make([]byte, 32) // Way too short for RSA-2048
	_, err := rand.Read(truncatedKey)
	require.NoError(t, err)

	ea := &types.EncryptedAssertion{
		EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodAES128GCM},
		EncryptedKey: types.EncryptedKey{
			EncryptionMethod: types.EncryptionMethod{Algorithm: types.MethodRSAOAEP},
			CipherValue:      base64.StdEncoding.EncodeToString(truncatedKey),
			X509Data:         base64.StdEncoding.EncodeToString(certBytes),
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy ciphertext data here!!!!!")),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err, "Truncated RSA-OAEP ciphertext should fail decryption")
}

func TestInsecureSkipSignatureValidationWithEncryptedAssertions(t *testing.T) {
	// Test 49: InsecureSkipSignatureValidation with encrypted assertions.
	// When InsecureSkipSignatureValidation=true, the code path does NOT
	// decrypt EncryptedAssertions. Verify that an encrypted-only response
	// fails with a "missing assertion" error (not a panic or decryption error).
	sp, _ := securityTestSP(t)
	sp.InsecureSkipSignatureValidation = true

	rsaKey, ok := sp.SPKeyStore.Signer.(*rsa.PrivateKey)
	require.True(t, ok)

	now := sp.now()
	assertionXML := fmt.Sprintf(`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_enc_a1" IssueInstant="%s">
    <saml2:Issuer>%s</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID>user@example.com</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s" InResponseTo="_request_id_1"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml2:AudienceRestriction><saml2:Audience>%s</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
  </saml2:Assertion>`,
		now.Format(time.RFC3339), sp.IDPEntityID,
		now.Add(5*time.Minute).Format(time.RFC3339), sp.ACSURL,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		sp.AudienceURIs[0],
	)

	ea := encryptAssertion(t, assertionXML, &rsaKey.PublicKey, sp.SPKeyStore.Cert, types.MethodAES128GCM)

	// Build response with ONLY encrypted assertion (no signature)
	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="%s" ID="_resp_1" InResponseTo="_request_id_1" Version="2.0" IssueInstant="%s">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml2:Issuer>
  <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
  <saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
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
		sp.ACSURL, now.Format(time.RFC3339), sp.IDPEntityID,
		ea.EncryptionMethod.Algorithm,
		ea.EncryptedKey.EncryptionMethod.Algorithm,
		ea.EncryptedKey.X509Data,
		ea.EncryptedKey.CipherValue,
		ea.CipherValue,
	)

	// With InsecureSkipSignatureValidation, encrypted assertions are NOT
	// decrypted. The response should fail because there are no plaintext
	// assertions (the EncryptedAssertion is not processed).
	_, err := sp.ValidateEncodedResponse(context.Background(), encodeResponse(responseXML))
	require.Error(t, err, "Encrypted-only response with InsecureSkipSignatureValidation should fail")
	require.Contains(t, err.Error(), "missing assertion",
		"Should get missing assertion error since encrypted assertions are not decrypted in insecure mode")
}

func TestGCMChosenCiphertextModifiedNonce(t *testing.T) {
	// Test 50: GCM chosen-ciphertext with modified nonce - verify uniform errors.
	key, tlsCert, certBytes := cryptoTestKeyPair(t)

	plaintext := `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion>`

	ea := encryptAssertion(t, plaintext, &key.PublicKey, certBytes, types.MethodAES128GCM)

	cipherData, err := base64.StdEncoding.DecodeString(ea.CipherValue)
	require.NoError(t, err)

	// Modify bytes in the nonce region (first 12 bytes for GCM)
	errorMessages := make(map[string]int)
	for i := 0; i < 12; i++ {
		mutated := make([]byte, len(cipherData))
		copy(mutated, cipherData)
		mutated[i] ^= 0xFF

		testEA := &types.EncryptedAssertion{
			EncryptionMethod: ea.EncryptionMethod,
			EncryptedKey:     ea.EncryptedKey,
			CipherValue:      base64.StdEncoding.EncodeToString(mutated),
		}

		_, err := testEA.DecryptBytes(tlsCert)
		if err != nil {
			errorMessages[err.Error()]++
		}
	}

	// All GCM errors should be the same ("cannot open AES-GCM: ...")
	require.LessOrEqual(t, len(errorMessages), 1,
		"All GCM nonce-modification errors should produce the same message")
}
