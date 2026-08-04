// Low-level GCM/CBC specific encryption tests and DecryptSymmetricKey edge cases.
//
// Category 4 subset: tests 29-33 (GCM nonce reuse, GCM truncated ciphertext,
// GCM auth tag modification, CBC non-block-aligned, CBC one-block-only) plus
// removePadding unit tests and DecryptSymmetricKey edge cases.

package types

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"hash"
	"math/big"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func cryptoTestSetup(t *testing.T) (*rsa.PrivateKey, *tls.Certificate, []byte) {
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

func makeEncryptedKey(t *testing.T, aesKey []byte, pubKey *rsa.PublicKey, certDER []byte) EncryptedKey {
	t.Helper()
	encKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, aesKey, nil)
	require.NoError(t, err)
	return EncryptedKey{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodRSAOAEP},
		CipherValue:      base64.StdEncoding.EncodeToString(encKey),
		X509Data:         base64.StdEncoding.EncodeToString(certDER),
	}
}

func newHashFromMethod(method string) hash.Hash {
	switch method {
	case MethodSHA256:
		return sha256.New()
	case MethodSHA512:
		return sha512.New()
	default:
		return sha1.New()
	}
}

// ---------------------------------------------------------------------------
// Test 29: GCM Nonce Reuse Detection
// ---------------------------------------------------------------------------

func TestSecurityCrypto_GCMNonceReuse(t *testing.T) {
	// Encrypt the same plaintext twice with the same key. If the
	// implementation uses crypto/rand for nonces (as it should), the two
	// ciphertexts must differ because the random nonces will differ.
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	plaintext := []byte("identical plaintext for nonce reuse test")

	// First encryption
	nonce1 := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce1)
	require.NoError(t, err)
	ct1 := gcm.Seal(nonce1, nonce1, plaintext, nil)

	// Second encryption
	nonce2 := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce2)
	require.NoError(t, err)
	ct2 := gcm.Seal(nonce2, nonce2, plaintext, nil)

	// The two ciphertexts must differ (random nonces ensure this).
	require.NotEqual(t, ct1, ct2, "Two GCM encryptions of the same plaintext must produce different ciphertext when using random nonces")
}

// ---------------------------------------------------------------------------
// Test 30: GCM Ciphertext Truncated to Only Nonce (12 bytes)
// ---------------------------------------------------------------------------

func TestSecurityCrypto_GCMTruncatedToNonce(t *testing.T) {
	key, tlsCert, certBytes := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	// Only 12 bytes = nonce size, no ciphertext or tag
	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	ea := &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodAES128GCM},
		EncryptedKey:     makeEncryptedKey(t, aesKey, &key.PublicKey, certBytes),
		CipherValue:      base64.StdEncoding.EncodeToString(nonce),
	}

	require.NotPanics(t, func() {
		_, err := ea.DecryptBytes(tlsCert)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too short")
	})
}

// ---------------------------------------------------------------------------
// Test 31: GCM Modified Authentication Tag
// ---------------------------------------------------------------------------

func TestSecurityCrypto_GCMModifiedAuthTag(t *testing.T) {
	key, tlsCert, certBytes := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	// Encrypt valid data with GCM
	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	plaintext := []byte("<Assertion>valid</Assertion>")
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Flip one bit in the GCM authentication tag (last 16 bytes)
	ciphertext[len(ciphertext)-1] ^= 0x01

	ea := &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodAES128GCM},
		EncryptedKey:     makeEncryptedKey(t, aesKey, &key.PublicKey, certBytes),
		CipherValue:      base64.StdEncoding.EncodeToString(ciphertext),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot open AES-GCM")
}

// ---------------------------------------------------------------------------
// Test 32: CBC Non-Block-Aligned Ciphertext
// ---------------------------------------------------------------------------

func TestSecurityCrypto_CBCNonBlockAligned(t *testing.T) {
	key, tlsCert, certBytes := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	// Create ciphertext whose length is not a multiple of 16.
	// 35 bytes: enough for 2+ blocks but not block-aligned.
	badCiphertext := make([]byte, 35)
	_, err = rand.Read(badCiphertext)
	require.NoError(t, err)

	ea := &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodAES128CBC},
		EncryptedKey:     makeEncryptedKey(t, aesKey, &key.PublicKey, certBytes),
		CipherValue:      base64.StdEncoding.EncodeToString(badCiphertext),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a multiple")
}

// ---------------------------------------------------------------------------
// Test 33: CBC One Block Only (16 bytes = IV only, no data)
// ---------------------------------------------------------------------------

func TestSecurityCrypto_CBCOneBlockOnly(t *testing.T) {
	key, tlsCert, certBytes := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	// 16 bytes = exactly one AES block = IV only, no data block
	oneBlock := make([]byte, 16)
	_, err = rand.Read(oneBlock)
	require.NoError(t, err)

	ea := &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodAES128CBC},
		EncryptedKey:     makeEncryptedKey(t, aesKey, &key.PublicKey, certBytes),
		CipherValue:      base64.StdEncoding.EncodeToString(oneBlock),
	}

	_, err = ea.DecryptBytes(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

// ---------------------------------------------------------------------------
// Test 34: removePadding with PKCS#7 padding (valid cases)
// ---------------------------------------------------------------------------

func TestRemovePadding_PKCS7Valid(t *testing.T) {
	// data with PKCS#7 padding of 4 bytes
	data := []byte("hello world\x04\x04\x04\x04")
	result, err := removePadding(data, 16)
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), result)
}

func TestRemovePadding_PKCS7AllPadValues(t *testing.T) {
	// Test every valid PKCS#7 pad value from 1 to 16.
	for padLen := 1; padLen <= 16; padLen++ {
		data := make([]byte, 16)
		for i := range data {
			data[i] = 'X'
		}
		data[15] = byte(padLen)

		result, err := removePadding(data, 16)
		require.NoError(t, err, "padLen=%d should succeed", padLen)
		require.Len(t, result, 16-padLen, "padLen=%d: expected %d bytes", padLen, 16-padLen)
	}
}

// ---------------------------------------------------------------------------
// Test 35: removePadding with zero-padding
// ---------------------------------------------------------------------------

func TestRemovePadding_ZeroPadding(t *testing.T) {
	// Data ending with zero bytes (zero-padding from an IdP).
	data := []byte("hello\x00\x00\x00")
	result, err := removePadding(data, 16)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), result)
}

// ---------------------------------------------------------------------------
// Test 36: removePadding with empty data
// ---------------------------------------------------------------------------

func TestRemovePadding_EmptyData(t *testing.T) {
	_, err := removePadding([]byte{}, 16)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid padding")
}

// ---------------------------------------------------------------------------
// Test 37: removePadding with invalid PKCS#7 (padLength > blockSize)
// ---------------------------------------------------------------------------

func TestRemovePadding_InvalidPKCS7PadTooLarge(t *testing.T) {
	// Last byte is 0xFF (255), which is > blockSize (16) and not zero,
	// so both PKCS#7 and zero-trim paths should fail.
	data := make([]byte, 16)
	for i := range data {
		data[i] = 0xFF
	}
	_, err := removePadding(data, 16)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid padding")
}

// ---------------------------------------------------------------------------
// Test 38: GCM with 0-byte additional authenticated data (normal case)
// ---------------------------------------------------------------------------

func TestSecurityCrypto_GCMZeroAAD(t *testing.T) {
	key, tlsCert, certBytes := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	// Encrypt with nil AAD (the normal SAML case).
	plaintext := []byte("<Assertion>test</Assertion>")
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	ea := &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodAES128GCM},
		EncryptedKey:     makeEncryptedKey(t, aesKey, &key.PublicKey, certBytes),
		CipherValue:      base64.StdEncoding.EncodeToString(ciphertext),
	}

	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, result)
}

// ---------------------------------------------------------------------------
// Test 39: GCM with exactly NonceSize + Overhead bytes (empty plaintext)
// ---------------------------------------------------------------------------

func TestSecurityCrypto_GCMMinimumValidSize(t *testing.T) {
	key, tlsCert, certBytes := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	// Encrypt empty plaintext: result is nonce (12) + tag (16) = 28 bytes.
	ciphertext := gcm.Seal(nonce, nonce, []byte{}, nil)
	require.Len(t, ciphertext, gcm.NonceSize()+gcm.Overhead(),
		"minimum valid GCM ciphertext should be nonce + overhead")

	ea := &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodAES128GCM},
		EncryptedKey:     makeEncryptedKey(t, aesKey, &key.PublicKey, certBytes),
		CipherValue:      base64.StdEncoding.EncodeToString(ciphertext),
	}

	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Empty(t, result, "decrypting empty plaintext should return empty bytes")
}

// ---------------------------------------------------------------------------
// Test 40: CBC with exactly 2 blocks (minimum valid: IV + 1 data block)
// ---------------------------------------------------------------------------

func TestSecurityCrypto_CBCMinimumValid(t *testing.T) {
	key, tlsCert, certBytes := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)

	// Build IV + one block of PKCS#7-padded data.
	iv := make([]byte, block.BlockSize())
	_, err = rand.Read(iv)
	require.NoError(t, err)

	// Plaintext "hello" (5 bytes) + PKCS#7 pad of 11 => 16 bytes
	padLen := block.BlockSize() - 5
	padded := make([]byte, block.BlockSize())
	copy(padded, "hello")
	for i := 5; i < block.BlockSize(); i++ {
		padded[i] = byte(padLen)
	}

	enc := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, block.BlockSize())
	enc.CryptBlocks(ct, padded)

	// Combine IV + ciphertext = 32 bytes
	combined := make([]byte, 0, len(iv)+len(ct))
	combined = append(combined, iv...)
	combined = append(combined, ct...)

	ea := &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodAES128CBC},
		EncryptedKey:     makeEncryptedKey(t, aesKey, &key.PublicKey, certBytes),
		CipherValue:      base64.StdEncoding.EncodeToString(combined),
	}

	result, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), result)
}

// ---------------------------------------------------------------------------
// Test 41: DecryptSymmetricKey with empty Certificate slice
// ---------------------------------------------------------------------------

func TestDecryptSymmetricKey_EmptyCertSlice(t *testing.T) {
	cert := &tls.Certificate{
		Certificate: [][]byte{},
		PrivateKey:  nil,
	}

	ek := &EncryptedKey{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodRSAOAEP},
		CipherValue:      base64.StdEncoding.EncodeToString([]byte("dummy")),
	}

	_, err := ek.DecryptSymmetricKey(cert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no public certs")
}

// ---------------------------------------------------------------------------
// Test 42: DecryptSymmetricKey with RSA PKCS#1 v1.5 - blocked
// ---------------------------------------------------------------------------

func TestDecryptSymmetricKey_RSAv15Blocked(t *testing.T) {
	_, tlsCert, _ := cryptoTestSetup(t)

	ek := &EncryptedKey{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodRSAv1_5},
		CipherValue:      base64.StdEncoding.EncodeToString([]byte("dummy")),
	}

	_, err := ek.DecryptSymmetricKey(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no longer supported")
}

// ---------------------------------------------------------------------------
// Test 43: DecryptSymmetricKey with missing algorithm
// ---------------------------------------------------------------------------

func TestDecryptSymmetricKey_MissingAlgorithm(t *testing.T) {
	_, tlsCert, _ := cryptoTestSetup(t)

	ek := &EncryptedKey{
		EncryptionMethod: EncryptionMethod{Algorithm: ""},
		CipherValue:      base64.StdEncoding.EncodeToString([]byte("dummy")),
	}

	_, err := ek.DecryptSymmetricKey(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing encryption algorithm")
}

// ---------------------------------------------------------------------------
// Test 44: DecryptSymmetricKey with unsupported algorithm
// ---------------------------------------------------------------------------

func TestDecryptSymmetricKey_UnsupportedAlgorithm(t *testing.T) {
	_, tlsCert, _ := cryptoTestSetup(t)

	ek := &EncryptedKey{
		EncryptionMethod: EncryptionMethod{Algorithm: "http://example.com/unsupported"},
		CipherValue:      base64.StdEncoding.EncodeToString([]byte("dummy")),
	}

	_, err := ek.DecryptSymmetricKey(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported encryption algorithm")
}

// ---------------------------------------------------------------------------
// Test 45: DecryptSymmetricKey with SHA-256 DigestMethod
// ---------------------------------------------------------------------------

func TestDecryptSymmetricKey_SHA256Digest(t *testing.T) {
	key, tlsCert, certBytes := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	// Encrypt the AES key with RSA-OAEP using SHA-256
	encKey, err := rsa.EncryptOAEP(
		newHashFromMethod(MethodSHA256),
		rand.Reader, &key.PublicKey, aesKey, nil,
	)
	require.NoError(t, err)

	ek := &EncryptedKey{
		EncryptionMethod: EncryptionMethod{
			Algorithm:    MethodRSAOAEP,
			DigestMethod: &DigestMethod{Algorithm: MethodSHA256},
		},
		CipherValue: base64.StdEncoding.EncodeToString(encKey),
		X509Data:    base64.StdEncoding.EncodeToString(certBytes),
	}

	block, err := ek.DecryptSymmetricKey(tlsCert)
	require.NoError(t, err)
	require.NotNil(t, block)
	require.Equal(t, 16, block.BlockSize(), "AES-128 block size should be 16")
}

// ---------------------------------------------------------------------------
// Test 46: DecryptSymmetricKey with SHA-512 DigestMethod
// ---------------------------------------------------------------------------

func TestDecryptSymmetricKey_SHA512Digest(t *testing.T) {
	key, tlsCert, certBytes := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	// Encrypt the AES key with RSA-OAEP using SHA-512
	encKey, err := rsa.EncryptOAEP(
		newHashFromMethod(MethodSHA512),
		rand.Reader, &key.PublicKey, aesKey, nil,
	)
	require.NoError(t, err)

	ek := &EncryptedKey{
		EncryptionMethod: EncryptionMethod{
			Algorithm:    MethodRSAOAEP,
			DigestMethod: &DigestMethod{Algorithm: MethodSHA512},
		},
		CipherValue: base64.StdEncoding.EncodeToString(encKey),
		X509Data:    base64.StdEncoding.EncodeToString(certBytes),
	}

	block, err := ek.DecryptSymmetricKey(tlsCert)
	require.NoError(t, err)
	require.NotNil(t, block)
	require.Equal(t, 16, block.BlockSize(), "AES-128 block size should be 16")
}

// ---------------------------------------------------------------------------
// Test 47: DecryptSymmetricKey with unsupported DigestMethod
// ---------------------------------------------------------------------------

func TestDecryptSymmetricKey_UnsupportedDigest(t *testing.T) {
	_, tlsCert, certBytes := cryptoTestSetup(t)

	ek := &EncryptedKey{
		EncryptionMethod: EncryptionMethod{
			Algorithm:    MethodRSAOAEP,
			DigestMethod: &DigestMethod{Algorithm: "http://example.com/unsupported-digest"},
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("dummy")),
		X509Data:    base64.StdEncoding.EncodeToString(certBytes),
	}

	_, err := ek.DecryptSymmetricKey(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported digest algorithm")
}

// ---------------------------------------------------------------------------
// Test 48: EncryptedKey X509Data mismatch
// ---------------------------------------------------------------------------

func TestDecryptSymmetricKey_X509DataMismatch(t *testing.T) {
	_, tlsCert, _ := cryptoTestSetup(t)

	// Generate a second, different certificate
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	otherCertBytes, err := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)
	require.NoError(t, err)

	ek := &EncryptedKey{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodRSAOAEP},
		CipherValue:      base64.StdEncoding.EncodeToString([]byte("dummy")),
		X509Data:         base64.StdEncoding.EncodeToString(otherCertBytes),
	}

	_, err = ek.DecryptSymmetricKey(tlsCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mismatched cert")
}
