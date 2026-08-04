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

package types

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
)

// This suite pins the interop-safe guarantees of AES-CBC decryption:
//
//   - XML-Enc padding (NOT PKCS#7) is honored: only the final octet is the pad
//     length; preceding pad octets are arbitrary and MUST NOT be validated.
//   - Length/structure failures never panic and never leak a padding oracle
//     (same-length content mutations all yield one uniform error).
//
// Note: these guarantees do not, on their own, close the CBC padding-oracle
// class — that requires decrypting only signature-verified ciphertext, which is
// the SP pipeline's responsibility. They ensure the symmetric layer is not the
// weak point and does not itself hand an attacker a finer oracle.

const blockSize = aes.BlockSize // 16

// encryptCBC returns IV || AES-CBC(padded) using a fresh random IV.
func encryptCBC(t *testing.T, padded, aesKey []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)
	require.Zero(t, len(padded)%blockSize, "test plaintext must be block-aligned")

	iv := make([]byte, blockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append(iv, ct...)
}

// cbcAssertion wraps CBC ciphertext (IV||CT) into an EncryptedAssertion with a
// matching OAEP-wrapped key.
func cbcAssertion(t *testing.T, ivAndCT, aesKey []byte, pub *rsa.PublicKey, certDER []byte) *EncryptedAssertion {
	t.Helper()
	return &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{Algorithm: MethodAES128CBC},
		CipherValue:      base64.StdEncoding.EncodeToString(ivAndCT),
		EncryptedKey:     makeEncryptedKey(t, aesKey, pub, certDER),
	}
}

// padXMLEnc applies XML-Encryption padding: pad to the next block boundary with
// `fill` bytes, then overwrite the final octet with the pad length. A full block
// of padding is added when the input is already block-aligned.
func padXMLEnc(plaintext []byte, fill byte) []byte {
	padLen := blockSize - (len(plaintext) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	out := make([]byte, len(plaintext)+padLen)
	copy(out, plaintext)
	for i := len(plaintext); i < len(out); i++ {
		out[i] = fill
	}
	out[len(out)-1] = byte(padLen)
	return out
}

// ---------------------------------------------------------------------------
// Interop: XML-Enc padding content is NOT validated
// ---------------------------------------------------------------------------

// The decisive interop test: padding octets other than the last are RANDOM
// (as Shibboleth and others emit). A PKCS#7 content check would wrongly reject
// this; we must accept it and recover the exact plaintext.
func TestCBC_RandomPadBytes_Roundtrips(t *testing.T) {
	key, tlsCert, certDER := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	plaintext := []byte(`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml2:Issuer>idp</saml2:Issuer></saml2:Assertion>`)

	padLen := blockSize - (len(plaintext) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	// Fill the pad region with random bytes...
	_, err = rand.Read(padded[len(plaintext):])
	require.NoError(t, err)
	// ...except the final octet, which must be the pad length.
	padded[len(padded)-1] = byte(padLen)

	ea := cbcAssertion(t, encryptCBC(t, padded, aesKey), aesKey, &key.PublicKey, certDER)

	got, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err, "XML-Enc padding with random non-final octets must be accepted")
	require.Equal(t, plaintext, got)
}

// PKCS#7-style padding (all pad octets equal the count) is the common case and
// must also work.
func TestCBC_PKCS7StylePad_Roundtrips(t *testing.T) {
	key, tlsCert, certDER := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	plaintext := []byte(`<x/>`)
	padLen := blockSize - (len(plaintext) % blockSize)
	padded := padXMLEnc(plaintext, byte(padLen)) // fill==count => PKCS#7

	ea := cbcAssertion(t, encryptCBC(t, padded, aesKey), aesKey, &key.PublicKey, certDER)

	got, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// A block-aligned plaintext must be padded with a whole extra block (pad
// length == blockSize) and recovered exactly.
func TestCBC_FullBlockPadding_Roundtrips(t *testing.T) {
	key, tlsCert, certDER := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	plaintext := make([]byte, 2*blockSize) // exactly block-aligned
	for i := range plaintext {
		plaintext[i] = 'a'
	}
	padded := padXMLEnc(plaintext, 0xAB)
	require.Len(t, padded, 3*blockSize)

	ea := cbcAssertion(t, encryptCBC(t, padded, aesKey), aesKey, &key.PublicKey, certDER)

	got, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// Zero-padding fallback: some IdPs pad with NUL bytes (final octet 0x00).
func TestCBC_ZeroPadding_Roundtrips(t *testing.T) {
	key, tlsCert, certDER := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	plaintext := []byte(`<x/>`)
	padded := make([]byte, blockSize) // single block, NUL-padded
	copy(padded, plaintext)           // remaining bytes already 0x00

	ea := cbcAssertion(t, encryptCBC(t, padded, aesKey), aesKey, &key.PublicKey, certDER)

	got, err := ea.DecryptBytes(tlsCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// ---------------------------------------------------------------------------
// removePadding unit-level: content is not validated, lengths are
// ---------------------------------------------------------------------------

func TestRemovePadding_ContentNotValidated(t *testing.T) {
	// Final octet says 3; the three pad bytes are 0x01 0x02 0x03 (not PKCS#7).
	// XML-Enc only mandates the final octet, so this is valid and yields "hello".
	data := []byte{'h', 'e', 'l', 'l', 'o', 0x01, 0x02, 0x03}
	out, err := removePadding(data, blockSize)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), out)
}

func TestRemovePadding_LengthBoundaries(t *testing.T) {
	full := make([]byte, blockSize)
	for i := range full {
		full[i] = byte(blockSize) // pad length == blockSize (valid)
	}
	out, err := removePadding(full, blockSize)
	require.NoError(t, err)
	require.Empty(t, out)

	// pad length == 1 (valid)
	one := []byte{'a', 0x01}
	out, err = removePadding(one, blockSize)
	require.NoError(t, err)
	require.Equal(t, []byte("a"), out)

	// pad length > blockSize (invalid)
	_, err = removePadding([]byte{'a', byte(blockSize + 1)}, blockSize)
	require.Error(t, err)

	// pad length > len(data) (invalid, no underflow)
	_, err = removePadding([]byte{0x05}, blockSize)
	require.Error(t, err)

	// empty input (invalid, no panic)
	_, err = removePadding(nil, blockSize)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// No-panic + uniform-error on malformed ciphertext
// ---------------------------------------------------------------------------

func TestCBC_MalformedCiphertext_NeverPanics(t *testing.T) {
	_, tlsCert, certDER := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	pub := tlsCert.PrivateKey.(*rsa.PrivateKey).Public().(*rsa.PublicKey)

	cases := map[string][]byte{
		"empty":             {},
		"one byte":          {0x01},
		"iv only":           make([]byte, blockSize),   // no data block
		"not block aligned": make([]byte, blockSize+1), // IV + 1 stray byte
		"garbage 2 blocks":  []byte("0123456789abcdef0123456789abcdef"),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			ea := cbcAssertion(t, raw, aesKey, pub, certDER)
			require.NotPanics(t, func() {
				_, _ = ea.DecryptBytes(tlsCert)
			})
		})
	}
}

// Same-length content mutations must all produce a single uniform error, so the
// symmetric layer offers no padding oracle. (The few mutations that happen to
// yield a valid pad length decrypt "successfully" at this layer; what matters is
// that the failures are indistinguishable.)
func TestCBC_PaddingOracle_UniformErrors(t *testing.T) {
	key, tlsCert, certDER := cryptoTestSetup(t)
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	require.NoError(t, err)

	plaintext := []byte(`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml2:Issuer>idp</saml2:Issuer></saml2:Assertion>`)
	padLen := blockSize - (len(plaintext) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	ea := cbcAssertion(t, encryptCBC(t, padXMLEnc(plaintext, byte(padLen)), aesKey), aesKey, &key.PublicKey, certDER)

	base, err := base64.StdEncoding.DecodeString(ea.CipherValue)
	require.NoError(t, err)

	errMsgs := map[string]int{}
	for i := 0; i < 256; i++ {
		mutated := make([]byte, len(base))
		copy(mutated, base)
		mutated[len(mutated)-1] = byte(i) // vary final octet only (same length)

		m := &EncryptedAssertion{
			EncryptionMethod: ea.EncryptionMethod,
			EncryptedKey:     ea.EncryptedKey,
			CipherValue:      base64.StdEncoding.EncodeToString(mutated),
		}
		if _, err := m.DecryptBytes(tlsCert); err != nil {
			errMsgs[err.Error()]++
		}
	}

	require.LessOrEqual(t, len(errMsgs), 1,
		"all same-length CBC failures must share one error message; got %v", errMsgs)
}
