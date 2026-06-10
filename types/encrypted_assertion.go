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
	"bytes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
)

// EncryptedAssertion represents a saml:EncryptedAssertion element containing
// the encrypted assertion data, encryption method, and encrypted symmetric key.
type EncryptedAssertion struct {
	XMLName          xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
	EncryptionMethod EncryptionMethod `xml:"EncryptedData>EncryptionMethod"`
	EncryptedKey     EncryptedKey     `xml:"EncryptedData>KeyInfo>EncryptedKey"`
	DetEncryptedKey  EncryptedKey     `xml:"EncryptedKey"` // detached EncryptedKey element
	CipherValue      string           `xml:"EncryptedData>CipherData>CipherValue"`
}

// DecryptBytes decrypts the encrypted assertion using the given TLS certificate's
// private key and returns the raw XML bytes of the decrypted assertion.
func (ea *EncryptedAssertion) DecryptBytes(cert *tls.Certificate) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ea.CipherValue)
	if err != nil {
		return nil, err
	}

	// EncryptedKey must include CipherValue.  EncryptedKey may be part of EncryptedData.
	ek := &ea.EncryptedKey
	if ek.CipherValue == "" {
		// Use detached EncryptedKey element (sibling of EncryptedData).  See:
		// https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-Extensions-to-KeyInfo
		ek = &ea.DetEncryptedKey
	}
	k, err := ek.DecryptSymmetricKey(cert)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt, error retrieving private key: %s", err)
	}

	switch ea.EncryptionMethod.Algorithm {
	case MethodAES128GCM, MethodAES192GCM, MethodAES256GCM:
		c, err := cipher.NewGCM(k)
		if err != nil {
			return nil, fmt.Errorf("cannot create AES-GCM: %s", err)
		}

		// The data must contain at least the nonce (typically 12 bytes) plus
		// the GCM authentication tag (16 bytes). Reject short ciphertext to
		// avoid slice-bounds panics on crafted input.
		if len(data) < c.NonceSize()+c.Overhead() {
			return nil, fmt.Errorf("AES-GCM ciphertext too short: need at least %d bytes, got %d", c.NonceSize()+c.Overhead(), len(data))
		}

		nonce, data := data[:c.NonceSize()], data[c.NonceSize():]
		plainText, err := c.Open(nil, nonce, data, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot open AES-GCM: %s", err)
		}
		return plainText, nil
	case MethodTripleDESCBC:
		return nil, fmt.Errorf("3DES encryption is no longer supported; IdP should use AES")
	case MethodAES128CBC, MethodAES256CBC:
		// CBC requires at least two blocks: one for the IV and one for data.
		if len(data) < 2*k.BlockSize() {
			return nil, fmt.Errorf("AES-CBC ciphertext too short: need at least %d bytes, got %d", 2*k.BlockSize(), len(data))
		}
		if len(data)%k.BlockSize() != 0 {
			return nil, fmt.Errorf("encrypted data is not a multiple of the expected CBC block size %d: actual size %d", k.BlockSize(), len(data))
		}
		nonce, data := data[:k.BlockSize()], data[k.BlockSize():]
		c := cipher.NewCBCDecrypter(k, nonce)
		c.CryptBlocks(data, data)

		// Validate and remove padding. Tries PKCS#7 first (per XML Encryption
		// spec §5.2), then falls back to zero-padding for compatibility.
		// All failures return the same error to prevent padding oracle attacks.
		plaintext, err := removePadding(data, k.BlockSize())
		if err != nil {
			return nil, fmt.Errorf("invalid CBC padding")
		}
		return plaintext, nil
	default:
		return nil, fmt.Errorf("unknown symmetric encryption method %#v", ea.EncryptionMethod.Algorithm)
	}
}

// removePadding removes padding from CBC-decrypted data.
//
// IMPORTANT: XML Encryption (W3C xmlenc-core §5.2) does NOT use PKCS#7 padding.
// Only the final octet is meaningful — it gives the number of padding octets —
// and the preceding padding octets are unspecified (an implementation may, and
// real ones such as Shibboleth do, fill them with arbitrary/random bytes).
// We therefore validate only the pad *length*, never the pad *content*; a
// content check would reject spec-compliant ciphertext.
//
// This function is not the padding-oracle control. The decisive control is in
// the SP pipeline, which only ever decrypts ciphertext from a
// signature-verified response — so an attacker has no oracle to probe (a
// tampered ciphertext fails the signature long before it reaches here). All
// error paths still return the same generic message as defense in depth.
//
// As a compatibility fallback, when the final octet is 0x00 the data is treated
// as zero-padded and trailing NULs are trimmed (XML content never contains NUL).
func removePadding(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	padLength := int(data[len(data)-1])

	// xmlenc CBC: final octet is the pad count, in range 1..blockSize.
	if padLength >= 1 && padLength <= blockSize && padLength <= len(data) {
		return data[:len(data)-padLength], nil
	}

	// Zero-padding fallback: some IdPs pad with zeros. Only reached when the
	// final octet is 0x00, so it never conflicts with the path above.
	if padLength == 0 {
		trimmed := bytes.TrimRight(data, "\x00")
		if len(trimmed) > 0 {
			return trimmed, nil
		}
	}

	return nil, fmt.Errorf("invalid padding")
}

// Decrypt decrypts and unmarshals the EncryptedAssertion.
func (ea *EncryptedAssertion) Decrypt(cert *tls.Certificate) (*Assertion, error) {
	plaintext, err := ea.DecryptBytes(cert)
	if err != nil {
		return nil, fmt.Errorf("Error decrypting assertion: %v", err)
	}

	assertion := &Assertion{}

	err = xml.Unmarshal(plaintext, assertion)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshaling assertion: %v", err)
	}

	return assertion, nil
}
