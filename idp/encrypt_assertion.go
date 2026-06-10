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

package idp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	saml2 "github.com/russellhaering/gosaml2/v2"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/russellhaering/gosaml2/v2/types"
)

func (idp *IdentityProvider) encryptAssertion(assertionEl *xmltree.Element, sp *SPConfig) (*xmltree.Element, error) {
	if sp.EncryptionCertificate == nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrEncryptionFailed,
			Detail: fmt.Sprintf("SP %s has no encryption certificate", sp.EntityID),
		}
	}

	doc := xmltree.NewDocument()
	doc.SetRoot(assertionEl.Copy())
	plaintext, err := doc.WriteToBytes()
	if err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrEncryptionFailed,
			Detail: fmt.Sprintf("error serializing assertion: %v", err),
		}
	}

	algorithm := sp.EncryptionAlgorithm
	if algorithm == "" {
		algorithm = types.MethodAES256GCM
	}

	keySize := encryptionKeySize(algorithm)
	if keySize == 0 {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrEncryptionFailed,
			Detail: fmt.Sprintf("unsupported encryption algorithm: %s", algorithm),
		}
	}

	symmetricKey := make([]byte, keySize)
	if _, err := rand.Read(symmetricKey); err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrEncryptionFailed,
			Detail: fmt.Sprintf("error generating symmetric key: %v", err),
		}
	}

	var ciphertext []byte
	switch algorithm {
	case types.MethodAES128GCM, types.MethodAES192GCM, types.MethodAES256GCM:
		ciphertext, err = encryptGCM(symmetricKey, plaintext)
	case types.MethodAES128CBC, types.MethodAES256CBC:
		ciphertext, err = encryptCBC(symmetricKey, plaintext)
	default:
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrEncryptionFailed,
			Detail: fmt.Sprintf("unsupported encryption algorithm: %s", algorithm),
		}
	}
	if err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrEncryptionFailed,
			Detail: fmt.Sprintf("symmetric encryption error: %v", err),
		}
	}

	rsaPub, ok := sp.EncryptionCertificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrEncryptionFailed,
			Detail: "SP encryption certificate does not contain an RSA public key",
		}
	}

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, symmetricKey, nil)
	if err != nil {
		return nil, &saml2.ValidationError{
			Reason: saml2.ErrEncryptionFailed,
			Detail: fmt.Sprintf("RSA-OAEP encryption error: %v", err),
		}
	}

	return buildEncryptedDataElement(algorithm, ciphertext, encryptedKey), nil
}

func encryptGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func encryptCBC(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	padLen := blockSize - (len(plaintext) % blockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	cbc.CryptBlocks(ciphertext, padded)

	return append(iv, ciphertext...), nil
}

func encryptionKeySize(algorithm string) int {
	switch algorithm {
	case types.MethodAES128GCM, types.MethodAES128CBC:
		return 16
	case types.MethodAES192GCM:
		return 24
	case types.MethodAES256GCM, types.MethodAES256CBC:
		return 32
	default:
		return 0
	}
}

func buildEncryptedDataElement(algorithm string, ciphertext, encryptedKey []byte) *xmltree.Element {
	encAssertionEl := xmltree.NewElement("saml:EncryptedAssertion")
	encAssertionEl.CreateAttr("xmlns:saml", saml2.SAMLAssertionNamespace)

	encDataEl := encAssertionEl.CreateElement("xenc:EncryptedData")
	encDataEl.CreateAttr("xmlns:xenc", saml2.XMLEncNamespace)
	encDataEl.CreateAttr("Type", saml2.EncryptedDataTypeElement)

	encMethodEl := encDataEl.CreateElement("xenc:EncryptionMethod")
	encMethodEl.CreateAttr("Algorithm", algorithm)

	keyInfoEl := encDataEl.CreateElement("ds:KeyInfo")
	keyInfoEl.CreateAttr("xmlns:ds", saml2.XMLDSigNamespace)

	encKeyEl := keyInfoEl.CreateElement("xenc:EncryptedKey")
	encKeyEl.CreateAttr("xmlns:xenc", saml2.XMLEncNamespace)

	keyEncMethodEl := encKeyEl.CreateElement("xenc:EncryptionMethod")
	keyEncMethodEl.CreateAttr("Algorithm", types.MethodRSAOAEP2)
	digestMethodEl := keyEncMethodEl.CreateElement("ds:DigestMethod")
	digestMethodEl.CreateAttr("xmlns:ds", saml2.XMLDSigNamespace)
	digestMethodEl.CreateAttr("Algorithm", types.MethodSHA256)

	keyCipherEl := encKeyEl.CreateElement("xenc:CipherData")
	keyCipherEl.CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(encryptedKey))

	cipherDataEl := encDataEl.CreateElement("xenc:CipherData")
	cipherDataEl.CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(ciphertext))

	return encAssertionEl
}
