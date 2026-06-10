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

package xmldsig

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// When a signature carries no KeyInfo, the verifier tries every trusted
// certificate rather than requiring exactly one. This keeps verification
// working when multiple certs are pinned, e.g. during IdP certificate
// rotation. KeyInfo, when present, still pins exactly: the embedded cert must
// match a trusted cert, and the fallback never engages.

func TestKeyInfoFallback_SignedByFirstTrustedCert(t *testing.T) {
	key1, cert1 := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert()

	signed := signDoc(t, key1, cert1, "_fb-first")
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	res, err := newVerifier(cert1, cert2).Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert1))
}

func TestKeyInfoFallback_SignedBySecondTrustedCert(t *testing.T) {
	_, cert1 := randomTestKeyAndCert()
	key2, cert2 := randomTestKeyAndCert()

	signed := signDoc(t, key2, cert2, "_fb-second")
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	res, err := newVerifier(cert1, cert2).Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(cert2))
}

func TestKeyInfoFallback_SignedByUntrustedKey(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	_, cert1 := randomTestKeyAndCert()
	_, cert2 := randomTestKeyAndCert()
	_, cert3 := randomTestKeyAndCert()

	signed := signDoc(t, key, cert, "_fb-untrusted")
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	_, err := newVerifier(cert1, cert2, cert3).Verify(signed)
	require.ErrorIs(t, err, ErrSignatureInvalid,
		"a signature by an untrusted key must fail against every trusted cert")
}

func TestKeyInfoFallback_ExpiredCandidateSkipped(t *testing.T) {
	now := time.Now()
	_, expiredCert := genKeyCert(t, 2048, now.Add(-2*time.Hour), now.Add(-1*time.Hour))
	validKey, validCert := genKeyCert(t, 2048, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	signed := signDoc(t, validKey, validCert, "_fb-expired-skip")
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	res, err := newVerifier(expiredCert, validCert).Verify(signed)
	require.NoError(t, err, "an expired candidate must not prevent a valid one from verifying")
	assert.True(t, res.Certificate.Equal(validCert))
}

func TestKeyInfoFallback_OnlyExpiredCertMatches(t *testing.T) {
	now := time.Now()
	expiredKey, expiredCert := genKeyCert(t, 2048, now.Add(-2*time.Hour), now.Add(-1*time.Hour))
	_, validCert := genKeyCert(t, 2048, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	signed := signDoc(t, expiredKey, expiredCert, "_fb-expired-match")
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	_, err := newVerifier(expiredCert, validCert).Verify(signed)
	require.Error(t, err,
		"a signature by an expired cert's key must not verify even with fallback")
}

// The fallback must never bypass pinning: a signature that embeds an
// untrusted certificate in KeyInfo is rejected outright, even if the
// signature was actually produced by a trusted key.
func TestKeyInfoFallback_DoesNotBypassPinning(t *testing.T) {
	trustedKey, trustedCert := randomTestKeyAndCert()
	_, otherTrustedCert := randomTestKeyAndCert()
	_, untrustedCert := randomTestKeyAndCert()

	// Sign with the trusted key but embed the untrusted cert in KeyInfo.
	signed := signDocWithCerts(t, trustedKey, []*x509.Certificate{untrustedCert}, "_fb-pin")

	_, err := newVerifier(trustedCert, otherTrustedCert).Verify(signed)
	require.ErrorIs(t, err, ErrCertificateNotTrusted,
		"an untrusted embedded cert must be rejected without trying other trusted certs")
}

func TestKeyInfoFallback_MixedKeyTypes(t *testing.T) {
	now := time.Now()
	_, rsaCert := genKeyCert(t, 2048, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	ecKey, ecCert := genECDSAKeyCert(t, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	signed := signDocWithCerts(t, ecKey, []*x509.Certificate{ecCert}, "_fb-mixed")
	removeKeyInfoFromSig(signed)
	signed = reparse(t, signed)

	// The RSA candidate (tried first) fails cleanly and the loop continues to
	// the matching ECDSA cert.
	res, err := newVerifier(rsaCert, ecCert).Verify(signed)
	require.NoError(t, err)
	assert.True(t, res.Certificate.Equal(ecCert))
}
