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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
)

// ---------------------------------------------------------------------------
// MemoryRequestTracker injectable clock
// ---------------------------------------------------------------------------

func TestMemoryRequestTracker_InjectedClock_Expiry(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	cur := base

	tr := NewMemoryRequestTracker(5 * time.Minute)
	tr.Clock = func() time.Time { return cur }

	ctx := context.Background()
	require.NoError(t, tr.StoreRequest(ctx, "id-expired"))

	// Within the window: consume succeeds.
	require.NoError(t, tr.StoreRequest(ctx, "id-fresh"))
	cur = base.Add(4 * time.Minute)
	require.NoError(t, tr.ConsumeRequest(ctx, "id-fresh"))

	// Past the window: the stale entry is swept and consume reports a replay.
	cur = base.Add(6 * time.Minute)
	err := tr.ConsumeRequest(ctx, "id-expired")
	require.ErrorIs(t, err, saml2.ErrReplay,
		"entry should expire according to the injected clock")
}

func TestMemoryRequestTracker_DefaultClock(t *testing.T) {
	tr := NewMemoryRequestTracker(5 * time.Minute)
	ctx := context.Background()
	require.NoError(t, tr.StoreRequest(ctx, "id1"))
	require.NoError(t, tr.ConsumeRequest(ctx, "id1"))
	// Second consume must fail (already consumed).
	require.ErrorIs(t, tr.ConsumeRequest(ctx, "id1"), saml2.ErrReplay)
}

// ---------------------------------------------------------------------------
// Redirect binding: SigAlg key family must match the certificate
// ---------------------------------------------------------------------------

// Before the cross-check, an RSA signature presented under an ECDSA SigAlg would
// verify: the code derived only the hash (SHA-256) from the SigAlg and then used
// the RSA certificate's RSA verification path. Now the declared key family must
// match the certificate's key type.
func TestRedirect_SigAlgKeyFamilyMismatch_Rejected(t *testing.T) {
	sp, key := redirectTestSP(t)

	encoded := deflateAndEncode(t, `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)

	// Declare an ECDSA SigAlg but actually sign with RSA-PKCS1v15/SHA-256 over a
	// string that embeds the (mismatched) ECDSA SigAlg, so the bytes themselves
	// verify against the RSA key.
	bogusAlg := dsig.ECDSASHA256SignatureMethod

	var buf bytes.Buffer
	buf.WriteString(url.QueryEscape("SAMLResponse") + "=" + url.QueryEscape(encoded))
	buf.WriteString("&" + url.QueryEscape("SigAlg") + "=" + url.QueryEscape(bogusAlg))

	h := crypto.SHA256.New()
	h.Write(buf.Bytes())
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	require.NoError(t, err)
	sig := base64.StdEncoding.EncodeToString(sigBytes)

	err = sp.verifyRedirectSignature("SAMLResponse", encoded, "", bogusAlg, sig)
	require.Error(t, err,
		"an RSA signature presented under an ECDSA SigAlg must be rejected")
}

// Control: a correctly-declared RSA SigAlg with the RSA certificate still
// verifies, so the cross-check does not break the common case.
func TestRedirect_SigAlgKeyFamilyMatch_Accepted(t *testing.T) {
	sp, key := redirectTestSP(t)

	encoded := deflateAndEncode(t, `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)
	sigAlg, sig := signRedirectParams(t, key, crypto.SHA256, "SAMLResponse", encoded, "")

	require.NoError(t, sp.verifyRedirectSignature("SAMLResponse", encoded, "", sigAlg, sig))
}
