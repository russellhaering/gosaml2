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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
)

// TestPreAuthCanonicalizationIsBounded is the regression test for the
// pre-authentication CPU amplification. Every candidate ds:Signature's
// SignedInfo is canonicalized before any crypto runs, and attribute sorting was
// quadratic in the attribute count, so a DEFLATE-compressed response turned
// tens of kilobytes on the wire into seconds of CPU.
func TestPreAuthCanonicalizationIsBounded(t *testing.T) {
	sp, _ := securityTestSP(t)

	raw := buildDecoySignatureResponse(2, 780, 250)
	wire := deflateAndEncode(t, raw)

	start := time.Now()
	_, err := sp.ValidateEncodedResponse(context.Background(), wire)
	elapsed := time.Since(start)

	require.Error(t, err)
	t.Logf("wire=%d B inflated=%d B CPU=%v", len(wire), len(raw), elapsed)

	// Before the quadratic attribute sort was fixed this took over 2s; it is
	// now a few hundred milliseconds, essentially the cost of parsing the
	// inflated document. The bound is deliberately loose so it fails only on a
	// real regression rather than on a slow machine.
	//
	// This guards the sort complexity. It does not isolate findSignature's
	// Reference-URI pre-filter: the bounded namespace traversal already caps
	// per-signature canonicalization, so skipping decoys early is a constant-
	// factor win (~1.75x here) rather than something a ratio test can pin.
	if elapsed > 1500*time.Millisecond {
		t.Errorf("pre-auth rejection of a %d byte request burned %v of CPU "+
			"(inflated to %d bytes) — canonicalization cost looks superlinear again",
			len(wire), elapsed, len(raw))
	}
}

// buildDecoySignatureResponse builds an unsigned Response carrying nSigs
// ds:Signature children whose Reference URIs match nothing, each with a
// SignedInfo padded with nElems elements carrying nAttrs prefixed attributes.
// None is ever selected for verification, but each is canonicalized first.
func buildDecoySignatureResponse(nSigs, nElems, nAttrs int) string {
	var sb strings.Builder
	sb.WriteString(`<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0">`)
	for s := 0; s < nSigs; s++ {
		sb.WriteString(`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`)
		sb.WriteString(`<ds:SignedInfo`)
		for j := 0; j < nAttrs; j++ {
			fmt.Fprintf(&sb, ` xmlns:p%04d="urn:%04d"`, j, j)
		}
		sb.WriteString(`><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`)
		sb.WriteString(`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>`)
		sb.WriteString(`<ds:Reference URI="#nomatch"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference>`)
		for i := 0; i < nElems; i++ {
			sb.WriteString(`<ds:Object`)
			for j := 0; j < nAttrs; j++ {
				fmt.Fprintf(&sb, ` p%04d:a="v"`, j)
			}
			sb.WriteString(`/>`)
		}
		sb.WriteString(`</ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>`)
	}
	sb.WriteString(`</saml2p:Response>`)
	return sb.String()
}
