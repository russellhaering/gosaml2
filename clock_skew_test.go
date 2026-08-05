// Copyright 2026 Russell Haering et al.
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

package saml2

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// signResponseWithTimes rewrites the time bounds on a fixture response so
// that clock skew scenarios can be expressed relative to the test clock,
// then re-signs it.
func signResponseWithTimes(t *testing.T, resp string, sp *SAMLServiceProvider, notBefore, notOnOrAfter, subjectNotOnOrAfter time.Time) string {
	t.Helper()

	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(resp))
	require.NoError(t, err)

	assertionEl := doc.Root().SelectElement("saml2:Assertion")
	require.NotNil(t, assertionEl)

	conditionsEl := assertionEl.SelectElement("saml2:Conditions")
	require.NotNil(t, conditionsEl)

	notBeforeAttr := conditionsEl.SelectAttr("NotBefore")
	require.NotNil(t, notBeforeAttr)
	notBeforeAttr.Value = notBefore.Format(time.RFC3339)

	notOnOrAfterAttr := conditionsEl.SelectAttr("NotOnOrAfter")
	require.NotNil(t, notOnOrAfterAttr)
	notOnOrAfterAttr.Value = notOnOrAfter.Format(time.RFC3339)

	subjectConfirmationDataEl := assertionEl.FindElement("./saml2:Subject/saml2:SubjectConfirmation/saml2:SubjectConfirmationData")
	require.NotNil(t, subjectConfirmationDataEl)

	subjectNotOnOrAfterAttr := subjectConfirmationDataEl.SelectAttr("NotOnOrAfter")
	require.NotNil(t, subjectNotOnOrAfterAttr)
	subjectNotOnOrAfterAttr.Value = subjectNotOnOrAfter.Format(time.RFC3339)

	str, err := doc.WriteToString()
	require.NoError(t, err)

	return signResponse(t, str, sp)
}

func TestClockSkew(t *testing.T) {
	// The fake clock in getSAMLServiceProvider is pinned to this instant.
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	newSP := func(t *testing.T) *SAMLServiceProvider {
		ks := testKeyStore(t, now)
		_, _cert, err := ks.GetKeyPair()
		require.NoError(t, err)
		sp := getSAMLServiceProvider(t, _cert)
		sp.SPKeyStore = ks
		return sp
	}

	t.Run("NotBeforeInFuture", func(t *testing.T) {
		sp := newSP(t)
		raw := signResponseWithTimes(t, rawResponse, sp,
			now.Add(3*time.Minute), now.Add(time.Hour), now.Add(time.Hour))
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))

		info, err := sp.RetrieveAssertionInfo(encoded)
		require.NoError(t, err)
		require.True(t, info.WarningInfo.InvalidTime)

		sp.ClockSkew = 4 * time.Minute
		info, err = sp.RetrieveAssertionInfo(encoded)
		require.NoError(t, err)
		require.False(t, info.WarningInfo.InvalidTime)
	})

	t.Run("ConditionsExpired", func(t *testing.T) {
		sp := newSP(t)
		raw := signResponseWithTimes(t, rawResponse, sp,
			now.Add(-time.Hour), now.Add(-5*time.Minute), now.Add(time.Hour))
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))

		info, err := sp.RetrieveAssertionInfo(encoded)
		require.NoError(t, err)
		require.True(t, info.WarningInfo.InvalidTime)

		sp.ClockSkew = 6 * time.Minute
		info, err = sp.RetrieveAssertionInfo(encoded)
		require.NoError(t, err)
		require.False(t, info.WarningInfo.InvalidTime)
	})

	t.Run("SubjectConfirmationExpired", func(t *testing.T) {
		sp := newSP(t)
		raw := signResponseWithTimes(t, rawResponse, sp,
			now.Add(-time.Hour), now.Add(time.Hour), now.Add(-5*time.Minute))
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))

		_, err := sp.RetrieveAssertionInfo(encoded)
		require.Error(t, err)

		sp.ClockSkew = 6 * time.Minute
		info, err := sp.RetrieveAssertionInfo(encoded)
		require.NoError(t, err)
		require.False(t, info.WarningInfo.InvalidTime)
	})

	t.Run("NotOnOrAfterIsExclusive", func(t *testing.T) {
		sp := newSP(t)
		raw := signResponseWithTimes(t, rawResponse, sp,
			now.Add(-time.Hour), now, now.Add(time.Hour))
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))

		info, err := sp.RetrieveAssertionInfo(encoded)
		require.NoError(t, err)
		require.True(t, info.WarningInfo.InvalidTime)
	})
}
