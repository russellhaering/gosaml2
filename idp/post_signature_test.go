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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

const postTestSPEntityID = "https://sp.test/metadata"

// signingTestIdP returns an IdP whose registered SP's signing certificate
// matches the returned signer, so POST-binding signatures can be produced.
func signingTestIdP(t *testing.T) (*IdentityProvider, *dsig.Signer) {
	t.Helper()
	idp, _ := testIdentityProvider(t)

	spKS, spCert := testSPKeyStore(t)
	idp.ServiceProviders[postTestSPEntityID].SigningCertificates = []*x509.Certificate{spCert}

	return idp, &dsig.Signer{
		Key:   spKS.Signer,
		Certs: []*x509.Certificate{spCert},
	}
}

// signPOSTMessage signs an XML message with an enveloped signature and
// base64-encodes it for the HTTP-POST binding.
func signPOSTMessage(t *testing.T, signer *dsig.Signer, xmlStr string) string {
	t.Helper()
	doc, err := xmltree.Parse([]byte(xmlStr))
	require.NoError(t, err)

	signed, err := signer.SignEnveloped(doc.Root())
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(signed.WriteToBytes())
}

func postTestLogoutRequestXML(idp *IdentityProvider, nameID string) string {
	return fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout1" Version="2.0" IssueInstant="2025-06-01T12:00:00Z" Destination="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID>%s</saml:NameID></samlp:LogoutRequest>`,
		idp.SLOURL, postTestSPEntityID, nameID)
}

// TestAuthnRequestPOSTRequiresSignature is the regression test for the binding
// downgrade: RequireSignedAuthnRequests was enforced only on the HTTP-Redirect
// binding, so a peer could strip the signature by switching to HTTP-POST.
func TestAuthnRequestPOSTRequiresSignature(t *testing.T) {
	idp, _ := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encodeAuthnRequestPOST(xmlStr))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingSignature)
}

// TestAuthnRequestPOSTAcceptsValidSignature confirms the new verification path
// accepts a properly signed request and reports the signed values.
func TestAuthnRequestPOSTAcceptsValidSignature(t *testing.T) {
	idp, signer := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")

	info, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), signPOSTMessage(t, signer, xmlStr))
	require.NoError(t, err)
	require.Equal(t, "_req123", info.ID)
	require.Equal(t, postTestSPEntityID, info.Issuer)
	require.Equal(t, "https://sp.test/acs", info.ACSURL)
}

// TestAuthnRequestPOSTRejectsTamperedSignature confirms the digest still binds
// the message content after signing.
func TestAuthnRequestPOSTRejectsTamperedSignature(t *testing.T) {
	idp, signer := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")
	encoded := signPOSTMessage(t, signer, xmlStr)

	rawSigned, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)

	// Swap the ACS URL for another registered one after signing.
	idp.ServiceProviders[postTestSPEntityID].ACSURLs = append(
		idp.ServiceProviders[postTestSPEntityID].ACSURLs, "https://sp.test/acs2")
	tampered := strings.Replace(string(rawSigned), "https://sp.test/acs", "https://sp.test/acs2", 1)
	require.NotEqual(t, string(rawSigned), tampered)

	_, err = idp.ValidateEncodedAuthnRequestPOST(context.Background(),
		base64.StdEncoding.EncodeToString([]byte(tampered)))
	require.Error(t, err)
}

// TestAuthnRequestPOSTUnsignedAllowedWhenNotRequired keeps the permissive
// default: an SP that does not require signed requests may still send them
// unsigned, since SAML does not mandate AuthnRequest signing.
func TestAuthnRequestPOSTUnsignedAllowedWhenNotRequired(t *testing.T) {
	idp, _ := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = false

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")

	info, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), encodeAuthnRequestPOST(xmlStr))
	require.NoError(t, err)
	require.Equal(t, "_req123", info.ID)
}

// TestAuthnRequestPOSTRejectsBadSignatureEvenWhenNotRequired confirms that a
// signature which is present but invalid is rejected rather than ignored,
// matching the Redirect binding's "verify whenever a signature is offered".
func TestAuthnRequestPOSTRejectsBadSignatureEvenWhenNotRequired(t *testing.T) {
	idp, _ := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = false

	// Sign with a different key than the one registered for the SP.
	otherKS, otherCert := testSPKeyStore(t)
	rogue := &dsig.Signer{Key: otherKS.Signer, Certs: []*x509.Certificate{otherCert}}

	xmlStr := buildTestAuthnRequestXML("_req123", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")

	_, err := idp.ValidateEncodedAuthnRequestPOST(context.Background(), signPOSTMessage(t, rogue, xmlStr))
	require.Error(t, err)
}

// TestLogoutRequestPOSTRequiresSignature is the regression test for a forged,
// unsigned LogoutRequest terminating an arbitrary user's session.
func TestLogoutRequestPOSTRequiresSignature(t *testing.T) {
	idp, _ := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	encoded := base64.StdEncoding.EncodeToString([]byte(postTestLogoutRequestXML(idp, "victim@example.com")))

	_, _, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingSignature)
}

// TestLogoutRequestPOSTAcceptsValidSignature confirms the signed path still works.
func TestLogoutRequestPOSTAcceptsValidSignature(t *testing.T) {
	idp, signer := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].RequireSignedAuthnRequests = true

	encoded := signPOSTMessage(t, signer, postTestLogoutRequestXML(idp, "victim@example.com"))

	req, spc, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.NoError(t, err)
	require.Equal(t, "_logout1", req.ID)
	require.Equal(t, "victim@example.com", req.NameID.Value)
	require.Equal(t, postTestSPEntityID, spc.EntityID)
}

// --- certificate validity on the redirect binding --------------------------

// certKeyStore builds a key whose certificate is valid over [from, to).
func certKeyStore(t *testing.T, from, to time.Time) (*saml2.KeyStore, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		NotBefore:             from,
		NotAfter:              to,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &saml2.KeyStore{Signer: key, Cert: der}, cert
}

// signRedirectQuery signs the redirect-binding query string for paramName.
func signRedirectQuery(t *testing.T, key *rsa.PrivateKey, paramName, msg, relayState string) (string, string) {
	t.Helper()
	sigAlg := saml2.SignatureMethodIdentifier(key, crypto.SHA256)
	var buf bytes.Buffer
	buf.WriteString(url.QueryEscape(paramName) + "=" + url.QueryEscape(msg))
	if relayState != "" {
		buf.WriteString("&" + url.QueryEscape("RelayState") + "=" + url.QueryEscape(relayState))
	}
	buf.WriteString("&" + url.QueryEscape("SigAlg") + "=" + url.QueryEscape(sigAlg))
	h := crypto.SHA256.New()
	h.Write(buf.Bytes())
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	require.NoError(t, err)
	return sigAlg, base64.StdEncoding.EncodeToString(sig)
}

// TestRedirectRejectsExpiredSPCertificate is the regression test for the IdP
// redirect verifier skipping the certificate validity window. Every other
// certificate-based verification path in the library enforces it, so without
// this a retired SP signing key stays usable forever and expiry cannot revoke.
func TestRedirectRejectsExpiredSPCertificate(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-2000*24*time.Hour), testTime.Add(-1000*24*time.Hour))
	spc := idp.ServiceProviders[postTestSPEntityID]
	spc.RequireSignedAuthnRequests = true
	spc.SigningCertificates = []*x509.Certificate{cert}

	xmlStr := buildTestAuthnRequestXML("_req1", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")
	msg := encodeAuthnRequestRedirect(xmlStr)
	sigAlg, sig := signRedirectQuery(t, ks.Signer.(*rsa.PrivateKey), "SAMLRequest", msg, "")

	_, err := idp.ValidateEncodedAuthnRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadSignature)
}

// TestRedirectRejectsNotYetValidSPCertificate covers the other end of the window.
func TestRedirectRejectsNotYetValidSPCertificate(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(1000*24*time.Hour), testTime.Add(2000*24*time.Hour))
	spc := idp.ServiceProviders[postTestSPEntityID]
	spc.RequireSignedAuthnRequests = true
	spc.SigningCertificates = []*x509.Certificate{cert}

	xmlStr := buildTestAuthnRequestXML("_req1", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")
	msg := encodeAuthnRequestRedirect(xmlStr)
	sigAlg, sig := signRedirectQuery(t, ks.Signer.(*rsa.PrivateKey), "SAMLRequest", msg, "")

	_, err := idp.ValidateEncodedAuthnRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadSignature)
}

// TestRedirectAcceptsCurrentSPCertificate confirms the validity check did not
// simply break the redirect binding.
func TestRedirectAcceptsCurrentSPCertificate(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	spc := idp.ServiceProviders[postTestSPEntityID]
	spc.RequireSignedAuthnRequests = true
	spc.SigningCertificates = []*x509.Certificate{cert}

	xmlStr := buildTestAuthnRequestXML("_req1", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")
	msg := encodeAuthnRequestRedirect(xmlStr)
	sigAlg, sig := signRedirectQuery(t, ks.Signer.(*rsa.PrivateKey), "SAMLRequest", msg, "")

	info, err := idp.ValidateEncodedAuthnRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.NoError(t, err)
	require.Equal(t, "_req1", info.ID)
}

// TestRedirectExpiredCertificateRejectedOnLogout covers the SLO path, where an
// expired key would otherwise forge session termination.
func TestRedirectExpiredCertificateRejectedOnLogout(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-2000*24*time.Hour), testTime.Add(-1000*24*time.Hour))
	spc := idp.ServiceProviders[postTestSPEntityID]
	spc.SigningCertificates = []*x509.Certificate{cert}

	msg := encodeAuthnRequestRedirect(postTestLogoutRequestXML(idp, "victim@example.com"))
	sigAlg, sig := signRedirectQuery(t, ks.Signer.(*rsa.PrivateKey), "SAMLRequest", msg, "")

	_, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadSignature)
}

// TestRedirectRejectsKeyTypeMismatch pins the SigAlg-to-key-family binding, so
// a signature is only ever checked against a matching certificate.
func TestRedirectRejectsKeyTypeMismatch(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	spc := idp.ServiceProviders[postTestSPEntityID]
	spc.RequireSignedAuthnRequests = true
	spc.SigningCertificates = []*x509.Certificate{cert}

	xmlStr := buildTestAuthnRequestXML("_req1", postTestSPEntityID, idp.SSOURL, "https://sp.test/acs")
	msg := encodeAuthnRequestRedirect(xmlStr)
	_, sig := signRedirectQuery(t, ks.Signer.(*rsa.PrivateKey), "SAMLRequest", msg, "")

	// Claim ECDSA while presenting an RSA signature against an RSA certificate.
	_, err := idp.ValidateEncodedAuthnRequestRedirect(context.Background(), msg, "",
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadSignature)
}

// --- logout signatures required by default ---------------------------------

// TestLogoutRedirectRequiresSignatureByDefault is the regression test for
// signature stripping on the redirect SLO binding: verification used to be
// gated on the AuthnRequest signing flag, so with its default of false an
// attacker just omitted SigAlg/Signature.
func TestLogoutRedirectRequiresSignatureByDefault(t *testing.T) {
	idp, _ := signingTestIdP(t)
	spc := idp.ServiceProviders[postTestSPEntityID]
	require.False(t, spc.RequireSignedAuthnRequests)
	require.False(t, spc.AllowUnsignedLogoutRequests)

	msg := encodeAuthnRequestRedirect(postTestLogoutRequestXML(idp, "victim@example.com"))

	_, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "", "", "")
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingSignature)
}

// TestLogoutPOSTRequiresSignatureByDefault is the same for the POST binding:
// the requirement must not depend on the AuthnRequest signing flag either.
func TestLogoutPOSTRequiresSignatureByDefault(t *testing.T) {
	idp, _ := signingTestIdP(t)
	spc := idp.ServiceProviders[postTestSPEntityID]
	require.False(t, spc.RequireSignedAuthnRequests)

	encoded := base64.StdEncoding.EncodeToString([]byte(postTestLogoutRequestXML(idp, "victim@example.com")))

	_, _, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingSignature)
}

// TestLogoutRedirectAcceptsValidSignature confirms the signed redirect path works.
func TestLogoutRedirectAcceptsValidSignature(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	idp.ServiceProviders[postTestSPEntityID].SigningCertificates = []*x509.Certificate{cert}

	msg := encodeAuthnRequestRedirect(postTestLogoutRequestXML(idp, "victim@example.com"))
	sigAlg, sig := signRedirectQuery(t, ks.Signer.(*rsa.PrivateKey), "SAMLRequest", msg, "relay1")

	req, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "relay1", sigAlg, sig)
	require.NoError(t, err)
	require.Equal(t, "_logout1", req.ID)
}

// TestLogoutUnsignedAllowedOnlyWithExplicitOptIn documents the escape hatch.
func TestLogoutUnsignedAllowedOnlyWithExplicitOptIn(t *testing.T) {
	idp, _ := signingTestIdP(t)
	idp.ServiceProviders[postTestSPEntityID].AllowUnsignedLogoutRequests = true

	msg := encodeAuthnRequestRedirect(postTestLogoutRequestXML(idp, "victim@example.com"))
	_, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "", "", "")
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString([]byte(postTestLogoutRequestXML(idp, "victim@example.com")))
	_, _, err = idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.NoError(t, err)
}

// TestLogoutOptInStillRejectsBadSignature confirms the opt-out only permits an
// ABSENT signature, not an invalid one.
func TestLogoutOptInStillRejectsBadSignature(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	_, cert := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	otherKS, _ := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	spc := idp.ServiceProviders[postTestSPEntityID]
	spc.AllowUnsignedLogoutRequests = true
	spc.SigningCertificates = []*x509.Certificate{cert}

	msg := encodeAuthnRequestRedirect(postTestLogoutRequestXML(idp, "victim@example.com"))
	sigAlg, sig := signRedirectQuery(t, otherKS.Signer.(*rsa.PrivateKey), "SAMLRequest", msg, "")

	_, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrBadSignature)
}

// --- logout message freshness ----------------------------------------------

// signedLogoutRedirect builds a signed redirect LogoutRequest with the given
// IssueInstant / NotOnOrAfter attributes.
func signedLogoutRedirect(t *testing.T, idp *IdentityProvider, key *rsa.PrivateKey, issueInstant, notOnOrAfter string) (string, string, string) {
	t.Helper()
	extra := ""
	if notOnOrAfter != "" {
		extra = fmt.Sprintf(` NotOnOrAfter="%s"`, notOnOrAfter)
	}
	xmlStr := fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lo1" Version="2.0" IssueInstant="%s"%s Destination="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID>victim@example.com</saml:NameID></samlp:LogoutRequest>`,
		issueInstant, extra, idp.SLOURL, postTestSPEntityID)
	msg := encodeAuthnRequestRedirect(xmlStr)
	sigAlg, sig := signRedirectQuery(t, key, "SAMLRequest", msg, "")
	return msg, sigAlg, sig
}

// TestIdPLogoutRequestStaleIssueInstantRejected is the regression test for the
// IdP accepting a captured signed LogoutRequest indefinitely. The redirect
// binding carries the whole signed message in a URL, so captures leak through
// browser history, proxy logs and Referer headers.
func TestIdPLogoutRequestStaleIssueInstantRejected(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	idp.ServiceProviders[postTestSPEntityID].SigningCertificates = []*x509.Certificate{cert}

	stale := testTime.Add(-24 * time.Hour).Format(time.RFC3339)
	msg, sigAlg, sig := signedLogoutRedirect(t, idp, ks.Signer.(*rsa.PrivateKey), stale, "")

	_, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// TestIdPLogoutRequestFreshAccepted confirms the bound is a window.
func TestIdPLogoutRequestFreshAccepted(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	idp.ServiceProviders[postTestSPEntityID].SigningCertificates = []*x509.Certificate{cert}

	msg, sigAlg, sig := signedLogoutRedirect(t, idp, ks.Signer.(*rsa.PrivateKey),
		testTime.Format(time.RFC3339), "")

	req, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.NoError(t, err)
	require.Equal(t, "_lo1", req.ID)
}

// TestIdPLogoutRequestFutureIssueInstantRejected covers the other direction.
func TestIdPLogoutRequestFutureIssueInstantRejected(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	idp.ServiceProviders[postTestSPEntityID].SigningCertificates = []*x509.Certificate{cert}

	future := testTime.Add(24 * time.Hour).Format(time.RFC3339)
	msg, sigAlg, sig := signedLogoutRedirect(t, idp, ks.Signer.(*rsa.PrivateKey), future, "")

	_, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrNotYetValid)
}

// TestIdPLogoutRequestNotOnOrAfterEnforced is the regression test for
// ReceivedLogoutRequest not modelling NotOnOrAfter at all: an SP that supplied
// the attribute could not have it honoured.
func TestIdPLogoutRequestNotOnOrAfterEnforced(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	idp.ServiceProviders[postTestSPEntityID].SigningCertificates = []*x509.Certificate{cert}

	// Fresh IssueInstant, but already expired by its own NotOnOrAfter.
	msg, sigAlg, sig := signedLogoutRedirect(t, idp, ks.Signer.(*rsa.PrivateKey),
		testTime.Format(time.RFC3339), testTime.Add(-time.Hour).Format(time.RFC3339))

	_, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrExpired)
}

// TestIdPLogoutRequestNotOnOrAfterInFutureAccepted confirms a live expiry passes
// and is surfaced on the struct.
func TestIdPLogoutRequestNotOnOrAfterInFutureAccepted(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	ks, cert := certKeyStore(t, testTime.Add(-time.Hour), testTime.Add(365*24*time.Hour))
	idp.ServiceProviders[postTestSPEntityID].SigningCertificates = []*x509.Certificate{cert}

	notOnOrAfter := testTime.Add(time.Hour).Format(time.RFC3339)
	msg, sigAlg, sig := signedLogoutRedirect(t, idp, ks.Signer.(*rsa.PrivateKey),
		testTime.Format(time.RFC3339), notOnOrAfter)

	req, _, err := idp.ValidateEncodedLogoutRequestRedirect(context.Background(), msg, "", sigAlg, sig)
	require.NoError(t, err)
	require.Equal(t, notOnOrAfter, req.NotOnOrAfter)
}

// TestIdPLogoutRequestMissingIssueInstantRejected: IssueInstant is mandatory on
// SAML protocol messages, and an absent one must not read as unbounded.
func TestIdPLogoutRequestMissingIssueInstantRejected(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	idp.ServiceProviders[postTestSPEntityID].AllowUnsignedLogoutRequests = true

	xmlStr := fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lo1" Version="2.0" Destination="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID>victim@example.com</saml:NameID></samlp:LogoutRequest>`,
		idp.SLOURL, postTestSPEntityID)

	_, _, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(),
		base64.StdEncoding.EncodeToString([]byte(xmlStr)))
	require.Error(t, err)
	require.ErrorIs(t, err, saml2.ErrMissingElement)
}

// TestIdPLogoutRequestMaxAgeConfigurable confirms the window is tunable.
func TestIdPLogoutRequestMaxAgeConfigurable(t *testing.T) {
	idp, _ := testIdentityProvider(t)
	idp.ServiceProviders[postTestSPEntityID].AllowUnsignedLogoutRequests = true
	idp.ClockSkew = time.Second

	xmlStr := fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lo1" Version="2.0" IssueInstant="%s" Destination="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID>victim@example.com</saml:NameID></samlp:LogoutRequest>`,
		testTime.Add(-time.Hour).Format(time.RFC3339), idp.SLOURL, postTestSPEntityID)
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))

	idp.MaxIssueInstantAge = 5 * time.Minute
	_, _, err := idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.ErrorIs(t, err, saml2.ErrExpired)

	idp.MaxIssueInstantAge = 24 * time.Hour
	_, _, err = idp.ValidateEncodedLogoutRequestPOST(context.Background(), encoded)
	require.NoError(t, err)
}
