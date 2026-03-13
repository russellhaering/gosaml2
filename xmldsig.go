package saml2

// Re-exported types, constructors, and sentinels from internal/xmldsig so that
// external consumers who reference these via the saml2 package are not broken
// by the vendoring of goxmldsig.

import dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"

// Type aliases — these keep the public API stable.
type Canonicalizer = dsig.Canonicalizer
type XMLSigner = dsig.Signer
type XMLVerifier = dsig.Verifier
type XMLVerifyResult = dsig.VerifyResult
type AlgorithmID = dsig.AlgorithmID

// Canonicalizer constructors.
var (
	MakeNullCanonicalizer                                       = dsig.MakeNullCanonicalizer
	MakeC14N10ExclusiveCanonicalizerWithPrefixList               = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList
	MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList   = dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList
	MakeC14N11Canonicalizer                                     = dsig.MakeC14N11Canonicalizer
	MakeC14N11WithCommentsCanonicalizer                         = dsig.MakeC14N11WithCommentsCanonicalizer
	MakeC14N10RecCanonicalizer                                  = dsig.MakeC14N10RecCanonicalizer
	MakeC14N10WithCommentsCanonicalizer                         = dsig.MakeC14N10WithCommentsCanonicalizer
)

// Error sentinels from xmldsig, re-exported for external consumers.
// Note: ErrMissingSignature is not re-exported here because the saml2
// package defines its own ErrMissingSignature sentinel. Internal code
// uses dsig.ErrMissingSignature (qualified) to refer to the xmldsig one.
var (
	ErrCertificateNotTrusted = dsig.ErrCertificateNotTrusted
	ErrCertificateExpired    = dsig.ErrCertificateExpired
	ErrAlgorithmNotAllowed   = dsig.ErrAlgorithmNotAllowed
	ErrDigestMismatch        = dsig.ErrDigestMismatch
	ErrSignatureInvalid      = dsig.ErrSignatureInvalid
	ErrMalformedSignature    = dsig.ErrMalformedSignature
)

// Signature method URI constants.
const (
	RSASHA1SignatureMethod     = dsig.RSASHA1SignatureMethod
	RSASHA256SignatureMethod   = dsig.RSASHA256SignatureMethod
	RSASHA384SignatureMethod   = dsig.RSASHA384SignatureMethod
	RSASHA512SignatureMethod   = dsig.RSASHA512SignatureMethod
	ECDSASHA1SignatureMethod   = dsig.ECDSASHA1SignatureMethod
	ECDSASHA256SignatureMethod = dsig.ECDSASHA256SignatureMethod
	ECDSASHA384SignatureMethod = dsig.ECDSASHA384SignatureMethod
	ECDSASHA512SignatureMethod = dsig.ECDSASHA512SignatureMethod
)

// Canonicalization algorithm identifiers.
const (
	CanonicalXML10ExclusiveAlgorithmId             = dsig.CanonicalXML10ExclusiveAlgorithmId
	CanonicalXML10ExclusiveWithCommentsAlgorithmId = dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId
	CanonicalXML11AlgorithmId                      = dsig.CanonicalXML11AlgorithmId
	CanonicalXML11WithCommentsAlgorithmId          = dsig.CanonicalXML11WithCommentsAlgorithmId
	CanonicalXML10RecAlgorithmId                   = dsig.CanonicalXML10RecAlgorithmId
	CanonicalXML10WithCommentsAlgorithmId          = dsig.CanonicalXML10WithCommentsAlgorithmId
	EnvelopedSignatureAlgorithmId                  = dsig.EnvelopedSignatureAlgorithmId
)
