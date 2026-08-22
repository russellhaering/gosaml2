package saml2

// Re-exported types and constructors from internal/xmldsig for the public API.

import dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"

// Canonicalizer is the interface for XML canonicalization algorithms.
// Used as a field type on ServiceProvider and IdentityProvider.
type Canonicalizer = dsig.Canonicalizer

// Canonicalizer constructors for use with ServiceProvider.SignAuthnRequestsCanonicalizer
// and IdentityProvider.SignatureCanonicalizer.
var (
	MakeC14N10ExclusiveCanonicalizerWithPrefixList             = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList
	MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList = dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList
	MakeC14N11Canonicalizer                                    = dsig.MakeC14N11Canonicalizer
	MakeC14N11WithCommentsCanonicalizer                        = dsig.MakeC14N11WithCommentsCanonicalizer
	MakeC14N10RecCanonicalizer                                 = dsig.MakeC14N10RecCanonicalizer
	MakeC14N10WithCommentsCanonicalizer                        = dsig.MakeC14N10WithCommentsCanonicalizer
)
