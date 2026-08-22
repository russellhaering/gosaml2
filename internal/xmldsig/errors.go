package xmldsig

import "errors"

var (
	// ErrMissingSignature indicates that no enveloped signature was found
	// referencing the top-level element passed for signature verification.
	ErrMissingSignature = errors.New("dsig: missing signature referencing the top-level element")

	// ErrCertificateNotTrusted indicates that the signing certificate is not
	// in the trusted set.
	ErrCertificateNotTrusted = errors.New("dsig: signing certificate not in trusted set")

	// ErrCertificateExpired indicates that the signing certificate is not
	// valid at the current time.
	ErrCertificateExpired = errors.New("dsig: certificate not valid at current time")

	// ErrAlgorithmNotAllowed indicates that the signature or digest algorithm
	// is not permitted by the verifier configuration.
	ErrAlgorithmNotAllowed = errors.New("dsig: signature or digest algorithm not allowed")

	// ErrDigestMismatch indicates that the computed digest does not match the
	// signed digest value.
	ErrDigestMismatch = errors.New("dsig: computed digest does not match signed digest value")

	// ErrSignatureInvalid indicates that cryptographic signature verification
	// failed.
	ErrSignatureInvalid = errors.New("dsig: cryptographic signature verification failed")

	// ErrMalformedSignature indicates that the signature element has an
	// unexpected structure.
	ErrMalformedSignature = errors.New("dsig: signature element has unexpected structure")

	// ErrCanonicalizationLimit indicates that canonicalization would have to
	// process more elements than its traversal limit allows.
	ErrCanonicalizationLimit = errors.New("dsig: canonicalization element limit exceeded")
)
