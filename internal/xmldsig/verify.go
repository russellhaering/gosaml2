package xmldsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

var uriRegexp = regexp.MustCompile("^#[a-zA-Z_][\\w.-]*$")
var whiteSpace = regexp.MustCompile("\\s+")

// VerifyResult contains metadata about a successful verification.
type VerifyResult struct {
	// Element is the verified XML element, reconstructed from the canonical
	// bytes that were actually signed.
	Element *xmltree.Element

	// Certificate is the trusted certificate that verified the signature.
	Certificate *x509.Certificate
}

// Verifier validates enveloped XML digital signatures.
type Verifier struct {
	// TrustedCerts are the certificates accepted for signature verification.
	TrustedCerts []*x509.Certificate

	// IDAttribute is the XML attribute used to identify referenced elements.
	// Default: "ID"
	IDAttribute string

	// Clock returns the current time for certificate validity checking.
	// Default: time.Now
	Clock func() time.Time

	// AllowSHA1 permits SHA-1 for digest and signature algorithms.
	// Default: false
	AllowSHA1 bool
}

func (v *Verifier) idAttribute() string {
	if v.IDAttribute == "" {
		return defaultIdAttr
	}
	return v.IDAttribute
}

func (v *Verifier) now() time.Time {
	if v.Clock != nil {
		return v.Clock()
	}
	return time.Now()
}

// parsedSignature holds the extracted fields from a ds:Signature element.
type parsedSignature struct {
	el           *xmltree.Element  // the ds:Signature element itself
	signedInfoEl *xmltree.Element  // detached ds:SignedInfo
	sigMethod    string            // SignatureMethod Algorithm
	c14nMethod   string            // CanonicalizationMethod Algorithm
	refURI       string            // Reference URI
	digestMethod string            // DigestMethod Algorithm
	digestValue  string            // DigestValue text (base64)
	transforms   []parsedTransform // Transform Algorithm URIs
	sigValue     string            // SignatureValue text (base64)
	keyInfoCerts []string          // X509Certificate text values (base64 DER)
}

type parsedTransform struct {
	algorithm  string
	prefixList string // for exc-c14n InclusiveNamespaces
}

func (v *Verifier) checkAlgorithm(method string) error {
	info, ok := signatureMethodsByIdentifier[method]
	if !ok {
		return fmt.Errorf("%w: %s", ErrAlgorithmNotAllowed, method)
	}
	if info.Hash == crypto.SHA1 && !v.AllowSHA1 {
		return fmt.Errorf("%w: %s (set AllowSHA1 to permit)", ErrAlgorithmNotAllowed, method)
	}
	return nil
}

func (v *Verifier) checkDigestAlgorithm(method string) error {
	hash, ok := digestAlgorithmsByIdentifier[method]
	if !ok {
		return fmt.Errorf("%w: unknown digest algorithm %s", ErrAlgorithmNotAllowed, method)
	}
	if hash == crypto.SHA1 && !v.AllowSHA1 {
		return fmt.Errorf("%w: %s (set AllowSHA1 to permit)", ErrAlgorithmNotAllowed, method)
	}
	return nil
}

// Verify validates an enveloped XML signature on el.
func (v *Verifier) Verify(el *xmltree.Element) (*VerifyResult, error) {
	if len(v.TrustedCerts) == 0 {
		return nil, fmt.Errorf("%w: TrustedCerts is empty", ErrMissingSignature)
	}

	// Work on a copy to avoid mutating the input.
	el = el.Copy()

	sig, err := v.findSignature(el)
	if err != nil {
		return nil, err
	}

	// Check algorithms before doing any crypto
	if err := v.checkAlgorithm(sig.sigMethod); err != nil {
		return nil, err
	}
	if err := v.checkDigestAlgorithm(sig.digestMethod); err != nil {
		return nil, err
	}

	// Decode signature value
	decodedSignature, err := base64.StdEncoding.DecodeString(
		whiteSpace.ReplaceAllString(sig.sigValue, ""))
	if err != nil {
		return nil, fmt.Errorf("%w: could not decode signature value", ErrMalformedSignature)
	}

	// Canonicalize SignedInfo
	canonicalSignedInfo, err := canonicalSerialize(sig.signedInfoEl)
	if err != nil {
		return nil, err
	}

	// Determine which trusted cert(s) may have produced the signature.
	candidates, err := v.candidateCertificates(sig)
	if err != nil {
		return nil, err
	}

	// Verify the signature over SignedInfo against each candidate.
	now := v.now()
	var cert *x509.Certificate
	var lastErr error
	for _, candidate := range candidates {
		if now.Before(candidate.NotBefore) || now.After(candidate.NotAfter) {
			lastErr = ErrCertificateExpired
			continue
		}
		if err := verifySignature(candidate, sig.sigMethod, canonicalSignedInfo, decodedSignature); err != nil {
			lastErr = err
			continue
		}
		cert = candidate
		break
	}
	if cert == nil {
		return nil, lastErr
	}

	// Now use only the verified SignedInfo to extract reference data.
	// Re-parse the canonical SignedInfo bytes to extract reference info.
	verifiedSig, err := v.parseVerifiedSignedInfo(canonicalSignedInfo)
	if err != nil {
		return nil, err
	}

	// Verify the digest
	verifiedEl, err := v.verifyDigest(el, sig, verifiedSig)
	if err != nil {
		return nil, err
	}

	return &VerifyResult{
		Element:     verifiedEl,
		Certificate: cert,
	}, nil
}

// parseVerifiedSignedInfo re-parses canonical SignedInfo bytes to extract
// Reference URI, DigestMethod, DigestValue, and Transforms.
func (v *Verifier) parseVerifiedSignedInfo(canonicalBytes []byte) (*parsedSignature, error) {
	doc, err := xmltree.Parse(canonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: could not parse canonical SignedInfo", ErrMalformedSignature)
	}

	signedInfo := doc.Root()
	if signedInfo == nil {
		return nil, fmt.Errorf("%w: empty canonical SignedInfo", ErrMalformedSignature)
	}

	ps := &parsedSignature{}

	// Extract Reference
	refEl := findChildByTag(signedInfo, referenceTag)
	if refEl == nil {
		return nil, fmt.Errorf("%w: missing Reference in SignedInfo", ErrMalformedSignature)
	}

	ps.refURI = refEl.SelectAttrValue(uriAttr, "")

	// DigestMethod
	digestMethodEl := findChildByTag(refEl, digestMethodTag)
	if digestMethodEl == nil {
		return nil, fmt.Errorf("%w: missing DigestMethod", ErrMalformedSignature)
	}
	ps.digestMethod = digestMethodEl.SelectAttrValue(algorithmAttr, "")

	// DigestValue
	digestValueEl := findChildByTag(refEl, digestValueTag)
	if digestValueEl == nil {
		return nil, fmt.Errorf("%w: missing DigestValue", ErrMalformedSignature)
	}
	ps.digestValue = digestValueEl.Text()

	// Transforms
	transformsEl := findChildByTag(refEl, transformsTag)
	if transformsEl != nil {
		for _, child := range transformsEl.ChildElements() {
			if child.Tag == transformTag {
				t := parsedTransform{
					algorithm: child.SelectAttrValue(algorithmAttr, ""),
				}
				// Check for InclusiveNamespaces
				for _, grandchild := range child.ChildElements() {
					if grandchild.Tag == inclusiveNamespacesTag {
						t.prefixList = grandchild.SelectAttrValue(prefixListAttr, "")
					}
				}
				ps.transforms = append(ps.transforms, t)
			}
		}
	}

	return ps, nil
}

// findChildByTag finds a direct child element by tag name, ignoring namespace prefix.
func findChildByTag(el *xmltree.Element, tag string) *xmltree.Element {
	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			return child
		}
	}
	return nil
}

// referencesElement reports whether a Reference URI selects the element whose
// ID attribute is idAttr. An empty URI means the whole document, which always
// selects it; otherwise the URI must be a same-document "#id" match.
func referencesElement(refURI, idAttr string) bool {
	if refURI == "" {
		return true
	}
	return len(refURI) > 1 && refURI[0] == '#' && refURI[1:] == idAttr
}

// peekReferenceURI reads SignedInfo/Reference/@URI from a ds:Signature without
// canonicalizing anything. ok is false when the URI cannot be located, in which
// case the caller must not treat the signature as non-matching.
func peekReferenceURI(sigEl *xmltree.Element) (refURI string, ok bool) {
	signedInfoEl := findChildByTag(sigEl, signedInfoTag)
	if signedInfoEl == nil {
		return "", false
	}
	refEl := findChildByTag(signedInfoEl, referenceTag)
	if refEl == nil {
		return "", false
	}
	uri := refEl.SelectAttrValue(uriAttr, "")
	if uri == "" {
		// Either absent or genuinely empty; both must fall through to the
		// full parse rather than be skipped.
		return "", false
	}
	return uri, true
}

// findSignature searches only direct children of el for a ds:Signature.
func (v *Verifier) findSignature(el *xmltree.Element) (*parsedSignature, error) {
	idAttr := el.SelectAttrValue(v.idAttribute(), "")

	var found *parsedSignature
	nsCtx, err := NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	elCtx, err := nsCtx.SubContext(el)
	if err != nil {
		return nil, err
	}

	for _, child := range el.ChildElements() {
		childCtx, err := elCtx.SubContext(child)
		if err != nil {
			continue
		}

		currentNS, err := childCtx.LookupPrefix(child.Space)
		if err != nil {
			continue
		}

		if currentNS != namespace || child.Tag != signatureTag {
			continue
		}

		// Validate shape
		if err := validateShape(child); err != nil {
			return nil, err
		}

		// Cheap pre-filter before the expensive step. Parsing a signature
		// canonicalizes its SignedInfo, and a signature whose Reference URI
		// names some other element can never be selected below -- so a message
		// full of decoy signatures would otherwise buy an unauthenticated
		// sender one full canonicalization each. Peek at the Reference URI
		// first and skip those. An unreadable or empty URI is not skipped, so
		// ambiguity costs work rather than dropping a real signature.
		if refURI, ok := peekReferenceURI(child); ok && !referencesElement(refURI, idAttr) {
			continue
		}

		// Parse the signature element
		sig, err := v.parseSignatureElement(elCtx, child)
		if err != nil {
			return nil, err
		}

		// Check if this signature references our element
		if referencesElement(sig.refURI, idAttr) {
			if found != nil {
				return nil, fmt.Errorf("%w: multiple signatures reference the same element", ErrMalformedSignature)
			}
			found = sig
		}
	}

	if found == nil {
		return nil, ErrMissingSignature
	}

	return found, nil
}

func validateShape(signatureEl *xmltree.Element) error {
	children := signatureEl.ChildElements()

	childCounts := map[string]int{}
	for _, child := range children {
		childCounts[child.Tag]++
	}

	if childCounts[signedInfoTag] != 1 || childCounts[keyInfoTag] > 1 || childCounts[signatureValueTag] != 1 {
		return ErrMalformedSignature
	}
	return nil
}

// parseSignatureElement extracts all fields from a ds:Signature.
func (v *Verifier) parseSignatureElement(parentCtx NSContext, sigEl *xmltree.Element) (*parsedSignature, error) {
	sig := &parsedSignature{
		el: sigEl,
	}

	sigCtx, err := parentCtx.SubContext(sigEl)
	if err != nil {
		return nil, err
	}

	// Find SignedInfo
	var signedInfoEl *xmltree.Element
	for _, child := range sigEl.ChildElements() {
		ctx, err := sigCtx.SubContext(child)
		if err != nil {
			continue
		}
		ns, err := ctx.LookupPrefix(child.Space)
		if err != nil {
			continue
		}
		if ns == namespace && child.Tag == signedInfoTag {
			signedInfoEl = child
			break
		}
	}
	if signedInfoEl == nil {
		return nil, fmt.Errorf("%w: missing SignedInfo", ErrMalformedSignature)
	}

	// Detach SignedInfo with proper namespace context for canonicalization
	signedInfoCtx, err := sigCtx.SubContext(signedInfoEl)
	if err != nil {
		return nil, err
	}

	// Get C14N method from SignedInfo before detaching
	c14nMethodEl := findChildByTag(signedInfoEl, canonicalizationMethodTag)
	if c14nMethodEl == nil {
		return nil, fmt.Errorf("%w: missing CanonicalizationMethod", ErrMalformedSignature)
	}
	sig.c14nMethod = c14nMethodEl.SelectAttrValue(algorithmAttr, "")

	// Detach and canonicalize SignedInfo
	detachedSignedInfo, err := NSDetach(signedInfoCtx, signedInfoEl)
	if err != nil {
		return nil, err
	}

	// Apply the canonicalization method specified in SignedInfo
	switch alg := AlgorithmID(sig.c14nMethod); alg {
	case CanonicalXML10ExclusiveAlgorithmId, CanonicalXML10ExclusiveWithCommentsAlgorithmId:
		err := TransformExcC14n(detachedSignedInfo, "", alg == CanonicalXML10ExclusiveWithCommentsAlgorithmId)
		if err != nil {
			return nil, err
		}
	case CanonicalXML11AlgorithmId, CanonicalXML10RecAlgorithmId:
		detachedSignedInfo = canonicalPrep(detachedSignedInfo, true, false)
	case CanonicalXML11WithCommentsAlgorithmId, CanonicalXML10WithCommentsAlgorithmId:
		detachedSignedInfo = canonicalPrep(detachedSignedInfo, true, true)
	default:
		return nil, fmt.Errorf("%w: invalid CanonicalizationMethod: %s", ErrMalformedSignature, sig.c14nMethod)
	}

	sig.signedInfoEl = detachedSignedInfo

	// SignatureMethod
	sigMethodEl := findChildByTag(signedInfoEl, signatureMethodTag)
	if sigMethodEl == nil {
		return nil, fmt.Errorf("%w: missing SignatureMethod", ErrMalformedSignature)
	}
	sig.sigMethod = sigMethodEl.SelectAttrValue(algorithmAttr, "")

	// Reference
	refEl := findChildByTag(signedInfoEl, referenceTag)
	if refEl == nil {
		return nil, fmt.Errorf("%w: missing Reference", ErrMalformedSignature)
	}
	sig.refURI = refEl.SelectAttrValue(uriAttr, "")

	// DigestMethod
	digestMethodEl := findChildByTag(refEl, digestMethodTag)
	if digestMethodEl == nil {
		return nil, fmt.Errorf("%w: missing DigestMethod", ErrMalformedSignature)
	}
	sig.digestMethod = digestMethodEl.SelectAttrValue(algorithmAttr, "")

	// DigestValue
	digestValueEl := findChildByTag(refEl, digestValueTag)
	if digestValueEl == nil {
		return nil, fmt.Errorf("%w: missing DigestValue", ErrMalformedSignature)
	}
	sig.digestValue = digestValueEl.Text()

	// Transforms
	transformsEl := findChildByTag(refEl, transformsTag)
	if transformsEl != nil {
		for _, child := range transformsEl.ChildElements() {
			if child.Tag == transformTag {
				t := parsedTransform{
					algorithm: child.SelectAttrValue(algorithmAttr, ""),
				}
				for _, grandchild := range child.ChildElements() {
					if grandchild.Tag == inclusiveNamespacesTag {
						t.prefixList = grandchild.SelectAttrValue(prefixListAttr, "")
					}
				}
				sig.transforms = append(sig.transforms, t)
			}
		}
	}

	// SignatureValue
	var sigValueEl *xmltree.Element
	for _, child := range sigEl.ChildElements() {
		if child.Tag == signatureValueTag {
			sigValueEl = child
			break
		}
	}
	if sigValueEl == nil {
		return nil, fmt.Errorf("%w: missing SignatureValue", ErrMalformedSignature)
	}
	sig.sigValue = sigValueEl.Text()

	// KeyInfo certs (optional)
	for _, child := range sigEl.ChildElements() {
		if child.Tag == keyInfoTag {
			for _, x509data := range child.ChildElements() {
				if x509data.Tag == x509DataTag {
					for _, certEl := range x509data.ChildElements() {
						if certEl.Tag == x509CertificateTag {
							sig.keyInfoCerts = append(sig.keyInfoCerts, certEl.Text())
						}
					}
				}
			}
			break
		}
	}

	return sig, nil
}

// candidateCertificates returns the trusted certificate(s) a signature may be
// verified against. When the signature embeds a certificate in KeyInfo, that
// certificate must exactly match a trusted certificate (pinning) and is the
// sole candidate — KeyInfo selects among trusted certs, it never expands
// trust. When KeyInfo is absent, every trusted certificate is a candidate;
// the caller tries each, which keeps verification working when multiple
// certs are pinned (e.g. during IdP certificate rotation).
func (v *Verifier) candidateCertificates(sig *parsedSignature) ([]*x509.Certificate, error) {
	if len(sig.keyInfoCerts) == 0 || sig.keyInfoCerts[0] == "" {
		// No KeyInfo — any trusted cert may have produced the signature.
		return v.TrustedCerts, nil
	}

	certData, err := base64.StdEncoding.DecodeString(
		whiteSpace.ReplaceAllString(sig.keyInfoCerts[0], ""))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode certificate", ErrMalformedSignature)
	}

	untrustedCert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse certificate", ErrMalformedSignature)
	}

	// Find matching trusted cert
	for _, root := range v.TrustedCerts {
		if root.Equal(untrustedCert) {
			return []*x509.Certificate{root}, nil
		}
	}
	return nil, ErrCertificateNotTrusted
}

// verifySignature performs direct signature verification without cert.CheckSignature.
// For ECDSA, it decodes raw r||s (XML-DSig format). For RSA, uses VerifyPKCS1v15.
func verifySignature(cert *x509.Certificate, sigMethod string, signed, sig []byte) error {
	info, ok := signatureMethodsByIdentifier[sigMethod]
	if !ok {
		return fmt.Errorf("%w: unknown signature method %s", ErrAlgorithmNotAllowed, sigMethod)
	}

	hash := info.Hash.New()
	hash.Write(signed)
	hashed := hash.Sum(nil)

	switch info.PublicKeyAlgorithm {
	case x509.RSA:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: certificate key is not RSA", ErrSignatureInvalid)
		}
		if err := rsa.VerifyPKCS1v15(pubKey, info.Hash, hashed, sig); err != nil {
			return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
		}
		return nil

	case x509.ECDSA:
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: certificate key is not ECDSA", ErrSignatureInvalid)
		}
		r, s, err := decodeXMLDSigECDSA(sig, pubKey.Curve)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
		}
		if !ecdsa.Verify(pubKey, hashed, r, s) {
			return ErrSignatureInvalid
		}
		return nil

	default:
		return fmt.Errorf("%w: unsupported key algorithm", ErrSignatureInvalid)
	}
}

// decodeXMLDSigECDSA decodes a raw r||s ECDSA signature (XML-DSig format).
func decodeXMLDSigECDSA(sig []byte, curve elliptic.Curve) (*big.Int, *big.Int, error) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(sig) != 2*byteLen {
		return nil, nil, fmt.Errorf("ECDSA signature has wrong length: got %d, expected %d", len(sig), 2*byteLen)
	}

	r := new(big.Int).SetBytes(sig[:byteLen])
	s := new(big.Int).SetBytes(sig[byteLen:])
	return r, s, nil
}

func mapPathToElement(tree, el *xmltree.Element) []int {
	for i, child := range tree.Child {
		if child == el {
			return []int{i}
		}
	}

	for i, child := range tree.Child {
		if childElement, ok := child.(*xmltree.Element); ok {
			childPath := mapPathToElement(childElement, el)
			if childPath != nil {
				return append([]int{i}, childPath...)
			}
		}
	}

	return nil
}

func removeElementAtPath(el *xmltree.Element, path []int) bool {
	if len(path) == 0 {
		return false
	}

	if len(el.Child) <= path[0] {
		return false
	}

	childElement, ok := el.Child[path[0]].(*xmltree.Element)
	if !ok {
		return false
	}

	if len(path) == 1 {
		el.RemoveChild(childElement)
		return true
	}

	return removeElementAtPath(childElement, path[1:])
}

// transform applies the transforms from a verified SignedInfo to produce the
// canonical element and the canonicalizer to use for digest computation.
func (v *Verifier) transform(el *xmltree.Element, origSig *parsedSignature, verifiedSig *parsedSignature) (*xmltree.Element, Canonicalizer, error) {
	// Map the path to the original signature element for removal
	signaturePath := mapPathToElement(el, origSig.el)

	// Make a copy
	el = el.Copy()

	var canonicalizer Canonicalizer

	for _, t := range verifiedSig.transforms {
		switch AlgorithmID(t.algorithm) {
		case EnvelopedSignatureAlgorithmId:
			if !removeElementAtPath(el, signaturePath) {
				return nil, nil, errors.New("Error applying canonicalization transform: Signature not found")
			}

		case CanonicalXML10ExclusiveAlgorithmId:
			canonicalizer = MakeC14N10ExclusiveCanonicalizerWithPrefixList(t.prefixList)

		case CanonicalXML10ExclusiveWithCommentsAlgorithmId:
			canonicalizer = MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(t.prefixList)

		case CanonicalXML11AlgorithmId:
			canonicalizer = MakeC14N11Canonicalizer()

		case CanonicalXML11WithCommentsAlgorithmId:
			canonicalizer = MakeC14N11WithCommentsCanonicalizer()

		case CanonicalXML10RecAlgorithmId:
			canonicalizer = MakeC14N10RecCanonicalizer()

		case CanonicalXML10WithCommentsAlgorithmId:
			canonicalizer = MakeC14N10WithCommentsCanonicalizer()

		default:
			return nil, nil, errors.New("Unknown Transform Algorithm: " + t.algorithm)
		}
	}

	if canonicalizer == nil {
		canonicalizer = MakeNullCanonicalizer()
	}

	return el, canonicalizer, nil
}

func (v *Verifier) verifyDigest(el *xmltree.Element, origSig *parsedSignature, verifiedSig *parsedSignature) (*xmltree.Element, error) {
	idAttr := el.SelectAttrValue(v.idAttribute(), "")

	// Verify the reference URI matches. This repeats the check findSignature
	// made against the unverified Signature, but now against the URI recovered
	// from the canonical bytes the signature actually covered -- and via the
	// same predicate, so the two cannot disagree.
	if !referencesElement(verifiedSig.refURI, idAttr) {
		return nil, fmt.Errorf("%w: reference URI does not match element", ErrMalformedSignature)
	}

	digestAlgorithmId := verifiedSig.digestMethod
	signedDigestValue, err := base64.StdEncoding.DecodeString(
		whiteSpace.ReplaceAllString(verifiedSig.digestValue, ""))
	if err != nil {
		return nil, err
	}

	// Apply transforms
	transformed, canonicalizer, err := v.transform(el, origSig, verifiedSig)
	if err != nil {
		return nil, err
	}

	referencedBytes, err := canonicalizer.Canonicalize(transformed)
	if err != nil {
		return nil, err
	}

	// Compute digest
	hashAlgorithm, ok := digestAlgorithmsByIdentifier[digestAlgorithmId]
	if !ok {
		return nil, fmt.Errorf("%w: unknown digest algorithm %s", ErrAlgorithmNotAllowed, digestAlgorithmId)
	}

	hash := hashAlgorithm.New()
	_, err = hash.Write(referencedBytes)
	if err != nil {
		return nil, err
	}

	computedDigest := hash.Sum(nil)

	if subtle.ConstantTimeCompare(computedDigest, signedDigestValue) != 1 {
		return nil, ErrDigestMismatch
	}

	// Reconstruct element from verified canonical bytes
	doc, err := xmltree.Parse(referencedBytes)
	if err != nil {
		return nil, err
	}

	return doc.Root(), nil
}

// VerifyString verifies a raw string signature (e.g. from the SAML
// HTTP-Redirect binding).
func (v *Verifier) VerifyString(content string, sig []byte, algorithmURI string) (*x509.Certificate, error) {
	if len(v.TrustedCerts) == 0 {
		return nil, fmt.Errorf("%w: TrustedCerts is empty", ErrMissingSignature)
	}

	if err := v.checkAlgorithm(algorithmURI); err != nil {
		return nil, err
	}

	info, ok := signatureMethodsByIdentifier[algorithmURI]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAlgorithmNotAllowed, algorithmURI)
	}

	hash := info.Hash.New()
	hash.Write([]byte(content))
	hashed := hash.Sum(nil)

	now := v.now()

	for _, cert := range v.TrustedCerts {
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			continue
		}

		switch info.PublicKeyAlgorithm {
		case x509.RSA:
			pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				continue
			}
			if err := rsa.VerifyPKCS1v15(pubKey, info.Hash, hashed, sig); err == nil {
				return cert, nil
			}

		case x509.ECDSA:
			pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				continue
			}
			r, s, err := decodeXMLDSigECDSA(sig, pubKey.Curve)
			if err != nil {
				continue
			}
			if ecdsa.Verify(pubKey, hashed, r, s) {
				return cert, nil
			}
		}
	}

	return nil, ErrSignatureInvalid
}
