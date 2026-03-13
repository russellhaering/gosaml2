package xmldsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/asn1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/beevik/etree"
)

// Signer creates enveloped XML digital signatures.
type Signer struct {
	// Key is the crypto.Signer used to create signatures.
	Key crypto.Signer

	// Certs is the certificate chain to embed in the signature's KeyInfo.
	Certs []*x509.Certificate

	// IDAttribute is the XML attribute used to reference the signed element.
	// Default: "ID"
	IDAttribute string

	// Prefix is the XML namespace prefix for ds: elements.
	// Default: "ds"
	Prefix string

	// Hash selects the digest and signature hash algorithm.
	// Default: crypto.SHA256
	Hash crypto.Hash

	// Canonicalizer is the canonicalization algorithm for signing.
	// Default: Inclusive C14N 1.1
	Canonicalizer Canonicalizer
}

func (s *Signer) idAttribute() string {
	if s.IDAttribute == "" {
		return defaultIdAttr
	}
	return s.IDAttribute
}

func (s *Signer) prefix() string {
	if s.Prefix == "" {
		return defaultSigPrefix
	}
	return s.Prefix
}

func (s *Signer) hash() crypto.Hash {
	if s.Hash == 0 {
		return crypto.SHA256
	}
	return s.Hash
}

func (s *Signer) canonicalizer() Canonicalizer {
	if s.Canonicalizer == nil {
		return MakeC14N11Canonicalizer()
	}
	return s.Canonicalizer
}

func (s *Signer) validate() error {
	if s.Key == nil {
		return errors.New("dsig: Key must not be nil")
	}
	if len(s.Certs) == 0 {
		return errors.New("dsig: Certs must not be empty")
	}
	if _, ok := s.Key.Public().(ed25519.PublicKey); ok {
		return errors.New("dsig: Ed25519 keys are not supported (no standardized XML-DSig algorithm URI)")
	}
	return nil
}

func (s *Signer) getPublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	switch s.Key.Public().(type) {
	case *ecdsa.PublicKey:
		return x509.ECDSA
	case *rsa.PublicKey:
		return x509.RSA
	}
	return x509.UnknownPublicKeyAlgorithm
}

func (s *Signer) getSignatureMethodIdentifier() string {
	algo := s.getPublicKeyAlgorithm()
	if ident, ok := signatureMethodIdentifiers[algo][s.hash()]; ok {
		return ident
	}
	return ""
}

func (s *Signer) getDigestAlgorithmIdentifier() string {
	if ident, ok := digestAlgorithmIdentifiers[s.hash()]; ok {
		return ident
	}
	return ""
}

func (s *Signer) createNamespacedElement(el *etree.Element, tag string) *etree.Element {
	child := el.CreateElement(tag)
	child.Space = s.prefix()
	return child
}

func (s *Signer) digest(el *etree.Element) ([]byte, error) {
	canonical, err := s.canonicalizer().Canonicalize(el)
	if err != nil {
		return nil, err
	}

	hash := s.hash().New()
	_, err = hash.Write(canonical)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// signDigest signs a digest using the configured key. For ECDSA, it converts
// the ASN.1 DER output from crypto.Signer.Sign() to raw r||s as required by
// XML-DSig.
func (s *Signer) signDigest(digest []byte) ([]byte, error) {
	rawSignature, err := s.Key.Sign(rand.Reader, digest, s.hash())
	if err != nil {
		return nil, err
	}

	// For ECDSA, convert ASN.1 DER to raw r||s
	if ecKey, ok := s.Key.Public().(*ecdsa.PublicKey); ok {
		rawSignature, err = convertECDSAASN1ToRawRS(rawSignature, ecKey.Curve)
		if err != nil {
			return nil, err
		}
	}

	return rawSignature, nil
}

// convertECDSAASN1ToRawRS converts an ASN.1 DER-encoded ECDSA signature to
// the raw r||s format required by XML-DSig. Each integer is zero-padded to
// the byte length of the curve order.
func convertECDSAASN1ToRawRS(derSig []byte, curve elliptic.Curve) ([]byte, error) {
	var sig struct{ R, S *big.Int }

	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, fmt.Errorf("dsig: invalid ASN.1 ECDSA signature: %w", err)
	}

	byteLen := (curve.Params().BitSize + 7) / 8

	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	if len(rBytes) > byteLen || len(sBytes) > byteLen {
		return nil, fmt.Errorf("dsig: ECDSA signature integer exceeds curve size")
	}

	rawSig := make([]byte, 2*byteLen)
	copy(rawSig[byteLen-len(rBytes):byteLen], rBytes)
	copy(rawSig[2*byteLen-len(sBytes):], sBytes)

	return rawSig, nil
}

func (s *Signer) constructSignedInfo(el *etree.Element, enveloped bool) (*etree.Element, error) {
	digestAlgorithmIdentifier := s.getDigestAlgorithmIdentifier()
	if digestAlgorithmIdentifier == "" {
		return nil, errors.New("unsupported hash mechanism")
	}

	signatureMethodIdentifier := s.getSignatureMethodIdentifier()
	if signatureMethodIdentifier == "" {
		return nil, errors.New("unsupported signature method")
	}

	digest, err := s.digest(el)
	if err != nil {
		return nil, err
	}

	signedInfo := &etree.Element{
		Tag:   signedInfoTag,
		Space: s.prefix(),
	}

	// /SignedInfo/CanonicalizationMethod
	canonicalizationMethod := s.createNamespacedElement(signedInfo, canonicalizationMethodTag)
	canonicalizationMethod.CreateAttr(algorithmAttr, string(s.canonicalizer().Algorithm()))

	// /SignedInfo/SignatureMethod
	signatureMethod := s.createNamespacedElement(signedInfo, signatureMethodTag)
	signatureMethod.CreateAttr(algorithmAttr, signatureMethodIdentifier)

	// /SignedInfo/Reference
	reference := s.createNamespacedElement(signedInfo, referenceTag)

	dataId := el.SelectAttrValue(s.idAttribute(), "")
	if dataId == "" {
		reference.CreateAttr(uriAttr, "")
	} else {
		reference.CreateAttr(uriAttr, "#"+dataId)
	}

	// /SignedInfo/Reference/Transforms
	transforms := s.createNamespacedElement(reference, transformsTag)
	if enveloped {
		envelopedTransform := s.createNamespacedElement(transforms, transformTag)
		envelopedTransform.CreateAttr(algorithmAttr, EnvelopedSignatureAlgorithmId.String())
	}
	canonicalizationAlgorithm := s.createNamespacedElement(transforms, transformTag)
	canonicalizationAlgorithm.CreateAttr(algorithmAttr, string(s.canonicalizer().Algorithm()))

	// /SignedInfo/Reference/DigestMethod
	digestMethod := s.createNamespacedElement(reference, digestMethodTag)
	digestMethod.CreateAttr(algorithmAttr, digestAlgorithmIdentifier)

	// /SignedInfo/Reference/DigestValue
	digestValue := s.createNamespacedElement(reference, digestValueTag)
	digestValue.SetText(base64.StdEncoding.EncodeToString(digest))

	return signedInfo, nil
}

func (s *Signer) constructSignature(el *etree.Element, enveloped bool) (*etree.Element, error) {
	signedInfo, err := s.constructSignedInfo(el, enveloped)
	if err != nil {
		return nil, err
	}

	sig := &etree.Element{
		Tag:   signatureTag,
		Space: s.prefix(),
	}

	xmlns := "xmlns"
	if s.prefix() != "" {
		xmlns += ":" + s.prefix()
	}

	sig.CreateAttr(xmlns, namespace)
	sig.AddChild(signedInfo)

	// Build cascading NS contexts for proper canonicalization of SignedInfo
	rootNSCtx, err := NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}

	elNSCtx, err := rootNSCtx.SubContext(el)
	if err != nil {
		return nil, err
	}

	sigNSCtx, err := elNSCtx.SubContext(sig)
	if err != nil {
		return nil, err
	}

	detachedSignedInfo, err := NSDetach(sigNSCtx, signedInfo)
	if err != nil {
		return nil, err
	}

	digest, err := s.digest(detachedSignedInfo)
	if err != nil {
		return nil, err
	}

	rawSignature, err := s.signDigest(digest)
	if err != nil {
		return nil, err
	}

	signatureValue := s.createNamespacedElement(sig, signatureValueTag)
	signatureValue.SetText(base64.StdEncoding.EncodeToString(rawSignature))

	keyInfo := s.createNamespacedElement(sig, keyInfoTag)
	x509Data := s.createNamespacedElement(keyInfo, x509DataTag)
	for _, cert := range s.Certs {
		x509Certificate := s.createNamespacedElement(x509Data, x509CertificateTag)
		x509Certificate.SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	}

	return sig, nil
}

// SignEnveloped creates an enveloped signature on el and returns a deep copy
// of el with the signature appended as the last child.
func (s *Signer) SignEnveloped(el *etree.Element) (*etree.Element, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	sig, err := s.constructSignature(el, true)
	if err != nil {
		return nil, err
	}

	ret := el.Copy()
	ret.Child = append(ret.Child, sig)

	return ret, nil
}

// SignString signs a raw string and returns the signature bytes.
// Used for the SAML HTTP-Redirect binding.
func (s *Signer) SignString(content string) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	hash := s.hash().New()
	if ln, err := hash.Write([]byte(content)); err != nil {
		return nil, fmt.Errorf("error calculating hash: %v", err)
	} else if ln < 1 {
		return nil, fmt.Errorf("zero length hash")
	}
	digest := hash.Sum(nil)

	return s.signDigest(digest)
}
