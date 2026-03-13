package xmldsig

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}
	testSignWithSigner(t, signer, RSASHA256SignatureMethod, crypto.SHA256)
}

func testSignWithSigner(t *testing.T, signer *Signer, sigMethodID string, digestAlgo crypto.Hash) {
	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	id := "_97e34c50-65ec-4132-8b39-02933960a96a"
	authnRequest.CreateAttr("ID", id)
	hash := digestAlgo.New()
	canonicalized, err := signer.canonicalizer().Canonicalize(authnRequest)
	require.NoError(t, err)

	_, err = hash.Write(canonicalized)
	require.NoError(t, err)
	digest := hash.Sum(nil)

	signed, err := signer.SignEnveloped(authnRequest)
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	sig := signed.FindElement("//" + signatureTag)
	require.NotEmpty(t, sig)

	signedInfo := sig.FindElement("//" + signedInfoTag)
	require.NotEmpty(t, signedInfo)

	canonicalizationMethodElement := signedInfo.FindElement("//" + canonicalizationMethodTag)
	require.NotEmpty(t, canonicalizationMethodElement)

	canonicalizationMethodAttr := canonicalizationMethodElement.SelectAttr(algorithmAttr)
	require.NotEmpty(t, canonicalizationMethodAttr)
	require.Equal(t, CanonicalXML11AlgorithmId.String(), canonicalizationMethodAttr.Value)

	signatureMethodElement := signedInfo.FindElement("//" + signatureMethodTag)
	require.NotEmpty(t, signatureMethodElement)

	signatureMethodAttr := signatureMethodElement.SelectAttr(algorithmAttr)
	require.NotEmpty(t, signatureMethodAttr)
	require.Equal(t, sigMethodID, signatureMethodAttr.Value)

	referenceElement := signedInfo.FindElement("//" + referenceTag)
	require.NotEmpty(t, referenceElement)

	idAttr := referenceElement.SelectAttr(uriAttr)
	require.NotEmpty(t, idAttr)
	require.Equal(t, "#"+id, idAttr.Value)

	transformsElement := referenceElement.FindElement("//" + transformsTag)
	require.NotEmpty(t, transformsElement)

	transformElement := transformsElement.FindElement("//" + transformTag)
	require.NotEmpty(t, transformElement)

	transformAlgo := transformElement.SelectAttr(algorithmAttr)
	require.NotEmpty(t, transformAlgo)
	require.Equal(t, EnvelopedSignatureAlgorithmId.String(), transformAlgo.Value)

	digestMethodElement := referenceElement.FindElement("//" + digestMethodTag)
	require.NotEmpty(t, digestMethodElement)

	digestMethodAlgo := digestMethodElement.SelectAttr(algorithmAttr)
	require.NotEmpty(t, digestMethodAlgo)
	require.Equal(t, digestAlgorithmIdentifiers[digestAlgo], digestMethodAlgo.Value)

	digestValueElement := referenceElement.FindElement("//" + digestValueTag)
	require.NotEmpty(t, digestValueElement)
	require.Equal(t, base64.StdEncoding.EncodeToString(digest), digestValueElement.Text())
}

func TestSignErrors(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{
		Key:         key,
		Certs:       []*x509.Certificate{cert},
		Hash:        crypto.SHA512_256,
		IDAttribute: defaultIdAttr,
		Prefix:      defaultSigPrefix,
	}

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	_, err := signer.SignEnveloped(authnRequest)
	require.Error(t, err)
}

func TestSignNonDefaultID(t *testing.T) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		IDAttribute:   "OtherID",
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	signable := &etree.Element{
		Space: "foo",
		Tag:   "Bar",
	}

	id := "_97e34c50-65ec-4132-8b39-02933960a96b"
	signable.CreateAttr("OtherID", id)
	signed, err := signer.SignEnveloped(signable)
	require.NoError(t, err)

	ref := signed.FindElement("./Signature/SignedInfo/Reference")
	require.NotNil(t, ref)
	refURI := ref.SelectAttrValue("URI", "")
	require.Equal(t, refURI, "#"+id)
}

func TestSignWithECDSA(t *testing.T) {
	key, cert := randomECDSATestKeyAndCert()
	signer := &Signer{
		Key:   key,
		Certs: []*x509.Certificate{cert},
		Hash:  crypto.SHA256,
	}

	testSignWithSigner(t, signer, ECDSASHA256SignatureMethod, crypto.SHA256)
}

func TestSignNilKey(t *testing.T) {
	signer := &Signer{}
	_, err := signer.SignEnveloped(&etree.Element{Tag: "Foo"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Key must not be nil")
}

func TestSignEmptyCerts(t *testing.T) {
	key, _ := randomTestKeyAndCert()
	signer := &Signer{Key: key}
	_, err := signer.SignEnveloped(&etree.Element{Tag: "Foo"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Certs must not be empty")
}
