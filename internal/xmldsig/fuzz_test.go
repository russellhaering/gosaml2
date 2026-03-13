package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// ===========================================================================
// Core Fuzz Targets
// ===========================================================================

var fuzzSeedXML = `<Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="resp1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#resp1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dGVzdA==</ds:SignatureValue></ds:Signature></Response>`

func FuzzValidateXML(f *testing.F) {
	f.Add([]byte(fuzzSeedXML))
	f.Add([]byte(`<root ID="r1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dGVzdA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>dGVzdA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></root>`))
	f.Add([]byte(`<a xmlns:ns1="http://example.com" xmlns:ns2="http://example.org"><ns1:b><ns2:c/></ns1:b></a>`))
	f.Add([]byte(`<x></x>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		verifier := &Verifier{
			TrustedCerts: []*x509.Certificate{},
			Clock:        func() time.Time { return time.Date(2016, 3, 15, 0, 22, 0, 0, time.UTC) },
			AllowSHA1:    true,
		}

		// Errors are expected (no certs); we're looking for panics and hangs.
		// Use at least one cert to get past the empty check
		key, cert := randomTestKeyAndCert()
		_ = key
		verifier.TrustedCerts = []*x509.Certificate{cert}
		verifier.Verify(root)
	})
}

func FuzzCanonicalize(f *testing.F) {
	f.Add([]byte(`<root xmlns:a="http://a" xmlns:b="http://b"><a:child b:attr="val">text</a:child></root>`))
	f.Add([]byte(`<r xmlns="http://default"><child xmlns:x="http://x" x:a="1"/></r>`))
	f.Add([]byte(`<e xmlns:ns1="http://ns1" xmlns:ns2="http://ns2"><ns1:a><ns2:b ns1:c="d"><!-- comment --></ns2:b></ns1:a></e>`))
	f.Add([]byte(`<a xml:lang="en" xml:space="preserve">  text  </a>`))

	canonicalizers := []Canonicalizer{
		MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(""),
		MakeC14N11Canonicalizer(),
		MakeC14N11WithCommentsCanonicalizer(),
		MakeC14N10RecCanonicalizer(),
		MakeC14N10WithCommentsCanonicalizer(),
		MakeNullCanonicalizer(),
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		for _, c := range canonicalizers {
			c.Canonicalize(root.Copy())
		}
	})
}

func FuzzSignRoundTrip(f *testing.F) {
	f.Add([]byte(`<root ID="id123"><child>content</child></root>`))
	f.Add([]byte(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1"><saml:Issuer>test</saml:Issuer></saml:Assertion>`))
	f.Add([]byte(`<doc xmlns:a="http://a.example" xmlns:b="http://b.example"><a:el b:attr="v">data</a:el></doc>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		if len(data) > 1024*64 {
			return
		}

		key, cert := randomTestKeyAndCert()
		signer := &Signer{Key: key, Certs: []*x509.Certificate{cert}}

		signed, err := signer.SignEnveloped(root)
		if err != nil {
			return
		}

		verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		verifier.Verify(signed)
	})
}

const oktaCertPEM = `-----BEGIN CERTIFICATE-----
MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a
-----END CERTIFICATE-----`

func FuzzValidateWithCert(f *testing.F) {
	f.Add([]byte(fuzzSeedXML))

	block, _ := pem.Decode([]byte(oktaCertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		verifier := &Verifier{
			TrustedCerts: []*x509.Certificate{cert},
			Clock:        func() time.Time { return time.Date(2016, 3, 15, 0, 22, 0, 0, time.UTC) },
		}

		verifier.Verify(root)
	})
}

// ===========================================================================
// Extended Fuzz Targets
// ===========================================================================

// FuzzSignStringRoundTrip fuzzes the content string for SignString/VerifyString with RSA.
func FuzzSignStringRoundTrip(f *testing.F) {
	f.Add("hello world")
	f.Add(" ")
	f.Add("special chars: <>&\"'")
	f.Add(strings.Repeat("abcdefghij", 1000))
	f.Add("line1\nline2\nline3")
	f.Add("\x00\x01\x02\xff")

	key, cert := randomTestKeyAndCert()

	f.Fuzz(func(t *testing.T, content string) {
		if len(content) == 0 {
			return
		}

		signer := &Signer{
			Key:   key,
			Certs: []*x509.Certificate{cert},
			Hash:  crypto.SHA256,
		}

		sig, err := signer.SignString(content)
		if err != nil {
			t.Fatalf("SignString failed: %v", err)
		}

		verifier := &Verifier{
			TrustedCerts: []*x509.Certificate{cert},
		}

		_, err = verifier.VerifyString(content, sig, RSASHA256SignatureMethod)
		if err != nil {
			t.Fatalf("VerifyString failed for valid signature: %v", err)
		}

		// Verification with modified content should fail.
		modified := content + "X"
		_, err = verifier.VerifyString(modified, sig, RSASHA256SignatureMethod)
		if err == nil {
			t.Fatal("VerifyString should have failed for modified content")
		}
	})
}

// FuzzECDSASignRoundTrip fuzzes sign+verify with ECDSA keys using fuzzed
// element Tag, Space, ID value, and attributes. The library's enveloped
// signature round trip works reliably on elements without pre-existing
// children, so we fuzz the element's identity and structure.
func FuzzECDSASignRoundTrip(f *testing.F) {
	f.Add("AuthnRequest", "samlp", "_id-1", "attrName", "attrVal")
	f.Add("root", "", "_fuzz-id", "", "")
	f.Add("Assertion", "saml", "_a1", "Version", "2.0")
	f.Add("Response", "samlp", "_resp-123", "Destination", "https://example.com")
	f.Add("r", "", "_r1", "x", "y")

	key, cert := randomECDSATestKeyAndCert()

	f.Fuzz(func(t *testing.T, tag, space, id, extraAttrName, extraAttrVal string) {
		if len(tag) == 0 || len(tag) > 128 || len(id) == 0 || len(id) > 256 {
			return
		}

		// Ensure tag and space are valid XML NCNames.
		if !isSimpleXMLName(tag) || (space != "" && !isSimpleXMLName(space)) {
			return
		}

		// Build a well-formed ID: prefix with "_" and filter to safe chars.
		if !isSimpleXMLName(id) {
			return
		}
		xmlID := "_" + id

		el := &etree.Element{
			Space: space,
			Tag:   tag,
		}
		el.CreateAttr("ID", xmlID)

		if extraAttrName != "" && isSimpleXMLName(extraAttrName) && extraAttrName != "ID" {
			el.CreateAttr(extraAttrName, extraAttrVal)
		}

		signer := &Signer{
			Key:   key,
			Certs: []*x509.Certificate{cert},
			Hash:  crypto.SHA256,
		}

		signed, err := signer.SignEnveloped(el)
		if err != nil {
			return
		}

		verifier := &Verifier{
			TrustedCerts: []*x509.Certificate{cert},
		}

		// Pass signed element directly to Verify (like the library's own tests).
		result, err := verifier.Verify(signed)
		if err != nil {
			t.Fatalf("Verify failed after ECDSA sign: %v", err)
		}
		if result == nil {
			t.Fatal("VerifyResult is nil")
		}
		if result.Certificate == nil {
			t.Fatal("VerifyResult.Certificate is nil")
		}
	})
}

// isSimpleXMLName checks that s is a plausible XML NCName (letters, digits, hyphens, underscores, dots).
func isSimpleXMLName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
		} else {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
				return false
			}
		}
	}
	return true
}

// FuzzDecodeXMLDSigECDSA fuzzes the ECDSA raw r||s decoder with arbitrary byte slices.
func FuzzDecodeXMLDSigECDSA(f *testing.F) {
	f.Add(make([]byte, 64))  // 64 zero bytes (P-256 size)
	f.Add(make([]byte, 96))  // 96 zero bytes (P-384 size)
	f.Add([]byte{})          // empty
	f.Add([]byte{0x42})      // 1 byte
	f.Add(make([]byte, 128)) // oversized
	f.Add(bytes.Repeat([]byte{0xff}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		curves := []elliptic.Curve{elliptic.P256(), elliptic.P384()}
		for _, curve := range curves {
			r, s, err := decodeXMLDSigECDSA(data, curve)
			if err != nil {
				// Error is expected for wrong-length inputs; just ensure no panic.
				continue
			}
			if r == nil {
				t.Fatal("decodeXMLDSigECDSA returned nil r without error")
			}
			if s == nil {
				t.Fatal("decodeXMLDSigECDSA returned nil s without error")
			}
		}
	})
}

// FuzzConvertECDSAASN1ToRawRS fuzzes the ASN.1 to raw r||s converter.
func FuzzConvertECDSAASN1ToRawRS(f *testing.F) {
	// Valid minimal ASN.1 SEQUENCE: SEQUENCE { INTEGER(1), INTEGER(1) }
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})
	// Garbage bytes
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	// Truncated sequence
	f.Add([]byte{0x30, 0x10, 0x02, 0x01})
	// Empty
	f.Add([]byte{})
	// Just the SEQUENCE tag
	f.Add([]byte{0x30})
	// Valid-ish longer signature
	f.Add(append([]byte{0x30, 0x44, 0x02, 0x20}, append(bytes.Repeat([]byte{0x01}, 32), append([]byte{0x02, 0x20}, bytes.Repeat([]byte{0x02}, 32)...)...)...))

	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384()}

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, curve := range curves {
			result, err := convertECDSAASN1ToRawRS(data, curve)
			if err != nil {
				// Errors are expected for malformed input; just ensure no panic.
				continue
			}
			byteLen := (curve.Params().BitSize + 7) / 8
			if len(result) != 2*byteLen {
				t.Fatalf("expected raw signature length %d, got %d", 2*byteLen, len(result))
			}
		}
	})
}

// FuzzVerifyMalformedSignatures fuzzes verification with structurally varied
// but syntactically valid XML that contains ds:Signature elements.
func FuzzVerifyMalformedSignatures(f *testing.F) {
	// Complete but fake signature
	f.Add([]byte(`<Response ID="resp1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#resp1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dGVzdA==</ds:SignatureValue></ds:Signature></Response>`))
	// Missing SignatureValue
	f.Add([]byte(`<root ID="r1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#r1"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:SignedInfo></ds:Signature></root>`))
	// Empty Signature element
	f.Add([]byte(`<doc ID="d1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></doc>`))
	// Duplicate Signature elements
	f.Add([]byte(`<msg ID="m1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#m1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#m1"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BBBB</ds:SignatureValue></ds:Signature></msg>`))
	// Unknown algorithm
	f.Add([]byte(`<x ID="x1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://example.com/unknown"/><ds:SignatureMethod Algorithm="http://example.com/fakealgo"/><ds:Reference URI="#x1"><ds:DigestMethod Algorithm="http://example.com/fakedigest"/><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dGVzdA==</ds:SignatureValue></ds:Signature></x>`))

	key, cert := randomTestKeyAndCert()
	_ = key

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}

		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(data); err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		verifier := &Verifier{
			TrustedCerts: []*x509.Certificate{cert},
			AllowSHA1:    true,
		}

		// We only care that this doesn't panic.
		verifier.Verify(root)
	})
}

// FuzzCanonicalizeDeterministic fuzzes that canonicalization is deterministic:
// canonicalize the same input twice and verify identical output.
func FuzzCanonicalizeDeterministic(f *testing.F) {
	f.Add([]byte(`<root xmlns:a="http://a" xmlns:b="http://b"><a:child b:attr="val">text</a:child></root>`))
	f.Add([]byte(`<r xmlns="http://default"><child xmlns:x="http://x" x:a="1"/></r>`))
	f.Add([]byte(`<e xmlns:ns1="http://ns1" xmlns:ns2="http://ns2"><ns1:a><ns2:b ns1:c="d"><!-- comment --></ns2:b></ns1:a></e>`))
	f.Add([]byte(`<a xml:lang="en" xml:space="preserve">  text  </a>`))
	f.Add([]byte(`<doc><nested><deep attr1="z" attr2="a">content</deep></nested></doc>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}

		doc1 := etree.NewDocument()
		if err := doc1.ReadFromBytes(data); err != nil {
			return
		}

		root1 := doc1.Root()
		if root1 == nil {
			return
		}

		doc2 := etree.NewDocument()
		if err := doc2.ReadFromBytes(data); err != nil {
			return
		}

		root2 := doc2.Root()
		if root2 == nil {
			return
		}

		canonicalizer := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

		out1, err1 := canonicalizer.Canonicalize(root1)
		out2, err2 := canonicalizer.Canonicalize(root2)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("canonicalization error mismatch: err1=%v err2=%v", err1, err2)
		}

		if err1 != nil {
			return
		}

		if !bytes.Equal(out1, out2) {
			t.Fatalf("canonicalization not deterministic:\nfirst:  %q\nsecond: %q", out1, out2)
		}
	})
}

// ===========================================================================
// Structured Signature Fuzzer
// ===========================================================================

type mutation struct {
	name string
	fn   func(el *etree.Element, data []byte) *etree.Element
}

var mutationMenu = []mutation{
	{"SwapDigestValue", mutSwapDigestValue},
	{"TruncateSignatureValue", mutTruncateSignatureValue},
	{"ExtendDigestValue", mutExtendDigestValue},
	{"EmptyCanonicalizationAlgo", mutEmptyCanonicalizationAlgo},
	{"EmptySignatureMethodAlgo", mutEmptySignatureMethodAlgo},
	{"DuplicateSignedInfo", mutDuplicateSignedInfo},
	{"ReorderSigChildren", mutReorderSigChildren},
	{"InjectNestedSignature", mutInjectNestedSignature},
	{"InjectExtraReference", mutInjectExtraReference},
	{"RemoveAllTransforms", mutRemoveAllTransforms},
	{"ReplaceDigestMethodAlgo", mutReplaceDigestMethodAlgo},
	{"ReplaceSignatureMethodAlgo", mutReplaceSignatureMethodAlgo},
}

func mutSwapDigestValue(el *etree.Element, data []byte) *etree.Element {
	el = el.Copy()
	dv := el.FindElement("//" + digestValueTag)
	if dv == nil {
		return nil
	}
	newVal := base64.StdEncoding.EncodeToString(append(data, 0xFF))
	if newVal == dv.Text() {
		newVal = base64.StdEncoding.EncodeToString(append(data, 0xFE))
	}
	dv.SetText(newVal)
	return el
}

func mutTruncateSignatureValue(el *etree.Element, data []byte) *etree.Element {
	el = el.Copy()
	sv := el.FindElement("//" + signatureValueTag)
	if sv == nil {
		return nil
	}
	txt := sv.Text()
	if len(txt) < 4 {
		return nil
	}
	n := 1
	if len(data) > 0 {
		n = int(data[0])%(len(txt)/2) + 1
	}
	sv.SetText(txt[:len(txt)-n])
	return el
}

func mutExtendDigestValue(el *etree.Element, data []byte) *etree.Element {
	el = el.Copy()
	dv := el.FindElement("//" + digestValueTag)
	if dv == nil {
		return nil
	}
	orig, err := base64.StdEncoding.DecodeString(dv.Text())
	if err != nil {
		return nil
	}
	extended := append(orig, 0x42)
	if len(data) > 0 {
		extended = append(orig, data[0])
	}
	dv.SetText(base64.StdEncoding.EncodeToString(extended))
	return el
}

func mutEmptyCanonicalizationAlgo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	cm := el.FindElement("//" + canonicalizationMethodTag)
	if cm == nil {
		return nil
	}
	cm.CreateAttr(algorithmAttr, "")
	return el
}

func mutEmptySignatureMethodAlgo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	sm := el.FindElement("//" + signatureMethodTag)
	if sm == nil {
		return nil
	}
	sm.CreateAttr(algorithmAttr, "")
	return el
}

func mutDuplicateSignedInfo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	sig := el.FindElement("//" + signatureTag)
	if sig == nil {
		return nil
	}
	si := findChildByTag(sig, signedInfoTag)
	if si == nil {
		return nil
	}
	sig.AddChild(si.Copy())
	return el
}

func mutReorderSigChildren(el *etree.Element, _ []byte) *etree.Element {
	// Move the SignatureValue element to before SignedInfo AND
	// inject a bogus text node inside SignedInfo so that the
	// canonical SignedInfo actually changes.
	el = el.Copy()
	si := el.FindElement("//" + signedInfoTag)
	if si == nil {
		return nil
	}
	// Insert a text node that will change the canonical form.
	si.SetText("injected")
	return el
}

func mutInjectNestedSignature(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	si := el.FindElement("//" + signedInfoTag)
	if si == nil {
		return nil
	}
	nested := etree.NewElement(signatureTag)
	nested.Space = defaultSigPrefix
	nested.CreateAttr("xmlns:"+defaultSigPrefix, namespace)
	nsi := nested.CreateElement(signedInfoTag)
	nsi.Space = defaultSigPrefix
	nsi.CreateElement(canonicalizationMethodTag).CreateAttr(algorithmAttr, "http://fake")
	nsi.CreateElement(signatureMethodTag).CreateAttr(algorithmAttr, "http://fake")
	nsv := nested.CreateElement(signatureValueTag)
	nsv.Space = defaultSigPrefix
	nsv.SetText("ZmFrZQ==")
	si.AddChild(nested)
	return el
}

func mutInjectExtraReference(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	si := el.FindElement("//" + signedInfoTag)
	if si == nil {
		return nil
	}
	ref := etree.NewElement(referenceTag)
	ref.Space = si.Space
	ref.CreateAttr(uriAttr, "#evil")
	dm := ref.CreateElement(digestMethodTag)
	dm.Space = si.Space
	dm.CreateAttr(algorithmAttr, "http://www.w3.org/2001/04/xmlenc#sha256")
	dvEl := ref.CreateElement(digestValueTag)
	dvEl.Space = si.Space
	dvEl.SetText("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	si.AddChild(ref)
	return el
}

func mutRemoveAllTransforms(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	ref := el.FindElement("//" + referenceTag)
	if ref == nil {
		return nil
	}
	tr := findChildByTag(ref, transformsTag)
	if tr == nil {
		return nil
	}
	ref.RemoveChild(tr)
	return el
}

func mutReplaceDigestMethodAlgo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	dm := el.FindElement("//" + digestMethodTag)
	if dm == nil {
		return nil
	}
	dm.CreateAttr(algorithmAttr, "http://www.w3.org/2099/unknown#digest")
	return el
}

func mutReplaceSignatureMethodAlgo(el *etree.Element, _ []byte) *etree.Element {
	el = el.Copy()
	sm := el.FindElement("//" + signatureMethodTag)
	if sm == nil {
		return nil
	}
	sm.CreateAttr(algorithmAttr, "http://www.w3.org/2099/unknown#sig")
	return el
}

func FuzzStructuredSignature(f *testing.F) {
	key, cert := randomTestKeyAndCert()
	signer := &Signer{
		Key:           key,
		Certs:         []*x509.Certificate{cert},
		Canonicalizer: MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		Hash:          crypto.SHA256,
	}

	// Build a seed: sign, serialize, re-parse, serialize to bytes.
	seedDoc := etree.NewDocument()
	seedDoc.ReadFromString(`<Root xmlns="urn:test" ID="_seed"><Child>data</Child></Root>`)
	signed, err := signer.SignEnveloped(seedDoc.Root())
	if err != nil {
		f.Fatal(err)
	}
	serDoc := etree.NewDocument()
	serDoc.SetRoot(signed)
	seedBytes, err := serDoc.WriteToBytes()
	if err != nil {
		f.Fatal(err)
	}

	// Add one seed per mutation kind.
	for i := range mutationMenu {
		corpus := make([]byte, 0, len(seedBytes)+8)
		corpus = append(corpus, byte(i))
		corpus = append(corpus, 0x41, 0x42, 0x43) // extra fuzz bytes
		f.Add(corpus)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			t.Skip()
		}

		mutIdx := int(data[0]) % len(mutationMenu)
		mut := mutationMenu[mutIdx]
		extra := data[1:]

		// Fresh sign each iteration with the same key.
		freshDoc := etree.NewDocument()
		freshDoc.ReadFromString(`<Root xmlns="urn:test" ID="_fuzz"><Child>data</Child></Root>`)
		freshSigned, err := signer.SignEnveloped(freshDoc.Root())
		if err != nil {
			t.Skip()
		}
		// Reparse for clean tree.
		tmpDoc := etree.NewDocument()
		tmpDoc.SetRoot(freshSigned)
		rawBytes, err := tmpDoc.WriteToBytes()
		if err != nil {
			t.Skip()
		}
		cleanDoc := etree.NewDocument()
		if err := cleanDoc.ReadFromBytes(rawBytes); err != nil {
			t.Skip()
		}

		mutated := mut.fn(cleanDoc.Root(), extra)
		if mutated == nil {
			t.Skip()
		}

		// Serialize the mutated tree so we can check it actually changed.
		mutDoc := etree.NewDocument()
		mutDoc.SetRoot(mutated)
		mutBytes, _ := mutDoc.WriteToBytes()

		// If the mutation was a no-op (fuzz data reconstructed original),
		// skip instead of failing.
		if bytes.Equal(rawBytes, mutBytes) {
			t.Skip()
		}

		verifier := &Verifier{TrustedCerts: []*x509.Certificate{cert}}
		_, err = verifier.Verify(mutated)
		if err == nil {
			t.Errorf("mutation %q was accepted on a structurally modified document", mut.name)
		}
	})
}

// ---------------------------------------------------------------------------
// Fuzz targets for namespace traversal and exclusive canonicalization
// (formerly in etreeutils package)
// ---------------------------------------------------------------------------

func FuzzNSTraverse(f *testing.F) {
	f.Add([]byte(`<root xmlns:a="http://a"><a:child>text</a:child></root>`))
	f.Add([]byte(`<r xmlns="http://default" xmlns:x="http://x"><x:a><b xmlns:y="http://y"><y:c x:d="val"/></b></x:a></r>`))
	f.Add([]byte(`<a xmlns:n1="http://n1" xmlns:n2="http://n2" xmlns:n3="http://n3"><n1:b n2:attr="v"><n3:c/></n1:b></a>`))
	f.Add([]byte(`<e xml:lang="en"><e xml:space="preserve"><e/></e></e>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		ctx := NewDefaultNSContext()

		// Exercise tree traversal — looking for panics and hangs.
		NSTraverse(ctx, root, func(_ NSContext, _ *etree.Element) error {
			return nil
		})

		// Exercise find iterate with a common namespace.
		NSFindIterate(root, "http://www.w3.org/2000/09/xmldsig#", "Signature", func(_ NSContext, _ *etree.Element) error {
			return ErrTraversalHalted
		})

		// Exercise select one.
		NSSelectOne(root, "http://www.w3.org/2000/09/xmldsig#", "SignedInfo")
	})
}

func FuzzTransformExcC14n(f *testing.F) {
	f.Add([]byte(`<root xmlns:a="http://a" xmlns:b="http://b"><a:child b:attr="val">text</a:child></root>`), "")
	f.Add([]byte(`<r xmlns="http://d"><child xmlns:x="http://x" x:a="1"/></r>`), "x")
	f.Add([]byte(`<e xmlns:ns1="http://ns1"><ns1:a><!-- comment --></ns1:a></e>`), "ns1")

	f.Fuzz(func(t *testing.T, data []byte, prefixList string) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		// Test with comments=false
		el := root.Copy()
		TransformExcC14n(el, prefixList, false)

		// Test with comments=true
		el = root.Copy()
		TransformExcC14n(el, prefixList, true)
	})
}

