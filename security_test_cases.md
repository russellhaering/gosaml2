# Security Test Case Tracking Document

This document tracks 310 security test cases for the gosaml2 library, organized across 6 categories. Each test case is classified by implementation status:

- **New** -- Test case has not yet been implemented
- **Exists** -- An existing test covers this scenario (or substantially overlaps)
- **Implemented** -- Test case was written as part of this tracking effort

File references indicate the target test file where each case should be (or already is) implemented.

---

## Category 1: Signature Wrapping / Verification (55 tests)

### XSW Classic Variants (1-8)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | XSW1-Cloned Response with Sig Moved | Exists | xsw_test.go |
| 2 | XSW2-Detached Sig in Extensions | Exists | xsw_test.go |
| 3 | XSW3-Assertion Moved to Sig Object | Exists | xsw_test.go |
| 4 | XSW4-Dup Assertion with Original in Extensions | Exists | xsw_test.go |
| 5 | XSW5-Dup Response with Evil Before Sig | Exists | xsw_test.go |
| 6 | XSW6-Nested Response in Assertion Advice | Exists | xsw_test.go |
| 7 | XSW7-Signed Assertion in Wrapper | Exists | xsw_test.go |
| 8 | XSW8-Double Sig Different References | Exists | xsw_test.go |

### Signature Exclusion (9-11)

| # | Name | Status | File |
|---|------|--------|------|
| 9 | Strip Response Sig | Exists | security_test.go (TestSignatureBypass_RemovedSignature) |
| 10 | Strip Assertion Sig Unsigned Path | New | security_sig_extended_test.go |
| 11 | Strip Assertion Sig Signed Path | New | security_sig_extended_test.go |

### Malformed Signature Values (12-18)

| # | Name | Status | File |
|---|------|--------|------|
| 12 | Empty SigValue | New | security_sig_extended_test.go |
| 13 | Whitespace SigValue | New | security_sig_extended_test.go |
| 14 | Truncated Base64 SigValue | New | security_sig_extended_test.go |
| 15 | Invalid Base64 SigValue | New | security_sig_extended_test.go |
| 16 | Missing SignedInfo | Exists | internal/xmldsig/security_test.go (TestXSW_Audit_ShapeValidation_NoSignedInfo) |
| 17 | Dup SignedInfo | Exists | internal/xmldsig/security_test.go (TestXSW_Audit_ShapeValidation_DuplicateSignedInfo) |
| 18 | Dup SigValue | New | security_sig_extended_test.go |

### Certificate / Key Confusion (19-23)

| # | Name | Status | File |
|---|------|--------|------|
| 19 | Attacker Cert in KeyInfo | Exists | internal/xmldsig/security_test.go (TestCert_UntrustedCertInKeyInfo, TestCert_SelfSignedAttackerCert) |
| 20 | Omit KeyInfo Multi Certs | Exists | internal/xmldsig/security_test.go (TestCert_NoKeyInfo_MultipleTrustedFails) |
| 21 | Omit KeyInfo Single Cert | Exists | internal/xmldsig/security_test.go (TestCert_NoKeyInfo_SingleTrustedFallback) |
| 22 | Expired Cert in KeyInfo | Exists | internal/xmldsig/security_test.go (TestCert_ExpiredCertificate) |
| 23 | NotYetValid Cert | Exists | internal/xmldsig/security_test.go (TestCertEdge_NotBeforeInFuture) |

### Digest Manipulation (24-26)

| # | Name | Status | File |
|---|------|--------|------|
| 24 | Replace DigestValue | Exists | internal/xmldsig/security_test.go (TestTamper_ModifiedDigestValue) |
| 25 | Verified vs Unverified SignedInfo | New | security_sig_extended_test.go |
| 26 | Empty DigestValue | New | security_sig_extended_test.go |

### Reference URI (27-31)

| # | Name | Status | File |
|---|------|--------|------|
| 27 | Empty URI | Exists | internal/xmldsig/security_test.go (TestCrossRef_EmptyURI_ValidRoundTrip) |
| 28 | NonExistent ID | Exists | internal/xmldsig/security_test.go (TestCrossRef_URIMismatch) |
| 29 | URI Points to Assertion | New | security_sig_extended_test.go |
| 30 | Malformed URI No Hash | Exists | internal/xmldsig/security_test.go (TestCrossRef_BareHashURI, TestCrossRef_RelativeURI) |
| 31 | URI with XPath | Exists | internal/xmldsig/security_test.go (TestCrossRef_XPointerURI) |

### Transform Manipulation (32-34)

| # | Name | Status | File |
|---|------|--------|------|
| 32 | Remove Enveloped Transform | New | security_sig_extended_test.go |
| 33 | Add XSLT Transform | New | security_sig_extended_test.go |
| 34 | Dup Transform | New | security_sig_extended_test.go |

### C14N Algorithm (35-38)

| # | Name | Status | File |
|---|------|--------|------|
| 35 | Unrecognized C14N | New | security_sig_extended_test.go |
| 36 | Inclusive C14N 1.0 | New | security_sig_extended_test.go |
| 37 | With vs Without Comments | New | security_sig_extended_test.go |
| 38 | PrefixList Manipulation | Exists | internal/xmldsig/security_test.go (TestXSW_Audit_ExcC14N_PrefixListTamper) |

### Wrong Elements / Dup IDs (39-42)

| # | Name | Status | File |
|---|------|--------|------|
| 39 | Sign Assertion Claim Response | Exists | xsw_test.go (TestXSW3_UnsignedResponseSignedAssertionIntegrity) |
| 40 | Sign Response Tamper Assertion | Exists | xsw_test.go (TestXSW4_SignedResponseTamperedAssertion) |
| 41 | Two Elements Same ID | Exists | internal/xmldsig/security_test.go (TestCrossRef_DuplicateIDs_EvilSiblingWithSameID) |
| 42 | Response and Assertion Same ID | New | security_sig_extended_test.go |

### Detached / Enveloping (43-45)

| # | Name | Status | File |
|---|------|--------|------|
| 43 | Sig as Sibling | Exists | internal/xmldsig/security_test.go (TestXSW_Audit_SignatureMovedToSibling) |
| 44 | Sig in Separate Doc | Exists | internal/xmldsig/security_test.go (TestCrossRef_SignatureTransplantBetweenDocuments) |
| 45 | Enveloping Sig Contains Response | New | security_sig_extended_test.go |

### SignedInfo / Scope (46-50)

| # | Name | Status | File |
|---|------|--------|------|
| 46 | Modify DigestMethod | Exists | internal/xmldsig/security_test.go (TestCrossRef_SignedInfoCoversDigestMethod) |
| 47 | Modify SigMethod | New | security_sig_extended_test.go |
| 48 | Response Signed Assertion Modified | Exists | xsw_test.go (TestXSW4_SignedResponseTamperedAssertion) |
| 49 | Missing Response Sig Only Assertion Signed | Exists | xsw_test.go (TestXSW3_UnsignedResponseSignedAssertionIntegrity) |
| 50 | Missing Assertion Sig Only Response Signed | Exists | xsw_test.go (TestXSW7_UnsignedResponseMixedAssertions) |

### HMAC / Algorithm (51-55)

| # | Name | Status | File |
|---|------|--------|------|
| 51 | HMAC Key Confusion | New | security_sig_extended_test.go |
| 52 | SHA1 Digest AllowSHA1 False | Exists | security_test.go (TestSHA1_RejectedByDefault) |
| 53 | Unknown Sig Algorithm | Exists | internal/xmldsig/security_test.go (TestAlgo_UnknownSignatureAlgorithm) |
| 54 | Null Bytes in SigValue | New | security_sig_extended_test.go |
| 55 | Half-Length RSA Sig | New | security_sig_extended_test.go |

---

## Category 2: XML Parsing / Entity / Encoding (55 tests)

### XXE (1-5)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | Classic file entity | New | security_xml_test.go |
| 2 | XXE in EncryptedAssertion | New | security_xml_test.go |
| 3 | Parameter Entity | New | security_xml_test.go |
| 4 | PUBLIC Identifier | New | security_xml_test.go |
| 5 | XInclude | New | security_xml_test.go |

### SSRF via XXE (6-8)

| # | Name | Status | File |
|---|------|--------|------|
| 6 | Cloud Metadata | New | security_xml_test.go |
| 7 | DNS Exfiltration | New | security_xml_test.go |
| 8 | Internal Services | New | security_xml_test.go |

### Entity Expansion (9-12)

| # | Name | Status | File |
|---|------|--------|------|
| 9 | Billion Laughs | Exists | security_test.go (TestDoS_BillionLaughs) |
| 10 | Quadratic Blowup | New | security_xml_test.go |
| 11 | Recursive | New | security_xml_test.go |
| 12 | In Attributes | New | security_xml_test.go |

### CDATA (13-15)

| # | Name | Status | File |
|---|------|--------|------|
| 13 | CDATA in NameID | New | security_xml_test.go |
| 14 | CDATA Splitting | New | security_xml_test.go |
| 15 | CDATA in CipherValue | New | security_xml_test.go |

### Namespace Confusion (16-21)

| # | Name | Status | File |
|---|------|--------|------|
| 16 | Prefix Remapping | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion) |
| 17 | Default NS Override | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion_SignatureInWrongDefaultNS) |
| 18 | NS Undeclaration | New | security_xml_test.go |
| 19 | NS Redefinition | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion_PrefixRebindOnSignedInfoChildren) |
| 20 | Dup NS Different URIs | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion_MultipleDsigPrefixesOnSameElement) |
| 21 | NS Prefix on Sig | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion_AlternativePrefixes_ExcC14N) |

### Comment Injection (22-24)

| # | Name | Status | File |
|---|------|--------|------|
| 22 | Split NameID | Exists | security_test.go (TestCommentInjection_InNameID) |
| 23 | Between Element Tags | New | security_xml_test.go |
| 24 | Double Hyphen | New | security_xml_test.go |

### Mixed Content (25-26)

| # | Name | Status | File |
|---|------|--------|------|
| 25 | Mixed Content in Assertion | New | security_xml_test.go |
| 26 | Significant Whitespace | New | security_xml_test.go |

### Processing Instructions (27-29)

| # | Name | Status | File |
|---|------|--------|------|
| 27 | PI Before Root | New | security_xml_test.go |
| 28 | PI Inside Signed Element | New | security_xml_test.go |
| 29 | PI Mimicking XML Declaration | New | security_xml_test.go |

### DTD (30-32)

| # | Name | Status | File |
|---|------|--------|------|
| 30 | Internal Subset Redefining | New | security_xml_test.go |
| 31 | Remote DTD | New | security_xml_test.go |
| 32 | NOTATION | New | security_xml_test.go |

### Encoding (33-35)

| # | Name | Status | File |
|---|------|--------|------|
| 33 | UTF7 | New | security_xml_test.go |
| 34 | UTF16BE | New | security_xml_test.go |
| 35 | UTF16LE No BOM | New | security_xml_test.go |

### BOM (36-38)

| # | Name | Status | File |
|---|------|--------|------|
| 36 | UTF8 BOM | New | security_xml_test.go |
| 37 | Double BOM | New | security_xml_test.go |
| 38 | BOM Between Declaration and Root | New | security_xml_test.go |

### Null Byte (39-41)

| # | Name | Status | File |
|---|------|--------|------|
| 39 | In NameID | New | security_xml_test.go |
| 40 | In Attribute | New | security_xml_test.go |
| 41 | In NS URI | New | security_xml_test.go |

### Size / Depth (42-44)

| # | Name | Status | File |
|---|------|--------|------|
| 42 | Oversized Decompressed | Exists | security_test.go (TestDoS_DecompressionBomb) |
| 43 | Oversized Uncompressed | New | security_xml_test.go |
| 44 | Deep Nesting 10K | New | security_xml_test.go |

### Version / Normalization (45-48)

| # | Name | Status | File |
|---|------|--------|------|
| 45 | XML 1.1 | New | security_xml_test.go |
| 46 | Attr Normalization Tabs | New | security_xml_test.go |
| 47 | CharRef Normalization | New | security_xml_test.go |
| 48 | Whitespace in Audience | New | security_xml_test.go |

### Unicode (49-50)

| # | Name | Status | File |
|---|------|--------|------|
| 49 | NFC vs NFD | New | security_xml_test.go |
| 50 | Homoglyph | New | security_xml_test.go |

### Double Encoding / Polyglot (51-55)

| # | Name | Status | File |
|---|------|--------|------|
| 51 | Double URL Encoding | New | security_xml_test.go |
| 52 | Double Base64 | New | security_xml_test.go |
| 53 | Polyglot XML/HTML | New | security_xml_test.go |
| 54 | Malformed Self-Closing | New | security_xml_test.go |
| 55 | Entity in Tag Name | New | security_xml_test.go |

---

## Category 3: Assertion / Condition Validation (50 tests)

### Time / Clock Skew (1-10)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | NotOnOrAfter Boundary | Exists | security_test.go (TestTemporal_ClockSkewBoundary) |
| 2 | NotBefore Boundary | Exists | security_test.go (TestTemporal_NotYetValid) |
| 3 | Missing NotBefore | New | security_conditions_test.go |
| 4 | Far-Future NotOnOrAfter | New | security_conditions_test.go |
| 5 | Missing NotOnOrAfter | Exists | security_test.go (TestTemporal_MissingNotOnOrAfter) |
| 6 | Non-RFC3339 Format | New | security_conditions_test.go |
| 7 | Timezone Offset | New | security_conditions_test.go |
| 8 | Negative Timezone | New | security_conditions_test.go |
| 9 | Clock Skew Zero | New | security_conditions_test.go |
| 10 | Large Clock Skew | New | security_conditions_test.go |

### SubjectConfirmationData Time (11-14)

| # | Name | Status | File |
|---|------|--------|------|
| 11 | SCD Expired Conditions Valid | New | security_conditions_test.go |
| 12 | SCD Valid Conditions Expired | Exists | security_test.go (TestTemporal_ExpiredAssertion) |
| 13 | SCD Missing NotOnOrAfter | New | security_conditions_test.go |
| 14 | SCD NotBefore Future | New | security_conditions_test.go |

### Audience (15-21)

| # | Name | Status | File |
|---|------|--------|------|
| 15 | Empty AudienceRestriction | New | security_conditions_test.go |
| 16 | No AudienceRestriction | New | security_conditions_test.go |
| 17 | Empty AudienceURIs | New | security_conditions_test.go |
| 18 | Multi AudienceRestriction | New | security_conditions_test.go |
| 19 | Single with Both | New | security_conditions_test.go |
| 20 | Trailing Slash | New | security_conditions_test.go |
| 21 | Case Sensitivity | New | security_conditions_test.go |

### Subject Confirmation (22-25)

| # | Name | Status | File |
|---|------|--------|------|
| 22 | Non-Bearer Method | Exists | security_test.go (TestValidation_WrongSubjectConfirmationMethod) |
| 23 | Empty Method | New | security_conditions_test.go |
| 24 | InResponseTo Mismatch | Exists | xsw_test.go (TestXSW8_InResponseToMismatch) |
| 25 | InResponseTo Present SCD Empty Response | New | security_conditions_test.go |

### Replay (26-27)

| # | Name | Status | File |
|---|------|--------|------|
| 26 | Empty InResponseTo NoIDP | Exists | security_test.go (TestReplay_IDPInitiated_Disallowed) |
| 27 | Same ID Twice | Exists | security_test.go (TestMemoryRequestTracker_DoubleConsume) |

### Destination / Recipient (28-31)

| # | Name | Status | File |
|---|------|--------|------|
| 28 | Recipient Mismatch | Exists | security_test.go (TestValidation_WrongRecipient) |
| 29 | Recipient Extra Path | New | security_conditions_test.go |
| 30 | Empty Destination | Exists | decode_redirect_security_test.go (TestVuln_RedirectLogoutResponse_EmptyDestination) |
| 31 | Destination Mismatch | Exists | security_test.go (TestValidation_WrongDestination) |

### Issuer (32-34)

| # | Name | Status | File |
|---|------|--------|------|
| 32 | Response Issuer Mismatch | Exists | security_test.go (TestValidation_WrongIssuer) |
| 33 | Response vs Assertion Issuer Differ | New | security_conditions_test.go |
| 34 | Empty IDPEntityID | New | security_conditions_test.go |

### Status (35-37)

| # | Name | Status | File |
|---|------|--------|------|
| 35 | Not Success | Exists | security_test.go (TestValidation_NonSuccessStatus) |
| 36 | Missing Status | New | security_conditions_test.go |
| 37 | Missing StatusCode | New | security_conditions_test.go |

### Version / Multi-Assertion (38-41)

| # | Name | Status | File |
|---|------|--------|------|
| 38 | Version Not 2.0 | Exists | security_test.go (TestValidation_WrongVersion) |
| 39 | Multi Assertions Different Subjects | New | security_conditions_test.go |
| 40 | No Subject | New | security_conditions_test.go |
| 41 | Subject Without NameID | New | security_conditions_test.go |

### NameID / Attribute (42-46)

| # | Name | Status | File |
|---|------|--------|------|
| 42 | XML Special Chars | New | security_conditions_test.go |
| 43 | Null Bytes | New | security_conditions_test.go |
| 44 | Dup Attr Names | New | security_conditions_test.go |
| 45 | Extra AttributeStatement | New | security_conditions_test.go |
| 46 | Type Confusion | New | security_conditions_test.go |

### Misc (47-50)

| # | Name | Status | File |
|---|------|--------|------|
| 47 | OneTimeUse | New | security_conditions_test.go |
| 48 | ProxyRestriction | New | security_conditions_test.go |
| 49 | Assertion ID Reuse | New | security_conditions_test.go |
| 50 | Response ID Manipulation | New | security_conditions_test.go |

---

## Category 4: Encryption / Decryption (50 tests)

### CBC Attacks (1-4)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | Padding Oracle Timing | Exists | types/encrypted_assertion_security_test.go (TestPaddingOracle_UniformErrors) |
| 2 | Error Message Uniformity | Exists | types/encrypted_assertion_security_test.go (TestPaddingOracle_UniformErrors) |
| 3 | Bit-Flipping IV | New | security_crypto_test.go |
| 4 | Bit-Flipping Interior | New | security_crypto_test.go |

### Algorithm Downgrade (5-6)

| # | Name | Status | File |
|---|------|--------|------|
| 5 | 3DES | Exists | security_test.go (TestDoS_3DESRejected) |
| 6 | Unknown Method | Exists | security_test.go (TestEncryption_UnknownAlgorithm) |

### Key Transport (7-12)

| # | Name | Status | File |
|---|------|--------|------|
| 7 | RSA PKCS1v1.5 | Exists | types/encrypted_assertion_security_test.go (TestRSAv15KeyTransportBlocked) |
| 8 | OAEP SHA1 Digest | New | security_crypto_test.go |
| 9 | OAEP Missing DigestMethod | New | security_crypto_test.go |
| 10 | Unsupported DigestMethod | New | security_crypto_test.go |
| 11 | Missing Encryption Algorithm | New | security_crypto_test.go |
| 12 | Unsupported Key Transport | New | security_crypto_test.go |

### Key / Data Structure (13-15)

| # | Name | Status | File |
|---|------|--------|------|
| 13 | Both Inline and Detached Key | New | security_crypto_test.go |
| 14 | Empty CipherValue | Exists | security_test.go (TestDoS_EmptyCipherValueGCM, TestDoS_EmptyCipherValueCBC) |
| 15 | Large CipherValue | New | security_crypto_test.go |

### Base64 Issues (16-18)

| # | Name | Status | File |
|---|------|--------|------|
| 16 | Invalid Base64 CipherValue | New | security_crypto_test.go |
| 17 | Base64 Whitespace | New | security_crypto_test.go |
| 18 | Invalid Base64 EncryptedKey | New | security_crypto_test.go |

### X509 / Cert (19-20)

| # | Name | Status | File |
|---|------|--------|------|
| 19 | Cert Mismatch | Exists | security_test.go (TestEncryption_MismatchedCert) |
| 20 | Empty X509Data | New | security_crypto_test.go |

### Post-Decryption (21-23)

| # | Name | Status | File |
|---|------|--------|------|
| 21 | XXE in Decrypted | New | security_crypto_test.go |
| 22 | Billion Laughs in Decrypted | New | security_crypto_test.go |
| 23 | XSW in Decrypted | New | security_crypto_test.go |

### Mixed / Missing (24-27)

| # | Name | Status | File |
|---|------|--------|------|
| 24 | Both Encrypted and Plaintext | New | security_crypto_test.go |
| 25 | No SPKeyStore | New | security_crypto_test.go |
| 26 | No EncryptedKey | New | security_crypto_test.go |
| 27 | Multiple EncryptedKey | New | security_crypto_test.go |

### Algorithm Mismatch (28)

| # | Name | Status | File |
|---|------|--------|------|
| 28 | Algorithm Mismatch | New | security_crypto_test.go |

### GCM / CBC Specific (29-33)

| # | Name | Status | File |
|---|------|--------|------|
| 29 | GCM Nonce Reuse | New | types/security_crypto_extended_test.go |
| 30 | GCM Truncated to Nonce | Exists | security_test.go (TestDoS_ShortCipherValueGCM) |
| 31 | GCM Modified Tag | New | types/security_crypto_extended_test.go |
| 32 | CBC Non-Block-Aligned | Exists | types/encrypted_assertion_security_test.go (TestZeroTrimBeforePadding_DataCorruption) |
| 33 | CBC One Block Only | Exists | types/encrypted_assertion_security_test.go (TestZeroTrimShiftsPadByte) |

### Compression / Encoding (34-40)

| # | Name | Status | File |
|---|------|--------|------|
| 34 | Deflate Bomb Redirect | Exists | decode_redirect_security_test.go (TestRedirect_DecompressionBomb) |
| 35 | Deflate Bomb POST | Exists | security_test.go (TestDoS_DecompressionBomb) |
| 36 | Malformed Deflate | New | security_crypto_test.go |
| 37 | Double Base64 | New | security_crypto_test.go |
| 38 | URL-Safe Base64 | New | security_crypto_test.go |
| 39 | URL Encoding Attack | New | security_crypto_test.go |
| 40 | URL Normalization | New | security_crypto_test.go |

### Cert Validity (41-44)

| # | Name | Status | File |
|---|------|--------|------|
| 41 | Self-Signed Substitution | Exists | security_test.go (TestSignatureBypass_SelfSignedCert) |
| 42 | Expired SP Cert | New | security_crypto_test.go |
| 43 | Wrong Key Usage | New | security_crypto_test.go |
| 44 | Malformed ASN.1 | New | security_crypto_test.go |

### Misc (45-50)

| # | Name | Status | File |
|---|------|--------|------|
| 45 | Non-XML Content | New | security_crypto_test.go |
| 46 | Wrong Root Element | New | security_crypto_test.go |
| 47 | Wrong AES Key Size | New | security_crypto_test.go |
| 48 | Truncated RSA-OAEP | New | security_crypto_test.go |
| 49 | InsecureSkip with Encrypted | Exists | security_test.go (TestSignatureBypass_InsecureSkipValidation) |
| 50 | GCM Chosen-Ciphertext | New | security_crypto_test.go |

---

## Category 5: Protocol / Binding (50 tests)

### HTTP POST (1-6)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | Base64 Padding | New | security_binding_test.go |
| 2 | Deflate Bomb | Exists | security_test.go (TestDoS_DecompressionBomb) |
| 3 | Double Encoded | New | security_binding_test.go |
| 4 | No Sig | Exists | security_test.go (TestSignatureBypass_RemovedSignature) |
| 5 | Signed Response Tampered Assertion | Exists | xsw_test.go (TestXSW4_SignedResponseTamperedAssertion) |
| 6 | Wrong Parent | New | security_binding_test.go |

### HTTP Redirect (7-11)

| # | Name | Status | File |
|---|------|--------|------|
| 7 | Sig Stripping | Exists | decode_redirect_security_test.go (TestVuln_SignatureBypassPartialParams) |
| 8 | Param Order | New | security_binding_test.go |
| 9 | SHA1 Downgrade | Exists | decode_redirect_security_test.go (TestVuln_SigAlg_SHA1Downgrade) |
| 10 | Unknown SigAlg | Exists | decode_redirect_security_test.go (TestVuln_UnknownSigAlg_FallsBackToSHA256) |
| 11 | Inflate Size Limit | Exists | decode_redirect_security_test.go (TestRedirect_DecompressionBomb) |

### RelayState (12-15)

| # | Name | Status | File |
|---|------|--------|------|
| 12 | XSS via POST Form | Exists | security_test.go (TestPostForm_XSSInRelayState) |
| 13 | Open Redirect | New | security_binding_test.go |
| 14 | Oversized | New | security_binding_test.go |
| 15 | Null Bytes | New | security_binding_test.go |

### CSRF (16-17)

| # | Name | Status | File |
|---|------|--------|------|
| 16 | No InResponseTo | Exists | security_test.go (TestReplay_IDPInitiated_Disallowed) |
| 17 | Forged InResponseTo | Exists | security_test.go (TestReplay_UnknownRequestID) |

### Replay (18-20)

| # | Name | Status | File |
|---|------|--------|------|
| 18 | Resubmit | Exists | security_test.go (TestMemoryRequestTracker_DoubleConsume) |
| 19 | Expired Request ID | Exists | security_test.go (TestMemoryRequestTracker_Expiry) |
| 20 | Valid Time Consumed ID | Exists | security_test.go (TestMemoryRequestTracker_DoubleConsume) |

### Destination (21-22)

| # | Name | Status | File |
|---|------|--------|------|
| 21 | Mismatch | Exists | security_test.go (TestValidation_WrongDestination) |
| 22 | Empty | Exists | decode_redirect_security_test.go (TestVuln_RedirectLogoutResponse_EmptyDestination) |

### Binding Mismatch (23-24)

| # | Name | Status | File |
|---|------|--------|------|
| 23 | Deflated via POST | New | security_binding_test.go |
| 24 | Non-Deflated via Redirect | New | security_binding_test.go |

### AuthnRequest (25-28)

| # | Name | Status | File |
|---|------|--------|------|
| 25 | ACS URL Injection | New | security_binding_test.go |
| 26 | Missing ID | New | security_binding_test.go |
| 27 | ForceAuthn Bypass | New | security_binding_test.go |
| 28 | IsPassive | New | security_binding_test.go |

### AuthnContext / Unsolicited (29-33)

| # | Name | Status | File |
|---|------|--------|------|
| 29 | AuthnContext Downgrade | New | security_binding_test.go |
| 30 | Unsolicited Disabled | Exists | security_test.go (TestReplay_IDPInitiated_Disallowed) |
| 31 | Unsolicited No Tracker | New | security_binding_test.go |
| 32 | SCD InResponseTo Mismatch | Exists | security_test.go (TestReplay_InResponseToMismatch) |
| 33 | Recipient Mismatch | Exists | security_test.go (TestValidation_WrongRecipient) |

### Multiple Assertions (34-35)

| # | Name | Status | File |
|---|------|--------|------|
| 34 | Mixed Signed Unsigned | Exists | xsw_test.go (TestXSW7_UnsignedResponseMixedAssertions) |
| 35 | Different Issuers | New | security_binding_test.go |

### URL Validation (36-40)

| # | Name | Status | File |
|---|------|--------|------|
| 36 | Scheme Confusion | New | security_binding_test.go |
| 37 | Trailing Slash | New | security_binding_test.go |
| 38 | Host Header Port | New | security_binding_test.go |
| 39 | Path Traversal | New | security_binding_test.go |
| 40 | Unicode Destination | New | security_binding_test.go |

### Protocol Version (41-42)

| # | Name | Status | File |
|---|------|--------|------|
| 41 | SAML 1.1 Response | New | security_binding_test.go |
| 42 | Assertion Version Mismatch | New | security_binding_test.go |

### Logout (43-45)

| # | Name | Status | File |
|---|------|--------|------|
| 43 | Request Forgery | New | security_binding_test.go |
| 44 | Missing Sig | New | security_binding_test.go |
| 45 | Destination Mismatch | Exists | decode_redirect_security_test.go (TestVuln_RedirectLogoutResponse_WrongDestination) |

### Session / Timing (46-50)

| # | Name | Status | File |
|---|------|--------|------|
| 46 | Session Fixation | New | security_binding_test.go |
| 47 | Error Exfiltration | New | security_binding_test.go |
| 48 | Timing Attack | New | security_binding_test.go |
| 49 | Race Condition MemoryRequestTracker | New | security_binding_test.go |
| 50 | Metadata Injection | New | security_binding_test.go |

---

## Category 6: Edge Cases & Novel Attacks (50 tests)

### IdP-Specific (1-14)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | Wrong SP ACS | New | idp/security_extended_test.go |
| 2 | Signer Cache Rotation | New | idp/security_extended_test.go |
| 3 | Rogue SP Metadata | New | idp/security_extended_test.go |
| 4 | KeyDescriptor Missing Use | New | idp/security_extended_test.go |
| 5 | Empty IDPEntityID | New | idp/security_extended_test.go |
| 6 | AuthnRequest Bad ACS | New | idp/security_extended_test.go |
| 7 | Empty ACS URLs | New | idp/security_extended_test.go |
| 8 | Redirect Empty Sig | New | idp/security_extended_test.go |
| 9 | Redirect SHA1 NoAllow | New | idp/security_extended_test.go |
| 10 | ECDSA SigAlg RSA Cert | New | idp/security_extended_test.go |
| 11 | LogoutRequest Destination | New | idp/security_extended_test.go |
| 12 | LogoutRequest Reuses Flag | New | idp/security_extended_test.go |
| 13 | MetadataValidDuration Far-Future | New | idp/security_extended_test.go |
| 14 | Decompression Bomb IdP | New | idp/security_extended_test.go |

### Interop (15-21)

| # | Name | Status | File |
|---|------|--------|------|
| 15 | RT Validation NS Bypass | Exists | security_test.go (TestRoundTripMutation_NamespacePrefixedAttributes) |
| 16 | AuthnReq Comment Injection | Exists | decode_redirect_security_test.go (TestVuln_Redirect_CommentInjection) |
| 17 | CDATA in Issuer | New | security_novel_test.go |
| 18 | Unicode Normalization | Exists | internal/xmldsig/security_test.go (TestCrossRef_UnicodeNormalization) |
| 19 | Homoglyph SP ID | New | security_novel_test.go |
| 20 | Multiple Issuer Elements | New | security_novel_test.go |
| 21 | Zero-Width Chars | New | security_novel_test.go |

### Creative (22-32)

| # | Name | Status | File |
|---|------|--------|------|
| 22 | Non-RSA Encryption Cert | New | security_novel_test.go |
| 23 | Unsupported Encryption Algo | Exists | security_test.go (TestEncryption_UnknownAlgorithm) |
| 24 | CBC Padding Oracle | Exists | types/encrypted_assertion_security_test.go (TestPaddingOraclePracticalExploit) |
| 25 | GCM Nonce Reuse | New | security_novel_test.go |
| 26 | XSW on IdP Response | New | idp/security_extended_test.go |
| 27 | XSW Both Sigs | New | security_novel_test.go |
| 28 | Encrypted XSW | New | security_novel_test.go |
| 29 | IDP Initiated Disabled | Exists | security_test.go (TestReplay_IDPInitiated_Disallowed) |
| 30 | InResponseTo Mismatch | Exists | security_test.go (TestReplay_InResponseToMismatch) |
| 31 | Replay Same ID | Exists | security_test.go (TestMemoryRequestTracker_DoubleConsume) |
| 32 | Time Skew Boundary | Exists | security_test.go (TestTemporal_ClockSkewBoundary) |

### More Interop (33-39)

| # | Name | Status | File |
|---|------|--------|------|
| 33 | Non-RFC3339 Timestamps | New | security_novel_test.go |
| 34 | Future NotBefore | Exists | security_test.go (TestTemporal_NotYetValid) |
| 35 | Empty Conditions | New | security_novel_test.go |
| 36 | AudienceRestriction Multi Match | New | security_novel_test.go |
| 37 | Multiple Restrictions | New | security_novel_test.go |
| 38 | etree vs encoding/xml NS | New | security_novel_test.go |
| 39 | Entity Expansion in Attr | New | security_novel_test.go |

### Misc (40-50)

| # | Name | Status | File |
|---|------|--------|------|
| 40 | Large Attributes Memory | New | security_novel_test.go |
| 41 | Concurrent Signer Access | New | security_novel_test.go |
| 42 | Negative X509 Serial | New | security_novel_test.go |
| 43 | PEM Extra Whitespace | New | security_novel_test.go |
| 44 | Long ID Attr | Exists | internal/xmldsig/security_test.go (TestCrossRef_LongID) |
| 45 | Sig Reference URI Regex Bypass | New | security_novel_test.go |
| 46 | BuildPOSTForm XSS RelayState | Exists | security_test.go (TestPostForm_XSSInRelayState) |
| 47 | BuildPOSTForm XSS ACS URL | Exists | security_test.go (TestPostForm_XSSInURL) |
| 48 | Empty Reference URI | Exists | internal/xmldsig/security_test.go (TestCrossRef_EmptyURI_ValidRoundTrip) |
| 49 | Chain Attack Metadata Poisoning | New | security_novel_test.go |
| 50 | SignatureInputString Param Order | New | security_novel_test.go |

---

## Summary

| Category | Total | New | Exists |
|----------|-------|-----|--------|
| 1. Signature Wrapping / Verification | 55 | 22 | 33 |
| 2. XML Parsing / Entity / Encoding | 55 | 47 | 8 |
| 3. Assertion / Condition Validation | 50 | 36 | 14 |
| 4. Encryption / Decryption | 50 | 36 | 14 |
| 5. Protocol / Binding | 50 | 30 | 20 |
| 6. Edge Cases & Novel Attacks | 50 | 36 | 14 |
| **Total** | **310** | **207** | **103** |
