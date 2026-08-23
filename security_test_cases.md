# Security Test Case Tracking Document

This document tracks 335 security test cases for the gosaml2 library, organized across 7 categories. It was audited against the `v2` test suite after the original tracking effort. Each test case is classified by its current coverage:

- **Exists** -- A test that predates the tracking effort covers this scenario (or substantially overlaps).
- **Implemented** -- A deterministic test added during the tracking effort exercises the scenario. This describes test coverage, not necessarily rejection: some tests intentionally assert supported or configurable behavior.
- **Characterization** -- A test exercises the scenario, but permits multiple outcomes or primarily documents robustness or operational behavior. It is not a strong regression guarantee for one security policy.
- **Application** -- A test documents a boundary that gosaml2 intentionally leaves to application configuration or policy.
- **Gap** -- No test currently covers the named scenario.

File references identify the test that provides the coverage. Rows may overlap when one test covers more than one scenario.

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
| 10 | Strip Assertion Sig Unsigned Path | Implemented | security_sig_extended_test.go |
| 11 | Strip Assertion Sig Signed Path | Implemented | security_sig_extended_test.go |

### Malformed Signature Values (12-18)

| # | Name | Status | File |
|---|------|--------|------|
| 12 | Empty SigValue | Implemented | security_sig_extended_test.go |
| 13 | Whitespace SigValue | Implemented | security_sig_extended_test.go |
| 14 | Truncated Base64 SigValue | Implemented | security_sig_extended_test.go |
| 15 | Invalid Base64 SigValue | Implemented | security_sig_extended_test.go |
| 16 | Missing SignedInfo | Exists | internal/xmldsig/security_test.go (TestXSW_Audit_ShapeValidation_NoSignedInfo) |
| 17 | Dup SignedInfo | Exists | internal/xmldsig/security_test.go (TestXSW_Audit_ShapeValidation_DuplicateSignedInfo) |
| 18 | Dup SigValue | Implemented | security_sig_extended_test.go |

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
| 25 | Verified vs Unverified SignedInfo | Implemented | security_sig_extended_test.go |
| 26 | Empty DigestValue | Implemented | security_sig_extended_test.go |

### Reference URI (27-31)

| # | Name | Status | File |
|---|------|--------|------|
| 27 | Empty URI | Exists | internal/xmldsig/security_test.go (TestCrossRef_EmptyURI_ValidRoundTrip) |
| 28 | NonExistent ID | Exists | internal/xmldsig/security_test.go (TestCrossRef_URIMismatch) |
| 29 | URI Points to Assertion | Implemented | security_sig_extended_test.go |
| 30 | Malformed URI No Hash | Exists | internal/xmldsig/security_test.go (TestCrossRef_BareHashURI, TestCrossRef_RelativeURI) |
| 31 | URI with XPath | Exists | internal/xmldsig/security_test.go (TestCrossRef_XPointerURI) |

### Transform Manipulation (32-34)

| # | Name | Status | File |
|---|------|--------|------|
| 32 | Remove Enveloped Transform | Implemented | security_sig_extended_test.go |
| 33 | Add XSLT Transform | Implemented | security_sig_extended_test.go |
| 34 | Dup Transform | Implemented | security_sig_extended_test.go |

### C14N Algorithm (35-38)

| # | Name | Status | File |
|---|------|--------|------|
| 35 | Unrecognized C14N | Implemented | security_sig_extended_test.go |
| 36 | Inclusive C14N 1.0 | Characterization | security_sig_extended_test.go |
| 37 | With vs Without Comments | Characterization | security_sig_extended_test.go |
| 38 | PrefixList Manipulation | Exists | internal/xmldsig/security_test.go (TestXSW_Audit_ExcC14N_PrefixListTamper) |

### Wrong Elements / Dup IDs (39-42)

| # | Name | Status | File |
|---|------|--------|------|
| 39 | Sign Assertion Claim Response | Exists | xsw_test.go (TestXSW3_UnsignedResponseSignedAssertionIntegrity) |
| 40 | Sign Response Tamper Assertion | Exists | xsw_test.go (TestXSW4_SignedResponseTamperedAssertion) |
| 41 | Two Elements Same ID | Exists | internal/xmldsig/security_test.go (TestCrossRef_DuplicateIDs_EvilSiblingWithSameID) |
| 42 | Response and Assertion Same ID | Implemented | security_sig_extended_test.go |

### Detached / Enveloping (43-45)

| # | Name | Status | File |
|---|------|--------|------|
| 43 | Sig as Sibling | Exists | internal/xmldsig/security_test.go (TestXSW_Audit_SignatureMovedToSibling) |
| 44 | Sig in Separate Doc | Exists | internal/xmldsig/security_test.go (TestCrossRef_SignatureTransplantBetweenDocuments) |
| 45 | Enveloping Sig Contains Response | Implemented | security_sig_extended_test.go |

### SignedInfo / Scope (46-50)

| # | Name | Status | File |
|---|------|--------|------|
| 46 | Modify DigestMethod | Exists | internal/xmldsig/security_test.go (TestCrossRef_SignedInfoCoversDigestMethod) |
| 47 | Modify SigMethod | Implemented | security_sig_extended_test.go |
| 48 | Response Signed Assertion Modified | Exists | xsw_test.go (TestXSW4_SignedResponseTamperedAssertion) |
| 49 | Missing Response Sig Only Assertion Signed | Exists | xsw_test.go (TestXSW3_UnsignedResponseSignedAssertionIntegrity) |
| 50 | Missing Assertion Sig Only Response Signed | Exists | xsw_test.go (TestXSW7_UnsignedResponseMixedAssertions) |

### HMAC / Algorithm (51-55)

| # | Name | Status | File |
|---|------|--------|------|
| 51 | HMAC Key Confusion | Implemented | security_sig_extended_test.go |
| 52 | SHA1 Digest AllowSHA1 False | Exists | security_test.go (TestSHA1_RejectedByDefault) |
| 53 | Unknown Sig Algorithm | Exists | internal/xmldsig/security_test.go (TestAlgo_UnknownSignatureAlgorithm) |
| 54 | Null Bytes in SigValue | Implemented | security_sig_extended_test.go |
| 55 | Half-Length RSA Sig | Implemented | security_sig_extended_test.go |

---

## Category 2: XML Parsing / Entity / Encoding (55 tests)

### XXE (1-5)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | Classic file entity | Implemented | security_xml_test.go |
| 2 | XXE in EncryptedAssertion | Implemented | security_xml_test.go |
| 3 | Parameter Entity | Implemented | security_xml_test.go |
| 4 | PUBLIC Identifier | Implemented | security_xml_test.go |
| 5 | XInclude | Implemented | security_xml_test.go |

### SSRF via XXE (6-8)

| # | Name | Status | File |
|---|------|--------|------|
| 6 | Cloud Metadata | Implemented | security_xml_test.go |
| 7 | DNS Exfiltration | Implemented | security_xml_test.go |
| 8 | Internal Services | Implemented | security_xml_test.go |

### Entity Expansion (9-12)

| # | Name | Status | File |
|---|------|--------|------|
| 9 | Billion Laughs | Exists | security_test.go (TestDoS_BillionLaughs) |
| 10 | Quadratic Blowup | Implemented | security_xml_test.go |
| 11 | Recursive | Implemented | security_xml_test.go |
| 12 | In Attributes | Implemented | security_xml_test.go |

### CDATA (13-15)

| # | Name | Status | File |
|---|------|--------|------|
| 13 | CDATA in NameID | Implemented | security_xml_test.go |
| 14 | CDATA Splitting | Implemented | security_xml_test.go |
| 15 | CDATA in CipherValue | Implemented | security_xml_test.go |

### Namespace Confusion (16-21)

| # | Name | Status | File |
|---|------|--------|------|
| 16 | Prefix Remapping | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion) |
| 17 | Default NS Override | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion_SignatureInWrongDefaultNS) |
| 18 | NS Undeclaration | Implemented | security_xml_test.go |
| 19 | NS Redefinition | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion_PrefixRebindOnSignedInfoChildren) |
| 20 | Dup NS Different URIs | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion_MultipleDsigPrefixesOnSameElement) |
| 21 | NS Prefix on Sig | Exists | internal/xmldsig/security_test.go (TestNamespaceConfusion_AlternativePrefixes_ExcC14N) |

### Comment Injection (22-24)

| # | Name | Status | File |
|---|------|--------|------|
| 22 | Split NameID | Exists | security_test.go (TestCommentInjection_InNameID) |
| 23 | Between Element Tags | Implemented | security_xml_test.go |
| 24 | Double Hyphen | Characterization | security_xml_test.go |

### Mixed Content (25-26)

| # | Name | Status | File |
|---|------|--------|------|
| 25 | Mixed Content in Assertion | Implemented | security_xml_test.go |
| 26 | Significant Whitespace | Implemented | security_xml_test.go |

### Processing Instructions (27-29)

| # | Name | Status | File |
|---|------|--------|------|
| 27 | PI Before Root | Characterization | security_xml_test.go |
| 28 | PI Inside Signed Element | Characterization | security_xml_test.go |
| 29 | PI Mimicking XML Declaration | Characterization | security_xml_test.go |

### DTD (30-32)

| # | Name | Status | File |
|---|------|--------|------|
| 30 | Internal Subset Redefining | Implemented | security_xml_test.go |
| 31 | Remote DTD | Implemented | security_xml_test.go |
| 32 | NOTATION | Implemented | security_xml_test.go |

### Encoding (33-35)

| # | Name | Status | File |
|---|------|--------|------|
| 33 | UTF7 | Characterization | security_xml_test.go |
| 34 | UTF16BE | Implemented | security_xml_test.go |
| 35 | UTF16LE No BOM | Implemented | security_xml_test.go |

### BOM (36-38)

| # | Name | Status | File |
|---|------|--------|------|
| 36 | UTF8 BOM | Characterization | security_xml_test.go |
| 37 | Double BOM | Characterization | security_xml_test.go |
| 38 | BOM Between Declaration and Root | Characterization | security_xml_test.go |

### Null Byte (39-41)

| # | Name | Status | File |
|---|------|--------|------|
| 39 | In NameID | Characterization | security_xml_test.go |
| 40 | In Attribute | Characterization | security_xml_test.go |
| 41 | In NS URI | Characterization | security_xml_test.go |

### Size / Depth (42-44)

| # | Name | Status | File |
|---|------|--------|------|
| 42 | Oversized Decompressed | Exists | security_test.go (TestDoS_DecompressionBomb) |
| 43 | Oversized Uncompressed | Characterization | security_xml_test.go |
| 44 | Deep Nesting 10K | Characterization | security_xml_test.go |

### Version / Normalization (45-48)

| # | Name | Status | File |
|---|------|--------|------|
| 45 | XML 1.1 | Characterization | security_xml_test.go |
| 46 | Attr Normalization Tabs | Implemented | security_xml_test.go |
| 47 | CharRef Normalization | Implemented | security_xml_test.go |
| 48 | Whitespace in Audience | Implemented | security_xml_test.go |

### Unicode (49-50)

| # | Name | Status | File |
|---|------|--------|------|
| 49 | NFC vs NFD | Implemented | security_xml_test.go |
| 50 | Homoglyph | Implemented | security_xml_test.go |

### Double Encoding / Polyglot (51-55)

| # | Name | Status | File |
|---|------|--------|------|
| 51 | Double URL Encoding | Implemented | security_xml_test.go |
| 52 | Double Base64 | Implemented | security_xml_test.go |
| 53 | Polyglot XML/HTML | Implemented | security_xml_test.go |
| 54 | Malformed Self-Closing | Implemented | security_xml_test.go |
| 55 | Entity in Tag Name | Implemented | security_xml_test.go |

---

## Category 3: Assertion / Condition Validation (50 tests)

### Time / Clock Skew (1-10)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | NotOnOrAfter Boundary | Exists | security_test.go (TestTemporal_ClockSkewBoundary) |
| 2 | NotBefore Boundary | Exists | security_test.go (TestTemporal_NotYetValid) |
| 3 | Missing NotBefore | Implemented | security_conditions_test.go |
| 4 | Far-Future NotOnOrAfter | Implemented | security_conditions_test.go |
| 5 | Missing NotOnOrAfter | Exists | security_test.go (TestTemporal_MissingNotOnOrAfter) |
| 6 | Non-RFC3339 Format | Implemented | security_conditions_test.go |
| 7 | Timezone Offset | Implemented | security_conditions_test.go |
| 8 | Negative Timezone | Implemented | security_conditions_test.go |
| 9 | Clock Skew Zero | Implemented | security_conditions_test.go |
| 10 | Large Clock Skew | Implemented | security_conditions_test.go |

### SubjectConfirmationData Time (11-14)

| # | Name | Status | File |
|---|------|--------|------|
| 11 | SCD Expired Conditions Valid | Implemented | security_conditions_test.go |
| 12 | SCD Valid Conditions Expired | Exists | security_test.go (TestTemporal_ExpiredAssertion) |
| 13 | SCD Missing NotOnOrAfter | Implemented | security_conditions_test.go |
| 14 | SCD NotBefore Future | Implemented | security_conditions_test.go |

### Audience (15-21)

| # | Name | Status | File |
|---|------|--------|------|
| 15 | Empty AudienceRestriction | Implemented | security_conditions_test.go |
| 16 | No AudienceRestriction | Characterization | security_conditions_test.go |
| 17 | Empty AudienceURIs | Application | security_conditions_test.go |
| 18 | Multi AudienceRestriction | Implemented | security_conditions_test.go |
| 19 | Single with Both | Implemented | security_conditions_test.go |
| 20 | Trailing Slash | Implemented | security_conditions_test.go |
| 21 | Case Sensitivity | Implemented | security_conditions_test.go |

### Subject Confirmation (22-25)

| # | Name | Status | File |
|---|------|--------|------|
| 22 | Non-Bearer Method | Exists | security_test.go (TestValidation_WrongSubjectConfirmationMethod) |
| 23 | Empty Method | Implemented | security_conditions_test.go |
| 24 | InResponseTo Mismatch | Exists | xsw_test.go (TestXSW8_InResponseToMismatch) |
| 25 | InResponseTo Present SCD Empty Response | Implemented | security_conditions_test.go |

### Replay (26-27)

| # | Name | Status | File |
|---|------|--------|------|
| 26 | Empty InResponseTo NoIDP | Exists | security_test.go (TestReplay_IDPInitiated_Disallowed) |
| 27 | Same ID Twice | Exists | security_test.go (TestMemoryRequestTracker_DoubleConsume) |

### Destination / Recipient (28-31)

| # | Name | Status | File |
|---|------|--------|------|
| 28 | Recipient Mismatch | Exists | security_test.go (TestValidation_WrongRecipient) |
| 29 | Recipient Extra Path | Implemented | security_conditions_test.go |
| 30 | Empty Destination | Exists | decode_redirect_security_test.go (TestVuln_RedirectLogoutResponse_EmptyDestination) |
| 31 | Destination Mismatch | Exists | security_test.go (TestValidation_WrongDestination) |

### Issuer (32-34)

| # | Name | Status | File |
|---|------|--------|------|
| 32 | Response Issuer Mismatch | Exists | security_test.go (TestValidation_WrongIssuer) |
| 33 | Response vs Assertion Issuer Differ | Implemented | security_conditions_test.go |
| 34 | Empty IDPEntityID | Application | security_conditions_test.go |

### Status (35-37)

| # | Name | Status | File |
|---|------|--------|------|
| 35 | Not Success | Exists | security_test.go (TestValidation_NonSuccessStatus) |
| 36 | Missing Status | Implemented | security_conditions_test.go |
| 37 | Missing StatusCode | Implemented | security_conditions_test.go |

### Version / Multi-Assertion (38-41)

| # | Name | Status | File |
|---|------|--------|------|
| 38 | Version Not 2.0 | Exists | security_test.go (TestValidation_WrongVersion) |
| 39 | Multi Assertions Different Subjects | Implemented | security_conditions_test.go |
| 40 | No Subject | Implemented | security_conditions_test.go |
| 41 | Subject Without NameID | Implemented | security_conditions_test.go |

### NameID / Attribute (42-46)

| # | Name | Status | File |
|---|------|--------|------|
| 42 | XML Special Chars | Implemented | security_conditions_test.go |
| 43 | Null Bytes | Implemented | security_conditions_test.go |
| 44 | Dup Attr Names | Implemented | security_conditions_test.go |
| 45 | Extra AttributeStatement | Implemented | security_conditions_test.go |
| 46 | Type Confusion | Implemented | security_conditions_test.go |

### Misc (47-50)

| # | Name | Status | File |
|---|------|--------|------|
| 47 | OneTimeUse | Application | security_conditions_test.go |
| 48 | ProxyRestriction | Application | security_conditions_test.go |
| 49 | Assertion ID Reuse | Application | security_conditions_test.go |
| 50 | Response ID Manipulation | Characterization | security_conditions_test.go |

---

## Category 4: Encryption / Decryption (50 tests)

### CBC Attacks (1-4)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | Padding Oracle Timing | Exists | types/encrypted_assertion_security_test.go (TestPaddingOracle_UniformErrors) |
| 2 | Error Message Uniformity | Exists | types/encrypted_assertion_security_test.go (TestPaddingOracle_UniformErrors) |
| 3 | Bit-Flipping IV | Implemented | security_crypto_test.go |
| 4 | Bit-Flipping Interior | Implemented | security_crypto_test.go |

### Algorithm Downgrade (5-6)

| # | Name | Status | File |
|---|------|--------|------|
| 5 | 3DES | Exists | security_test.go (TestDoS_3DESRejected) |
| 6 | Unknown Method | Exists | security_test.go (TestEncryption_UnknownAlgorithm) |

### Key Transport (7-12)

| # | Name | Status | File |
|---|------|--------|------|
| 7 | RSA PKCS1v1.5 | Exists | types/encrypted_assertion_security_test.go (TestRSAv15KeyTransportBlocked) |
| 8 | OAEP SHA1 Digest | Implemented | security_crypto_test.go |
| 9 | OAEP Missing DigestMethod | Implemented | security_crypto_test.go |
| 10 | Unsupported DigestMethod | Implemented | security_crypto_test.go |
| 11 | Missing Encryption Algorithm | Implemented | security_crypto_test.go |
| 12 | Unsupported Key Transport | Implemented | security_crypto_test.go |

### Key / Data Structure (13-15)

| # | Name | Status | File |
|---|------|--------|------|
| 13 | Both Inline and Detached Key | Implemented | security_crypto_test.go |
| 14 | Empty CipherValue | Exists | security_test.go (TestDoS_EmptyCipherValueGCM, TestDoS_EmptyCipherValueCBC) |
| 15 | Large CipherValue | Implemented | security_crypto_test.go |

### Base64 Issues (16-18)

| # | Name | Status | File |
|---|------|--------|------|
| 16 | Invalid Base64 CipherValue | Implemented | security_crypto_test.go |
| 17 | Base64 Whitespace | Implemented | security_crypto_test.go |
| 18 | Invalid Base64 EncryptedKey | Implemented | security_crypto_test.go |

### X509 / Cert (19-20)

| # | Name | Status | File |
|---|------|--------|------|
| 19 | Cert Mismatch | Exists | security_test.go (TestEncryption_MismatchedCert) |
| 20 | Empty X509Data | Implemented | security_crypto_test.go |

### Post-Decryption (21-23)

| # | Name | Status | File |
|---|------|--------|------|
| 21 | XXE in Decrypted | Implemented | security_crypto_test.go |
| 22 | Billion Laughs in Decrypted | Implemented | security_crypto_test.go |
| 23 | XSW in Decrypted | Implemented | security_crypto_test.go |

### Mixed / Missing (24-27)

| # | Name | Status | File |
|---|------|--------|------|
| 24 | Both Encrypted and Plaintext | Implemented | security_crypto_test.go |
| 25 | No SPKeyStore | Implemented | security_crypto_test.go |
| 26 | No EncryptedKey | Implemented | security_crypto_test.go |
| 27 | Multiple EncryptedKey | Implemented | security_crypto_test.go |

### Algorithm Mismatch (28)

| # | Name | Status | File |
|---|------|--------|------|
| 28 | Algorithm Mismatch | Implemented | security_crypto_test.go |

### GCM / CBC Specific (29-33)

| # | Name | Status | File |
|---|------|--------|------|
| 29 | GCM Nonce Reuse | Implemented | types/security_crypto_extended_test.go |
| 30 | GCM Truncated to Nonce | Exists | security_test.go (TestDoS_ShortCipherValueGCM) |
| 31 | GCM Modified Tag | Implemented | types/security_crypto_extended_test.go |
| 32 | CBC Non-Block-Aligned | Exists | types/encrypted_assertion_security_test.go (TestZeroTrimBeforePadding_DataCorruption) |
| 33 | CBC One Block Only | Exists | types/encrypted_assertion_security_test.go (TestZeroTrimShiftsPadByte) |

### Compression / Encoding (34-40)

| # | Name | Status | File |
|---|------|--------|------|
| 34 | Deflate Bomb Redirect | Exists | decode_redirect_security_test.go (TestRedirect_DecompressionBomb) |
| 35 | Deflate Bomb POST | Exists | security_test.go (TestDoS_DecompressionBomb) |
| 36 | Malformed Deflate | Implemented | security_crypto_test.go |
| 37 | Double Base64 | Implemented | security_crypto_test.go |
| 38 | URL-Safe Base64 | Implemented | security_crypto_test.go |
| 39 | URL Encoding Attack | Implemented | security_crypto_test.go |
| 40 | URL Normalization | Implemented | security_crypto_test.go |

### Cert Validity (41-44)

| # | Name | Status | File |
|---|------|--------|------|
| 41 | Self-Signed Substitution | Exists | security_test.go (TestSignatureBypass_SelfSignedCert) |
| 42 | Expired SP Cert | Implemented | security_crypto_test.go |
| 43 | Wrong Key Usage | Implemented | security_crypto_test.go |
| 44 | Malformed ASN.1 | Implemented | security_crypto_test.go |

### Misc (45-50)

| # | Name | Status | File |
|---|------|--------|------|
| 45 | Non-XML Content | Implemented | security_crypto_test.go |
| 46 | Wrong Root Element | Implemented | security_crypto_test.go |
| 47 | Wrong AES Key Size | Implemented | security_crypto_test.go |
| 48 | Truncated RSA-OAEP | Implemented | security_crypto_test.go |
| 49 | InsecureSkip with Encrypted | Exists | security_test.go (TestSignatureBypass_InsecureSkipValidation) |
| 50 | GCM Chosen-Ciphertext | Implemented | security_crypto_test.go |

---

## Category 5: Protocol / Binding (50 tests)

### HTTP POST (1-6)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | Base64 Padding | Implemented | security_binding_test.go |
| 2 | Deflate Bomb | Exists | security_test.go (TestDoS_DecompressionBomb) |
| 3 | Double Encoded | Implemented | security_binding_test.go |
| 4 | No Sig | Exists | security_test.go (TestSignatureBypass_RemovedSignature) |
| 5 | Signed Response Tampered Assertion | Exists | xsw_test.go (TestXSW4_SignedResponseTamperedAssertion) |
| 6 | Wrong Parent | Implemented | security_binding_test.go |

### HTTP Redirect (7-11)

| # | Name | Status | File |
|---|------|--------|------|
| 7 | Sig Stripping | Exists | decode_redirect_security_test.go (TestVuln_SignatureBypassPartialParams) |
| 8 | Param Order | Implemented | security_binding_test.go |
| 9 | SHA1 Downgrade | Exists | decode_redirect_security_test.go (TestVuln_SigAlg_SHA1Downgrade) |
| 10 | Unknown SigAlg | Exists | decode_redirect_security_test.go (TestVuln_UnknownSigAlg_FallsBackToSHA256) |
| 11 | Inflate Size Limit | Exists | decode_redirect_security_test.go (TestRedirect_DecompressionBomb) |

### RelayState (12-15)

| # | Name | Status | File |
|---|------|--------|------|
| 12 | XSS via POST Form | Exists | security_test.go (TestPostForm_XSSInRelayState) |
| 13 | Open Redirect | Application | security_binding_test.go |
| 14 | Oversized | Application | security_binding_test.go |
| 15 | Null Bytes | Application | security_binding_test.go |

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
| 23 | Deflated via POST | Characterization | security_binding_test.go |
| 24 | Non-Deflated via Redirect | Implemented | security_binding_test.go |

### AuthnRequest (25-28)

| # | Name | Status | File |
|---|------|--------|------|
| 25 | ACS URL Injection | Application | security_binding_test.go |
| 26 | Missing ID | Implemented | security_binding_test.go |
| 27 | ForceAuthn Bypass | Application | security_binding_test.go |
| 28 | IsPassive | Application | security_binding_test.go |

### AuthnContext / Unsolicited (29-33)

| # | Name | Status | File |
|---|------|--------|------|
| 29 | AuthnContext Downgrade | Application | security_binding_test.go |
| 30 | Unsolicited Disabled | Exists | security_test.go (TestReplay_IDPInitiated_Disallowed) |
| 31 | Unsolicited No Tracker | Implemented | security_binding_test.go |
| 32 | SCD InResponseTo Mismatch | Exists | security_test.go (TestReplay_InResponseToMismatch) |
| 33 | Recipient Mismatch | Exists | security_test.go (TestValidation_WrongRecipient) |

### Multiple Assertions (34-35)

| # | Name | Status | File |
|---|------|--------|------|
| 34 | Mixed Signed Unsigned | Exists | xsw_test.go (TestXSW7_UnsignedResponseMixedAssertions) |
| 35 | Different Issuers | Implemented | security_binding_test.go |

### URL Validation (36-40)

| # | Name | Status | File |
|---|------|--------|------|
| 36 | Scheme Confusion | Implemented | security_binding_test.go |
| 37 | Trailing Slash | Implemented | security_binding_test.go |
| 38 | Host Header Port | Implemented | security_binding_test.go |
| 39 | Path Traversal | Implemented | security_binding_test.go |
| 40 | Unicode Destination | Implemented | security_binding_test.go |

### Protocol Version (41-42)

| # | Name | Status | File |
|---|------|--------|------|
| 41 | SAML 1.1 Response | Implemented | security_binding_test.go |
| 42 | Assertion Version Mismatch | Implemented | security_binding_test.go |

### Logout (43-45)

| # | Name | Status | File |
|---|------|--------|------|
| 43 | Request Forgery | Implemented | security_binding_test.go |
| 44 | Missing Sig | Implemented | security_binding_test.go |
| 45 | Destination Mismatch | Exists | decode_redirect_security_test.go (TestVuln_RedirectLogoutResponse_WrongDestination) |

### Session / Timing (46-50)

| # | Name | Status | File |
|---|------|--------|------|
| 46 | Session Fixation | Characterization | security_binding_test.go |
| 47 | Error Exfiltration | Implemented | security_binding_test.go |
| 48 | Timing Attack | Characterization | security_binding_test.go |
| 49 | Race Condition MemoryRequestTracker | Implemented | security_binding_test.go |
| 50 | Metadata Injection | Application | security_binding_test.go |

---

## Category 6: Edge Cases & Novel Attacks (50 tests)

### IdP-Specific (1-14)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | Wrong SP ACS | Implemented | idp/security_extended_test.go |
| 2 | Signer Cache Rotation | Characterization | idp/security_extended_test.go |
| 3 | Rogue SP Metadata | Application | idp/security_extended_test.go |
| 4 | KeyDescriptor Missing Use | Implemented | idp/security_extended_test.go |
| 5 | Empty IDPEntityID | Application | idp/security_extended_test.go |
| 6 | AuthnRequest Bad ACS | Implemented | idp/security_extended_test.go |
| 7 | Empty ACS URLs | Implemented | idp/security_extended_test.go |
| 8 | Redirect Empty Sig | Implemented | idp/security_extended_test.go |
| 9 | Redirect SHA1 NoAllow | Implemented | idp/security_extended_test.go |
| 10 | ECDSA SigAlg RSA Cert | Implemented | idp/security_extended_test.go |
| 11 | LogoutRequest Destination | Implemented | idp/security_extended_test.go |
| 12 | LogoutRequest Reuses Flag | Implemented | idp/security_extended_test.go |
| 13 | MetadataValidDuration Far-Future | Implemented | idp/security_extended_test.go |
| 14 | Decompression Bomb IdP | Implemented | idp/security_extended_test.go |

### Interop (15-21)

| # | Name | Status | File |
|---|------|--------|------|
| 15 | RT Validation NS Bypass | Exists | security_test.go (TestRoundTripMutation_NamespacePrefixedAttributes) |
| 16 | AuthnReq Comment Injection | Exists | decode_redirect_security_test.go (TestVuln_Redirect_CommentInjection) |
| 17 | CDATA in Issuer | Implemented | security_novel_test.go |
| 18 | Unicode Normalization | Exists | internal/xmldsig/security_test.go (TestCrossRef_UnicodeNormalization) |
| 19 | Homoglyph SP ID | Implemented | security_novel_test.go |
| 20 | Multiple Issuer Elements | Implemented | security_novel_test.go |
| 21 | Zero-Width Chars | Implemented | security_novel_test.go |

### Creative (22-32)

| # | Name | Status | File |
|---|------|--------|------|
| 22 | Non-RSA Encryption Cert | Implemented | security_novel_test.go |
| 23 | Unsupported Encryption Algo | Exists | security_test.go (TestEncryption_UnknownAlgorithm) |
| 24 | CBC Padding Oracle | Exists | types/encrypted_assertion_security_test.go (TestPaddingOraclePracticalExploit) |
| 25 | GCM Nonce Reuse | Implemented | security_novel_test.go |
| 26 | XSW on IdP Response | Implemented | security_novel_test.go (TestSecurityNovel_XSWCloneAssertionModifyNameID) |
| 27 | XSW Both Sigs | Implemented | security_novel_test.go |
| 28 | Encrypted XSW | Implemented | security_novel_test.go |
| 29 | IDP Initiated Disabled | Exists | security_test.go (TestReplay_IDPInitiated_Disallowed) |
| 30 | InResponseTo Mismatch | Exists | security_test.go (TestReplay_InResponseToMismatch) |
| 31 | Replay Same ID | Exists | security_test.go (TestMemoryRequestTracker_DoubleConsume) |
| 32 | Time Skew Boundary | Exists | security_test.go (TestTemporal_ClockSkewBoundary) |

### More Interop (33-39)

| # | Name | Status | File |
|---|------|--------|------|
| 33 | Non-RFC3339 Timestamps | Implemented | security_novel_test.go |
| 34 | Future NotBefore | Exists | security_test.go (TestTemporal_NotYetValid) |
| 35 | Empty Conditions | Implemented | security_novel_test.go |
| 36 | AudienceRestriction Multi Match | Implemented | security_novel_test.go |
| 37 | Multiple Restrictions | Implemented | security_novel_test.go |
| 38 | etree vs encoding/xml NS | Implemented | security_novel_test.go |
| 39 | Double-Encoded Entity in Attribute | Implemented | security_novel_test.go |

### Misc (40-50)

| # | Name | Status | File |
|---|------|--------|------|
| 40 | Large Attributes Memory | Characterization | security_novel_test.go |
| 41 | Concurrent Signer Access | Implemented | security_novel_test.go |
| 42 | Zero/Large X509 Serial | Implemented | security_novel_test.go |
| 43 | PEM Extra Whitespace | Implemented | security_novel_test.go |
| 44 | Long ID Attr | Exists | internal/xmldsig/security_test.go (TestCrossRef_LongID) |
| 45 | Sig Reference URI Regex Bypass | Implemented | security_novel_test.go |
| 46 | BuildPOSTForm XSS RelayState | Exists | security_test.go (TestPostForm_XSSInRelayState) |
| 47 | BuildPOSTForm XSS ACS URL | Exists | security_test.go (TestPostForm_XSSInURL) |
| 48 | Empty Reference URI | Exists | internal/xmldsig/security_test.go (TestCrossRef_EmptyURI_ValidRoundTrip) |
| 49 | Chain Attack Metadata Poisoning | Application | security_novel_test.go |
| 50 | SignatureInputString Param Order | Exists | security_binding_test.go (TestSecurityBinding_Redirect_ParameterOrderManipulation) |

---

## Audit Notes

- Every row formerly marked **New** now has a corresponding test or substantially overlapping coverage; no named scenario remains a **Gap**.
- Category 6 case 26 is implemented in `sp/security_novel_test.go`, not `idp/security_extended_test.go` as originally planned.
- Category 6 case 50 is covered by the redirect parameter-order test in `sp/security_binding_test.go`. The separately numbered `TestSecurityNovel_SignedInfoAttributeReorder` exercises XML `SignedInfo` algorithm tampering, not HTTP-Redirect `SignatureInputString` ordering.
- Category 6 cases 39 and 42 were renamed to match what their tests actually exercise.

---

## Category 7: Algorithmic Complexity & Replay Hardening (25 tests)

Cases added while auditing pre-authentication CPU cost and replay bounds. Every
row is **Implemented**: each has a deterministic test, and each perf case was
verified to fail with its fix reverted rather than merely to pass.

### Pre-authentication CPU (1-8)

| # | Name | Status | File |
|---|------|--------|------|
| 1 | Quadratic attribute sort via comparator-time prefix resolution | Implemented | internal/xmldsig/attr_sort_complexity_test.go (TestSortAttrsIsNotQuadratic) |
| 2 | Fast/slow attribute comparators agree on ordering | Implemented | internal/xmldsig/attr_sort_complexity_test.go (TestSortAttrsMatchesSortedAttrs) |
| 3 | Decoy signatures skipped before canonicalization | Implemented | sp/preauth_hardening_test.go (TestPreAuthCanonicalizationIsBounded) |
| 4 | Parser prefix resolution independent of in-scope scope size | Implemented | internal/xmltree/ns_resolution_test.go (TestPrefixResolutionCostIndependentOfScopeSize) |
| 5 | Inclusive c14n enforces an element limit | Implemented | internal/xmldsig/canonicalize_limit_test.go (TestInclusiveC14NEnforcesElementLimit) |
| 6 | Element limit applies to every inclusive variant | Implemented | internal/xmldsig/canonicalize_limit_test.go (TestInclusiveC14NLimitAppliesToEveryVariant) |
| 7 | Inclusive c14n per-element cost independent of ancestor declarations | Implemented | internal/xmldsig/canonicalize_limit_test.go (TestInclusiveC14NPerElementCostIndependentOfAncestorDeclarations) |
| 8 | Encrypted-assertion guard fails closed on traversal limit | Implemented | sp/encrypted_assertion_guard_test.go |

### Namespace scope correctness (9-13)

Regression cover for the scope-sharing refactors that the cost fixes required.

| # | Name | Status | File |
|---|------|--------|------|
| 9 | Prefix shadowing restored for later siblings | Implemented | internal/xmltree/ns_resolution_test.go (TestNamespaceShadowingRestoredAfterElement) |
| 10 | Deep redeclaration chain unwinds correctly | Implemented | internal/xmltree/ns_resolution_test.go (TestNamespaceRedeclarationDeepChain) |
| 11 | Undeclared prefixes still rejected | Implemented | internal/xmltree/ns_resolution_test.go (TestUndeclaredPrefixStillRejected) |
| 12 | Reserved namespace rules still enforced | Implemented | internal/xmltree/ns_resolution_test.go (TestReservedNamespacesStillRejected) |
| 13 | Sibling subtrees do not leak c14n declarations | Implemented | internal/xmldsig/canonicalize_limit_test.go (TestInclusiveC14NSiblingScopeIsolation) |

### Signature requirements by binding (14-18)

| # | Name | Status | File |
|---|------|--------|------|
| 14 | AuthnRequest POST honours the signing requirement | Implemented | idp/post_signature_test.go (TestAuthnRequestPOSTRequiresSignature) |
| 15 | POST signature bound to message content | Implemented | idp/post_signature_test.go (TestAuthnRequestPOSTRejectsTamperedSignature) |
| 16 | LogoutRequest signed by default on both bindings | Implemented | idp/post_signature_test.go (TestLogoutRedirectRequiresSignatureByDefault, TestLogoutPOSTRequiresSignatureByDefault) |
| 17 | Expired / not-yet-valid SP certificate rejected on redirect | Implemented | idp/post_signature_test.go (TestRedirectRejectsExpiredSPCertificate, TestRedirectRejectsNotYetValidSPCertificate) |
| 18 | SigAlg bound to certificate key family | Implemented | idp/post_signature_test.go (TestRedirectRejectsKeyTypeMismatch) |

### Replay bounds (19-25)

| # | Name | Status | File |
|---|------|--------|------|
| 19 | IdP-initiated SSO requires an assertion replay cache | Implemented | sp/assertion_replay_test.go (TestIDPInitiatedRequiresReplayCache) |
| 20 | Unsolicited assertion accepted at most once | Implemented | sp/assertion_replay_test.go (TestIDPInitiatedAcceptedOnceWithCache) |
| 21 | OneTimeUse enforced rather than advisory | Implemented | sp/assertion_replay_test.go (TestOneTimeUseRejectedWhenNothingBoundsReuse, TestOneTimeUseHonouredWithCache) |
| 22 | InResponseTo correlated without a RequestTracker | Implemented | sp/assertion_replay_test.go (TestFabricatedInResponseToRejectedWithoutTracker, TestMismatchedInResponseToRejectedWithoutTracker) |
| 23 | Stale logout messages rejected on both sides | Implemented | sp/logout_freshness_test.go, idp/post_signature_test.go (TestIdPLogoutRequest*) |
| 24 | Example code does not bootstrap trust over cleartext HTTP | Implemented | examples_transport_test.go |
| 25 | LogoutResponse correlated to a pending LogoutRequest, consumed once | Implemented | sp/logout_response_correlation_test.go |

---

## Summary

| Category | Total | Exists | Implemented | Characterization | Application | Gap |
|----------|-------|--------|-------------|------------------|-------------|-----|
| 1. Signature Wrapping / Verification | 55 | 33 | 20 | 2 | 0 | 0 |
| 2. XML Parsing / Entity / Encoding | 55 | 8 | 33 | 14 | 0 | 0 |
| 3. Assertion / Condition Validation | 50 | 14 | 29 | 2 | 5 | 0 |
| 4. Encryption / Decryption | 50 | 14 | 36 | 0 | 0 | 0 |
| 5. Protocol / Binding | 50 | 20 | 19 | 3 | 8 | 0 |
| 6. Edge Cases & Novel Attacks | 50 | 15 | 30 | 2 | 3 | 0 |
| 7. Algorithmic Complexity & Replay Hardening | 25 | 0 | 25 | 0 | 0 | 0 |
| **Total** | **335** | **104** | **192** | **23** | **16** | **0** |
