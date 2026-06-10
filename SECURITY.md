# Security Policy

## Reporting a Vulnerability

Security vulnerabilities can be reported using GitHub's [private vulnerability reporting tool](https://github.com/russellhaering/gosaml2/security/advisories/new).

### Response Timeline

- **Acknowledgment**: Within 3 business days of report submission
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Dependent on severity and complexity

## Security Design Principles

gosaml2 v2 is designed with security as the primary concern:

- **Secure by default.** SHA-1 is rejected, signatures are required, IDP-initiated SSO is off, and condition violations are hard errors. Insecure behavior requires explicit opt-in.
- **Encrypted assertions require a signed response.** An `EncryptedAssertion` is decrypted only after the enclosing response's signature has been verified. A response that carries an encrypted assertion but no verified signature is rejected with `ErrUnsignedEncryptedAssertion` — the library never feeds attacker-reachable ciphertext to the decrypter. This eliminates the CBC padding-oracle (e.g. CVE-2021-29108) and XML-Signature-Wrapping-on-decrypted-content attack classes, and matches the strict behavior of SAML SPs such as PingFederate.
- **No panics.** Every code path returns errors. A panic in this library is considered a bug.
- **Defense in depth.** XML roundtrip validation (via xml-roundtrip-validator), signature verification, condition enforcement, and InResponseTo tracking each provide independent layers of protection.

## Security Test Coverage

The test suite includes 335 security-focused tests across these categories:

- **Signature validation**: Unsigned messages, invalid signatures, algorithm downgrade attacks
- **XML wrapping attacks**: Assertion injection, response manipulation
- **Replay prevention**: InResponseTo validation, request tracker enforcement
- **Time-based attacks**: Expired assertions, not-yet-valid assertions, clock skew handling
- **Encryption**: CBC padding validation, GCM authentication, short ciphertext rejection
- **Input validation**: Malformed XML, oversized payloads, invalid versions

## Known Limitations

The following security concerns are the application's responsibility:

- **RelayState validation**: The library passes RelayState through without validation. Applications must validate RelayState values to prevent open redirect attacks.
- **AuthnContextClassRef enforcement**: The library does not enforce the authentication context class returned by the IdP. Applications requiring specific authentication strengths (e.g. MFA) must check this themselves.
- **Metadata integrity**: The library parses metadata XML but does not verify metadata signatures. Applications should obtain IdP metadata through a trusted channel.
- **Session management**: The library provides `SessionNotOnOrAfter` and `SessionIndex` in assertion info, but session lifecycle management is the application's responsibility.
- **TLS**: All SAML endpoints should be served over HTTPS. This is the application's responsibility.
- **IdP encryption configuration**: Because encrypted assertions require a signed response (see Security Design Principles), an IdP that encrypts assertions must also sign the *response* (not only the assertion). Configure the IdP accordingly: AD FS signs the response by default (`SamlResponseSignature = MessageOnly`); Microsoft Entra ID and OneLogin sign only the assertion by default, so select a "sign response" / "sign response and assertion" option when enabling token encryption. A response with an encrypted assertion but an unsigned envelope is rejected.
