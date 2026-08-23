# Security Policy

## Reporting a Vulnerability

Security vulnerabilities can be reported using GitHub's [private vulnerability reporting tool](https://github.com/russellhaering/gosaml2/security/advisories/new).

### Response Timeline

- **Acknowledgment**: Within 3 business days of report submission
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Dependent on severity and complexity

## Security Design Principles

gosaml2 v2 is designed with security as the primary concern:

- **Secure by default.** SHA-1 is rejected, signatures are required (including on LogoutRequests, over both bindings), IDP-initiated SSO is off, audience scoping and replay protection are required rather than optional where they are the only bound on misuse, and condition violations are hard errors. A security control whose configuration is absent fails closed rather than silently not running. Insecure behavior requires explicit opt-in via a named `Insecure*` or `Allow*` field.
- **Encrypted assertions require a signed response.** An `EncryptedAssertion` is decrypted only after the enclosing response's signature has been verified. A response that carries an encrypted assertion but no verified signature is rejected with `ErrUnsignedEncryptedAssertion` — the library never feeds attacker-reachable ciphertext to the decrypter. This eliminates the CBC padding-oracle (e.g. CVE-2021-29108) and XML-Signature-Wrapping-on-decrypted-content attack classes, and matches the strict behavior of SAML SPs such as PingFederate.
- **Certificate pinning, rotation-safe.** A certificate embedded in a signature's `KeyInfo` is never trusted on its own — it must exactly match one of the configured IdP certificates, and then only selects which pinned certificate to verify against. When a signature omits `KeyInfo`, each pinned certificate is tried in turn, so configuring both the outgoing and incoming certificate during IdP certificate rotation works regardless of whether the IdP embeds `KeyInfo`.
- **Purpose-built strict XML parser.** gosaml2 ships its own XML parser (`internal/xmltree`) and uses it for *all* XML ingestion — the standard library's `encoding/xml` is never used to parse attacker-reachable input, and neither is a general-purpose XML library. The parser accepts only the subset of XML that real SAML messages use and hard-rejects everything else: DOCTYPE declarations, entity declarations, processing instructions, comments, CDATA sections, byte-order marks, non-UTF-8 encodings, and any entity beyond the five predefined ones (plus numeric character references). It enforces namespace well-formedness, rejecting undeclared prefixes and attributes that collide after namespace resolution, and applies spec-correct attribute-value and line-ending normalization. This eliminates entire vulnerability classes at the door — XXE and entity-expansion (no DTD/entities), comment- and CDATA-splitting of values such as `NameID` (CVE-2017-11427 / CVE-2020-29509 class; both rejected outright), and the parser-differential attacks that arise when two different XML parsers disagree (there is now only one parser, used by every binding). Federation *metadata* — which is commonly hand-edited and annotated — is parsed under the same profile except that comments are tolerated and dropped. Hard limits on document size, nesting depth, node and attribute counts bound the shape of a document, and the code paths that walk it are kept linear in its size so those limits bound CPU as well: namespace resolution is indexed rather than scanned, canonicalization does not copy per-element state proportional to ancestor declarations, and both canonicalization algorithms share one element budget. Every rejection names the offending construct so misconfigured IdPs are debuggable.
- **No panics.** Every code path returns errors. A panic in this library is considered a bug.
- **Defense in depth.** Strict XML parsing, signature verification, condition enforcement, and InResponseTo tracking each provide independent layers of protection.

## Security Test Coverage

The test suite includes hundreds of security-focused tests across these categories:

- **Strict XML parsing**: Conformance and rejection tests for the bespoke parser, a real-world fixture corpus (responses, assertions, logout messages, and metadata harvested from other open-source SAML implementations), fuzzing with a serialization-fixpoint check, and a differential oracle against an independent XML parser
- **Signature validation**: Unsigned messages, invalid signatures, algorithm downgrade attacks
- **XML wrapping attacks**: Assertion injection, response manipulation
- **Replay prevention**: InResponseTo correlation against the signed `SubjectConfirmationData` (no tracker required), request-ID consumption via `RequestTracker`, assertion single-use via `AssertionReplayCache`, and an age bound on logout messages
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
- **Replay state is per-process by default**: `MemoryRequestTracker` and `MemoryAssertionReplayCache` are in-process only. A service provider running more than one instance must supply shared implementations of `RequestTracker` and `AssertionReplayCache`, or an attacker replays a captured response against a different instance. `AllowIDPInitiated` requires an `AssertionReplayCache` for this reason; `InsecureAllowIDPInitiatedReplay` disables the requirement and accepts replay.
- **Logout message single-use**: a `LogoutResponse` is correlated against a pending `LogoutRequest` and consumed once when a `RequestTracker` is configured, so it cannot complete a logout flow twice. Inbound `LogoutRequest` messages have no such identifier to consume and are bounded by age (`MaxIssueInstantAge`, default 5 minutes) and by `NotOnOrAfter` when present, which bounds but does not eliminate replay inside that window. As on the login path, the application stores the ID of each request it sends; the library generates but does not store them.
- **Metadata transport**: because metadata signatures are not verified, the certificates in a metadata document are trusted on the strength of the channel that delivered it. Fetch it over HTTPS with certificate verification, or load it from a local operator-controlled file.
- **IdP encryption configuration**: Because encrypted assertions require a signed response (see Security Design Principles), an IdP that encrypts assertions must also sign the *response* (not only the assertion). Configure the IdP accordingly: AD FS signs the response by default (`SamlResponseSignature = MessageOnly`); Microsoft Entra ID and OneLogin sign only the assertion by default, so select a "sign response" / "sign response and assertion" option when enabling token encryption. A response with an encrypted assertion but an unsigned envelope is rejected.
