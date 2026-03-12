# gosaml2 v2 Plan

This is a breaking-change release. The module path will become `github.com/russellhaering/gosaml2/v2`. Since we're already breaking the API, we should make all the breaking changes we want in one shot.

## Design Principles

1. **Secure by default.** Validations are errors, not warnings. SHA-1 off. IDP-initiated SSO off. Signatures required.
2. **Modern SaaS focus.** HTTP-POST + HTTP-Redirect bindings. No SOAP, no Artifact binding. These cover 99% of real-world IdP integrations.
3. **Opinionated but escapable.** Strong defaults with explicit opt-out fields for compatibility with quirky IdPs.
4. **No panics.** Every code path returns errors. Panics are bugs.
5. **Pluggable where it matters.** Interfaces for request tracking (replay prevention) and clock, not for things nobody swaps out.
6. **IdP-ready foundation.** Types, crypto, metadata parsing, and error handling are role-neutral. Adding an `IdentityProvider` struct later should require no changes to existing code.

---

## Phase 1: Security Fixes (Do First)

These are the changes that address known vulnerabilities and spec violations.

### 1.1 Assertion signature verification when Response is signed (#219)

**Problem:** When the Response envelope is signed, assertion signatures are skipped entirely. An attacker who can modify the response after signing (e.g., via an XML wrapping attack within the signed envelope) can tamper with assertion content.

**Fix:** Always verify assertion signatures when they are present, regardless of whether the Response is also signed. Add a `RequireAssertionSignature` field (default: `false` for backwards compat with IdPs that only sign the Response) that lets users require it.

### 1.2 Conditions and AudienceRestriction as errors, not warnings

**Problem:** `NotBefore`, `NotOnOrAfter`, and `AudienceRestriction` violations on the `<Conditions>` element are returned as warnings in `WarningInfo`. Callers must remember to check warnings or they silently accept expired/wrong-audience assertions.

**Fix:** These become hard errors. Remove `WarningInfo` entirely. `OneTimeUse` and `ProxyRestriction` become informational fields on `AssertionInfo` instead.

### 1.3 InResponseTo validation

**Problem:** `InResponseTo` is parsed but never validated. This is the #1 missing SAML spec requirement and enables unsolicited-response injection attacks.

**Fix:** Add a `RequestTracker` interface:

```go
type RequestTracker interface {
    // StoreRequest saves a request ID. Called when building an AuthnRequest.
    // The implementation should expire entries (recommended: 5 minutes).
    StoreRequest(ctx context.Context, requestID string) error
    // VerifyRequest checks that requestID was previously stored and removes it.
    // Returns ErrRequestNotTracked if not found.
    VerifyRequest(ctx context.Context, requestID string) error
}
```

When `RequestTracker` is set, `InResponseTo` is validated. When nil, IDP-initiated SSO is implicitly allowed (no `InResponseTo` check). This replaces the need for a separate `AllowIDPInitiated` flag — if you set a RequestTracker, you've opted into SP-initiated-only mode. Provide a `MemoryRequestTracker` implementation for simple deployments.

### 1.4 Fix CBC padding oracle / panic

**Problem:** `encrypted_assertion.go` has `lastGoodIndex := len(data) - int(padLength)` with no bounds check. Crafted ciphertext can cause a panic (negative slice index) or incorrect padding removal.

**Fix:** Bounds-check `padLength`. Return error if `padLength == 0 || int(padLength) > len(data)`. Also validate all padding bytes are consistent (PKCS#7 requires all padding bytes equal `padLength`).

### 1.5 Remove panics

**Problem:** `Signer()` panics on bad cert. `uuid.go` panics on `rand.Read` failure. `decryptAssertions` panics on element removal failure.

**Fix:** `Signer()` returns `(*dsig.Signer, error)`. Propagate errors everywhere. `uuid` can keep panicking on `rand.Read` failure (this is standard Go practice — `crypto/rand` failing means the system is broken).

### 1.6 Unsigned logout requests/responses silently accepted

**Problem:** When signature validation is enabled but a logout request/response has no signature, it's silently accepted with `signatureValidated = false`.

**Fix:** If `SkipSignatureValidation` is false, a missing signature is an error. The caller set `SignatureValidated` on the returned struct to communicate this, but nobody checks. Just reject.

---

## Phase 2: API Cleanup (Breaking Changes)

Since this is a v2 module, fix all the warts.

### 2.1 Restructure `SAMLServiceProvider`

The current struct has 22+ exported fields with no validation. Restructure into logical groups:

```go
type ServiceProvider struct {
    // Identity
    EntityID string // was ServiceProviderIssuer
    ACSURL   string // was AssertionConsumerServiceURL  
    SLOURL   string // was ServiceProviderSLOURL
    
    // IDP Configuration
    IDP IDPConfig
    
    // Security
    SPKey            *KeyStore      // signing + encryption (was SPKeyStore)
    SPSigningKey     *KeyStore      // signing only, overrides SPKey (was SPSigningKeyStore)
    IDPCertificates  []*x509.Certificate
    AllowSHA1        bool
    
    // Validation Behavior
    ClockSkew        time.Duration  // default: 30s
    RequestTracker   RequestTracker // nil = allow IDP-initiated SSO
    RequireAssertionSignature bool  // default: false
    
    // Request Building
    SignAuthnRequests  bool
    RequestedAuthnContext *RequestedAuthnContext
    ForceAuthn         bool
    IsPassive          bool
    NameIDFormat       string
    
    // Advanced
    Clock                      func() time.Time
    MaximumDecompressedBodySize int64
    SkipSignatureValidation     bool // escape hatch, not for production
}

type IDPConfig struct {
    EntityID    string // was IdentityProviderIssuer
    SSOURL      string // was IdentityProviderSSOURL
    SSOBinding  string // was IdentityProviderSSOBinding  
    SLOURL      string // was IdentityProviderSLOURL
    SLOBinding  string // was IdentityProviderSLOBinding
}
```

Drop the `ServiceProviderIssuer`-falls-back-to-`IdentityProviderIssuer` legacy behavior. Require `EntityID`.

### 2.2 Remove `WarningInfo`, strengthen `AssertionInfo`

Replace:
```go
type AssertionInfo struct {
    // ... current fields ...
    WarningInfo *WarningInfo
}
```

With:
```go
type AssertionInfo struct {
    NameID       string
    NameIDFormat string  // NEW (#54)
    Values       Values
    
    // Full assertion data
    Assertions           []types.Assertion
    ResponseSignatureValidated  bool
    AssertionSignatureValidated bool
    
    // Session management
    SessionIndex        string
    SessionNotOnOrAfter *time.Time
    AuthnInstant        *time.Time
    
    // Informational
    OneTimeUse       bool
    ProxyRestriction *ProxyRestriction
}
```

No more warnings — everything that was a warning is now either an error (conditions, audience) or a data field (OneTimeUse, ProxyRestriction).

### 2.3 Merge duplicate attributes (#241)

When multiple `AttributeStatement` entries contain the same attribute name, merge values into a single slice instead of overwriting.

### 2.4 Return full Response from validation (#235)

Change `RetrieveAssertionInfo` to return `(*AssertionInfo, *types.Response, error)` so callers have access to `InResponseTo`, status details, etc.

Actually — reconsider. If we have `RequestTracker` handling `InResponseTo`, callers don't need the raw Response for that. But there are other uses. Let's add a `ValidateAndRetrieve` that returns both, and keep `RetrieveAssertionInfo` returning just `*AssertionInfo` for the simple case.

### 2.5 Expose `Audiences` in unverified response (#253)

Add `Audiences []string` to `UnverifiedBaseResponse` for multi-IdP routing.

### 2.6 Error types cleanup

All errors get `Unwrap()` support. Use `%w` wrapping throughout. Define sentinel errors for common cases:

```go
var (
    ErrExpired           = errors.New("saml: assertion expired")
    ErrAudienceMismatch  = errors.New("saml: audience mismatch") 
    ErrBadRecipient      = errors.New("saml: recipient mismatch")
    ErrBadDestination    = errors.New("saml: destination mismatch")
    ErrBadIssuer         = errors.New("saml: issuer mismatch")
    ErrBadSignature      = errors.New("saml: signature verification failed")
    ErrMissingSignature  = errors.New("saml: required signature missing")
    ErrBadStatus         = errors.New("saml: response status not success")
    ErrReplay            = errors.New("saml: InResponseTo not recognized")
    ErrNotYetValid       = errors.New("saml: assertion not yet valid")
)
```

Callers can use `errors.Is()` for control flow.

### 2.7 Fix `ErrParsing.Error()` format bug

The format string references Tag and Value but the semantics are wrong. Fix it.

### 2.8 `context.Context` on public methods

Add `context.Context` as first parameter to `ValidateEncodedResponse`, `RetrieveAssertionInfo`, and other public entry points. This supports:
- Request-scoped timeouts
- Passing context to `RequestTracker`
- Future middleware integration

---

## Phase 3: Missing Spec Compliance

### 3.1 Clock skew tolerance (#57, #101, #225)

**Problem:** No configurable tolerance. Sub-millisecond comparison causes spurious failures.

**Fix:** `ClockSkew time.Duration` field on `ServiceProvider` (default: `30 * time.Second`). Applied to all time comparisons. Truncate times to millisecond precision per SAML spec §1.3.3.

### 3.2 Destination validation

**Problem:** Response `Destination` is checked only if present, but per spec it MUST be validated when present. Current code only checks against ACS URL, but the check itself is fine.

**Status:** Already implemented. Keep as-is.

### 3.3 Assertion Version check

Add check: `assertion.Version` must be `"2.0"`. Reject otherwise.

### 3.4 LogoutRequest.NotOnOrAfter validation

Check `NotOnOrAfter` on logout requests. Reject expired ones.

### 3.5 SessionNotOnOrAfter exposure (#96)

Already planned in AssertionInfo restructure (Phase 2.2). Expose `SessionNotOnOrAfter` and `AuthnInstant` so callers can enforce session lifetime.

### 3.6 SubjectConfirmationData.NotBefore check

If present, validate `current time >= NotBefore - ClockSkew`.

### 3.7 NameIDPolicy Format fix (#88)

Don't emit `Format=""` when no format is configured. Only include the `Format` attribute when `NameIDFormat` is explicitly set.

---

## Phase 4: Feature Additions

### 4.1 Proper HTTP-Redirect binding support (#89, #98)

**Problem:** Redirect binding doesn't include `SigAlg` and `Signature` query parameters. No exported function for redirect-binding AuthnRequest URLs.

**Fix:**
- `BuildAuthnRequestRedirectURL(relayState string) (string, error)` — proper redirect binding with query-string signature
- `BuildAuthnRequestPOSTForm(relayState string) (string, error)` — POST binding with auto-submit form
- Fix `BuildLogoutRequestRedirectURL` similarly
- Deprecate old `BuildAuthURL` / `BuildAuthBodyPost` names

### 4.2 SP Metadata generation (#51)

Clean up the existing `Metadata()` / `MetadataWithSLO()` mess:
- Single `Metadata() (string, error)` method
- Includes SLO endpoints if `SLOURL` is configured
- Includes signing/encryption key descriptors if keys are configured
- `AuthnRequestsSigned` reflects `SignAuthnRequests`
- Fix the `validityHours` bug (nanoseconds vs hours confusion)
- Add `MetadataValidDuration time.Duration` field (default: 7 days)

### 4.3 Metadata parsing

Add a shared `ParseEntityDescriptor` that parses SAML metadata XML into the existing `types.EntityDescriptor` struct, then role-specific convenience functions that extract the relevant bits:

```go
// Shared — parses any SAML EntityDescriptor
func ParseEntityDescriptor(xmlBytes []byte) (*types.EntityDescriptor, error)

// SP-side convenience — extracts IdP config + signing certs from IdP metadata
func IDPConfigFromMetadata(ed *types.EntityDescriptor) (*IDPConfig, []*x509.Certificate, error)
```

`IDPConfigFromMetadata` extracts: entity ID, SSO URL + binding preference, SLO URL + binding, signing certificates from `IDPSSODescriptor`.

This two-layer design keeps the door open for a future `IdentityProvider` struct that would use the same `ParseEntityDescriptor` with a mirror function:

```go
// Future IdP-side convenience
func SPConfigFromMetadata(ed *types.EntityDescriptor) (*SPConfig, []*x509.Certificate, error)
```

This is table-stakes for SaaS integration — every customer sends you their IdP metadata XML.

### 4.4 Certificate rotation support

`IDPCertificates` is already a slice, so multiple certs are supported. But add:
- Validation tries all certs, succeeds if any match (already works this way via `Verifier.TrustedCerts`)
- Document the rotation workflow: add new cert → wait → remove old cert

### 4.5 `MemoryRequestTracker` implementation

Simple in-memory implementation with TTL-based expiry:

```go
func NewMemoryRequestTracker(expiry time.Duration) *MemoryRequestTracker
```

Uses `sync.Map` + periodic cleanup. Good enough for single-instance deployments. Multi-instance deployments implement `RequestTracker` against Redis/DB.

### 4.6 Internal code deduplication

- Unify signature reordering into a single helper
- Unify HTML POST form templates into a single template
- Unify redirect URL building with signing
- Unify response/logout/request attribute validation

---

## Phase 5: Deprecation & Removal

### 5.1 Remove TripleDES support

3DES is deprecated (NIST SP 800-131A). Remove `MethodTripleDESCBC`. Any IdP still using 3DES in 2025 needs to upgrade.

### 5.2 Deprecate RSA PKCS#1 v1.5 key transport

Keep support but log a warning. RSA-OAEP should be preferred. Full removal in a future version.

### 5.3 Remove `SkipSignatureValidation` → rename to `InsecureSkipSignatureValidation`

Make the name scary. Keep it for development/debugging but make it clear this is not for production.

### 5.4 Remove deprecated `validateAssertionSignatures`

Already deprecated in the v2 branch. Remove the dead code.

### 5.5 Remove `SetSPKeyStore` / `SetSPSigningKeyStore` / `GetEncryptionKey` / `GetSigningKey`

Already removed in the v2 branch (fields are set directly). Confirm no vestiges remain.

---

## Non-Goals for v2

These are explicitly out of scope:

1. **HTTP-Artifact binding** — Requires back-channel SOAP. Very rare in SaaS.
2. **SOAP binding** — Same. Enterprise-only, complex, low demand (#202).
3. **IdP implementation** — Not in this release. But the architecture is designed so that an `IdentityProvider` struct can be added later as a peer to `ServiceProvider`, reusing shared types, crypto, metadata parsing, and error handling. The split: `ParseEntityDescriptor` is shared, role-specific config extraction is separate, and `ServiceProvider`/`IdentityProvider` are independent structs in the same package.
4. **HTTP middleware / session management** — Opinionated middleware belongs in a separate package (maybe `gosaml2/samlhttp` later). The core library should stay framework-agnostic.
5. **EncryptedID** — Extremely rare. EncryptedAssertion covers the common case.
6. **EntitiesDescriptor parsing** — Multi-entity metadata documents are an IdP federation concern.
7. **Metadata auto-refresh** — Application concern, not library concern.
8. **Certificate chain validation** — We pin to specific certs, not CA chains.

---

## Migration Path

Since this is a new major version (`v2` module path), both versions can coexist. The migration guide should cover:

1. Module path change: `gosaml2` → `gosaml2/v2`
2. Struct rename: field mapping table from old → new names
3. `WarningInfo` removal: what was a warning is now an error — callers must handle
4. `RequestTracker`: how to add replay prevention (or explicitly opt out)
5. `context.Context`: add `ctx` to call sites
6. Error handling: switch to `errors.Is()` with new sentinel errors

---

## Implementation Order

| Step | Phase | Description | Risk |
|------|-------|-------------|------|
| 1 | 2.1 | Restructure `SAMLServiceProvider` → `ServiceProvider` | High — touches everything |
| 2 | 1.4 | Fix CBC padding bounds check | Low |
| 3 | 1.5 | Remove panics from Signer() and decryptAssertions | Low |
| 4 | 1.2 | Conditions/Audience as errors, remove WarningInfo | Medium |
| 5 | 3.1 | Clock skew tolerance | Low |
| 6 | 2.2 | Restructure AssertionInfo | Medium |
| 7 | 2.6 | Error types cleanup + sentinels | Medium |
| 8 | 1.1 | Always verify assertion signatures when present | Medium |
| 9 | 1.3 | InResponseTo validation + RequestTracker | Medium |
| 10 | 1.6 | Reject unsigned logout when signatures required | Low |
| 11 | 3.3-3.7 | Remaining spec compliance fixes | Low |
| 12 | 4.1 | HTTP-Redirect binding fix | Medium |
| 13 | 4.2 | Metadata generation cleanup | Low |
| 14 | 4.3 | IdP metadata parsing | Medium |
| 15 | 4.4-4.5 | Request tracker impl, cert rotation docs | Low |
| 16 | 4.6 | Internal deduplication | Low |
| 17 | 5.x | Removals and deprecations | Low |
| 18 | 2.8 | context.Context on public methods | Medium — touches everything |
| 19 | — | Migration guide + examples | — |

---

## Open Questions

1. **Module path**: `github.com/russellhaering/gosaml2/v2` — confirm with maintainer.
2. **Minimum Go version**: Go 1.21 (current) or bump to 1.22+?
3. **`ServiceProvider` vs `SAMLServiceProvider`**: The `SAML` prefix is redundant in a SAML package. Drop it?
4. **Should `ValidateEncryptionCert` be configurable?** (#147) — Some IdPs embed certs in `EncryptedKey` that don't match. Currently this causes errors. Add a `SkipEncryptionCertValidation` flag?
