# Migrating from gosaml2 v1 to v2

This guide covers the breaking changes in gosaml2 v2 and how to update your code.

## Module Path

```
// v1
import "github.com/russellhaering/gosaml2"

// v2
import "github.com/russellhaering/gosaml2/v2"
```

Both versions can coexist in the same project during migration.

## Package Restructure

The SP logic moved from the root package into `sp/`, and a new `idp/` package was added:

```
// v1 - everything in the root package
sp := &saml2.SAMLServiceProvider{...}

// v2 - SP in sp/, shared types in root
import (
    saml2 "github.com/russellhaering/gosaml2/v2"
    "github.com/russellhaering/gosaml2/v2/sp"
    "github.com/russellhaering/gosaml2/v2/types"
)
s := &sp.ServiceProvider{...}
```

## Struct Rename: SAMLServiceProvider → sp.ServiceProvider

The main SP struct was renamed and its fields simplified:

| v1 Field | v2 Field | Notes |
|----------|----------|-------|
| `ServiceProviderIssuer` | `EntityID` | |
| `IdentityProviderIssuer` | `IDPEntityID` | |
| `IdentityProviderSSOURL` | `IDPSSOURL` | |
| `IdentityProviderSSOBinding` | `IDPSSOBinding` | |
| `IdentityProviderSLOURL` | `IDPSLOURL` | |
| `IdentityProviderSLOBinding` | `IDPSLOBinding` | |
| `AssertionConsumerServiceURL` | `ACSURL` | |
| `ServiceProviderSLOURL` | `SLOURL` | |
| `SPKeyStore` | `SPKeyStore` | Type changed to `*saml2.KeyStore` |
| `SPSigningKeyStore` | `SPSigningKeyStore` | Type changed to `*saml2.KeyStore` |
| `IDPCertificateStore` | `IDPCertificates` | Now `[]*x509.Certificate` directly |
| `SkipSignatureValidation` | `InsecureSkipSignatureValidation` | Renamed to discourage production use |
| `AudienceURI` | `AudienceURIs` | Now a `[]string` for multiple audiences |

## WarningInfo Removal

In v1, condition violations (expired assertions, audience mismatch) were returned as warnings in `WarningInfo`. Callers had to remember to check them.

In v2, these are hard errors. There is no `WarningInfo` struct.

```go
// v1 - easy to forget the warning check
info, err := sp.RetrieveAssertionInfo(encoded)
if err != nil {
    // handle error
}
if info.WarningInfo.NotInAudience {
    // easy to forget this!
}

// v2 - conditions are errors, no warnings to forget
info, err := sp.RetrieveAssertionInfo(ctx, encoded)
if err != nil {
    // audience mismatch, expiry, etc. are all errors now
}
```

The `OneTimeUse` and `ProxyRestriction` conditions are informational fields on `AssertionInfo` instead.

## Error Handling: Sentinel Errors + errors.Is()

v2 uses sentinel errors for programmatic error matching:

```go
import (
    "errors"
    saml2 "github.com/russellhaering/gosaml2/v2"
)

info, err := s.RetrieveAssertionInfo(ctx, encoded)
if errors.Is(err, saml2.ErrExpired) {
    // assertion expired
} else if errors.Is(err, saml2.ErrAudienceMismatch) {
    // wrong audience
} else if errors.Is(err, saml2.ErrReplay) {
    // InResponseTo not recognized
} else if err != nil {
    // other error
}
```

Available sentinel errors: `ErrExpired`, `ErrNotYetValid`, `ErrAudienceMismatch`, `ErrBadRecipient`, `ErrBadDestination`, `ErrBadIssuer`, `ErrBadSignature`, `ErrMissingSignature`, `ErrBadStatus`, `ErrReplay`, `ErrMissingAssertion`, `ErrMissingElement`, `ErrBadVersion`, `ErrMalformed`.

## context.Context on Public Methods

All validation and request-building methods now take `context.Context` as the first parameter:

```go
// v1
info, err := sp.RetrieveAssertionInfo(encoded)

// v2
info, err := s.RetrieveAssertionInfo(ctx, encoded)
```

## RequestTracker for Replay Prevention

v2 adds an optional `RequestTracker` interface for `InResponseTo` validation. When set, the SP validates that each response corresponds to a request it previously sent:

```go
s := &sp.ServiceProvider{
    // ...
    RequestTracker: sp.NewMemoryRequestTracker(5 * time.Minute),
}
```

When `RequestTracker` is set and `AllowIDPInitiated` is false (the default), responses without `InResponseTo` are rejected.

For single-instance deployments, use `sp.NewMemoryRequestTracker`. For multi-instance deployments, implement the `RequestTracker` interface against your session store (Redis, database, etc.).

## Security Defaults That Changed

| Behavior | v1 | v2 |
|----------|----|----|
| SHA-1 signatures | Accepted | Rejected (set `AllowSHA1: true` to allow) |
| Unsigned logout requests | Silently accepted | Rejected |
| Condition violations | Warnings | Hard errors |
| `SkipSignatureValidation` | Named simply | Renamed to `InsecureSkipSignatureValidation` |
| Assertion version check | Not checked | Must be "2.0" |
| `SubjectConfirmationData.NotBefore` | Not checked | Validated with clock skew |
| `LogoutRequest.NotOnOrAfter` | Not checked | Validated with clock skew |

## Metadata Configuration

v2 provides helpers to configure SP or IdP from partner metadata:

```go
// SP: configure from IdP metadata
ed, err := saml2.ParseEntityDescriptor(idpMetadataXML)
if err != nil {
    log.Fatal(err)
}
if err := s.ConfigureFromMetadata(ed); err != nil {
    log.Fatal(err)
}

// IdP: configure SP from its metadata
ed, err := saml2.ParseEntityDescriptor(spMetadataXML)
if err != nil {
    log.Fatal(err)
}
spConfig, err := idp.ConfigureFromSPMetadata(ed)
if err != nil {
    log.Fatal(err)
}
```

## Clock Skew

v2 adds a configurable `ClockSkew` field (default: 60 seconds) applied to all time comparisons:

```go
s := &sp.ServiceProvider{
    // ...
    ClockSkew: 30 * time.Second,
}
```

## 3DES Removal

TripleDES (3DES-CBC) encryption is no longer supported. If your IdP uses 3DES, it must be configured to use AES instead.
