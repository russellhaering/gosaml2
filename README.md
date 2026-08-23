# gosaml2

[![Build Status](https://github.com/russellhaering/gosaml2/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/russellhaering/gosaml2/actions/workflows/test.yml?query=branch%3Amain)
[![GoDoc](https://pkg.go.dev/badge/github.com/russellhaering/gosaml2/v2)](https://pkg.go.dev/github.com/russellhaering/gosaml2/v2)

SAML 2.0 library for Go with both **Service Provider** and **Identity Provider** support. Built on a purpose-built strict XML parser and a vendored pure-Go XML digital signatures implementation — no general-purpose XML library is used to parse attacker-reachable input. See [SECURITY.md](SECURITY.md) for the parser's accepted profile and the vulnerability classes it eliminates.

## Features

- **Service Provider (SP)**: Validate SAML responses, build AuthnRequests, generate SP metadata, single logout
- **Identity Provider (IdP)**: Build SAML responses, validate AuthnRequests, generate IdP metadata, single logout
- **Secure defaults**: SHA-1 disabled, signatures required, IDP-initiated SSO off by default
- **Replay prevention**: `RequestTracker` interface with in-memory implementation for `InResponseTo` validation
- **Encryption**: AES-GCM and AES-CBC assertion encryption/decryption
- **HTTP bindings**: HTTP-POST and HTTP-Redirect with proper query-string signatures
- **Metadata parsing**: `ParseEntityDescriptor` for configuring SP or IdP from partner metadata XML
- **Comprehensive test suite**: hundreds of security tests covering strict XML parsing, signature validation, replay attacks, XML wrapping, and more

## Installation

```
go get github.com/russellhaering/gosaml2/v2
```

Requires Go 1.23 or later.

## Quick Start: Service Provider

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    saml2 "github.com/russellhaering/gosaml2/v2"
    "github.com/russellhaering/gosaml2/v2/sp"
    "github.com/russellhaering/gosaml2/v2/types"
)

func main() {
    // Parse your IdP's metadata XML to extract SSO URL and certificates.
    ed, err := saml2.ParseEntityDescriptor(idpMetadataXML)
    if err != nil {
        log.Fatal(err)
    }

    s := &sp.ServiceProvider{
        EntityID:    "https://my-app.example.com",
        ACSURL:      "https://my-app.example.com/saml/acs",
        AudienceURIs: []string{"https://my-app.example.com"},
        // Replay prevention (recommended).
        RequestTracker: sp.NewMemoryRequestTracker(5 * time.Minute),
    }
    // Configure IdP settings from metadata.
    if err := s.ConfigureFromMetadata(ed); err != nil {
        log.Fatal(err)
    }

    http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
        r.ParseForm()
        info, err := s.RetrieveAssertionInfo(context.Background(), r.FormValue("SAMLResponse"))
        if err != nil {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }
        fmt.Fprintf(w, "Hello, %s\n", info.NameID)
    })
}
```

## Quick Start: Identity Provider

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/russellhaering/gosaml2/v2/idp"
    "github.com/russellhaering/gosaml2/v2/types"
)

func main() {
    identity := &idp.IdentityProvider{
        EntityID:       "https://idp.example.com",
        SSOURL:         "https://idp.example.com/sso",
        SigningKeyStore: signingKey, // *saml2.KeyStore
        SignResponses:   true,
        SignAssertions:  true,
        ServiceProviders: map[string]*idp.SPConfig{
            "https://sp.example.com": {
                EntityID: "https://sp.example.com",
                ACSURLs:  []string{"https://sp.example.com/saml/acs"},
            },
        },
    }

    http.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
        reqInfo, err := identity.ValidateEncodedAuthnRequestPOST(context.Background(), r.FormValue("SAMLRequest"))
        if err != nil {
            http.Error(w, "Bad Request", http.StatusBadRequest)
            return
        }
        // Authenticate user, then build response...
        body, err := identity.BuildResponseBodyPost(reqInfo.SP.EntityID, &idp.AssertionParams{
            NameID:       "user@example.com",
            InResponseTo: reqInfo.ID,
            Recipient:    reqInfo.ACSURL,
        }, r.FormValue("RelayState"))
        if err != nil {
            http.Error(w, "Internal Error", http.StatusInternalServerError)
            return
        }
        w.Write(body)
    })
}
```

## Security Defaults

gosaml2 v2 is secure by default:

| Setting | Default | Override |
|---------|---------|----------|
| SHA-1 signatures | **Rejected** | `AllowSHA1: true` |
| Response/assertion signatures | **Required** | `InsecureSkipSignatureValidation: true` |
| IDP-initiated SSO | **Rejected** | `AllowIDPInitiated: true` (requires `AssertionReplayCache`) |
| Assertion replay | **Rejected** (with `AssertionReplayCache`) | `InsecureAllowIDPInitiatedReplay: true` |
| Unsigned logout requests (SP) | **Rejected** | `InsecureSkipSignatureValidation: true` |
| Unsigned logout requests (IdP) | **Rejected** | `SPConfig.AllowUnsignedLogoutRequests: true` |
| Conditions (NotBefore/NotOnOrAfter) | **Hard errors** | Not overridable |
| Audience restriction | **Required** (set `AudienceURIs`) | `InsecureSkipAudienceValidation: true` |
| Clock skew tolerance | **60 seconds** | `ClockSkew: duration` |

## Examples

- [SP example](examples/sp/demo.go) - Service Provider with Okta
- [IdP example](examples/idp/demo.go) - Identity Provider serving SAML responses

## Migration from v1

See [MIGRATING.md](MIGRATING.md) for a detailed guide on upgrading from gosaml2 v1.

## Tested Identity Providers

This library is meant to be a standards-compliant SAML implementation. The following identity providers have been tested:

- Okta
- Auth0
- Shibboleth
- OneLogin
- Azure Active Directory (Azure AD)
- Keycloak
- Google Workspace
- Microsoft ADFS

If you find a standards-compliant identity provider that doesn't work, please submit a bug or pull request.

## Documentation

- [GoDoc (pkg.go.dev)](https://pkg.go.dev/github.com/russellhaering/gosaml2/v2)
- [Migration Guide](MIGRATING.md)
- [Security Policy](SECURITY.md)

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
