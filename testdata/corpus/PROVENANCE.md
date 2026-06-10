# SAML XML Corpus

A corpus of real-world-shaped SAML documents (responses, assertions, logout
messages, AuthnRequests, metadata) harvested from the test suites of other
open-source SAML implementations. It exists to validate gosaml2's strict XML
parser profile: everything in the per-provider directories must parse; the
profile may not reject a feature these documents use.

Documents were normalized at import: base64-encoded fixtures were decoded and
DEFLATE-compressed fixtures inflated, so every file here is raw XML. Fixtures
whose names or contents marked them as XML-level attacks (XXE, comment/CDATA
node-splitting), as deliberately malformed, or as non-XML (HTML form output,
namespace-unbound fragments) were excluded or quarantined (see `_hostile/`).

## Sources

| Directory | Upstream | Commit | License |
|---|---|---|---|
| `ruby-saml/` | https://github.com/SAML-Toolkits/ruby-saml (`test/responses`, `test/metadata`, `test/logout_requests`) | 83fe3eec8a56 | MIT |
| `python3-saml/` | https://github.com/SAML-Toolkits/python3-saml (`tests/data/{responses,metadata,logout_requests,logout_responses}`) | 52d2ac8da3f3 | MIT |
| `node-saml/` | https://github.com/node-saml/node-saml (`test/static`) | 25c434a3ccad | MIT |
| `crewjam-saml/` | https://github.com/crewjam/saml (`testdata`, `samlsp/testdata`, `samlidp/testdata`, `xmlenc/testdata`) | 346540312f72 | BSD-2-Clause |

Files prefixed `invalid_` are *SAML-semantically* invalid upstream fixtures
(bad audience, expired, broken signature, ...). They are deliberately kept in
the legit corpus: they are well-formed XML of the shape IdPs produce, and the
parser must accept them — rejection happens at the validation layer, not the
parser.

## `_hostile/`

XML-level attack documents and deliberately malformed XML. The strict parser
is expected to REJECT (or safely neutralize) these; they seed the
expected-reject tests and the fuzz corpus:

- `ruby-saml_attackxee.xml` — XXE / DTD entity expansion
- `*_response_node_text_attack*.xml` — comment/CDATA text-node-splitting
  attacks against NameID extraction (CVE-2017-11427 class)
- `python3-saml_metadata_unparsed_metadata.xml` — malformed (mismatched tag)

## Feature survey findings (drives the parser profile)

Scan of the 302 legit documents (see `corpus_scan_test.go`):

- **Zero** DOCTYPE, `<!ENTITY`, CDATA, processing instructions, BOMs,
  non-UTF-8 encoding declarations, or named entities beyond the predefined
  five → all hard-rejected by the strict profile.
- **CRLF line endings in ~100 documents** → the parser must implement XML
  §2.11 line-ending normalization.
- **Comments appear only in metadata documents** (real TestShib federation
  metadata — hand-edited metadata commonly carries comments; machine-generated
  protocol messages never do) → protocol-message profile hard-rejects
  comments; the metadata entry point accepts and **drops** them (matching
  c14n-omit-comments semantics and eliminating comment-splitting attacks).
- Single-quoted attributes (incl. an ADFS-shaped response), `standalone`
  declarations, and numeric character references occur → must-support.
  (Numeric charrefs are also required because gosaml2's own canonical output
  escapes CR/TAB as `&#xD;`/`&#x9;`.)
