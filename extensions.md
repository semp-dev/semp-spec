## Abstract

This document specifies the Sealed Envelope Messaging Protocol
(SEMP) wire-level extension framework, the
`semp.dev/large-attachment` wire-level extension for
external-storage attachments with HKDF-derived per-attachment
keys, and the conformance requirements that an implementation
MUST satisfy to claim SEMP support. It defines the extension
entry structure and criticality signaling, per-layer size
constraints, the extension registry and namespacing convention,
the extension definition document format and signature
requirements, conflict detection and resolution, the extension
lifecycle from experimental to core, and the library
extension enforcement contract that enforces declared
extension permissions at runtime. It also catalogues conformance requirements for
servers, clients, and federation peers across the SEMP
specification series.

# Introduction

This document covers two related concerns of the SEMP
specification: extensibility and conformance.

The extension framework defines how SEMP evolves without
fragmenting. Wire-level extensions are namespaced entries in
per-layer `extensions` objects defined in
[Envelope](envelope.md), with criticality signaling, size
constraints, and a definition-document contract that pins each
extension to a signed, machine-readable specification.

The first registered wire-level extension,
`semp.dev/large-attachment`, replaces inline attachment bytes
with encrypted external blobs and a pointer carrying the URL,
ciphertext hash, and AEAD parameters. The encryption key for
each blob is derived deterministically from the enclosure key,
so any recipient who can decrypt the enclosure can also decrypt
the blob.

Conformance defines what it means for an implementation to
claim SEMP support: which features are mandatory, which are
optional, which interactions implementations MUST get right
across the specification series, and how implementations
declare and verify support.

The architectural role of extensibility is defined in
[Architecture](architecture.md). The envelope `extensions`
object structure is in [Envelope](envelope.md).

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

This document additionally uses terminology from [RFC 4949](https://www.rfc-editor.org/rfc/rfc4949)
for general security-protocol terms.

# Extension Framework

This section governs wire-level extensibility: per-envelope,
per-message, and per-record `extensions` objects carried inside
SEMP payloads. A wire-level extension is identified by a
namespaced key (for example `semp.dev/<name>`), carries a
`required` flag, and has a definition document resolvable by
identifier.

Optional core modules (account recovery, provider migration,
account closure, key transparency) are a separate concept. They
are full protocol modules that define their own wire types and
endpoints and do not use the wire-level extension framework
defined here.

## Extension Points

SEMP provides wire-level extension points at multiple layers,
each with different visibility and trust properties:

| Layer | Extension field | Visibility |
|---|---|---|
| Routing | `postmark.extensions` | All servers in transit. |
| Integrity | `seal.extensions` | All servers in transit. |
| Private metadata | `brief.extensions` | Recipient server and client only. |
| Content | `enclosure.extensions` | Recipient client only. |
| Discovery | `configuration.extensions` | Any querying server. |
| Handshake | `init.extensions` | Handshake participants. |
| Delivery | `block_entry.extensions` | Local server only (never transmitted). |

Extensions at public layers (`postmark.extensions`,
`seal.extensions`) are visible on the wire and MUST
be treated as public metadata. Extensions at private layers
(`brief.extensions`, `enclosure.extensions`) are protected by
the same encryption as their parent structure.

## Extension Entry Structure

Each entry in an `extensions` object is keyed by a namespaced
identifier and contains a structured value with a `required`
flag:

~~~ json
{
    "extensions": {
        "semp.dev/priority": {
            "required": false,
            "data": { "level": "urgent" }
        },
        "semp.dev/expiry": {
            "required": true,
            "data": { "delete_after": "2026-07-01T00:00:00Z" }
        }
    }
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `required` | boolean | Yes | Whether the recipient MUST understand this extension to process the envelope. |
| `data` | object | Yes | Extension-specific payload. Structure defined by the extension specification. |

## Namespacing

Extension keys MUST be namespaced to prevent collision. Three
namespaces are defined:

| Namespace pattern | Usage |
|---|---|
| `semp.dev/<name>` | Core extensions governed by the SEMP specification process. |
| `<vendor-host>/<name>` | Vendor-specific extensions. The domain MUST be controlled by the defining party. |
| `x-<name>` | Experimental extensions. No stability guarantees. MUST NOT be used in production deployments. |

Extension keys MUST NOT contain whitespace, path separators
beyond the single `/` after the namespace, or control
characters. Maximum key length is 128 UTF-8 bytes.

## Criticality Signaling

When `required` is `true`, the recipient MUST understand and
process the extension to handle the envelope correctly. A
recipient that encounters a required extension it does not
recognize MUST reject the envelope (or message, handshake step,
etc.) with reason code `extension_unsupported`. The rejection
MUST include the unrecognized extension key in the error
response.

When `required` is `false`, the recipient SHOULD process the
extension if it understands it and MUST ignore it silently if
it does not. An unrecognized optional extension MUST NOT cause
rejection.

Because required extensions at public layers (`postmark`,
`seal`) can cause rejection by any server in the routing path,
senders SHOULD use `required: true` at these layers only when
the extension has achieved broad adoption. Premature use of
required public-layer extensions will cause delivery failures
through intermediate servers that have not yet implemented the
extension.

To avoid delivery failures from required extensions, senders
SHOULD verify that the recipient supports the extension before
sending. Extension support is advertised through:

* server-level extension support in the `extensions` field of
  the configuration document and the `extensions` array in
  per-address discovery results;
* session-level extension support in the
  `capabilities.extensions` array in the handshake init and
  response messages.

A sender that marks an extension as `required: true` without
confirming recipient support through capability negotiation
accepts the risk of rejection.

## Size Constraints

Extensions are included in the signed canonical form of the
envelope and are parsed by every entity that processes the
containing layer. Unbounded extension payloads create both a
computational burden and an abuse vector through resource
exhaustion.

The following size limits apply to the serialized JSON byte
length of each `extensions` object (the entire object,
including all keys and values):

| Layer | Maximum size | Rationale |
|---|---|---|
| `postmark.extensions` | 4 KB | Parsed by every home server. Must be minimal. |
| `seal.extensions` | 4 KB | Parsed by every home server. Must be minimal. |
| `brief.extensions` | 16 KB | Parsed by recipient server and client only. |
| `enclosure.extensions` | 64 KB | Parsed by recipient client only. Largest scope. |

Servers MUST reject envelopes where any `extensions` object
exceeds the size limit for its layer. The rejection reason
code is `extension_size_exceeded`.

Servers MAY enforce stricter limits than those defined above
as a matter of local policy. Servers MUST NOT enforce limits
below the values above.

Extension size limits are independent of the overall envelope
size limit advertised in discovery (`max_envelope_size`). An
envelope may be within the overall size limit but still be
rejected if an individual `extensions` object exceeds its
layer limit.

## Extension Registry

The extension registry is the authoritative list of all
defined SEMP extensions. It prevents namespace collisions for
`semp.dev/` extensions, provides a single reference for
implementers, and tracks the lifecycle status of each
extension.

Each registry entry contains:

| Field | Description |
|---|---|
| Identifier | Namespaced key (for example `semp.dev/large-attachment`). |
| Status | Current lifecycle status (see [Lifecycle](#lifecycle)). |
| Layer(s) | Which extension points the extension occupies. |
| Required-capable | Whether the extension may be marked `required: true`. |
| Specification | Reference to the defining document. |
| Implementations | Count and identity of independent implementations. |
| Introduced | Protocol version in which the extension was first registered. |
| Deprecated | Protocol version in which the extension was deprecated, if applicable. |

Vendor-specific extensions (`<vendor-host>/<name>`) do not
require registry approval. The defining party is responsible
for ensuring their extensions do not conflict with `semp.dev/`
extensions. Vendor extensions MUST NOT use the `semp.dev/`
namespace.

Vendor extensions that achieve broad adoption MAY be submitted
to the registry for consideration as core extensions under a
`semp.dev/` identifier.

## Extension Definition Documents

The wire-level extension entry carries only an identifier, a
`required` flag, and a `data` payload. The interpretation of
that payload, the layers the extension may occupy, the
dependencies it requires, and the permissions it claims are
defined in a separate definition document fetched by
identifier.

### Canonical URL Derivation

Every extension identifier MUST resolve to a fetchable
definition document at a derivable URL under the
`.well-known/semp-extensions/` path [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615):

| Identifier | Definition URL |
|---|---|
| `semp.dev/<name>` | `https://semp.dev/.well-known/semp-extensions/<name>.json` |
| `<vendor-host>/<name>` | `https://<vendor-host>/.well-known/semp-extensions/<name>.json` |
| `x-<name>` | No derivation rule. Experimental extensions are not subject to definition document requirements. |

Implementations MUST be able to derive the definition URL
from the identifier without out-of-band configuration. A
vendor publishing an extension under their own namespace
MUST serve the definition document at the derived URL over
HTTPS.

### Definition Document Schema

~~~ json
{
    "identifier": "vendor.example.com/example-extension",
    "spec_version": "1.0.0",
    "status": "standard",
    "specification_uri":
        "https://vendor.example.com/extensions/example.html",
    "placement": {
        "allowed_layers": ["brief", "enclosure"],
        "required_layer": "brief"
    },
    "data_schema":
        "https://vendor.example.com/extensions/example/schema.json",
    "authority": {
        "produced_by": ["sender_client", "recipient_client"],
        "consumed_by": ["recipient_client"]
    },
    "permissions": {
        "reads": ["brief.message_id", "brief.thread_id"],
        "writes":
            ["brief.extensions.vendor.example.com/example"],
        "triggers": ["example_event"]
    },
    "hooks": ["on_compose", "on_decrypt", "on_display"],
    "dependencies": [],
    "conflicts_with": [],
    "test_vectors":
        "https://vendor.example.com/extensions/example/vectors.json",
    "reference_implementations": [
        {
            "name": "example-impl",
            "uri": "https://vendor.example.com/example-impl",
            "module": "extensions/example-extension"
        }
    ],
    "introduced": "1.0.0",
    "deprecated": null,
    "signature": {
        "algorithm": "ed25519",
        "key_id": "vendor.example.com-domain-key-fingerprint",
        "value": "base64-signature-over-canonical-document"
    }
}
~~~

Field meanings:

| Field | Required | Description |
|---|---|---|
| `identifier` | Yes | The namespaced extension identifier. MUST match the URL the document is served from. |
| `spec_version` | Yes | Semantic version of this definition document. Breaking changes require a new identifier. |
| `status` | Yes | Lifecycle status (see [Lifecycle](#lifecycle)). |
| `specification_uri` | Yes | URL of the human-readable specification document. |
| `placement` | Yes | Where this extension may appear. |
| `data_schema` | Yes | URL of a JSON Schema document describing the structure of the `data` field. |
| `authority` | Yes | Which parties may produce and consume this extension. |
| `permissions` | Yes | Declared read, write, and trigger scope. |
| `hooks` | Yes | Processing points at which this extension participates. |
| `dependencies` | Yes | Other extension identifiers required for this extension. MAY be empty. |
| `conflicts_with` | Yes | Other extension identifiers that cannot coexist with this one. MAY be empty. |
| `introduced` | Yes | SEMP protocol version in which this extension was first registered. |
| `deprecated` | Yes | SEMP protocol version in which this extension was deprecated, or null. |
| `signature` | Yes | Signature over the canonical form of the document. |

### Placement Object

| Field | Description |
|---|---|
| `allowed_layers` | Layers in which this extension MAY appear. Subset of: `postmark`, `seal`, `brief`, `enclosure`, `configuration`, `handshake`, `delivery`. |
| `required_layer` | Layer in which this extension MUST appear when present at all, or `null` if any allowed layer is acceptable. |

An extension entry that appears in a layer not listed in
`allowed_layers` MUST be treated as `extension_unsupported`
regardless of `required` flag state.

### Authority Object

| Field | Description |
|---|---|
| `produced_by` | Roles that may add this extension to an envelope. Subset of: `sender_client`, `sender_server`, `recipient_server`, `recipient_client`. |
| `consumed_by` | Roles that act on this extension. Same vocabulary as `produced_by`. |

A receiver MUST verify that the producing party of an
extension matches its declared `produced_by` roles. An
extension whose authority is `sender_client` but appears
injected by a `recipient_server` MUST be rejected with
`extension_unsupported` and SHOULD be reported as
`protocol_abuse`.

### Permissions Object

| Field | Description |
|---|---|
| `reads` | Field paths the extension reads. MAY be empty. |
| `writes` | Field paths the extension writes. MUST include only paths under the extension's own entry, except for extensions that explicitly modify protocol-managed fields with prior governance approval. |
| `triggers` | Application or protocol events the extension may emit. |

Permissions are declared in JSON path notation rooted at the
envelope (`brief.message_id`, `enclosure.body`, etc.). The
SEMP library enforces these declarations at runtime.

### Hooks

| Hook | When invoked |
|---|---|
| `on_compose` | Before envelope encryption, on the sender client. |
| `on_seal` | After envelope encryption, before signature, on the sending server. |
| `on_route` | At each home server, on the public envelope layers only. |
| `on_deliver` | At the recipient server, after seal verification. |
| `on_decrypt` | At the recipient client, after enclosure decryption. |
| `on_display` | At the recipient client, before user-visible rendering. |
| `on_capability_negotiate` | During handshake capability advertisement. |

Future hooks MAY be defined by future SEMP protocol versions.
Extensions MUST NOT declare hooks that are not recognized by
the SEMP version they target.

### Signature Requirement

The definition document MUST be signed by the namespace
owner's domain signing key. The signature covers the canonical
JSON form of the document with the `signature` field excluded.
The signature serves to pin the document to a specific
version, preventing silent rewrites of an extension's
contract, and to anchor trust in the extension to the same
domain identity that anchors SEMP routing.

An implementation that fetches a definition document MUST
verify the signature against the namespace owner's published
domain key before treating the document as authoritative. A
definition document with an invalid, missing, or unverifiable
signature MUST be treated as if the extension had no
definition.

### Resolution and Caching

Implementations resolve extension definitions by fetching the
derived URL the first time an unknown identifier is
encountered. Definition documents SHOULD be cached locally,
with cache TTLs honored from HTTP `Cache-Control` headers. In
the absence of an explicit TTL, implementations SHOULD cache
for at least 24 hours.

A definition document MAY be re-fetched on demand if an
implementation observes behavior that contradicts the cached
definition; the new document MUST be signature-verified
before replacing the cached copy.

<a id="conflict-detection"></a>

## Conflict Detection
Conflicts between extensions fall into three categories with
distinct detection mechanisms:

| Category | Definition | Detection |
|---|---|---|
| Structural | Two extensions with overlapping declared permissions or incompatible declared placement. | Static (registry) and runtime. |
| Declared | Two extensions that declare each other in `conflicts_with`. | Runtime, on capability negotiation. |
| Behavioral | Two extensions with semantically incompatible behavior not visible from declarations. | Governance and observation. |

### Structural Conflict Detection

Structural conflicts are detectable mechanically from
definition documents. The registry MUST run a structural
conflict checker at submission time that compares the new
definition against all `standard` and `core` extensions for:

1. Identifier collision within the same namespace.
2. `permissions.writes` paths overlapping with another
   extension's writes, excluding writes scoped under the
   extension's own identifier.
3. `placement.required_layer` collisions for extensions that
   share an identifier prefix or claim mutually exclusive
   layer ownership.
4. Hook ordering inconsistencies for extensions that target
   the same hook with declared assumptions about state
   visibility.

Structural conflicts identified at submission MUST block
registry acceptance until the conflict is resolved by either
deprecation of an existing extension (per the
one-solution-per-problem rule, [Anti-Fragmentation Rules](#anti-fragmentation-rules))
or revision of the new submission.

Implementations MUST also enforce structural conflict
detection at runtime. An envelope containing two extensions
whose declared write paths overlap MUST be rejected with
`extension_unsupported`.

### Declared Conflicts

When an extension declares another in `conflicts_with`, the
declaration MUST be symmetric. Both extensions MUST list each
other. The registry MUST reject submissions with asymmetric
conflict declarations.

At runtime, an implementation that processes an envelope
containing both sides of a declared conflict pair MUST reject
the envelope with `extension_unsupported`. The rejection
MUST identify both conflicting extension identifiers in the
error response.

### Behavioral Conflicts

Behavioral conflicts are not detectable from declarations.
Two extensions may have non-overlapping permissions and
unrelated placement, yet produce semantically incompatible
results when combined. These conflicts surface through
implementation testing, deployment incidents, or
user-observable disagreement.

When a behavioral conflict is identified, the resolution
path is governance-driven:

1. The conflict is documented in both extensions'
   specifications via the `conflicts_with` field, made
   symmetric per the declared-conflicts rule above.
2. The next `spec_version` of each affected extension
   publishes the updated `conflicts_with` list.
3. Implementations re-fetch the updated definitions and
   apply the new declared conflict at runtime.

Behavioral conflicts that affect the security or correctness
of envelope processing SHOULD be reported as
`protocol_abuse` observations
([Delivery](delivery.md)) when an implementation can
demonstrate the conflict in production.

<a id="validation"></a>

## Validation
Validation occurs at two distinct surfaces: static
validation of definition documents (registry-side), and
runtime validation of extension entries (per-envelope).

### Static Validation

Every definition document MUST be validated at registry
submission and MAY be re-validated by any party fetching the
document. Static validation checks:

1. JSON Schema conformance against the canonical definition
   document schema.
2. Signature verification against the namespace owner's
   domain signing key.
3. Identifier consistency: the `identifier` field MUST match
   the URL the document is served from.
4. Internal consistency:
   - Every entry in `dependencies` MUST be a valid extension
     identifier resolvable to its own definition document.
   - Every entry in `conflicts_with` MUST be symmetric.
   - Every layer in `placement.allowed_layers` MUST be a
     defined SEMP extension layer.
   - Every hook in `hooks` MUST be a recognized hook name.
5. Cross-extension consistency: structural conflict checks
   against the registry per [Conflict Detection](#conflict-detection).

A definition document that fails any static validation check
MUST NOT be accepted into the registry. Implementations that
fetch a non-conformant document MUST treat the extension as
undefined.

### Runtime Validation

Implementations MUST validate every received extension entry
against its definition document before processing. Runtime
validation checks:

1. The `data` field conforms to the extension's
   `data_schema`.
2. The entry appears in a layer listed in
   `placement.allowed_layers`.
3. The producing party (inferred from envelope context) is
   listed in `authority.produced_by`.
4. All entries in `dependencies` are also present in the
   envelope or have been advertised in capability
   negotiation.
5. No entry from `conflicts_with` is present in the
   envelope.

Any runtime validation failure MUST result in
`extension_unsupported` rejection. The rejection MUST
identify which validation rule failed and which extension
identifier was rejected.

### Validation Failures

Validation failures are reported via the existing
`extension_unsupported` reason code with an `errors` array,
one entry per failing extension:

~~~ json
{
    "reason_code": "extension_unsupported",
    "reason": "Extension validation failed",
    "errors": [
        {
            "extension": "vendor.example.com/feature1",
            "validation_failure": "data_schema_mismatch"
        },
        {
            "extension": "vendor.example.com/feature2",
            "validation_failure": "placement_violation"
        }
    ]
}
~~~

Each entry carries the failing `extension` identifier and a
`validation_failure` diagnostic. The array form lets a
single rejection report multiple distinct failures in the
same envelope; implementations MAY stop validation at the
first failure and report a single-entry array, or continue
and report all failures.

The `validation_failure` field is informational and aids
debugging. Its defined values are:

| Value | Meaning |
|---|---|
| `definition_unfetchable` | The definition document could not be fetched. |
| `definition_signature_invalid` | Signature on the definition document is invalid. |
| `data_schema_mismatch` | The `data` field does not conform to `data_schema`. |
| `placement_violation` | The extension appeared in a layer not in `allowed_layers`. |
| `authority_violation` | The producing party is not in `authority.produced_by`. |
| `dependency_unsatisfied` | A required dependency is not present or not advertised. |
| `conflict_present` | A declared conflict is present in the envelope. |

<a id="lifecycle"></a>

## Lifecycle
### Status Definitions

The extension lifecycle has six statuses:

| Status | Meaning |
|---|---|
| `experimental` | Defined by any party. No stability guarantees. May change or be withdrawn without notice. MUST NOT be used in production. |
| `proposed` | Formally submitted to the registry. Under review. Specification is public and stable enough for trial implementation. |
| `standard` | Accepted into the registry as `semp.dev/<name>`. Implementations SHOULD support it. Specification is stable. Breaking changes require a new extension identifier. |
| `core` | Promoted into the core protocol specification in a major version. Implementations MUST support it. No longer optional. |
| `deprecated` | Superseded or found unsuitable. Implementations SHOULD phase out support. New deployments MUST NOT depend on it. |
| `retired` | Removed from the registry. Implementations MUST ignore it if encountered. The identifier MUST NOT be reused. |

### Status Transitions

~~~
experimental -> proposed -> standard -> core
                                     \
                              deprecated -> retired
~~~

An extension MAY move directly from `experimental` to
`deprecated` if it is found unsuitable during
experimentation. An extension MUST NOT skip from
`experimental` directly to `standard`; the `proposed` stage
ensures public review.

An extension in `core` status MUST NOT be deprecated without
a major protocol version change.

### Promotion to Core

When a new major version of the SEMP protocol is defined,
extensions that have achieved universal adoption are
candidates for promotion to `core`. Promotion means the
extension's semantics are incorporated into the relevant
core specification ([Envelope](envelope.md),
[Handshake](handshake.md), and so on) and compliance
with the extension becomes mandatory.

Promotion criteria:

* The extension MUST be in `standard` status.
* The extension MUST have at least three independent
  implementations in production use.
* The extension MUST have been in `standard` status for at
  least one year.
* There MUST be rough consensus among implementers that the
  extension belongs in the core.

Promotion is the mechanism by which SEMP's core grows over
time.

When an extension is promoted to `core`, its wire-format
identifier MUST drop the namespace prefix. The functionality
becomes a defined part of the core wire format under its own
unprefixed field name in the appropriate core specification
([Envelope](envelope.md), [Handshake](handshake.md),
and so on). Implementations MUST handle the core form, not
the prefixed extension form, once a major protocol version
has promoted the extension. The prefixed form MAY remain
accepted during a transition window defined by the
specification revision that performs the promotion.

### Vendor Extensions Are Not Eligible for Standardization

Extensions under the `vendor.<host>/` namespace MUST NOT
enter the `proposed` or `standard` lifecycle status. The
`semp.dev/` namespace is the standardization signal: an
extension that is being considered for standardization MUST
already be republished under `semp.dev/` and MUST be
governed by the registry's standardization process. A
vendor that wishes to propose their extension for
standardization MUST submit a `semp.dev/`-namespaced
version of it, at which point the one-solution-per-problem
and implementation-requirement rules in
[Anti-Fragmentation Rules](#anti-fragmentation-rules) apply.

### Deprecation

Deprecation is announced via the `deprecated` field in the
definition document, set to the SEMP protocol version in
which the extension is deprecated. Implementations MUST
continue to handle deprecated extensions for at least one
year after deprecation announcement.

<a id="anti-fragmentation-rules"></a>

## Anti-Fragmentation Rules
### One Solution Per Problem

The registry MUST NOT accept a new `semp.dev/` extension
that addresses the same problem as an existing `standard`
or `core` extension unless the existing extension is
formally deprecated as part of the same proposal. Competing
solutions to the same problem cause ecosystem fragmentation
and interoperability failures.

If a proposed extension offers a better approach to a
problem already addressed by an existing extension, the
proposal MUST include a deprecation plan for the existing
extension and a migration path for implementations that
already support it.

Vendor extensions are exempt from this rule. Vendors MAY
experiment freely in their own namespace. If a vendor
extension is submitted for registry inclusion as a
`semp.dev/` extension, the one-solution-per-problem rule
applies at that point.

### Implementation Requirement

No extension MAY advance from `proposed` to `standard`
without at least two independent implementations that
interoperate successfully. An independent implementation
means developed by different parties without shared
codebases. This rule prevents paper extensions that no one
builds.

### Standard Extension Cap

The registry SHOULD maintain no more than twenty extensions
in `standard` status at any given time. This cap forces
prioritization: promoting a new extension to `standard`
when the cap is reached requires either promoting an
existing standard extension to `core` or deprecating one.

The cap is a governance guideline rather than a hard
protocol constraint. Exceeding it requires explicit
justification and consensus among the governing body. The
intent is to create convergence pressure: a bounded set of
well-supported extensions rather than an unbounded
constellation of optional features.

### Thick Core Principle

The core specification covers encryption, metadata
protection, blocking, reputation, delivery semantics, key
management, and session security. These are part of the
core protocol, not extensions.

Extensions MUST NOT be used to defer core functionality that
all conformant implementations require. Two conformant SEMP
implementations MUST be able to exchange sealed envelopes
with full security properties without negotiating any
extension.

Extensions exist for capabilities that are genuinely
optional, where reasonable deployments may differ in their
needs.

<a id="library-extension-enforcement"></a>

# Library Extension Enforcement
The SEMP library implementation enforces declared extension
contracts at runtime. The enforcement contract below is a
normative requirement on every SEMP library that loads
extension code, regardless of whether the library is
distributed as a reference implementation, embedded in a
client or server, or built as a vendor's own runtime.

A conformant SEMP library MUST:

1. Resolve extension definition documents from their
   identifiers, verify their signatures against the namespace
   owner's domain key, and cache the verified document.
2. Enforce per-extension `placement.allowed_layers` and
   `placement.required_layer` constraints. Reject envelopes
   that place an extension at a layer the definition does not
   allow.
3. Enforce per-extension `authority.produced_by` constraints.
   Reject envelopes whose extension entries appear at a layer
   that the producing role is not authorized to write to.
4. Enforce per-extension `permissions.writes` constraints.
   Reject envelopes whose extension data fields write outside
   the declared write scope.
5. Validate the `data` payload against the
   `data_schema`-referenced JSON Schema before invoking the
   extension's hooks.
6. Invoke extension hooks at the declared lifecycle points
   (`on_compose`, `on_seal`, `on_route`, `on_deliver`,
   `on_decrypt`, `on_display`, `on_capability_negotiate`) and
   not at other points.
7. Reject extensions whose `dependencies` list names
   extensions the implementation does not support, or whose
   `conflicts_with` list names extensions present in the same
   envelope.

There is no separate SDK artifact in SEMP. The library IS
the implementation surface that loads extensions and
enforces their declared contracts. The contract above is
normative for any library that loads extension code,
whether the library is a vendor's own implementation, a
reference implementation distributed by the SEMP project,
or any other.

## Enforcement Layers

SEMP defines four enforcement layers. Implementations choose
the layer appropriate to their threat model:

| Layer | Mechanism | Status |
|---|---|---|
| Wire-level validation | Cryptographic and schema checks defined in [Validation](#validation). | MUST for all conformant implementations. |
| Library-level enforcement | Permission and hook mediation in the SEMP library process. See [Library Extension Enforcement](#library-extension-enforcement). | RECOMMENDED. Strongly RECOMMENDED for `semp.dev/*` extensions handling sensitive data. |
| Cryptographic key scoping | Per-extension enclosure key wrapping. See [Envelope](envelope.md). | OPTIONAL. Available for read-scope isolation of high-stakes extensions. |
| Sandbox attestation | WASM or TEE isolation. Future extension layer. | OPTIONAL. |

For extensions whose `data` field in the enclosure must be
readable by some devices but not others (for example, a
classification result intended for a filter device but not
for the user's main reading device), SEMP supports
per-extension key wrapping in the seal. The wire format and
key derivation are defined in [Envelope](envelope.md).
A conformant SEMP library MUST surface per-extension key
scoping as a first-class option for extension authors.

<a id="trust-model"></a>

# Trust Model
The SEMP extension framework concentrates trust at specific
points rather than attempting to eliminate it. Implementers,
operators, and users benefit from understanding what each
layer does and does not guarantee.

## What Is Enforced

The following properties are enforced by the protocol or by
any conformant implementation:

| Property | Enforced By |
|---|---|
| Identifier uniqueness within a namespace | Namespace ownership (DNS/HTTPS for vendors, governance for `semp.dev/*`). |
| Definition document authenticity | Domain key signature on the definition document. |
| Wire-level structure of `data` | Runtime validation against `data_schema` ([Validation](#validation)). |
| Layer placement | Runtime validation against `placement.allowed_layers`. |
| Producing party | Runtime validation against `authority.produced_by`. |
| Dependency presence | Capability negotiation and runtime validation. |
| Declared conflict absence | Capability negotiation and runtime validation. |
| Read scope (when cryptographic key scoping is used) | Cryptographic key wrapping ([Envelope](envelope.md)). |

## What Is Not Enforced

The following properties are not enforced by the wire
protocol. They are assumed to hold based on implementation
honesty, observable behavior, and abuse reporting:

| Property | Trust Basis |
|---|---|
| Internal data flow within an implementation | SEMP library enforcement, implementer audit, operator attestation. |
| Side effects (logging, persistence, exfiltration) | Operator policy, regulatory frameworks, observable misbehavior. |
| Hook discipline (running code only at declared hooks) | SEMP library enforcement, code audit. |
| Behavioral correctness beyond test vectors | Test coverage, governance review, deployment experience. |

## Detection and Reporting

When an implementation behaves inconsistently with its
declared extension support (for example, misses a hook,
mishandles `data`, leaks scoped content), the misbehavior
is detectable through one or more of:

1. Test vector failure: any party can run published test
   vectors against the implementation's responses.
2. Observable inconsistency: peer implementations and users
   can observe outcomes that contradict the declared
   behavior.
3. Cryptographic violation: any wire-level violation
   (signature failure, layer placement, authority mismatch)
   is provable from the captured envelope alone.

Detected misbehavior SHOULD be reported via
`SEMP_ABUSE_REPORT` under the `protocol_abuse` category
([Delivery](delivery.md)). Reports MAY include the
captured envelope or test vector output as
self-authenticating evidence. Patterns of misbehavior
across multiple unrelated sessions MAY result in trust
gossip observations against the implementation's operator.

Users and operators who require stronger guarantees than
the protocol provides SHOULD adopt one of the optional
enforcement layers (cryptographic key scoping, WASM
sandboxing, or TEE attestation) appropriate to their
threat model.

<a id="large-attachment"></a>

# Large-Attachment Extension
The `semp.dev/large-attachment` wire-level extension allows
attachments whose content is stored externally to the
envelope. The extension replaces inline attachment bytes with
encrypted external blobs and a pointer carrying the URL,
ciphertext hash, and AEAD parameters.

The extension occupies `enclosure.extensions` and is visible
only to the recipient client after enclosure decryption.

## Extension Schema

~~~ json
"enclosure": {
    "extensions": {
        "semp.dev/large-attachment": {
            "required": true,
            "data": {
                "items": [
                    { "id": "...", "url": "...", "...": "..." }
                ]
            }
        }
    }
}
~~~

The `required` flag MUST be `true` when the envelope's body
references an external attachment in a way that makes the
envelope incomplete without it. The `required` flag MAY be
`false` when external attachments are auxiliary and the
envelope is intelligible without them.

## Item Schema

~~~ json
{
    "id": "attachment-ulid",
    "filename": "presentation.pdf",
    "mime_type": "application/pdf",
    "plaintext_size": 204800000,
    "url": "https://blobs.example.com/a/abcd1234",
    "ciphertext_hash": "sha256:hex-of-ciphertext",
    "aead_algorithm": "xchacha20-poly1305",
    "aead_nonce": "base64-24-byte-nonce",
    "extensions": {}
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique attachment identifier within the envelope. ULID RECOMMENDED. Used as KDF input. |
| `filename` | string | Yes | Original filename. MUST NOT contain path separators. |
| `mime_type` | string | Yes | MIME type of the plaintext. |
| `plaintext_size` | integer | Yes | Size in bytes of the plaintext. |
| `url` | string | Yes | HTTPS URL from which the ciphertext is fetched. |
| `ciphertext_hash` | string | Yes | Hash of the ciphertext bytes. Format: `algorithm:hex`. |
| `aead_algorithm` | string | Yes | AEAD algorithm. MUST match one of the suites supported by the envelope's algorithm suite. |
| `aead_nonce` | string | Yes | Base64-encoded nonce for AEAD decryption. |
| `extensions` | object | No | Per-item extensions. Non-normative retrieval hints MAY appear here. |

`id` MUST be unique across both `enclosure.attachments[]` (the
inline attachments list) and the external item list. A single
attachment MUST NOT appear in both lists. Clients display the
union of both lists to the user.

## Per-Attachment Key Derivation

Each external attachment is encrypted under a key
`K_attachment` derived from the enclosure key `K_enclosure`
using HKDF [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869):

~~~
K_attachment := HKDF-Expand(
    PRK  = K_enclosure,
    info = "semp-attachment:" || attachment_id,
    L    = length-of-K_enclosure)
~~~

Where `||` denotes byte concatenation, `attachment_id` is the
UTF-8 bytes of the item's `id` field, and `L` matches the key
length required by the AEAD algorithm.

Any recipient that holds `K_enclosure` (wrapped for them in
`seal.enclosure_recipients`) can derive `K_attachment` for
each external attachment. No additional key wrapping is
required in the seal.

## AEAD Parameters

The `aead_algorithm` MUST be consistent with the envelope's
negotiated suite. For the baseline suite
(`x25519-chacha20-poly1305`), the AEAD is ChaCha20-Poly1305
[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) with a 12-byte nonce. For the post-quantum suite
(`pq-kyber768-x25519`), the AEAD is XChaCha20-Poly1305 with a
24-byte nonce. Implementations MUST validate the nonce length
against the algorithm.

The associated data field for AEAD MUST be the canonical
UTF-8 JSON encoding of the item with `ciphertext_hash`,
`aead_nonce`, and `extensions` set to empty values (`""`,
`""`, `{}`). Binding the item's metadata into AEAD
additional-data prevents an attacker from swapping `filename`
or `mime_type` while leaving the ciphertext intact.

## Ciphertext Structure

The bytes stored at `url` are exactly the AEAD ciphertext
output (ciphertext concatenated with the authentication tag).
No framing, header, or length prefix is added.

## Storage

`url` MUST be an HTTPS URL. Plain HTTP MUST NOT be used. The
host MUST be a fully qualified domain name or an IPv6 literal
in brackets; bare IPv4 literals MUST NOT be used.

The server at `url` MAY require authentication for retrieval.
Bearer tokens, signed query parameters, or other
authentication schemes are implementation-specific and MAY be
carried in `item.extensions` as retrieval hints.

The sender MUST ensure that the ciphertext remains
retrievable at `url` for the retention minimum:

~~~
retention_minimum = max(postmark.expires, upload_time + 30 days)
~~~

RECOMMENDED retention is 90 days after upload.

The storage URL used by an extension instance is a
client-side configuration value. A user configures the
attachment storage URL in their client at account setup.
The same code path applies regardless of where the storage
lives: a SEMP server operator's hosting offer is a URL
configured into the client (typically communicated to the
user at account signup), a third-party blob service is a
URL configured into the client, and a self-hosted bucket
is a URL configured into the client. The storage URL is
not advertised in the SEMP discovery configuration.

If a SEMP server operator hosts a blob-hosting service for
their users, the operator MUST NOT decrypt, scan, or
inspect ciphertext content stored on that service.

## Upload Flow

The sender client:

1. Generates `attachment_id` (ULID RECOMMENDED).
2. Derives `K_attachment` from `K_enclosure`.
3. Generates a fresh nonce per the AEAD algorithm's
   requirements.
4. Constructs the item object with all fields except
   `ciphertext_hash`.
5. Computes AEAD additional-data from the item object.
6. Encrypts the plaintext under `K_attachment` with the nonce
   and additional-data to produce the ciphertext.
7. Computes `ciphertext_hash` over the ciphertext bytes.
8. Writes `ciphertext_hash` into the item object.
9. Uploads the ciphertext to the chosen storage, obtaining
   the final `url`.
10. Writes `url` into the item object.
11. Adds the item to the extension's `items` array.

## Download and Decryption Flow

The recipient client:

1. Decrypts the envelope's enclosure, obtaining `K_enclosure`
   and the enclosure plaintext.
2. Verifies `enclosure.sender_signature`.
3. For each item:
   * Derives `K_attachment` from `K_enclosure` and `item.id`.
   * Fetches ciphertext bytes from `item.url` over HTTPS.
   * Verifies `ciphertext_hash` against the fetched bytes.
     On hash mismatch, the client MUST NOT attempt
     decryption and MUST surface a ciphertext-integrity
     failure.
   * Reconstructs AEAD additional-data.
   * Decrypts the ciphertext under `K_attachment` with
     `aead_nonce` and additional-data. On AEAD authentication
     failure, the client MUST surface a decryption-integrity
     failure.
   * Presents the plaintext to the user with the declared
     `filename` and `mime_type`, applying the same safety
     defaults as for inline attachments.

The client MAY perform fetch and decryption on demand (when
the user opens the attachment) or eagerly (during envelope
open) per its own UX policy.

## Failure Handling

If a fetch of `item.url` fails (network error, HTTP 4xx or
5xx, timeout), the recipient client MUST surface the failure
to the user with the `filename` for context. The client MUST
NOT suppress the failure or present the attachment as
available.

A ciphertext hash mismatch indicates the stored blob has been
corrupted, tampered with, or replaced. The client MUST treat
the attachment as unavailable, MUST NOT attempt decryption,
and MUST surface an integrity failure that distinguishes this
case from a simple fetch failure.

If `postmark.expires` has passed and the sender's retention
minimum has elapsed, the storage provider MAY have deleted
the blob. The client MUST display this as a
retention-elapsed state distinct from a transient fetch
failure when the fetch returns HTTP 404 or 410 and the
envelope's `postmark.expires` is in the past.

# Conformance

This section catalogs the conformance requirements that an
implementation MUST satisfy to claim SEMP support. The
requirements are grouped by role.

## Implementation Roles

SEMP defines three implementation roles. A single software
product may implement one or more roles.

| Role | Description |
|---|---|
| SEMP Server | Operates on behalf of a domain. Handles handshakes, envelope routing, delivery policy, key publication, and discovery responses. |
| SEMP Client | Operates on behalf of a user. Handles envelope composition, encryption, decryption, key management, and home server communication. |

SEMP federation is direct between the two home servers. There is
no intermediate relay tier. While an envelope is in transit, only
its public layers (postmark and seal) are exposed on the wire.
The brief is readable only by the recipient server. The enclosure
is readable only by the recipient client.

## Conformance Levels

### Baseline Conformance

An implementation achieves baseline conformance by
satisfying all MUST and MUST NOT requirements applicable to
its role. Baseline conformance is the minimum for
interoperability.

### Recommended Conformance

An implementation achieves recommended conformance by
satisfying all MUST, MUST NOT, SHOULD, and SHOULD NOT
requirements applicable to its role. Recommended
conformance represents the expected behavior of a
production-quality implementation.

### Feature Conformance

Individual features (such as trust gossip publication,
proof-of-work challenges, or legacy interoperability) MAY
be implemented independently. An implementation that
claims support for a feature MUST satisfy all requirements
associated with that feature. Partial feature
implementation is non-conformant for that feature.

## Server Conformance

A conformant SEMP server MUST:

* Implement the envelope wire format defined in
  [Envelope](envelope.md), including canonical-byte
  computation, seal verification, signature domain
  separation, and recipient-count obfuscation.
* Implement both algorithm suites: `x25519-chacha20-poly1305`
  (baseline) and `pq-kyber768-x25519` (post-quantum hybrid).
  Implementations are RECOMMENDED to prefer the post-quantum
  suite when both peers support it.
* Implement the four-message client and federation handshakes
  defined in [Handshake](handshake.md), including
  optional proof-of-work challenges with the difficulty cap
  and expiry floor specified there.
* Erase ephemeral private keys immediately after the shared
  secret is computed.
* Maintain only in-memory session state. Session keys MUST
  NOT be written to disk, swap, or any persistent storage.
* Enforce the concurrent-session bounds (one active session
  per authenticated client identity, one per peer domain for
  federation).
* Implement the discovery flow defined in
  [Discovery](discovery.md), including DNS SRV and TXT
  records, the well-known URI configuration document with
  monotonic revision, and (when enabled) the protocol lookup
  exchange with domain-level statuses.
* Publish domain keys via DANE TLSA records (RECOMMENDED) or
  via the configuration `domain_keys` endpoint.
* Implement the delivery pipeline defined in
  [Delivery](delivery.md) in the prescribed order, with
  explicit rejection or silent-mode disposition.
* Issue signed delivery receipts on every `delivered`
  acknowledgment.
* Implement the per-sender-domain rate limiting defined in
  [Delivery](delivery.md) and switch to silent-mode
  disposition when the threshold is exceeded.
* Implement first-contact policy enforcement with
  address-enumeration resistance.
* Support HTTP/2 as the baseline transport. Support of
  WebSocket and QUIC is RECOMMENDED.
* On the HTTP/2 transport binding: accept `GET` on
  `/v1/discovery/{address}` and `/v1/keys/{address}` for
  read-only lookups, and additionally accept `POST` on those
  same paths so that callers requiring a signed request body
  MAY use the lookup paths with `POST`. Use `POST` for
  `/v1/handshake` and `/v1/envelope`. Use `GET` for
  long-lived server-initiated streams at `/v1/session/{id}`.
  ([Handshake](handshake.md))
* When supporting the QUIC transport: resolve the QUIC
  endpoint host and port from the `_semp._tcp` SRV target by
  default. Operators MAY publish an optional `_semp._udp` SRV
  record alongside `_semp._tcp` to advertise a distinct UDP
  target for QUIC; when published, the `_semp._udp` target
  MUST resolve to a SEMP endpoint that accepts QUIC
  connections. ([Discovery](discovery.md))
* Implement the reason code registry from
  [Delivery](delivery.md) with case-sensitive matching.
* Apply the size limits defined in {{size-constraints}} to
  every `extensions` object.
* Verify extension definition document signatures before
  treating any definition as authoritative.
* For per-recipient persistent silent classification:
  maintain a per-recipient counter of consecutive `silent`
  outcomes for envelopes addressed to the same recipient.
  When the counter reaches the operator-configured threshold
  (RECOMMENDED 5 consecutive `silent` outcomes observed
  over at least 24 hours with no intervening non-`silent`
  acknowledgment), the sending server SHOULD shorten the
  effective delivery deadline (RECOMMENDED 4 hours) for
  subsequent envelopes addressed to that recipient. The
  counter MUST be reset to zero on any non-`silent`
  acknowledgment from the same recipient. The counter MAY
  be expired after an operator-configured idle period
  (RECOMMENDED 30 days).

A conformant SEMP server MUST NOT:

* Decrypt the enclosure under any circumstances.
* Use IP addresses as inputs to protocol-layer trust
  decisions.
* Issue a `delivered` acknowledgment for an envelope it has
  not accepted for delivery.
* Generate synthetic bounce envelopes addressed to the
  sending user or to any third party.
* Speak SMTP. Legacy interoperability is a client-layer
  responsibility.
* Propagate the per-recipient persistent silent counter to
  any other party. The counter is sender-side state and
  MUST NOT appear on the wire, MUST NOT be published as a
  trust gossip observation, and MUST NOT be shared outside
  the local sending-server boundary.

<a id="trust-gossip-conformance"></a>

## Trust Gossip Conformance
The conformance requirements in this subsection apply to
SEMP servers that publish or consume trust gossip
observations as defined in [Delivery](delivery.md).
Servers that neither publish nor consume trust gossip MAY
skip this subsection.

A conformant SEMP server publishing or consuming trust
gossip MUST:

* Reject trust-gossip observation records exceeding 16384
  bytes (16 KiB) in canonical UTF-8 JSON form as malformed,
  and MUST NOT propagate them. ([Delivery](delivery.md))
* Cap evidence fetches at a locally-configured limit
  (RECOMMENDED 1 MiB) and parse evidence content in an
  isolated context. Consumers MUST NOT recursively fetch
  URLs found within evidence content.
  ([Delivery](delivery.md))
* For observation records with `evidence_available: true`:
  include an `evidence_hash` field bound into the signed
  observation. A consumer fetching the evidence MUST
  compute the digest under `evidence_hash.algorithm` and
  MUST treat any mismatch as a verification failure
  equivalent to a signature failure. When
  `evidence_available` is `false`, both `evidence_uri` and
  `evidence_hash` MUST be absent.
  ([Delivery](delivery.md))
* Disclose reciprocity policy in the configuration
  document's `reciprocity` object when the server enforces
  reciprocity, using the schema defined in
  [Discovery](discovery.md).
  ([Delivery](delivery.md), [Discovery](discovery.md))

A conformant trust-gossip publisher MUST:

* Not publish an observation about a subject domain unless
  the observer has directly observed at least 16 envelopes
  (or an equivalent number of handshake attempts) involving
  the subject during the observation window.
  ([Delivery](delivery.md))
* Not publish observations whose `metrics` fields are
  uniformly zero. ([Delivery](delivery.md))

A conformant trust-gossip consumer SHOULD:

* Weight each observation by its locally-computed
  credibility for the publishing observer. Inputs to local
  credibility are implementation-defined and include
  evidence-hash verification rate, alignment with the
  consumer's own direct experience, schema conformance
  history, and observer domain-stability signals.
  ([Delivery](delivery.md))

A conformant trust-gossip consumer MUST:

* Not publish or share credibility scores about other
  observers as part of trust gossip or any other SEMP wire
  artifact. Consumer credibility is per-consumer, local
  state. Shared scores would introduce transitive trust,
  which is incompatible with the no-transitive-trust
  principle. ([Delivery](delivery.md))

## Client Conformance

A conformant SEMP client MUST:

* Compose envelopes per the encryption flow defined in
  [Envelope](envelope.md), including sender signature
  computation over the enclosure.
* Verify sender signatures on received envelopes before
  rendering content. The client MUST NOT silently render
  content for envelopes whose sender signature does not
  verify.
* Apply the multi-level forwarding verification chain when
  `enclosure.forwarded_from` is non-null.
* Erase session key material on application termination,
  device lock, and (when applicable) backgrounding.
* Detect key changes per the rules above when an envelope
  arrives from a previously known correspondent whose
  identity key has changed, and require explicit user
  confirmation before treating the new key as a known
  correspondent.
* Implement the user policy synchronization protocol
  including signed updates and monotonic version handling.
* Sign every outbound envelope with a fresh sender signature.
* Implement HTTP/2 as the baseline transport.
* On the HTTP/2 transport binding: issue `GET` to
  `/v1/discovery/{address}` and `/v1/keys/{address}` for
  read-only lookups outside an established session, and issue
  `POST` to `/v1/handshake` and `/v1/envelope` for
  state-changing operations.
  ([Handshake](handshake.md))
* When selecting QUIC as the transport: resolve the QUIC
  endpoint host and port from the `_semp._tcp` SRV target by
  default, and prefer the `_semp._udp` SRV target when both
  records are published for the same domain.
  ([Discovery](discovery.md))
* Verify recipient domain signatures on key responses
  before trusting key material.
* Verify domain signatures on lookup responses before
  caching results.

A conformant SEMP client MUST NOT:

* Reuse session keys across application restarts.
* Store session keys on disk, in cloud backups, in crash
  reports, or in any persistent storage.
* Render enclosure content as authored by the claimed sender
  if signature verification fails.
* Submit envelopes to a server other than the user's home
  server.

## Federation Peer Conformance

A SEMP server acting as a federation peer MUST satisfy all
server conformance requirements above and additionally:

* Implement the federation handshake variant in
  [Handshake](handshake.md) including domain
  ownership verification.
* Verify the peer's domain signing key by DANE cross-check
  (when DNSSEC is available) or via the peer's
  configuration document.
* Apply per-peer-domain rate limits.
* Forward acknowledgments to the originating sending server
  without modification.
* Verify the seal signature of every envelope before
  forwarding.

## Algorithm Suite Requirements

A conformant implementation MUST implement both algorithm
suites:

* `x25519-chacha20-poly1305` (baseline). Required for
  interoperability.
* `pq-kyber768-x25519` (post-quantum hybrid). RECOMMENDED;
  implementations are RECOMMENDED to prefer it when both
  peers support it.

Both currently defined suites use:

* HKDF-SHA-512 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)) for session key derivation.
* Salt: `client_nonce || server_nonce` (concatenation, in
  that order).
* For the post-quantum hybrid suite, the shared secret
  input to HKDF is `K_kyber || K_x25519` in that order.
* Distinct HKDF Expand labels for the six derived session
  keys: `SEMP-v1-session-enc-c2s`,
  `SEMP-v1-session-enc-s2c`, `SEMP-v1-session-mac-c2s`,
  `SEMP-v1-session-mac-s2c`, `SEMP-v1-session-env-mac`,
  `SEMP-v1-session-resumption`.

Implementations MAY define and negotiate additional suites,
each specifying all five components (key agreement,
symmetric cipher, MAC, KDF, signing). Additional suites
MUST explicitly name their HKDF hash function. The
negotiated suite MUST be recorded in `seal.algorithm`.
Implementations MUST NOT negotiate suites below the
baseline.

## Retention Policy

A conformant server MUST apply per-artifact retention rules
so that operator data holdings are bounded to what the
protocol requires for correct operation. The rules below
are the normative minimums and maximums. Operators MAY
apply shorter retention where permitted and MUST NOT exceed
the maximums.

### Delivery Receipts

Delivery receipts at the sending server SHOULD be dropped
after the sending client has acknowledged receipt of the
delivery event. They MUST NOT be retained beyond 30 days
after the envelope's `postmark.expires`.

Delivery receipts at the recipient server SHOULD NOT be
retained beyond what is needed to produce the
acknowledgment response.

### Abuse Evidence

Sealed abuse evidence MUST be retained at the reporting
server for at least 90 days, to support observation
publication and peer review. MAY be retained longer under
operator policy. Evidence MUST be deleted on request by the
reporter.

### Session Tickets and Session State

Resumption tickets MUST NOT have a lifetime exceeding 7
days from issuance. A server MUST delete ticket-encryption
key material for tickets issued under a rotated key at
least quarterly.

Active session state MUST be held in memory only and MUST
NOT be persisted beyond the session's `expires_at`.

The expired-`session_id` log for replay prevention MUST be
retained for at least one session TTL window and MUST NOT
exceed 30 days.

### Revocation Records

Revocation records MUST be retained for the operational
lifetime of the publishing domain's SEMP service.
Revocation records prevent key-substitution attacks and
cannot be safely deleted: a deleted revocation record would
allow an attacker holding a compromised key to act as if
the revocation never occurred.

Revocation records also serve as the cryptographic
discontinuity at local-part reassignment. When a local-part
is later reassigned to a new occupant per
[Recovery](recovery.md), the prior occupant's
revocation records are the verifiable proof that the new
identity key is unrelated to the prior one. Correspondents
fetching the current key for a reassigned address observe
the prior revocation alongside the new key publication and
treat the address as a fresh identity, not a continuation.

### Backup Bundles

Current bundle: retained as long as the account is active.
Superseded bundles MUST be retained for at least 30 days
after supersession. After account closure, retention
follows the closure retention window rules in
[Recovery](recovery.md).

### Block Lists

User block lists are user-owned state. MUST be retained
for as long as the account is active. MUST be deleted at
account finalization unless the user has explicitly
requested carry-over to a migrated account.

### Correspondent-Graph Derivatives

Any data that encodes who corresponded with whom beyond
the minimum required for delivery (search indexes,
per-conversation metadata caches, archived delivery-receipt
summaries) is a correspondent-graph derivative. Operators
SHOULD NOT create such derivatives. Where operational
requirements demand them, they MUST be retained no longer
than the minimum needed for that requirement and MUST be
surfaced in the operator's privacy documentation.

### Queued Envelopes

Envelopes in the sender-side delivery queue are persisted
until a terminal outcome. MUST be deleted from the queue at
the earlier of: reaching a terminal outcome, or
`postmark.expires` plus one retention window. The retention
window for expired-but-queued envelopes SHOULD NOT exceed
24 hours.

### First-Contact Challenge State

The `(challenge_id, prefix, postmark_id)` triple for
issued first-contact challenges MUST be retained at least
until the challenge's `expires` timestamp, to support
single-use enforcement. MAY be retained up to 24 hours past
`expires` for diagnostics. Consumed challenge IDs SHOULD be
retained for at least the challenge's original lifetime to
prevent replay.

### Logs and Diagnostics

Server operational logs (access logs, error logs,
rate-limit counters) are out of scope for this
specification. Operators MUST NOT log decrypted `brief` or
`enclosure` content under any circumstances and MUST NOT
log private key material, recovery secrets, or session
keys.

## Version Negotiation

SEMP protocol versions follow semantic versioning
`MAJOR.MINOR.PATCH`. The current version is `1.0.0`. Every
SEMP message type MUST carry a `version` field in this
format.

### Version Format

* MAJOR is incremented on any wire-incompatible change.
* MINOR is incremented on backward-compatible additions.
* PATCH is incremented for editorial clarifications and
  typo fixes only. A PATCH bump MUST NOT change any
  conforming implementation's behavior.

### Supported Version Declaration

Every implementation MUST declare the MAJOR version it
speaks in:

* Its DNS TXT record (`v=semp1` for MAJOR 1, per
  [Discovery](discovery.md)).
* Its configuration document (`version` field).
* Every handshake message it sends (`version` field).

An implementation MAY declare support for more than one
MAJOR by publishing one configuration document per
supported MAJOR under distinct DNS TXT records.

### Cross-Major Interoperability

Different MAJOR versions are not wire-interoperable.
Implementations encountering a peer whose declared MAJOR
does not match any MAJOR they support MUST:

* At discovery: treat the domain as non-SEMP for this
  MAJOR and fall back per client policy or abandon
  delivery per operator policy.
* At handshake: reject the `init` with `reason_code:
  "version_unsupported"`. The rejecting side MAY include
  the list of MAJOR versions it does support in the
  response `reason` string (advisory).

An implementation MUST NOT attempt to negotiate down to a
lower MAJOR than it supports. Cross-MAJOR federation is
achieved by operators who run gateways, outside the scope
of this specification at the wire level.

The specification revision that introduces MAJOR N+1 MUST
document a migration path from MAJOR N. The migration path
MAY include sunset timing for MAJOR N, dual-stack support
during the transition window, operator-run gateway
guidance, or other operational means. Wire-level
interoperability across MAJORs is not required; what is
required is that the successor specification explicitly
addresses how deployments holding MAJOR N traffic move
forward.

### Within-Major Interoperability

Implementations on the same MAJOR MUST interoperate
regardless of MINOR or PATCH differences:

* Unknown fields MUST be ignored, not rejected.
* Unknown optional message types MUST be rejected with
  `extension_unsupported` if the sender marked them
  critical, and silently dropped otherwise.
* New extensions introduced in a later MINOR are
  advertised and negotiated at handshake capability
  exchange.

### Sunset

MINOR versions are not deprecated: older MINOR
implementations continue to interoperate indefinitely
within the same MAJOR. A MAJOR version is sunset when a
successor MAJOR has been widely deployed. The specification
revision that introduces MAJOR N+1 SHOULD state the
recommended end-of-support date for MAJOR N, giving
operators at least 24 months to migrate.

## Clock Skew Tolerance

SEMP relies on timestamp-bearing fields throughout the
protocol. Every implementation MUST enforce a consistent
clock tolerance for every such field.

### Tolerance Rules

Let `now` be the implementation's current wall-clock UTC
time and let `T` be a timestamp being validated.

Future-dated timestamps (`T > now`):

* Implementations MUST reject the record if `T - now > 15
  minutes`.
* Implementations SHOULD reject the record if `T - now > 5
  minutes`.
* Records with `T - now` in the range 0 to 5 minutes MUST
  be accepted.

Expired timestamps (`expires_at` fields, where validity
ends at `T`):

* Implementations MUST reject as expired when `now > T +
  15 minutes`.
* Implementations SHOULD reject as expired at `now > T`.
* Implementations MAY apply up to 5 minutes of grace
  (`T < now <= T + 5 minutes`).

Senders MUST NOT rely on grace windows. Senders MUST set
`expires_at` values with at least 15 minutes of headroom
beyond the worst-case expected delivery delay.

### Time Source

Implementations MUST maintain clocks within the tolerance
bounds above. NTP ([RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)), Precision Time Protocol
(IEEE 1588), or a provider-supplied equivalent is
RECOMMENDED.

### Monotonic Clock for Internal TTL

Servers SHOULD track internal session TTLs (handshake
session lifetime, queue retry scheduling, rate-limit
throttling windows) against a monotonic clock rather than
the wall clock. Cross-party timestamps MUST continue to use
wall-clock values in UTC per ISO 8601, since monotonic
clock values are not comparable across processes.

### Fail-Closed on Undetectable Clock State

If an implementation cannot determine its own clock state
with confidence (for example, NTP unreachable at boot and
no other time source available, or hardware clock detected
as stopped or faulty), it MUST NOT process operations that
require timestamp validation. Specifically:

* A server MUST NOT accept new handshakes.
* A server MUST NOT accept envelope submissions.
* A server MUST NOT issue acknowledgments with timestamp
  fields.
* A server SHOULD surface the clock-state error to
  operators through its operational alerting channel.

A client that cannot determine its own clock state SHOULD
surface the error to the user rather than compose envelopes
with uncertain timestamps.

## Legacy Interoperability

A conformant client implementing SMTP fallback MUST:

* Surface the encryption degradation to the user before
  proceeding with SMTP fallback when `legacy_required` is
  received.
* Require explicit user confirmation before sending via
  SMTP.
* MUST NOT transmit legacy mail credentials (SMTP
  Submission, IMAP, POP3, JMAP, or provider API) to the
  home server.
* MUST NOT automatically send via SMTP without user
  awareness.
* Produce MIME messages for SMTP fallback that MUST NOT
  include postmark, seal, or encrypted brief/enclosure
  artifacts.
* MUST NOT emit `Bcc` headers; blind recipients are carried
  only via SMTP `RCPT TO`.
* Use the A-label form of IDN domains in SMTP envelope
  addresses.

For mixed-recipient composes (some SEMP-reachable, some
`legacy_required`), a conformant client MUST:

* Split the send into a SEMP envelope for the
  SEMP-reachable group and an SMTP message for the legacy
  group.
* Surface the split to the user with a degradation warning
  attached to the SMTP group, and require explicit
  confirmation before transmission.
* Record both outbound artifacts under the same thread key
  in the local threading map.
* MUST NOT silently downgrade SEMP-reachable recipients to
  SMTP.
* MUST NOT combine encrypted and plaintext renditions of
  the same content into a single MIME message.

For legacy-origin inbound messages, a conformant client
MUST:

* Distinguish legacy messages from SEMP messages with a
  persistent, unambiguous origin indicator visible without
  additional user interaction. The indicator MUST
  distinguish at least three states: SEMP,
  legacy, and legacy-with-verified-SEMP-capable-sender.
* MUST NOT present legacy and SEMP messages in a unified
  inbox without such an indicator.

## Delegation

A conformant primary client that issues scoped device
certificates MUST:

* Sign the certificate with its own device key.
* Include all five scope fields (`send`, `receive`,
  `blocklist`, `keys`, `devices`), each with its uniform
  object shape and `rate_limits` array (possibly empty).
* Use matcher mode `unrestricted`, `restricted`,
  `denylist`, or `none` for `send` and `receive`, with
  `allow` or `deny` populated as the mode requires.
* MUST NOT mix `allow` and `deny` in a single matcher.
* Populate `rate_limits` as an array of zero or more
  tiers, each with integer `period_seconds >= 1` and
  integer `amount_allowed >= 0`, with no more than 16
  tiers per array.
* Include `delivery_stage: integer >= 1` on the `receive`
  matcher and omit it from `send`.
* Set `expires_at` within `issued_at < expires_at <=
  issued_at + 365 days`.

A conformant delegated client MUST:

* Accept `scope_exceeded` rejections gracefully and not
  retry submissions rejected for scope reasons without
  operator intervention.
* MUST NOT attempt operations outside its certificate
  scope.
* MUST NOT issue `SEMP_DEVICE_CERTIFICATE` records under
  any scope.

A conformant home server MUST:

* Reject certificate registrations whose signature does
  not verify, whose issuer is not a registered full-access
  device of the account, or whose issuer is revoked.
* Reject certificates with combined `allow` and `deny`
  exceeding 10,000 entries in any single matcher, or more
  than 16 rate-limit tiers in a single `rate_limits` array,
  or `period_seconds < 1` or `amount_allowed < 0` in any
  tier, with `reason_code: "scope_invalid"`.
* Reject certificates that mix `allow` and `deny` within a
  single matcher with `reason_code: "scope_invalid"`.
* Reject certificates whose `expires_at` exceeds
  `issued_at + 365 days` with `reason_code:
  "scope_invalid"`.
* Apply the current certificate on every operation, not
  the certificate active at session establishment.
* Reject nested delegation attempts (an `issued_by`
  pointing at a delegated device) with `reason_code:
  "scope_invalid"`.
* Preserve the delegated device's active session across
  certificate update. Session invalidation is triggered
  only by device-key rotation or explicit revocation.
* Terminate the delegated device's session immediately on
  acceptance of a revocation record and reject subsequent
  handshakes with `reason_code: "revoked"`.
* Reject operations from a delegated device whose
  certificate has expired with `reason_code:
  "certificate_expired"`.

## Security Requirements

A conformant implementation MUST:

* Use cryptographically secure pseudorandom number
  generators for every key, nonce, and session identifier.
* Apply constant-time operations for key comparisons and
  MAC verifications.
* Apply the memory-safety rules in
  [Handshake](handshake.md) (memory locking where
  available, crash-dump exclusion, zeroing before
  deallocation).
* Apply the forward-secrecy property: past session keys
  MUST be unrecoverable from compromise of long-term keys.
* Reject envelopes whose `postmark.session_id` references a
  session in the expired-session log (replay prevention).

## Privacy Requirements

A conformant implementation MUST:

* Apply the identity-confidentiality property: an
  observer of the wire MUST NOT be able to learn the
  client identity from the handshake until the session is
  established.
* Apply the metadata-protection property: routing
  infrastructure MUST NOT see envelope contents beyond
  what is required for delivery.
* Apply the block-list-privacy property: block list
  contents MUST NOT be transmitted to other domains or to
  the blocked party.
* Apply the abuse-reporter-privacy property: abuse reports
  are sent to the reporter's home server only, and the
  reporter's identity MUST NOT be propagated to the
  reported party.

## Encoding

* All JSON MUST be UTF-8 encoded.
* Canonical serialization for seal computation requires
  lexicographically sorted keys and no insignificant
  whitespace.
* Binary data (keys, nonces, signatures) MUST be
  base64-encoded in JSON fields unless otherwise
  specified. Hash values MUST be hex-encoded where the
  schema specifies hex.

## Optional-Core Module Conformance

Optional-core modules (account recovery, provider migration,
account closure, key transparency) are advertised through
specific endpoints in the configuration document. An
implementation that advertises support for an optional-core
module MUST conform to that module's specific normative
requirements as defined in [Recovery](recovery.md).

Absence of an endpoint indicates the module is not
supported. Implementations MUST NOT probe for module
endpoints not advertised in the configuration document.

## Conformance Self-Reporting

Servers SHOULD expose a conformance self-report at a
well-known URI for operator audit:

~~~
GET https://<server>/.well-known/semp/conformance
~~~

The response, when present, lists supported algorithm suites,
supported transports, supported optional-core modules,
supported wire-level extensions (with their definition
document URLs), the maximum envelope size enforced, the
clock skew tolerance applied, and the SEMP protocol version
range supported.

This endpoint is OPTIONAL. The discovery configuration
document remains the authoritative source for capability
negotiation.

# Security Considerations

For the consolidated adversary model under which this section
is evaluated, see [Architecture](architecture.md).

## Extension Authority Enforcement

Extensions declare which roles (`sender_client`,
`sender_server`, `recipient_server`, `recipient_client`) may
produce them. Receivers MUST enforce these declarations: an
extension whose authority is `sender_client` but appears
injected by a `recipient_server` MUST be rejected.

Without this enforcement, a malicious server in the routing
path could inject extensions that change the apparent
authorship of envelope content. The authority model defends
against this at every receiving role.

## Definition Document Trust

The definition document anchors trust in an extension to the
namespace owner's domain key. An attacker who compromises a
domain key can substitute definition documents under that
domain's namespace. Defense relies on the same key
transparency and revocation mechanisms that defend against
forged user keys.

Implementations SHOULD pin definition documents by content
hash for `core` extensions to defend against silent
post-publication rewrites.

## Permission Scope Enforcement

The library extension enforcement contract requires runtime
enforcement of declared `permissions.writes` constraints.
An implementation
that ignores permission declarations could allow extensions
to corrupt protocol-managed fields.

Permission enforcement is a normative requirement, not a
recommendation. Non-conformant implementations that bypass
permission checks are not interoperable with conformant
peers and SHOULD be reported as `protocol_abuse`.

## Large Attachment Confidentiality

Confidentiality of large attachments is provided by AEAD
encryption under `K_attachment`. `K_attachment` is derived
from `K_enclosure`, which is wrapped only to the recipient
clients listed in `seal.enclosure_recipients`. The storage
provider, on-path observers, and non-recipient parties
possessing the `url` cannot recover plaintext.

## Large Attachment Integrity

`ciphertext_hash` binds the URL to specific ciphertext bytes.
An attacker controlling the storage provider cannot
substitute alternative ciphertext without invalidating the
hash. The hash is covered by the enclosure's encryption and
by `enclosure.sender_signature`, so an attacker cannot
substitute the hash itself without forging the sender
identity signature.

AEAD additional-data binds the item metadata (filename,
mime_type, url). An attacker that possesses the ciphertext
but not the enclosure cannot substitute a different filename
or mime_type to cause confusion in the recipient's client.

## Per-Attachment Key Compartmentalization

Deriving `K_attachment` per attachment limits the blast
radius of a single-attachment key leak. Leaking one
attachment's plaintext does not reveal other attachments,
the enclosure body, or the brief.

## Conformance and Defensive Posture

Conformance to the requirements in this document is a
necessary but not sufficient condition for security.
Operators are responsible for choosing and configuring the
implementation, deploying TLS correctly, monitoring for
anomalies, and applying operator policy that the protocol
does not prescribe.

# Privacy Considerations

## Extension Visibility by Layer

The choice of layer for an extension determines its
visibility:

* `postmark.extensions` and `seal.extensions` are visible on the wire and MUST be treated as public.
* `brief.extensions` is visible to the recipient server and
  client.
* `enclosure.extensions` is visible only to the recipient
  client.

Extension authors MUST select the most restrictive layer
that satisfies the extension's functional requirements.
Placing an extension at a more public layer than required
exposes user metadata unnecessarily.

## Storage Provider Visibility

For large attachments, the storage provider observes the URL
and ciphertext bytes, the IP addresses and approximate timing
of upload and download, and the ciphertext size. The storage
provider does not observe the plaintext content or which
envelope references the blob.

Users sensitive to traffic-analysis exposure SHOULD use an
anonymizing transport (Tor or equivalent) for uploads and
downloads against untrusted storage providers.

## Filename and Size Leakage in Large Attachments

`filename`, `mime_type`, and `plaintext_size` are carried in
the enclosure plaintext and are therefore visible to the
recipient client. They are not visible to home servers or
to the storage provider. Senders concerned about filename
leakage to the recipient SHOULD rename files before
attaching.

## Operator-Hosted Storage Correlation

When the recipient uses the same operator as the sender, and
the operator also hosts the blob storage, the operator can
correlate upload and download events with envelope transit.
This correlation is accepted as a local property of
shared-operator deployments. Users who wish to avoid it
SHOULD choose storage providers distinct from their SEMP
operator.

<a id="test-vectors"></a>

# Test Vectors
The cross-language test vector corpus at `vectors/v1.0.0/` of
the SEMP specification repository pins the byte-level behavior
of the constructions in this document. The following files
exercise extension validation and registration:

| File | What it pins |
|---|---|
| `extension-entries.json` | Extension entry parsing, criticality enforcement, per-layer size limits, the canonical `.well-known/semp-extensions/{name}.json` URL form. |
| `validation-failures.json` | `extension_unsupported` rejection with the `errors[]` array form; single-entry and multi-entry shapes. |

# IANA Considerations

This document defines the SEMP extension namespace. The
canonical SEMP extension registry is maintained at
`https://semp.dev/extensions/` and is not subject to IANA
registration; the namespace owner (the SEMP project) is the
registry maintainer.

Vendor and experimental extensions are namespaced under DNS
labels controlled by the extension author and require no
IANA action.

The reason codes `extension_unsupported` and
`extension_size_exceeded` introduced by this document for
the extension framework are registered as part of the
reason-code registry in [Delivery](delivery.md).

The wire-level extension `semp.dev/large-attachment`
specified in [Large-Attachment Extension](#large-attachment) is the first extension
registered in the SEMP extension registry. Its definition
document is served at
`https://semp.dev/.well-known/semp-extensions/large-attachment.json`
per the canonical URL derivation in this document.

# Acknowledgments

The author thanks the contributors to the SEMP specification
for review, design discussion, and prior-art analysis.

