# SEMP Extensions Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.1.0  
Related: `DESIGN.md`, `ENVELOPE.md`, `HANDSHAKE.md`, `DISCOVERY.md`

---

## Abstract

This specification defines the extension framework for the SEMP protocol:
the structure of extension entries, criticality signaling, size constraints,
the extension registry, the lifecycle from experimental to core, and the
governance rules that prevent ecosystem fragmentation. It governs all
`extensions` fields across every layer of the protocol.

---

## 1. Extension Points

SEMP provides extension points at multiple layers of the protocol. Each layer
exposes an `extensions` object with different visibility and trust properties:

| Layer                    | Extension Field             | Visibility                              | Defined In           |
|--------------------------|-----------------------------|-----------------------------------------|----------------------|
| Routing                  | `postmark.extensions`       | All servers in transit                  | `ENVELOPE.md` §8     |
| Integrity                | `seal.extensions`           | All servers in transit                  | `ENVELOPE.md` §8     |
| Private metadata         | `brief.extensions`          | Recipient server and client only        | `ENVELOPE.md` §8     |
| Content                  | `enclosure.extensions`      | Recipient client only                   | `ENVELOPE.md` §8     |
| Discovery                | `configuration.extensions`  | Any querying server                     | `DISCOVERY.md` §3.1  |
| Handshake                | `init.extensions`           | Handshake participants                  | `HANDSHAKE.md`       |
| Delivery                 | `block_entry.extensions`    | Local server only (never transmitted)   | `DELIVERY.md` §4.2   |

Extensions at public layers (`postmark.extensions`, `seal.extensions`) are
visible to all routing servers and MUST be treated as public metadata. Extensions
at private layers (`brief.extensions`, `enclosure.extensions`) are protected by
the same encryption as their parent structure.

---

## 2. Extension Entry Structure

### 2.1 Schema

Each entry in an `extensions` object is keyed by a namespaced identifier and
contains a structured value with a `required` flag:

```json
{
    "extensions": {
        "semp.dev/priority": {
            "required": false,
            "data": {
                "level": "urgent"
            }
        },
        "semp.dev/expiry": {
            "required": true,
            "data": {
                "delete_after": "2025-07-01T00:00:00Z"
            }
        }
    }
}
```

### 2.2 Extension Entry Fields

| Field      | Type      | Required | Description                                                    |
|------------|-----------|----------|----------------------------------------------------------------|
| `required` | `boolean` | Yes      | Whether the recipient MUST understand this extension to process the envelope. See section 3. |
| `data`     | `object`  | Yes      | Extension-specific payload. Structure defined by the extension specification. |

### 2.3 Namespacing

Extension keys MUST be namespaced to prevent collision. Three namespaces are
defined:

| Namespace Pattern                    | Usage                                                       |
|--------------------------------------|-------------------------------------------------------------|
| `semp.dev/<name>`                    | Core extensions governed by the SEMP specification process.  |
| `vendor.example.com/<name>`          | Vendor-specific extensions. The domain MUST be controlled by the defining party. |
| `x-<name>`                           | Experimental extensions. No stability guarantees. MUST NOT be used in production deployments. |

Extension keys MUST NOT contain whitespace, path separators beyond the single
`/` after the namespace, or control characters. Maximum key length is 128
UTF-8 bytes.

---

## 3. Criticality Signaling

### 3.1 Required Extensions

When `required` is `true`, the recipient MUST understand and process the
extension to handle the envelope correctly. A recipient that encounters a
required extension it does not recognize MUST reject the envelope (or message,
handshake step, etc.) with reason code `extension_unsupported`.

The rejection MUST include the unrecognized extension key in the error response
so the sender can identify which extension caused the failure.

### 3.2 Optional Extensions

When `required` is `false`, the recipient SHOULD process the extension if it
understands it and MUST ignore it silently if it does not. An unrecognized
optional extension MUST NOT cause rejection.

### 3.3 Criticality and Layer Visibility

The `required` flag interacts with layer visibility:

| Layer                       | `required: true` rejected by             |
|-----------------------------|------------------------------------------|
| `postmark.extensions`       | Any routing server that does not understand it. |
| `seal.extensions`           | Any routing server that does not understand it. |
| `brief.extensions`          | Recipient server or recipient client.    |
| `enclosure.extensions`      | Recipient client only.                   |

Because required extensions at public layers (`postmark`, `seal`) can cause
rejection by any server in the routing path, senders SHOULD use `required: true`
at these layers only when the extension has achieved broad adoption. Premature
use of required public-layer extensions will cause delivery failures through
intermediate servers that have not yet implemented the extension.

### 3.4 Capability Pre-Negotiation

To avoid delivery failures from required extensions, senders SHOULD verify
that the recipient supports the extension before sending. Extension support
is advertised in two places:

- **Discovery capability documents** (`DISCOVERY.md` §3.1): the
  `extensions` field of the server's `SEMP_CONFIGURATION` document, and
  the `extensions` array in per-address `SEMP_DISCOVERY` results,
  advertise server-level extension support.
- **Handshake capabilities** (`HANDSHAKE.md`): the
  `capabilities.extensions` array in the handshake init and response
  messages advertises session-level extension support.

A sender that marks an extension as `required: true` without confirming
recipient support through capability negotiation accepts the risk of rejection.

---

## 4. Size Constraints

### 4.1 Per-Layer Extension Size Limits

Extensions are included in the signed canonical form of the envelope and are
parsed by every entity that processes the containing layer. Unbounded extension
payloads create both a computational burden (signature verification over
arbitrarily large inputs) and an abuse vector (resource exhaustion through
oversized envelopes).

The following size limits apply to the serialized JSON byte length of each
`extensions` object (the entire object, including all keys and values):

| Layer                       | Maximum Size | Rationale                                          |
|-----------------------------|--------------|----------------------------------------------------|
| `postmark.extensions`       | 4 KB         | Parsed by every routing server. Must be minimal.   |
| `seal.extensions`           | 4 KB         | Parsed by every routing server. Must be minimal.   |
| `brief.extensions`          | 16 KB        | Parsed by recipient server and client only.        |
| `enclosure.extensions`      | 64 KB        | Parsed by recipient client only. Largest scope.    |

These limits apply to the serialized UTF-8 JSON representation of the
`extensions` object at each layer, measured after encryption for the `brief`
and `enclosure` layers and before encryption for the `postmark` and `seal`
layers.

### 4.2 Enforcement

Servers MUST reject envelopes where any `extensions` object exceeds the size
limit for its layer. The rejection reason code is `extension_size_exceeded`.

Servers MAY enforce stricter limits than those defined above as a matter of
local policy. Servers MUST NOT enforce limits below the values in section 4.1,
as this would break interoperability with conformant senders.

### 4.3 Interaction with Envelope Size Limits

Extension size limits are independent of the overall envelope size limit
advertised in `DISCOVERY.md` §3.1 (`max_envelope_size`). An envelope may be
within the overall size limit but still be rejected if an individual
`extensions` object exceeds its layer limit.

---

## 5. Extension Registry

### 5.1 Purpose

The extension registry is the authoritative list of all defined SEMP
extensions. It prevents namespace collisions for `semp.dev/` extensions,
provides a single reference for implementers, and tracks the lifecycle status
of each extension.

### 5.2 Registry Entry Fields

Each registry entry contains:

| Field              | Description                                                            |
|--------------------|------------------------------------------------------------------------|
| Identifier         | Namespaced key (e.g., `semp.dev/message-expiry`).                      |
| Status             | Current lifecycle status (section 6).                                  |
| Layer(s)           | Which extension points the extension occupies.                         |
| Required-capable   | Whether the extension may be marked `required: true`.                  |
| Specification      | Reference to the defining document.                                    |
| Implementations    | Count and identity of independent implementations (section 7.2).       |
| Introduced         | Protocol version in which the extension was first registered.          |
| Deprecated         | Protocol version in which the extension was deprecated, if applicable. |

### 5.3 Vendor Extensions

Vendor-specific extensions (`vendor.example.com/<name>`) do not require
registry approval. The defining party is responsible for ensuring their
extensions do not conflict with `semp.dev/` extensions. Vendor extensions
MUST NOT use the `semp.dev/` namespace.

Vendor extensions that achieve broad adoption MAY be submitted to the registry
for consideration as core extensions under a `semp.dev/` identifier.

---

## 6. Extension Definition Documents

The wire-level extension entry (section 2) carries only an identifier, a
`required` flag, and a `data` payload. The interpretation of that payload,
the layers the extension may occupy, the dependencies it requires, and the
permissions it claims are defined in a separate **definition document**
fetched by identifier. The definition document is the authoritative
specification of an extension's structural contract.

### 6.1 Canonical URL Derivation

Every extension identifier MUST resolve to a fetchable definition document
at a derivable URL. The derivation rule depends on the namespace:

| Identifier              | Definition URL                                              |
|-------------------------|-------------------------------------------------------------|
| `semp.dev/<name>`       | `https://semp.dev/extensions/<name>.json`                   |
| `<vendor-host>/<name>`  | `https://<vendor-host>/extensions/<name>.json`              |
| `x-<name>`              | No derivation rule. Experimental extensions are not subject to definition document requirements. |

Implementations MUST be able to derive the definition URL from the
identifier without out-of-band configuration. A vendor publishing an
extension under their own namespace MUST serve the definition document at
the derived URL over HTTPS.

### 6.2 Definition Document Schema

The definition document is a JSON object with the following structure:

```json
{
    "identifier": "semp.dev/read-receipts",
    "spec_version": "1.0.0",
    "status": "standard",
    "specification_uri": "https://semp.dev/extensions/read-receipts.html",

    "placement": {
        "allowed_layers": ["brief", "enclosure"],
        "required_layer": "brief"
    },

    "data_schema": "https://semp.dev/extensions/read-receipts/schema.json",

    "authority": {
        "produced_by": ["sender_client", "recipient_client"],
        "consumed_by": ["recipient_client"]
    },

    "permissions": {
        "reads": ["brief.message_id", "brief.thread_id"],
        "writes": ["brief.extensions.semp.dev/read-receipts"],
        "triggers": ["read_event"]
    },

    "hooks": ["on_compose", "on_decrypt", "on_display"],

    "dependencies": [],
    "conflicts_with": [],

    "test_vectors": "https://semp.dev/extensions/read-receipts/vectors.json",
    "reference_implementations": [
        {
            "name": "semp-go",
            "uri": "https://github.com/semp-dev/semp-go",
            "module": "extensions/readreceipts"
        }
    ],

    "introduced": "1.0.0",
    "deprecated": null,

    "signature": {
        "algorithm": "ed25519",
        "key_id": "semp.dev-domain-key-fingerprint",
        "value": "base64-signature-over-canonical-document"
    }
}
```

### 6.3 Definition Document Fields

| Field                    | Type      | Required | Description                                                                       |
|--------------------------|-----------|----------|-----------------------------------------------------------------------------------|
| `identifier`             | `string`  | Yes      | The namespaced extension identifier. MUST match the URL the document is served from. |
| `spec_version`           | `string`  | Yes      | Semantic version of this definition document. Breaking changes require a new identifier. |
| `status`                 | `string`  | Yes      | Lifecycle status (section 11.1).                                                  |
| `specification_uri`      | `string`  | Yes      | URL of the human-readable specification document.                                 |
| `placement`              | `object`  | Yes      | Where this extension may appear. See section 6.4.                                 |
| `data_schema`            | `string`  | Yes      | URL of a JSON Schema document describing the structure of the `data` field.       |
| `authority`              | `object`  | Yes      | Which parties may produce and consume this extension. See section 6.5.            |
| `permissions`            | `object`  | Yes      | Declared read, write, and trigger scope. See section 6.6.                         |
| `hooks`                  | `array`   | Yes      | Processing points at which this extension participates. See section 6.7.          |
| `dependencies`           | `array`   | Yes      | Other extension identifiers required for this extension to be usable. MAY be empty. |
| `conflicts_with`         | `array`   | Yes      | Other extension identifiers that cannot coexist with this one. MAY be empty.      |
| `test_vectors`           | `string`  | No       | URL of a test vector document for conformance verification.                       |
| `reference_implementations` | `array` | No       | List of known reference implementations.                                         |
| `introduced`             | `string`  | Yes      | SEMP protocol version in which this extension was first registered.               |
| `deprecated`             | `string\|null` | Yes  | SEMP protocol version in which this extension was deprecated, or null.            |
| `signature`              | `object`  | Yes      | Signature over the canonical form of the document. See section 6.8.               |

### 6.4 Placement Object

| Field             | Type     | Required | Description                                                              |
|-------------------|----------|----------|--------------------------------------------------------------------------|
| `allowed_layers`  | `array`  | Yes      | Layers in which this extension MAY appear. Subset of: `postmark`, `seal`, `brief`, `enclosure`, `configuration`, `handshake`, `delivery`. |
| `required_layer`  | `string\|null` | Yes | Layer in which this extension MUST appear when present at all, or `null` if any allowed layer is acceptable. |

An extension entry that appears in a layer not listed in `allowed_layers`
MUST be treated as `extension_unsupported` regardless of `required` flag
state.

### 6.5 Authority Object

| Field          | Type    | Required | Description                                                                |
|----------------|---------|----------|----------------------------------------------------------------------------|
| `produced_by`  | `array` | Yes      | Roles that may add this extension to an envelope. Subset of: `sender_client`, `sender_server`, `recipient_server`, `recipient_client`. |
| `consumed_by`  | `array` | Yes      | Roles that act on this extension. Same vocabulary as `produced_by`.         |

A receiver MUST verify that the producing party of an extension matches
its declared `produced_by` roles. An extension whose authority is
`sender_client` but appears injected by a `recipient_server` MUST be
rejected with `extension_unsupported` and SHOULD be reported as
`protocol_abuse` (`REPUTATION.md` section 3.4).

### 6.6 Permissions Object

| Field      | Type    | Required | Description                                                                       |
|------------|---------|----------|-----------------------------------------------------------------------------------|
| `reads`    | `array` | Yes      | Field paths the extension reads. MAY be empty.                                    |
| `writes`   | `array` | Yes      | Field paths the extension writes. MUST include only paths under the extension's own entry, except for extensions that explicitly modify protocol-managed fields with prior governance approval. |
| `triggers` | `array` | Yes      | Application or protocol events the extension may emit. Vocabulary defined in the registry. |

Permissions are declared in JSON path notation rooted at the envelope
(`brief.message_id`, `enclosure.body`, etc.). The reference SDK
(section 9) enforces these declarations at runtime. Permissions outside
an extension's own data scope require explicit registry approval.

### 6.7 Hooks

The recognized hook vocabulary is:

| Hook            | When invoked                                                          |
|-----------------|-----------------------------------------------------------------------|
| `on_compose`    | Before envelope encryption, on the sender client.                     |
| `on_seal`       | After envelope encryption, before signature, on the sender server.    |
| `on_route`      | At each routing server, on the public envelope layers only.           |
| `on_deliver`    | At the recipient server, after seal verification.                     |
| `on_decrypt`    | At the recipient client, after enclosure decryption.                  |
| `on_display`    | At the recipient client, before user-visible rendering.               |
| `on_capability_negotiate` | During handshake capability advertisement.                  |

Future hooks MAY be defined by future SEMP protocol versions. Extensions
MUST NOT declare hooks that are not recognized by the SEMP version they
target.

### 6.8 Signature Requirement

The definition document MUST be signed by the namespace owner's domain
signing key (the same key used for SEMP routing per `KEY.md` section 2).
The signature covers the canonical JSON form of the document with the
`signature` field excluded.

The signature serves two purposes: it pins the document to a specific
version (preventing silent rewrites of an extension's contract), and it
anchors trust in the extension to the same domain identity that anchors
SEMP routing. An implementation that fetches a definition document MUST
verify the signature against the namespace owner's published domain key
before treating the document as authoritative.

A definition document with an invalid, missing, or unverifiable signature
MUST be treated as if the extension had no definition. Implementations
MUST reject any extension entry whose definition document fails signature
verification.

### 6.9 Resolution and Caching

Implementations resolve extension definitions by fetching the derived URL
the first time an unknown identifier is encountered. Definition documents
SHOULD be cached locally, with cache TTLs honored from HTTP `Cache-Control`
headers. In the absence of an explicit TTL, implementations SHOULD cache
for at least 24 hours.

A definition document MAY be re-fetched on demand if an implementation
observes behavior that contradicts the cached definition; the new document
MUST be signature-verified before replacing the cached copy.

The reference SDK (section 9) MAY ship with bundled definition documents
for `semp.dev/*` extensions to avoid runtime fetching during cold start.
Bundled definitions MUST still be signature-verified at load time.

---

## 7. Conflict Detection and Resolution

Conflicts between extensions fall into three categories with distinct
detection mechanisms.

### 7.1 Conflict Taxonomy

| Category    | Definition                                                                   | Detection                          |
|-------------|------------------------------------------------------------------------------|------------------------------------|
| Structural  | Two extensions with overlapping declared permissions or incompatible declared placement. | Static (registry, runtime).        |
| Declared    | Two extensions that declare each other in `conflicts_with`.                  | Runtime, on capability negotiation.|
| Behavioral  | Two extensions with semantically incompatible behavior not visible from declarations. | Governance and observation.        |

### 7.2 Structural Conflict Detection

Structural conflicts are detectable mechanically from definition documents.
The registry MUST run a structural conflict checker at submission time
that compares the new definition against all `standard` and `core`
extensions for:

1. Identifier collision within the same namespace.
2. `permissions.writes` paths overlapping with another extension's writes,
   excluding writes scoped under the extension's own identifier.
3. `placement.required_layer` collisions for extensions that share an
   identifier prefix or claim mutually exclusive layer ownership.
4. Hook ordering inconsistencies for extensions that target the same hook
   with declared assumptions about state visibility.

Structural conflicts identified at submission MUST block registry
acceptance until the conflict is resolved by either deprecation of an
existing extension (per the one-solution-per-problem rule, section 12.1)
or revision of the new submission.

Implementations MUST also enforce structural conflict detection at runtime.
An envelope containing two extensions whose declared write paths overlap
MUST be rejected with `extension_unsupported`.

### 7.3 Declared Conflicts

When an extension declares another in `conflicts_with`, the declaration
MUST be symmetric. Both extensions MUST list each other. The registry MUST
reject submissions with asymmetric conflict declarations.

At runtime, an implementation that processes an envelope containing both
sides of a declared conflict pair MUST reject the envelope with
`extension_unsupported`. The rejection MUST identify both conflicting
extension identifiers in the error response.

### 7.4 Behavioral Conflicts

Behavioral conflicts are not detectable from declarations. Two extensions
may have non-overlapping permissions and unrelated placement, yet produce
semantically incompatible results when combined. These conflicts surface
through implementation testing, deployment incidents, or user-observable
disagreement.

When a behavioral conflict is identified, the resolution path is
governance-driven:

1. The conflict is documented in both extensions' specifications via the
   `conflicts_with` field, made symmetric per section 7.3.
2. The next `spec_version` of each affected extension publishes the
   updated `conflicts_with` list.
3. Implementations re-fetch the updated definitions and apply the new
   declared conflict at runtime.

Behavioral conflicts that affect the security or correctness of envelope
processing SHOULD be reported as `protocol_abuse` observations
(`REPUTATION.md` section 3.4) when an implementation can demonstrate the
conflict in production.

---

## 8. Validation

Validation occurs at two distinct surfaces: static validation of
definition documents (registry-side), and runtime validation of extension
entries (per-envelope).

### 8.1 Static Validation

Every definition document MUST be validated at registry submission and
MAY be re-validated by any party fetching the document. Static validation
checks:

1. JSON Schema conformance against the canonical definition document
   schema (section 6.2).
2. Signature verification against the namespace owner's domain signing
   key (section 6.8).
3. Identifier consistency: the `identifier` field MUST match the URL the
   document is served from.
4. Internal consistency:
   - Every entry in `dependencies` MUST be a valid extension identifier
     resolvable to its own definition document.
   - Every entry in `conflicts_with` MUST be symmetric (section 7.3).
   - Every layer in `placement.allowed_layers` MUST be a defined SEMP
     extension layer (section 1).
   - Every hook in `hooks` MUST be a recognized hook name (section 6.7).
5. Cross-extension consistency: structural conflict checks against the
   registry (section 7.2).

A definition document that fails any static validation check MUST NOT be
accepted into the registry. Implementations that fetch a non-conformant
document MUST treat the extension as undefined.

### 8.2 Runtime Validation

Implementations MUST validate every received extension entry against its
definition document before processing. Runtime validation checks:

1. The `data` field conforms to the extension's `data_schema`.
2. The entry appears in a layer listed in `placement.allowed_layers`.
3. The producing party (inferred from envelope context) is listed in
   `authority.produced_by`.
4. All entries in `dependencies` are also present in the envelope or have
   been advertised in capability negotiation per section 3.4.
5. No entry from `conflicts_with` is present in the envelope.

Any runtime validation failure MUST result in `extension_unsupported`
rejection. The rejection MUST identify which validation rule failed and
which extension identifier was rejected.

### 8.3 Validation Failures

Validation failures are reported via the existing `extension_unsupported`
reason code (`ERRORS.md` section 3) with an extended diagnostic field:

```json
{
    "reason_code": "extension_unsupported",
    "reason": "Definition validation failed",
    "extension": "vendor.example.com/feature",
    "validation_failure": "data_schema_mismatch"
}
```

The `validation_failure` field is informational and aids debugging. Its
defined values are:

| Value                       | Meaning                                                              |
|-----------------------------|----------------------------------------------------------------------|
| `definition_unfetchable`    | The definition document could not be fetched.                        |
| `definition_signature_invalid` | Signature on the definition document is invalid.                  |
| `data_schema_mismatch`      | The `data` field does not conform to `data_schema`.                  |
| `placement_violation`       | The extension appeared in a layer not in `allowed_layers`.           |
| `authority_violation`       | The producing party is not in `authority.produced_by`.               |
| `dependency_unsatisfied`    | A required dependency is not present or not advertised.              |
| `conflict_present`          | A declared conflict is present in the envelope.                      |

---

## 9. Reference SDK Enforcement

The wire protocol cannot enforce internal implementation behavior. SEMP
ships a reference SDK that enforces declared extension contracts at the
language and library boundary, providing strong guarantees for
implementations that adopt it.

### 9.1 Enforcement Layers

SEMP defines four enforcement layers. Implementations choose the layer
appropriate to their threat model:

| Layer                        | Mechanism                                                               | Status                |
|------------------------------|-------------------------------------------------------------------------|-----------------------|
| Wire-level validation        | Cryptographic and schema checks defined in section 8.                   | MUST for all conformant implementations. |
| Reference SDK enforcement    | Permission and hook mediation in the SDK process. See section 9.2.      | RECOMMENDED. Strongly RECOMMENDED for `semp.dev/*` extensions handling sensitive data. |
| Cryptographic key scoping    | Per-extension enclosure key wrapping. See `ENVELOPE.md` section 7.4.    | OPTIONAL. Available for read-scope isolation of high-stakes extensions. |
| Sandbox attestation          | WASM or TEE isolation. See section 14 candidate extensions.             | OPTIONAL. Future extension layer.       |

### 9.2 Reference SDK Contract

A SEMP implementation that claims reference SDK conformance MUST provide
an extension API where:

1. Extensions declare their definition document URL at load time. The SDK
   fetches and verifies the definition before activating the extension.
2. All extension access to envelope state is mediated through host-provided
   accessor functions. Direct memory access to envelope structures is not
   exposed.
3. Each accessor function checks the calling extension's
   `permissions.reads` or `permissions.writes` against the requested field
   path. Access outside the declared permissions returns an error.
4. Extensions register for hooks via the host. The host invokes registered
   extensions only at their declared hook points. Extensions cannot run
   arbitrary code at undeclared points.
5. Extensions cannot register additional extensions, modify other
   extensions' state, or invoke host APIs not in their declared scope.

The reference SDK MUST log any access attempt that is denied due to
permission violation. Repeated denied attempts from a single extension MAY
be reported as `protocol_abuse` against the namespace owner that publishes
the extension.

### 9.3 Cryptographic Key Scoping

For extensions whose `data` field in the enclosure must be readable by
some devices but not others (for example, a classification result
intended for a filter device but not for the user's main reading device),
SEMP supports per-extension key wrapping in the seal. The wire format is
defined in `ENVELOPE.md` section 7.4. The reference SDK MUST surface
per-extension key scoping as a first-class option for extension authors.

This mechanism enforces read scope cryptographically, independent of any
SDK or sandbox guarantees. An extension whose enclosure data is wrapped
under a key not held by a given device cannot be read by that device,
full stop.

### 9.4 Sandboxing Layers

Stronger isolation through sandboxing or hardware attestation is defined
as candidate extensions (section 14): `semp.dev/wasm-extension` for
language-level sandboxing of extension code, and `semp.dev/tee-attestation`
for hardware-rooted execution attestation. These layers are opt-in and
appropriate for high-stakes deployments.

---

## 10. Trust Model

The SEMP extension framework concentrates trust at specific points rather
than attempting to eliminate it. Implementers, operators, and users
benefit from understanding what each layer does and does not guarantee.

### 10.1 What Is Enforced

The following properties are enforced by the protocol or by any
conformant implementation:

| Property                                                | Enforced By                                            |
|---------------------------------------------------------|--------------------------------------------------------|
| Identifier uniqueness within a namespace                | Namespace ownership (DNS/HTTPS for vendors, governance for `semp.dev/*`). |
| Definition document authenticity                        | Domain key signature (section 6.8).                    |
| Wire-level structure of `data`                          | Runtime validation against `data_schema` (section 8.2). |
| Layer placement                                         | Runtime validation against `placement.allowed_layers`. |
| Producing party                                         | Runtime validation against `authority.produced_by`.    |
| Dependency presence                                     | Capability negotiation and runtime validation.         |
| Declared conflict absence                               | Capability negotiation and runtime validation.         |
| Read scope (when cryptographic key scoping is used)     | Cryptographic key wrapping (section 9.3).              |

### 10.2 What Is Not Enforced

The following properties are not enforced by the wire protocol. They are
assumed to hold based on implementation honesty, observable behavior, and
abuse reporting:

| Property                                                | Trust Basis                                            |
|---------------------------------------------------------|--------------------------------------------------------|
| Internal data flow within an implementation             | Reference SDK (when used), implementer audit, operator attestation. |
| Side effects (logging, persistence, exfiltration)       | Operator policy, regulatory frameworks, observable misbehavior. |
| Hook discipline (running code only at declared hooks)   | Reference SDK (when used), code audit.                 |
| Behavioral correctness beyond test vectors              | Test coverage, governance review, deployment experience. |

### 10.3 Detection and Reporting

When an implementation behaves inconsistently with its declared extension
support (for example, misses a hook, mishandles `data`, leaks scoped
content), the misbehavior is detectable through one or more of:

1. **Test vector failure**: any party can run published test vectors
   against the implementation's responses.
2. **Observable inconsistency**: peer implementations and users can
   observe outcomes that contradict the declared behavior.
3. **Cryptographic violation**: any wire-level violation (signature
   failure, layer placement, authority mismatch) is provable from the
   captured envelope alone.

Detected misbehavior SHOULD be reported via `SEMP_ABUSE_REPORT` under
the `protocol_abuse` category (`REPUTATION.md` section 3.4). Reports MAY
include the captured envelope or test vector output as
self-authenticating evidence. Patterns of misbehavior across multiple
unrelated sessions MAY result in trust gossip observations against the
implementation's operator.

The trust model is honest about its scope. Users and operators who
require stronger guarantees than the protocol provides SHOULD adopt one
of the optional enforcement layers (cryptographic key scoping, WASM
sandboxing, or TEE attestation) appropriate to their threat model.

---

## 11. Extension Lifecycle

### 11.1 Status Definitions

| Status           | Meaning                                                                                      |
|------------------|----------------------------------------------------------------------------------------------|
| `experimental`   | Defined by any party. No stability guarantees. May change or be withdrawn without notice. Not suitable for production use. |
| `proposed`       | Formally submitted to the registry. Under review. Specification is public and stable enough for trial implementation. |
| `standard`       | Accepted into the registry. Implementations SHOULD support it. Specification is stable. Breaking changes require a new extension identifier. |
| `core`           | Promoted into the core protocol specification in a major version. Implementations MUST support it. No longer optional. |
| `deprecated`     | Superseded or found unsuitable. Implementations SHOULD phase out support. New deployments MUST NOT depend on it. |
| `retired`        | Removed from the registry. Implementations MUST ignore it if encountered. The identifier MUST NOT be reused. |

### 11.2 Status Transitions

```
experimental → proposed → standard → core
                                   ↘
                             deprecated → retired
```

An extension MAY move directly from `experimental` to `deprecated` if it is
found unsuitable during experimentation. An extension MUST NOT skip from
`experimental` directly to `standard`; the `proposed` stage ensures public
review.

An extension in `core` status cannot be deprecated without a major protocol
version change.

### 11.3 Promotion to Core

When a new major version of the SEMP protocol is defined, extensions that have
achieved universal adoption are candidates for promotion to `core`. Promotion
means the extension's semantics are incorporated into the relevant core
specification (`ENVELOPE.md`, `HANDSHAKE.md`, etc.) and compliance with the
extension becomes mandatory.

Promotion criteria:

- The extension MUST be in `standard` status.
- The extension MUST have at least three independent implementations in
  production use.
- The extension MUST have been in `standard` status for at least one year.
- There MUST be rough consensus among implementers that the extension
  belongs in the core.

Promotion is the mechanism by which SEMP's core grows over time. Extensions
are a staging ground, not a permanent home.

---

## 12. Anti-Fragmentation Rules

### 12.1 One Solution Per Problem

The registry MUST NOT accept a new `semp.dev/` extension that addresses the
same problem as an existing `standard` or `core` extension unless the existing
extension is formally deprecated as part of the same proposal. Competing
solutions to the same problem cause ecosystem fragmentation and
interoperability failures.

If a proposed extension offers a better approach to a problem already addressed
by an existing extension, the proposal MUST include a deprecation plan for
the existing extension and a migration path for implementations that already
support it.

Vendor extensions are exempt from this rule. Vendors may experiment freely in
their own namespace. However, if a vendor extension is submitted for registry
inclusion as a `semp.dev/` extension, the one-solution-per-problem rule
applies at that point.

### 12.2 Implementation Requirement

No extension may advance from `proposed` to `standard` without at least two
independent implementations that interoperate successfully. An "independent
implementation" means developed by different parties without shared codebases.
This rule prevents paper extensions that no one builds.

### 12.3 Standard Extension Cap

The registry SHOULD maintain no more than twenty extensions in `standard`
status at any given time. This cap forces prioritization: promoting a new
extension to `standard` when the cap is reached requires either promoting an
existing standard extension to `core` or deprecating one.

The cap is a governance guideline, not a hard protocol constraint.
Exceeding it requires explicit justification and consensus among the
governing body. The intent is to create convergence pressure: a bounded
set of well-supported extensions rather than an unbounded constellation of
optional features.

### 12.4 Thick Core Principle

SEMP's core specification is intentionally comprehensive. Encryption,
metadata protection, blocking, reputation, delivery semantics, key management,
and session security are all part of the core protocol, not extensions. Two
conformant SEMP implementations can exchange sealed envelopes with full
security properties without negotiating a single extension.

Extensions exist for capabilities that are genuinely optional, features
where reasonable deployments may differ in their needs. Extensions MUST NOT
be used to defer core functionality that all implementations require.

---

## 13. Security Considerations

### 13.1 Public-Layer Extension Privacy

Extensions in `postmark.extensions` and `seal.extensions` are visible to every
server that handles the envelope in transit. Senders MUST NOT place private
metadata in public-layer extensions. Information that identifies specific users,
reveals message content, or exposes communication patterns beyond what the
postmark already reveals MUST be placed in `brief.extensions` or
`enclosure.extensions`.

### 13.2 Extension Size as Attack Vector

Without size constraints, a malicious sender could place arbitrarily large
payloads in `postmark.extensions`, forcing every routing server to parse and
include them in signature verification. The size limits in section 4 bound
this attack. Servers MUST enforce these limits before performing signature
verification. The size check is a pre-parse validation that prevents
resource exhaustion.

### 13.3 Required Extensions as Denial of Service

A malicious sender could mark an extension as `required: true` knowing the
recipient does not support it, causing guaranteed rejection. This is mitigated
by the capability pre-negotiation mechanism (section 3.4) and by the fact that
the sender gains nothing from causing a rejection of their own message.

In the case of routing-layer extensions (`postmark.extensions`), a required
extension that is not broadly supported would cause rejection at intermediate
servers, making the envelope undeliverable. Senders bear the cost of this
failure. Servers SHOULD log rejections caused by unsupported required
extensions to help operators identify misconfigured senders.

### 13.4 Malicious Extension Definitions

A vendor extension could be designed to exfiltrate data, exploit parsing
vulnerabilities, or introduce backdoors. Implementations MUST NOT execute
code contained in extension payloads. Extension `data` fields are passive
data structures, not executable content. Implementations SHOULD validate
extension payloads against the expected schema before processing.

---

## 14. Candidate Extensions

The following extensions are anticipated for early definition. Their inclusion
here does not constitute a commitment; each will be specified independently
once this framework is established.

| Candidate                     | Layer         | Description                                                                    |
|-------------------------------|---------------|--------------------------------------------------------------------------------|
| MLS group key agreement       | seal, brief   | Binding to RFC 9420 for large-group key management. See `ENVELOPE.md` §4.4.   |
| Read receipts                 | brief         | Delivery and read confirmation signaling between clients.                      |
| Message editing               | enclosure     | Replacement semantics for previously sent envelopes.                           |
| Message expiry                | brief         | Sender-requested deletion after a specified time.                              |
| Reactions                     | enclosure     | Lightweight response annotations on existing messages.                         |
| Priority hints                | postmark      | Delivery urgency signaling visible to routing servers.                         |
| Content negotiation           | enclosure     | Sender capability advertisement for rich content formats.                      |
| Device sync marker            | brief         | `semp.dev/device-sync`. Core marker identifying an envelope as device sync traffic rather than correspondence. See `CLIENT.md` §4.5. |
| New device onboarding         | enclosure     | QR-code or code-based authorization, identity key transfer, and initial registration payload exchanged between an existing device and a newly joining device. Builds on `KEY.md` §10.1. |
| Historical mail rewrap        | enclosure     | Rewrapped `K_brief` and `K_enclosure` seal entries sent from an existing device to a new device so the new device can decrypt mail received before its keys existed. Builds on `CLIENT.md` §4.4.1. |
| Read-state synchronization    | enclosure     | Per-envelope read, unread, and archive state propagated between the user's own devices. |
| Draft synchronization         | enclosure     | In-progress compose state propagated between the user's own devices. |
| Classification result         | enclosure     | `semp.dev/classification-result`. Label and confidence payload produced by a delegated filter device. See `CLIENT.md` §4.5.3. |

The following extensions define stronger isolation layers for high-stakes
deployments. They build on the reference SDK enforcement contract (section 9)
and are anticipated as future core candidates rather than near-term
proposals. They are listed here to reserve their identifiers and signal the
direction of the enforcement layer.

| Candidate                     | Layer            | Description                                                                    |
|-------------------------------|------------------|--------------------------------------------------------------------------------|
| WASM extension sandbox        | sdk (host-side)  | `semp.dev/wasm-extension`. Runs an extension as a WebAssembly module with capability-based imports. The host runtime enforces memory isolation and import scope at the bytecode level. Extensions distributed as signed `.wasm` modules. Provides language-level isolation for extension code without trusting the implementation language or runtime. Aligns with the Component Model and WASI Preview 2 capability scoping. |
| TEE attestation               | sdk (host-side)  | `semp.dev/tee-attestation`. Wraps an extension or an entire SEMP implementation in a Trusted Execution Environment (Intel SGX, AMD SEV-SNP, ARM CCA, Apple Secure Enclave). Peers verify hardware attestation that a specific code measurement is running in a TEE. Provides hardware-rooted execution attestation for parties whose threat model includes a compromised host operating system. |

---

## 15. Relationship to Other Specifications

| Specification   | Relationship                                                                               |
|-----------------|--------------------------------------------------------------------------------------------|
| `DESIGN.md`     | Extensibility is a governing design principle (§2.5).                                      |
| `ENVELOPE.md`   | Defines the per-layer extension fields and current extension rules (§8). Extension size is included in the canonical form covered by `seal.signature` (§4.3). Per-extension cryptographic key scoping defined in §7.4. |
| `HANDSHAKE.md`  | Capability negotiation during session establishment is the primary extension negotiation point. |
| `DISCOVERY.md`  | Capability documents advertise supported extensions (§3.1).                                |
| `KEY.md`        | Extension definition documents are signed with the namespace owner's domain key (§2). |
| `REPUTATION.md` | Extension misbehavior is reportable as `protocol_abuse` (§3.4).                           |
| `CONFORMANCE.md`| Extensibility conformance requirements (§4.9).                                             |
| `ERRORS.md`     | `extension_unsupported` and `extension_size_exceeded` reason codes originate here. The `validation_failure` diagnostic vocabulary is defined in §8.3 of this document. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
