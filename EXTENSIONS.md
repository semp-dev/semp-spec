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

- **Discovery capability documents** (`DISCOVERY.md` §3.1): the `features`
  array and `extensions` field advertise server-level extension support.
- **Handshake capabilities** (`HANDSHAKE.md`): the `capabilities` field in
  the handshake init and response messages advertises session-level extension
  support.

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
advertised in `DISCOVERY.md` §3.1 (`max_message_size`). An envelope may be
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

## 6. Extension Lifecycle

### 6.1 Status Definitions

| Status           | Meaning                                                                                      |
|------------------|----------------------------------------------------------------------------------------------|
| `experimental`   | Defined by any party. No stability guarantees. May change or be withdrawn without notice. Not suitable for production use. |
| `proposed`       | Formally submitted to the registry. Under review. Specification is public and stable enough for trial implementation. |
| `standard`       | Accepted into the registry. Implementations SHOULD support it. Specification is stable. Breaking changes require a new extension identifier. |
| `core`           | Promoted into the core protocol specification in a major version. Implementations MUST support it. No longer optional. |
| `deprecated`     | Superseded or found unsuitable. Implementations SHOULD phase out support. New deployments MUST NOT depend on it. |
| `retired`        | Removed from the registry. Implementations MUST ignore it if encountered. The identifier MUST NOT be reused. |

### 6.2 Status Transitions

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

### 6.3 Promotion to Core

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

## 7. Anti-Fragmentation Rules

### 7.1 One Solution Per Problem

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

### 7.2 Implementation Requirement

No extension may advance from `proposed` to `standard` without at least two
independent implementations that interoperate successfully. An "independent
implementation" means developed by different parties without shared codebases.
This rule prevents paper extensions that no one builds.

### 7.3 Standard Extension Cap

The registry SHOULD maintain no more than twenty extensions in `standard`
status at any given time. This cap forces prioritization: promoting a new
extension to `standard` when the cap is reached requires either promoting an
existing standard extension to `core` or deprecating one.

The cap is a governance guideline, not a hard protocol constraint.
Exceeding it requires explicit justification and consensus among the
governing body. The intent is to create convergence pressure: a bounded
set of well-supported extensions rather than an unbounded constellation of
optional features.

### 7.4 Thick Core Principle

SEMP's core specification is intentionally comprehensive. Encryption,
metadata protection, blocking, reputation, delivery semantics, key management,
and session security are all part of the core protocol, not extensions. Two
conformant SEMP implementations can exchange sealed envelopes with full
security properties without negotiating a single extension.

Extensions exist for capabilities that are genuinely optional, features
where reasonable deployments may differ in their needs. Extensions MUST NOT
be used to defer core functionality that all implementations require.

---

## 8. Security Considerations

### 8.1 Public-Layer Extension Privacy

Extensions in `postmark.extensions` and `seal.extensions` are visible to every
server that handles the envelope in transit. Senders MUST NOT place private
metadata in public-layer extensions. Information that identifies specific users,
reveals message content, or exposes communication patterns beyond what the
postmark already reveals MUST be placed in `brief.extensions` or
`enclosure.extensions`.

### 8.2 Extension Size as Attack Vector

Without size constraints, a malicious sender could place arbitrarily large
payloads in `postmark.extensions`, forcing every routing server to parse and
include them in signature verification. The size limits in section 4 bound
this attack. Servers MUST enforce these limits before performing signature
verification. The size check is a pre-parse validation that prevents
resource exhaustion.

### 8.3 Required Extensions as Denial of Service

A malicious sender could mark an extension as `required: true` knowing the
recipient does not support it, causing guaranteed rejection. This is mitigated
by the capability pre-negotiation mechanism (section 3.4) and by the fact that
the sender gains nothing from causing a rejection of their own message.

In the case of routing-layer extensions (`postmark.extensions`), a required
extension that is not broadly supported would cause rejection at intermediate
servers, making the envelope undeliverable. Senders bear the cost of this
failure. Servers SHOULD log rejections caused by unsupported required
extensions to help operators identify misconfigured senders.

### 8.4 Malicious Extension Definitions

A vendor extension could be designed to exfiltrate data, exploit parsing
vulnerabilities, or introduce backdoors. Implementations MUST NOT execute
code contained in extension payloads. Extension `data` fields are passive
data structures, not executable content. Implementations SHOULD validate
extension payloads against the expected schema before processing.

---

## 9. Candidate Extensions

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

---

## 10. Relationship to Other Specifications

| Specification   | Relationship                                                                               |
|-----------------|--------------------------------------------------------------------------------------------|
| `DESIGN.md`     | Extensibility is a governing design principle (§2.5).                                      |
| `ENVELOPE.md`   | Defines the per-layer extension fields and current extension rules (§8). Extension size is included in the canonical form covered by `seal.signature` (§4.3). |
| `HANDSHAKE.md`  | Capability negotiation during session establishment is the primary extension negotiation point. |
| `DISCOVERY.md`  | Capability documents advertise supported extensions (§3.1).                                |
| `CONFORMANCE.md`| Extensibility conformance requirements (§4.9).                                             |
| `ERRORS.md`     | `extension_unsupported` and `extension_size_exceeded` reason codes originate here.         |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
