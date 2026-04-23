# SEMP Media Types and File Formats

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `DESIGN.md`, `ENVELOPE.md`, `DELIVERY.md`, `RECOVERY.md`, `MIGRATION.md`

---

## Abstract

This specification defines media type registrations and file formats for
user-facing SEMP artifacts. It establishes `application/semp-envelope` and
`.semp` for envelope files, `application/semp-receipt` and `.semp-receipt`
for signed delivery receipts, `application/semp-recovery` and
`.semp-recovery` for recovery bundles, and `application/semp-migration`
and `.semp-migration` for migration records.

Only user-facing artifacts receive media types. Handshake traffic,
discovery configuration documents, key records, and other live-fetch
artifacts are JSON documents exchanged over HTTP with `application/json`
or as payloads within a session, and do not define independent media types.

---

## 1. Media Type Registration

### 1.1 MIME Type

The MIME type for SEMP envelopes is:

```
application/semp-envelope
```

This type identifies a serialized SEMP envelope as defined in `ENVELOPE.md`.
It applies to envelopes transmitted over HTTP, HTTP/2, QUIC, and WebSocket
transports, as well as envelopes stored as files.

### 1.2 Registration Template

The following registration template follows the format specified in RFC 6838.

| Field                  | Value                                                    |
|------------------------|----------------------------------------------------------|
| Type name              | `application`                                            |
| Subtype name           | `semp-envelope`                                          |
| Required parameters    | None                                                     |
| Optional parameters    | `version`: SEMP protocol version (semver). Defaults to the version declared in the envelope's `version` field. |
| Encoding considerations| 8bit. The envelope is a UTF-8 JSON object. Binary content within the envelope (encrypted brief, encrypted enclosure, key material) is base64-encoded within the JSON structure. |
| Security considerations| See section 5.                                           |
| Interoperability considerations | See section 4.                                  |
| Published specification| This document and `ENVELOPE.md`.                         |
| Fragment identifier    | None                                                     |

### 1.3 Content-Type Usage

Servers MUST use `application/semp-envelope` as the `Content-Type` header when
transmitting envelopes over HTTP-based transports:

```
Content-Type: application/semp-envelope
```

Servers SHOULD include the `charset=utf-8` parameter:

```
Content-Type: application/semp-envelope; charset=utf-8
```

WebSocket frames carrying SEMP envelopes MUST use text frames (opcode 0x1),
as the content is UTF-8 JSON.

---

## 2. File Format

### 2.1 File Extension

The file extension for serialized SEMP envelopes is:

```
.semp
```

A `.semp` file contains exactly one SEMP envelope serialized as a UTF-8 JSON
object. The JSON structure is identical to the on-the-wire format defined in
`ENVELOPE.md` section 2.1.

### 2.2 File Structure

A `.semp` file is a complete, self-contained SEMP envelope:

```json
{
    "type": "SEMP_ENVELOPE",
    "version": "1.0.0",
    "postmark": { ... },
    "seal": { ... },
    "brief": "<base64-encoded-encrypted-bytes>",
    "enclosure": "<base64-encoded-encrypted-bytes>"
}
```

The file MUST contain valid JSON. The file MUST be encoded as UTF-8 without a
byte order mark (BOM). The file SHOULD use the canonical serialization defined
in `ENVELOPE.md` section 4.3 (lexicographically sorted keys, no insignificant
whitespace) but MAY use pretty-printed JSON for human inspection. Seal
verification MUST always be performed against the canonical form regardless of
the file's whitespace formatting.

### 2.3 Multiple Envelopes

A `.semp` file contains exactly one envelope. Applications that need to store
multiple envelopes MUST use one file per envelope or use an archive format
(`.tar`, `.zip`) containing multiple `.semp` files.

A future extension MAY define a `.sempb` (SEMP bundle) format for efficient
multi-envelope storage. This is not defined in this specification.

---

## 3. File Semantics

### 3.1 Security Properties at Rest

A `.semp` file preserves the full security model of the envelope:

| Component     | State in file       | Readable by                              |
|---------------|---------------------|------------------------------------------|
| `postmark`    | Plaintext JSON      | Anyone with access to the file.          |
| `seal`        | Plaintext JSON      | Anyone with access to the file. Signature and MAC are verifiable by any party with the appropriate keys. |
| `brief`       | Encrypted (base64)  | Recipient server (via domain key) and recipient client (via encryption key). |
| `enclosure`   | Encrypted (base64)  | Recipient client only.                   |

A party that obtains a `.semp` file can:

- Read the postmark (sender domain, recipient domain, expiry, session ID).
- Verify `seal.signature` against the sender's published domain key, confirming
  the envelope was produced by the claimed domain.
- Confirm that the envelope has not been tampered with since creation.

A party that obtains a `.semp` file cannot (without the appropriate private keys):

- Read the brief (sender address, recipient addresses, timestamps, threading).
- Read the enclosure (subject, body, attachments).

This makes `.semp` files suitable as evidence artifacts. A user can share a
`.semp` file to prove that a domain sent an envelope at a certain time without
revealing the message content. The recipient of the file can independently
verify the domain signature using the sender's published key.

### 3.2 Verification Without Decryption

Applications that handle `.semp` files SHOULD offer a verification mode that
checks `seal.signature` against the sender's domain key without attempting
decryption. This allows third parties to verify envelope authenticity and
integrity without access to private key material.

`seal.session_mac` cannot be verified from a file alone because it requires
the session key (`K_env_mac`), which is ephemeral and erased after the session
ends per `SESSION.md` section 2. This is expected. The session MAC proves
the envelope was delivered within a valid session, a property that is
meaningful at delivery time, not at rest.

### 3.3 Opening a `.semp` File

When a client application opens a `.semp` file:

1. Parse the JSON and validate that `type` is `"SEMP_ENVELOPE"`.
2. Verify `seal.signature` against the sender's published domain key.
3. Attempt to decrypt `K_brief` from `seal.brief_recipients` using each of
   the user's active private encryption keys.
4. If step 3 succeeds, decrypt the `brief` and display message metadata.
5. Attempt to decrypt `K_enclosure` from `seal.enclosure_recipients` using
   each of the user's active private encryption keys.
6. If step 5 succeeds, decrypt the `enclosure` and display message content.
7. If steps 3 or 5 fail, display what is available (postmark, seal
   verification result) and indicate that the user is not a recipient of
   this envelope.

### 3.4 Exporting Envelopes

SEMP clients SHOULD support exporting received envelopes as `.semp` files.
The exported file is the envelope exactly as received: postmark, seal,
encrypted brief, and encrypted enclosure. The client MUST NOT export
decrypted content into the `.semp` file. The file preserves the envelope's
security properties at rest.

If the user needs to export decrypted content (for example, for legal
discovery or personal archival), the client SHOULD export it in a separate
format (plaintext, PDF, or similar) with a clear indication that the exported
content is no longer cryptographically protected.

---

## 4. Interoperability Considerations

### 4.1 Version Handling

Applications that encounter a `.semp` file with an unrecognized `version`
value SHOULD attempt to parse it as best-effort rather than rejecting it
outright. The top-level envelope structure is stable across versions. Unknown
fields SHOULD be preserved and ignored, consistent with SEMP's extensibility
rules.

### 4.2 Character Encoding

`.semp` files MUST be UTF-8. Applications MUST reject files that are not valid
UTF-8. Applications MUST NOT assume or attempt other encodings.

### 4.3 Maximum File Size

The maximum size of a `.semp` file is bounded by the maximum envelope size
advertised by the recipient's server in `DISCOVERY.md` section 3.1
(`max_envelope_size`). For files created by export (section 3.4), the maximum
size is the size of the original envelope. Applications SHOULD handle files
up to at least 25 MB, consistent with common maximum envelope sizes.

### 4.4 Operating System Integration

Applications that register to handle `.semp` files SHOULD register the
following:

- File extension: `.semp`
- MIME type: `application/semp-envelope`
- UTI (Apple platforms): `org.semp.envelope`
- File type description: "SEMP Envelope"

---

## 5. Security Considerations

### 5.1 File Access Control

A `.semp` file exposes the postmark in plaintext, including sender and
recipient domains. While this is less sensitive than the full brief, it still
reveals that two domains corresponded. Users who require domain-level privacy
SHOULD store `.semp` files in encrypted storage.

### 5.2 Seal Verification and Trust

Verifying `seal.signature` on a `.semp` file confirms the envelope was
produced by the claimed sender domain. It does NOT confirm that the envelope
was successfully delivered, that the intended recipient received it, or that
the content has not been selectively omitted (an attacker could create a valid
envelope with arbitrary content and a valid domain signature if they control
the domain). Seal verification proves provenance, not delivery or truthfulness.

### 5.3 Encrypted Content Extraction

Applications MUST NOT cache or store decrypted brief or enclosure content
alongside the `.semp` file. The security value of the file format depends on
the encrypted content remaining encrypted at rest. Decrypted content that is
written to disk MUST be in a separate file under the user's explicit control,
not as metadata or a sidecar to the `.semp` file.

### 5.4 Parsing Safety

Applications parsing `.semp` files MUST validate JSON structure before
processing. Malformed JSON, excessively nested objects, or unexpectedly large
fields could be used for denial-of-service attacks. Applications SHOULD impose
reasonable limits on parsing depth and field sizes consistent with the envelope
size limits defined in `ENVELOPE.md` and `EXTENSIONS.md` section 4.

---

## 6. Delivery Receipt Media Type

### 6.1 MIME Type and File Extension

| Attribute           | Value                            |
|---------------------|----------------------------------|
| MIME type           | `application/semp-receipt`       |
| File extension      | `.semp-receipt`                  |
| UTI (Apple)         | `org.semp.receipt`               |
| File description    | "SEMP Delivery Receipt"          |

A `.semp-receipt` file contains exactly one signed delivery receipt as
defined in `DELIVERY.md` section 1.1.1, serialized as a UTF-8 JSON object.
One receipt per file.

### 6.2 Registration Template

| Field                  | Value                                                    |
|------------------------|----------------------------------------------------------|
| Type name              | `application`                                            |
| Subtype name           | `semp-receipt`                                           |
| Required parameters    | None                                                     |
| Optional parameters    | `version`: receipt format version (semver). Defaults to the version declared in the receipt's `version` field. |
| Encoding considerations| 8bit. UTF-8 JSON object. Signature bytes are base64-encoded within the JSON structure. |
| Security considerations| See section 6.4.                                         |
| Interoperability considerations | The receipt format is defined in `DELIVERY.md` section 1.1.1.1 and is stable across SEMP versions per the extensibility rules in `DESIGN.md` section 2.5. |
| Published specification| This document and `DELIVERY.md`.                         |
| Fragment identifier    | None                                                     |

### 6.3 File Semantics

A `.semp-receipt` file is a portable evidence artifact. The holder of the
file, together with the recipient domain's published signing key, can
verify per `DELIVERY.md` section 1.1.1.7 that the recipient domain
accepted a specific envelope at a specific time.

Clients SHOULD offer an export action that writes a received receipt as a
`.semp-receipt` file. Clients SHOULD offer a verification action that
opens a `.semp-receipt` file and reports the receipt's signature status,
recipient domain, accepted-at time, and envelope hash.

A `.semp-receipt` file does not contain the envelope it attests to. A
holder who also possesses the `.semp` envelope file can additionally
confirm that the receipt's `envelope_hash` matches the canonical envelope
bytes.

### 6.4 Security Considerations

A `.semp-receipt` file is a cryptographically binding statement by the
recipient domain that it accepted the referenced envelope. Distribution
of the file is uncontrolled by the recipient domain once issued. Operator
liability considerations are documented in `DELIVERY.md` section 9.4.

The receipt exposes the recipient domain, the canonical envelope hash,
and the accepted-at time. It does not expose postmark contents, brief
contents, enclosure contents, or any identifiers beyond the canonical
hash. A holder who does not also hold the envelope cannot reconstruct
what the envelope contained.

---

## 7. Recovery Bundle Media Type

### 7.1 MIME Type and File Extension

| Attribute           | Value                            |
|---------------------|----------------------------------|
| MIME type           | `application/semp-recovery`      |
| File extension      | `.semp-recovery`                 |
| UTI (Apple)         | `org.semp.recovery`              |
| File description    | "SEMP Recovery Bundle"           |

A `.semp-recovery` file contains one recovery bundle as defined in
`RECOVERY.md`. The bundle is a user-exportable artifact used to restore
identity key material after device loss.

### 7.2 Registration Template

| Field                  | Value                                                    |
|------------------------|----------------------------------------------------------|
| Type name              | `application`                                            |
| Subtype name           | `semp-recovery`                                          |
| Required parameters    | None                                                     |
| Optional parameters    | `version`: recovery bundle format version (semver).      |
| Encoding considerations| 8bit. UTF-8 JSON object. Binary fields are base64-encoded within the JSON structure. |
| Security considerations| See section 7.4.                                         |
| Interoperability considerations | The bundle format is defined in `RECOVERY.md`. |
| Published specification| This document and `RECOVERY.md`.                         |
| Fragment identifier    | None                                                     |

### 7.3 File Semantics

A recovery bundle contains key material protected by user-supplied
passphrase derivation and, for server-assisted bundles, by server-held
unlock material. Possession of the file alone is insufficient to recover
the identity; the recovery flow requires additional inputs per
`RECOVERY.md`.

Clients SHOULD offer an export action that writes a recovery bundle as a
`.semp-recovery` file. Clients SHOULD offer an import action that accepts
a `.semp-recovery` file and initiates the restore flow.

### 7.4 Security Considerations

A `.semp-recovery` file contains protected key material. A holder with
sufficient resources and access to additional recovery inputs (passphrase,
Shamir shares, server cooperation) may be able to recover the associated
identity keys. Users SHOULD store recovery bundles on encrypted media and
SHOULD NOT transmit them over unauthenticated channels.

The protection model and attack boundary for recovery bundles are defined
in `RECOVERY.md`.

---

## 8. Migration Record Media Type

### 8.1 MIME Type and File Extension

| Attribute           | Value                            |
|---------------------|----------------------------------|
| MIME type           | `application/semp-migration`     |
| File extension      | `.semp-migration`                |
| UTI (Apple)         | `org.semp.migration`             |
| File description    | "SEMP Migration Record"          |

A `.semp-migration` file contains one migration record as defined in
`MIGRATION.md` section 3. The record is a signed, publicly verifiable
artifact linking an old address and identity key to a new address and
identity key.

### 8.2 Registration Template

| Field                  | Value                                                    |
|------------------------|----------------------------------------------------------|
| Type name              | `application`                                            |
| Subtype name           | `semp-migration`                                         |
| Required parameters    | None                                                     |
| Optional parameters    | `version`: migration record format version (semver).     |
| Encoding considerations| 8bit. UTF-8 JSON object. Signature bytes are base64-encoded within the JSON structure. |
| Security considerations| See section 8.4.                                         |
| Interoperability considerations | The record format is defined in `MIGRATION.md` section 3.1. |
| Published specification| This document and `MIGRATION.md`.                        |
| Fragment identifier    | None                                                     |

### 8.3 File Semantics

A `.semp-migration` file is independently verifiable against the published
domain signing keys of the old and new providers and the identity keys
named in the record. Users MAY distribute the file out of band to
correspondents who wish to verify continuity without performing a live
fetch from the new provider's `migration` endpoint.

Clients SHOULD offer an export action that writes a verified migration
record as a `.semp-migration` file. Clients SHOULD offer an import action
that opens a `.semp-migration` file and performs verification per
`MIGRATION.md` section 7.1 before presenting the record to the user.

### 8.4 Security Considerations

A migration record is a public artifact by design. Its contents expose the
old and new addresses, the old and new identity key identifiers, and the
timestamps of the migration. Users requiring migration without public
announcement MUST NOT use this mechanism, per `MIGRATION.md` section 10.1.

Verification of a `.semp-migration` file establishes continuity of identity
only if every signature in the record verifies against the appropriate
published key. A file whose signatures do not verify MUST NOT be treated
as authoritative.

---

## 9. Relationship to Other Specifications

| Specification  | Relationship                                                                     |
|----------------|----------------------------------------------------------------------------------|
| `DESIGN.md`    | The envelope model (section 4) defines the conceptual structure that `.semp` files serialize. Evidence properties (section 4.5) define what each artifact proves. |
| `ENVELOPE.md`  | Defines the envelope schema, field semantics, canonicalization, and encryption model that `.semp` files contain. |
| `DELIVERY.md`  | Defines the signed delivery receipt schema (section 1.1.1) that `.semp-receipt` files contain. |
| `RECOVERY.md`  | Defines the recovery bundle schema that `.semp-recovery` files contain.          |
| `MIGRATION.md` | Defines the migration record schema (section 3) that `.semp-migration` files contain. |
| `SESSION.md`   | Session key ephemerality (section 2) explains why `seal.session_mac` cannot be verified from a `.semp` file at rest. |
| `KEY.md`       | Domain key publication (section 2) enables verification of `.semp`, `.semp-receipt`, and `.semp-migration` files by third parties. |
| `TRANSPORT.md` | Transport bindings (section 4) use `application/semp-envelope` as the content type for envelope transmission. |
| `EXTENSIONS.md`| Extension size limits (section 4) apply to envelopes within `.semp` files. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
