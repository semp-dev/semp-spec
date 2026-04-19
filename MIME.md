# SEMP Media Type and File Format

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `DESIGN.md`, `ENVELOPE.md`

---

## Abstract

This specification defines the media type registration and file format for
SEMP envelopes. It establishes `application/semp-envelope` as the MIME type
for SEMP envelopes on the wire and at rest, and `.semp` as the file extension
for serialized envelope files.

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
| Optional parameters    | `version` — SEMP protocol version (semver). Defaults to the version declared in the envelope's `version` field. |
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
ends per `SESSION.md` section 2. This is expected — the session MAC proves
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
The exported file is the envelope exactly as received — postmark, seal,
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

## 6. Relationship to Other Specifications

| Specification  | Relationship                                                                     |
|----------------|----------------------------------------------------------------------------------|
| `DESIGN.md`    | The envelope model (section 4) defines the conceptual structure that this file format serializes. |
| `ENVELOPE.md`  | Defines the envelope schema, field semantics, canonicalization, and encryption model that `.semp` files contain. |
| `SESSION.md`   | Session key ephemerality (section 2) explains why `seal.session_mac` cannot be verified from a file at rest. |
| `KEY.md`       | Domain key publication (section 2) enables seal verification on `.semp` files by third parties. |
| `TRANSPORT.md` | Transport bindings (section 4) use `application/semp-envelope` as the content type for envelope transmission. |
| `EXTENSIONS.md`| Extension size limits (section 4) apply to envelopes within `.semp` files. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
