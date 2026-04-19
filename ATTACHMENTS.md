# SEMP Large Attachments

**Wire-level Extension: `semp.dev/large-attachment`**  
Status: Internet-Draft  
Version: 0.1.0  
Related: `ENVELOPE.md`, `EXTENSIONS.md`, `DISCOVERY.md`, `CLIENT.md`

---

## Abstract

This specification defines a wire-level SEMP extension for sending
attachments whose content is stored externally to the envelope. The
extension replaces inline attachment bytes with encrypted external blobs
and a pointer carrying the URL, ciphertext hash, and AEAD parameters.
The encryption key for each blob is derived deterministically from the
enclosure key, so that any recipient who can decrypt the enclosure can
also decrypt the blob.

---

## 1. Overview

### 1.1 Scope

Inline attachments carried in `enclosure.attachments[]` (`ENVELOPE.md`
section 6.3) are suitable for small content. Large content (images,
audio, video, multi-megabyte documents) bloats the envelope and stresses
transport. This extension allows such content to be carried by reference
to an external HTTPS location, while preserving the end-to-end
encryption and integrity guarantees of inline attachments.

### 1.2 Extension Identifier

The extension identifier is `semp.dev/large-attachment`. The canonical
definition document is served at
`https://semp.dev/extensions/large-attachment.json` per
`EXTENSIONS.md` section 6.1.

The extension occupies `enclosure.extensions` and is visible only to the
recipient client after enclosure decryption.

### 1.3 Relationship to Inline Attachments

An envelope MAY carry both inline attachments in
`enclosure.attachments[]` and external attachments in
`enclosure.extensions["semp.dev/large-attachment"]`. The two lists are
independent. A single attachment MUST NOT appear in both lists. Clients
display the union of both lists to the user.

---

## 2. Extension Schema

### 2.1 Extension Entry

```json
"enclosure": {
    "extensions": {
        "semp.dev/large-attachment": {
            "required": true,
            "data": {
                "items": [
                    { "...item schema (section 2.2)..." }
                ]
            }
        }
    }
}
```

The `required` flag MUST be `true` when the envelope's body references an
external attachment in a way that makes the envelope incomplete without
it. Clients composing such envelopes MUST set `required: true`.

The `required` flag MAY be `false` when external attachments are
auxiliary and the envelope is intelligible without them. In either case,
recipient clients that understand the extension MUST process external
attachments per this specification.

### 2.2 Item Schema

```json
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
```

### 2.3 Field Definitions

| Field             | Type      | Required | Description                                                                                |
|-------------------|-----------|----------|--------------------------------------------------------------------------------------------|
| `id`              | `string`  | Yes      | Unique attachment identifier within the envelope. ULID RECOMMENDED. Used as KDF input.     |
| `filename`        | `string`  | Yes      | Original filename. MUST NOT contain path separators.                                       |
| `mime_type`       | `string`  | Yes      | MIME type of the plaintext.                                                                |
| `plaintext_size`  | `integer` | Yes      | Size in bytes of the plaintext. Present so the client can render a progress indicator.     |
| `url`             | `string`  | Yes      | HTTPS URL from which the ciphertext is fetched.                                            |
| `ciphertext_hash` | `string`  | Yes      | Hash of the ciphertext bytes at the URL. Format: `algorithm:hex`.                          |
| `aead_algorithm`  | `string`  | Yes      | AEAD algorithm. MUST match one of the suites supported by the envelope's algorithm suite.  |
| `aead_nonce`      | `string`  | Yes      | Base64-encoded nonce for AEAD decryption. Nonce length is algorithm-defined.               |
| `extensions`      | `object`  | No       | Per-item extensions. Non-normative retrieval hints MAY appear here (bearer tokens, range-support flags). |

### 2.4 Uniqueness and Ordering

`id` MUST be unique across both `enclosure.attachments[]` and the
external item list. Clients MAY order the external items in any order;
order is not semantic.

---

## 3. Encryption

### 3.1 Per-Attachment Key Derivation

Each external attachment is encrypted under a key `K_attachment` derived
from the enclosure key `K_enclosure`:

```
K_attachment = HKDF-Expand(
    PRK  = K_enclosure,
    info = "semp-attachment:" || attachment_id,
    L    = length-of-K_enclosure
)
```

Where `||` denotes byte concatenation, `attachment_id` is the UTF-8 bytes
of the item's `id` field, and `L` matches the key length required by the
AEAD algorithm.

Any recipient that holds `K_enclosure` (wrapped for them in
`seal.enclosure_recipients`) can derive `K_attachment` for each external
attachment. No additional key wrapping is required in the seal.

### 3.2 AEAD Parameters

The `aead_algorithm` MUST be consistent with the envelope's negotiated
suite per `ENVELOPE.md` section 7.3. For the baseline suite
(`x25519-chacha20-poly1305`), the AEAD is `chacha20-poly1305` with a
12-byte nonce. For the post-quantum suite (`pq-kyber768-x25519`), the
AEAD is `xchacha20-poly1305` with a 24-byte nonce. Implementations MUST
validate the nonce length against the algorithm.

The associated data field for AEAD MUST be the canonical UTF-8 JSON
encoding of the item with `ciphertext_hash`, `aead_nonce`, and
`extensions` set to empty values (`""`, `""`, `{}`). Binding the item's
metadata into AEAD additional-data prevents an attacker from swapping
`filename` or `mime_type` while leaving the ciphertext intact.

### 3.3 Ciphertext Structure

The bytes stored at `url` are exactly the AEAD ciphertext output
(ciphertext concatenated with the authentication tag). No framing,
header, or length prefix is added. Streaming decryption MAY use
algorithm-specific chunked AEAD modes if both parties support them; such
modes MUST be declared via a suite identifier in `aead_algorithm` and
are outside the scope of this base specification.

---

## 4. Storage

### 4.1 URL Requirements

`url` MUST be an HTTPS URL. Plain HTTP MUST NOT be used. The scheme MUST
be `https`. The host MUST be a fully qualified domain name or an IPv6
literal in brackets; bare IPv4 literals MUST NOT be used.

The server at `url` MAY require authentication for retrieval. Bearer
tokens, signed query parameters, or other authentication schemes are
implementation-specific and MAY be carried in `item.extensions` as
retrieval hints.

### 4.2 Retention

The sender MUST ensure that the ciphertext remains retrievable at `url`
for the retention minimum. The retention minimum is:

```
retention_minimum = max(postmark.expires, upload_time + 30 days)
```

RECOMMENDED retention is 90 days after upload. Senders MAY retain longer.

If the sender cannot guarantee the retention minimum (for example, the
chosen storage provider enforces shorter lifetimes), the sender's client
MUST surface this to the user before composition, not after the
envelope has been sent.

### 4.3 Operator-Hosted Storage

A SEMP server operator MAY provide a blob-hosting service for their
users. When offered, the service is advertised via the
`attachment_storage` endpoint in the server's discovery configuration
(`DISCOVERY.md` section 3.1.1). Clients hosted by the operator SHOULD
prefer the operator's storage when the user has not configured a
different provider.

Operator-hosted storage MUST NOT be used as a covert channel. The
operator MUST NOT decrypt, scan, or inspect ciphertext content. Access
to stored ciphertext MUST be limited to the uploading user's authorized
clients and to parties possessing the `url` (which is carried in the
encrypted enclosure).

### 4.4 Third-Party and User Storage

The sender MAY use any HTTPS storage: a user-owned cloud bucket, a
third-party blob service, a self-hosted endpoint. The extension makes
no distinction. Security properties (confidentiality, integrity,
retention) are guaranteed by the AEAD encryption and ciphertext hash
regardless of the storage provider.

---

## 5. Upload Flow

The sender client:

1. Generates `attachment_id` (ULID RECOMMENDED).
2. Derives `K_attachment` from `K_enclosure` per section 3.1.
3. Generates a fresh nonce per the AEAD algorithm's requirements.
4. Constructs the item object with all fields except `ciphertext_hash`.
5. Computes AEAD additional-data from the item object per section 3.2.
6. Encrypts the plaintext under `K_attachment` with the nonce and
   additional-data to produce the ciphertext.
7. Computes `ciphertext_hash` over the ciphertext bytes.
8. Writes `ciphertext_hash` into the item object.
9. Uploads the ciphertext to the chosen storage, obtaining the final
   `url`.
10. Writes `url` into the item object.
11. Adds the item to the extension's `items` array.

Steps 9 and 10 MAY interleave with earlier steps if the storage
provider returns a pre-assigned URL before the ciphertext is uploaded.

---

## 6. Download and Decryption Flow

The recipient client:

1. Decrypts the envelope's enclosure per `ENVELOPE.md` section 7.2,
   obtaining `K_enclosure` and the enclosure plaintext.
2. Verifies `enclosure.sender_signature` per `ENVELOPE.md` section 6.5.3.
3. For each item in
   `enclosure.extensions["semp.dev/large-attachment"].data.items`:

   a. Derives `K_attachment` from `K_enclosure` and `item.id` per
      section 3.1.
   b. Fetches ciphertext bytes from `item.url` over HTTPS.
   c. Verifies `ciphertext_hash` against the fetched bytes. On hash
      mismatch, the client MUST NOT attempt decryption and MUST surface
      a ciphertext-integrity failure.
   d. Reconstructs AEAD additional-data per section 3.2.
   e. Decrypts the ciphertext under `K_attachment` with `aead_nonce`
      and additional-data. On AEAD authentication failure, the client
      MUST surface a decryption-integrity failure.
   f. Presents the plaintext to the user with the declared `filename`
      and `mime_type`, applying the same safety defaults as for inline
      attachments.

The client MAY perform steps 3.b through 3.e on demand (when the user
opens the attachment) or eagerly (during envelope open) per its own UX
policy.

---

## 7. Failure Handling

### 7.1 Fetch Failure

If a fetch of `item.url` fails (network error, HTTP 4xx or 5xx, timeout),
the recipient client MUST surface the failure to the user with the
`filename` for context. The client MUST NOT suppress the failure or
present the attachment as available.

The client MAY retry per its own policy. No normative retry schedule is
defined. Retries SHOULD respect any `Retry-After` header from the
storage provider.

### 7.2 Ciphertext Hash Mismatch

A ciphertext hash mismatch indicates the stored blob has been corrupted,
tampered with, or replaced. The client MUST treat the attachment as
unavailable, MUST NOT attempt decryption, and MUST surface an integrity
failure that distinguishes this case from a simple fetch failure.

### 7.3 AEAD Decryption Failure

AEAD decryption failure after a successful hash match indicates mismatch
between the ciphertext and the additional-data bound in the item
metadata. The client MUST treat the attachment as unavailable and MUST
surface the failure. This case is rare if the hash matches.

### 7.4 Retention Window Elapsed

If `postmark.expires` has passed and the sender's retention minimum has
elapsed, the storage provider MAY have deleted the blob. The client
MUST display this as a retention-elapsed state distinct from a transient
fetch failure when the fetch returns HTTP 404 or 410 and the envelope's
`postmark.expires` is in the past.

---

## 8. Security Considerations

### 8.1 Confidentiality

Confidentiality is provided by AEAD encryption under `K_attachment`.
`K_attachment` is derived from `K_enclosure`, which is wrapped only to
the recipient clients listed in `seal.enclosure_recipients`. The storage
provider, on-path observers, and non-recipient parties possessing the
`url` MUST NOT be able to recover plaintext.

### 8.2 Integrity

`ciphertext_hash` binds the URL to specific ciphertext bytes. An
attacker controlling the storage provider cannot substitute alternative
ciphertext without invalidating the hash. The hash is covered by the
enclosure's encryption and by `enclosure.sender_signature`, so an
attacker cannot substitute the hash itself without forging the sender
identity signature.

AEAD additional-data binds the item metadata (filename, mime_type,
url). An attacker that possesses the ciphertext but not the enclosure
cannot substitute a different filename or mime_type to cause confusion
in the recipient's client.

### 8.3 Per-Attachment Key Compartmentalization

Deriving `K_attachment` per attachment limits the blast radius of a
single-attachment key leak. Leaking one attachment's plaintext (for
example via a client bug that logs decrypted content) does not reveal
other attachments, the enclosure body, or the brief. A leak of
`K_enclosure` compromises everything, but `K_enclosure` is wrapped to
the same recipient clients and is not transmitted out of the client.

### 8.4 URL as Capability

Possessing the `url` is a capability to fetch the ciphertext. The
ciphertext is useless without `K_attachment`, which is derived from
`K_enclosure`. URL secrecy is therefore not load-bearing, but URL
enumeration resistance is still useful: storage providers SHOULD use
high-entropy path components to raise the cost of enumeration attacks.

### 8.5 Sender Repudiation

The sender's identity signature on the enclosure
(`enclosure.sender_signature`, `ENVELOPE.md` section 6.5) covers the
extension block including `ciphertext_hash` values. A sender cannot
credibly deny having authored an attachment whose hash is bound in
their signed enclosure.

### 8.6 Replay and Cross-Envelope Use

An attacker who obtains `K_attachment` for a specific item cannot use
it to decrypt other attachments or other envelopes, because the KDF
incorporates both `K_enclosure` and the attachment's `id`.
Cross-envelope reuse of the same `id` with the same `K_enclosure` is
prohibited (K_enclosure is unique per envelope per `CLIENT.md` section
3.1), so the derived key is unique per attachment per envelope.

---

## 9. Privacy Considerations

### 9.1 Storage Provider Visibility

The storage provider observes:

- The URL and the ciphertext bytes.
- The IP addresses and approximate timing of upload and download.
- The ciphertext size.

The storage provider does NOT observe:

- The plaintext content.
- The sender or recipient identity (unless they inspect the session
  establishing the upload or download).
- Which envelope references the blob.

Users sensitive to traffic-analysis exposure SHOULD use an anonymizing
transport (Tor or equivalent) for uploads and downloads against
untrusted storage providers.

### 9.2 Filename and Size Leakage

`filename`, `mime_type`, and `plaintext_size` are carried in the
enclosure plaintext and are therefore visible to the recipient client.
They are not visible to routing servers or to the storage provider.
Senders concerned about filename leakage to the recipient SHOULD rename
files before attaching.

### 9.3 Operator-Hosted Storage Correlation

When the recipient uses the same operator as the sender, and the
operator also hosts the blob storage, the operator can correlate
upload and download events with envelope transit. This correlation is
accepted as a local property of shared-operator deployments and is
mentioned here for transparency. Users who wish to avoid it SHOULD
choose storage providers distinct from their SEMP operator.

---

## 10. Conformance

### 10.1 Client Conformance

A client claiming `semp.dev/large-attachment` support MUST:

- Implement HKDF-Expand over the envelope's suite-bound hash function
  for `K_attachment` derivation (section 3.1).
- Implement the AEAD algorithm declared in `aead_algorithm`, bind
  additional-data per section 3.2, and verify authentication tags on
  decryption.
- Verify `ciphertext_hash` against fetched ciphertext before attempting
  decryption (section 6 step 3.c).
- Distinguish fetch failure, hash mismatch, and decryption failure in
  the user-facing error surface (section 7).
- Treat retention-elapsed state as distinct from transient fetch
  failure when appropriate (section 7.4).
- Guarantee the retention minimum when choosing a storage provider, or
  surface the shortfall to the user before send (section 4.2).
- Not use plain HTTP URLs (section 4.1).
- Not silently suppress fetch or decryption failures.

A client MAY:

- Perform eager or lazy fetches per its own policy.
- Implement retry with operator-chosen backoff.
- Use chunked AEAD modes declared via future suite identifiers.

### 10.2 Server Conformance

A SEMP server does not handle this extension directly; envelopes pass
through the standard pipeline. A server operator who hosts blob
storage MUST:

- Advertise the storage endpoint via the `attachment_storage` field in
  its discovery configuration (`DISCOVERY.md` section 3.1.1).
- Serve blobs over HTTPS.
- Not decrypt, scan, or inspect ciphertext content.
- Apply access controls that limit retrieval to the uploading user's
  authorized clients and to parties possessing the URL.
- Honor the retention minimum documented at the upload time.

---

## 11. Relationship to Other Specifications

| Specification    | Relationship                                                                                                  |
|------------------|---------------------------------------------------------------------------------------------------------------|
| `ENVELOPE.md`    | Extension occupies `enclosure.extensions`. `K_attachment` derives from `K_enclosure`. Sender signature covers the extension block. |
| `EXTENSIONS.md`  | Registered under `semp.dev/large-attachment`. Definition document at the canonical URL per section 6.1.       |
| `DISCOVERY.md`   | The `attachment_storage` endpoint is advertised by operators offering blob hosting for their users.           |
| `CLIENT.md`      | Composition per section 3 of this document integrates with the envelope composition sequence (`CLIENT.md` §3.1). |
| `CONFORMANCE.md` | Client and server conformance bullets are referenced from `CONFORMANCE.md`.                                   |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
